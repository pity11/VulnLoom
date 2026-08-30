"""Fail-closed Tool Broker orchestration and typed HTTP policy enforcement."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from urllib.parse import urljoin, urlsplit

from pydantic import ValidationError

from vulnloom.domain.models import ApprovalRequest, Scope
from vulnloom.domain.protocol import WorkerRole
from vulnloom.policy.engine import ActionRequest, DecisionEffect, PolicyEngine
from vulnloom.runners.models import NetworkMode, SandboxProfileKind, sandbox_profile_digest

from .http import HostResolver, HttpTransport, HttpWireRequest
from .models import (
    BrokerCall,
    BrokerResult,
    BrokerStatus,
    HttpRequestPlan,
    HttpToolResult,
    PolicyRecord,
    RedirectRecord,
    broker_call_digest,
    url_digest,
)
from .registry import ToolRegistry


class BrokerRejected(ValueError):
    """A malformed or untrusted call failed before tool execution."""


class BrokerIdempotencyConflict(ValueError):
    """A Broker idempotency key was reused for a different call."""


_KNOWN_METADATA_IPS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)


class ToolBroker:
    def __init__(
        self,
        *,
        scope: Scope,
        registry: ToolRegistry,
        resolver: HostResolver,
        http_transport: HttpTransport,
        blocked_ips: frozenset[str] = frozenset(),
    ):
        self.scope = scope
        self.policy = PolicyEngine(scope)
        self.registry = registry
        self.resolver = resolver
        self.http_transport = http_transport
        self.blocked_ips = frozenset(
            str(ipaddress.ip_address(item)) for item in blocked_ips | _KNOWN_METADATA_IPS
        )
        self._results: dict[str, tuple[str, BrokerResult]] = {}

    def execute(
        self,
        call: BrokerCall,
        *,
        now: datetime,
        approvals: tuple[ApprovalRequest, ...] = (),
    ) -> BrokerResult:
        try:
            call = BrokerCall.model_validate(call.model_dump(mode="python"))
        except ValidationError as exc:
            raise BrokerRejected("Broker call failed boundary validation") from exc
        registration = self._preflight(call)
        digest = broker_call_digest(call)
        existing = self._results.get(call.idempotency_key)
        if existing is not None:
            if existing[0] != digest:
                raise BrokerIdempotencyConflict(
                    "Broker idempotency key was reused with a different call"
                )
            return existing[1]
        if now >= call.task.deadline:
            return self._store(
                call,
                digest,
                BrokerStatus.TIMED_OUT,
                now,
                error_codes=("task_deadline_exceeded",),
            )
        if call.http.credential_ref and not registration.accepts_credential_ref:
            raise BrokerRejected("registered tool does not accept credential references")
        return self._execute_http(call, digest, now, approvals)

    def _preflight(self, call: BrokerCall):
        try:
            registration = self.registry.require(call.tool_id)
        except ValueError as exc:
            raise BrokerRejected("tool is absent from the trusted registry") from exc
        profile_digest = sandbox_profile_digest(call.profile)
        if call.task.sandbox_profile_digest != profile_digest:
            raise BrokerRejected("TaskEnvelope is bound to another SandboxProfile")
        if (
            call.task.scope_id != self.scope.scope_id
            or call.task.scope_version != self.scope.version
        ):
            raise BrokerRejected("TaskEnvelope is bound to another Scope version")
        if call.task.engagement_id != self.scope.engagement_id:
            raise BrokerRejected("TaskEnvelope is bound to another Engagement")
        if call.task.policy_digest != self.policy.policy_digest:
            raise BrokerRejected("TaskEnvelope policy digest does not match current Scope policy")
        if call.task.tool_registry_digest != self.registry.digest:
            raise BrokerRejected("TaskEnvelope is bound to another Tool Registry")
        if (
            call.tool_id not in call.task.allowed_tools
            or call.tool_id not in call.profile.allowed_tools
        ):
            raise BrokerRejected("tool is not allowed by both TaskEnvelope and SandboxProfile")
        if call.profile.kind not in registration.allowed_profiles:
            raise BrokerRejected("tool registration does not allow this SandboxProfile kind")
        if registration.capability.value != "http_request":
            raise BrokerRejected("typed HTTP call requires an HTTP tool registration")
        if call.task.worker_role is not WorkerRole.VALIDATOR:
            raise BrokerRejected("typed HTTP calls are restricted to Validator Workers")
        if registration.requires_network and (
            call.profile.kind is not SandboxProfileKind.VALIDATION
            or call.profile.network_mode is not NetworkMode.TARGET_ONLY
        ):
            raise BrokerRejected("network tool requires a target-only Validation Profile")
        if call.task.budget.tool_calls < 1:
            raise BrokerRejected("TaskEnvelope has no tool-call budget")
        return registration

    def _execute_http(self, call, digest, now, approvals):
        current = call.http.url
        records = []
        redirects = []
        evidence = []
        total_elapsed = 0.0
        total_bytes = 0
        requests = 0
        while True:
            if requests >= min(call.http.limits.max_requests, call.task.budget.tool_calls):
                return self._store(
                    call,
                    digest,
                    BrokerStatus.FAILED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("http_request_budget_exhausted",),
                )
            action = self._action(call, current, now)
            decision = self.policy.decide(action, approvals)
            records.append(
                PolicyRecord(
                    action_digest=action.digest(),
                    effect=decision.effect,
                    reasons=decision.reasons,
                    obligations=decision.obligations,
                    policy_digest=decision.policy_digest,
                )
            )
            if decision.effect is not DecisionEffect.ALLOW:
                status = (
                    BrokerStatus.APPROVAL_REQUIRED
                    if decision.effect is DecisionEffect.APPROVAL_REQUIRED
                    else BrokerStatus.DENIED
                )
                return self._store(
                    call,
                    digest,
                    status,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("scope_policy_not_satisfied",),
                )
            parsed = urlsplit(current)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if not any(
                parsed.hostname == grant.host
                and port in grant.ports
                and parsed.scheme in grant.schemes
                for grant in call.profile.network_grants
            ):
                return self._store(
                    call,
                    digest,
                    BrokerStatus.DENIED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("sandbox_network_grant_not_satisfied",),
                )
            addresses = self.resolver.resolve(parsed.hostname or "")
            if not addresses:
                return self._store(
                    call,
                    digest,
                    BrokerStatus.DENIED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("dns_resolution_failed",),
                )
            normalized = self._validated_addresses(addresses)
            if normalized is None:
                return self._store(
                    call,
                    digest,
                    BrokerStatus.DENIED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("resolved_address_forbidden",),
                )
            pinned_ip = sorted(normalized)[0]
            requests += 1
            try:
                hop = self.http_transport.send(
                    HttpWireRequest(
                        method=call.http.method,
                        url=current,
                        pinned_ip=pinned_ip,
                        headers=call.http.headers,
                        credential_ref=call.http.credential_ref,
                        body_ref=call.http.body_ref,
                        body_bytes=call.http.body_bytes,
                        connect_seconds=call.http.limits.connect_seconds,
                        read_seconds=call.http.limits.read_seconds,
                        max_response_bytes=call.http.limits.max_response_bytes,
                    )
                )
            except (OSError, TimeoutError, RuntimeError):
                return self._store(
                    call,
                    digest,
                    BrokerStatus.FAILED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("http_transport_failed",),
                )
            total_elapsed += hop.elapsed_seconds
            total_bytes += hop.response_bytes
            if hop.peer_ip != pinned_ip:
                return self._store(
                    call,
                    digest,
                    BrokerStatus.DENIED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("http_peer_ip_mismatch",),
                )
            if (
                total_elapsed > call.http.limits.total_seconds
                or now.timestamp() + total_elapsed >= call.task.deadline.timestamp()
            ):
                return self._store(
                    call,
                    digest,
                    BrokerStatus.TIMED_OUT,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("http_total_timeout",),
                )
            if total_bytes > call.http.limits.max_response_bytes:
                return self._store(
                    call,
                    digest,
                    BrokerStatus.FAILED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("http_response_size_exceeded",),
                )
            evidence.append(hop.evidence_ref)
            if hop.location is None:
                output = HttpToolResult(
                    status_code=hop.status_code,
                    final_url_digest=url_digest(current),
                    peer_ip=hop.peer_ip,
                    response_bytes=total_bytes,
                    redirects=tuple(redirects),
                    evidence_refs=tuple(evidence),
                )
                return self._store(
                    call,
                    digest,
                    BrokerStatus.COMPLETED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    http=output,
                )
            if call.http.credential_ref is not None:
                return self._store(
                    call,
                    digest,
                    BrokerStatus.DENIED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("credentialed_redirect_forbidden",),
                )
            if not call.http.follow_redirects or len(redirects) >= call.http.limits.max_redirects:
                return self._store(
                    call,
                    digest,
                    BrokerStatus.DENIED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("http_redirect_not_allowed",),
                )
            try:
                target = HttpRequestPlan.safe_url(urljoin(current, hop.location))
            except (ValueError, ValidationError):
                return self._store(
                    call,
                    digest,
                    BrokerStatus.DENIED,
                    now,
                    policy_records=tuple(records),
                    tool_calls_used=requests,
                    error_codes=("http_redirect_url_invalid",),
                )
            redirects.append(
                RedirectRecord(
                    status_code=hop.status_code,
                    from_url_digest=url_digest(current),
                    to_url_digest=url_digest(target),
                    peer_ip=hop.peer_ip,
                )
            )
            current = target

    def _action(self, call: BrokerCall, url: str, now: datetime) -> ActionRequest:
        return ActionRequest(
            engagement_id=call.task.engagement_id,
            target_id=call.task.target_id,
            action=call.tool_id,
            requested_at=now,
            url=url,
            test_class=call.http.test_class,
            mutates_state=call.http.method.mutates_state,
            uses_real_credentials=call.http.credential_ref is not None,
        )

    def _validated_addresses(self, addresses):
        if len(addresses) > 32:
            return None
        normalized = set()
        try:
            for value in addresses:
                address = ipaddress.ip_address(value)
                text = str(address)
                if (
                    text in self.blocked_ips
                    or address.is_loopback
                    or address.is_link_local
                    or address.is_multicast
                    or address.is_unspecified
                ):
                    return None
                normalized.add(text)
        except ValueError:
            return None
        return frozenset(normalized) if normalized else None

    def _store(
        self,
        call,
        digest,
        status,
        now,
        *,
        policy_records=(),
        tool_calls_used=0,
        http=None,
        error_codes=(),
    ):
        result = BrokerResult(
            call_id=call.call_id,
            task_id=call.task.task_id,
            tool_id=call.tool_id,
            status=status,
            registry_digest=self.registry.digest,
            call_digest=digest,
            tool_calls_used=tool_calls_used,
            policy_records=policy_records,
            http=http,
            error_codes=error_codes,
            completed_at=now,
        )
        self._results[call.idempotency_key] = (digest, result)
        return result
