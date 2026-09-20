"""Trusted HTTP execution boundary for an explicitly admitted local attack chain."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Annotated, Self
from urllib.parse import urlunsplit

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.broker import (
    BrokerCall,
    BrokerStatus,
    HttpLimits,
    HttpMethod,
    HttpRequestPlan,
    ToolBroker,
)
from vulnloom.broker.models import url_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalRequest, DomainModel
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkMode, SandboxProfile, sandbox_profile_digest
from vulnloom.runners.models import SandboxProfileKind

from .attack_models import (
    AttackAction,
    AttackActionCommand,
    AttackActionKind,
    AttackActionObservation,
    AttackActionOutcome,
    AttackChainPlan,
    Digest,
)
from .attack_service import AttackActionAdapterInterrupted, AttackChainRejected

_METHODS = {
    AttackActionKind.INITIAL_ACCESS_ATTEMPT: HttpMethod.POST,
    AttackActionKind.VERIFY_TEST_SESSION: HttpMethod.GET,
    AttackActionKind.VERIFY_OBJECTIVE: HttpMethod.GET,
    AttackActionKind.CLEANUP_TEST_SESSION: HttpMethod.DELETE,
}


class AttackActionHttpBinding(DomainModel):
    """Expected wire result without retaining a full endpoint or response body."""

    binding_id: Digest
    action_id: Digest
    method: HttpMethod
    url_digest: Digest
    expected_status_code: int = Field(ge=100, le=599)
    expected_content_sha256: Digest

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.binding_id != canonical_digest(
            self.model_dump(mode="python", exclude={"binding_id"})
        ):
            raise ValueError("Attack Action HTTP binding digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackActionHttpBinding:
        expanded = cls.model_construct(binding_id="0" * 64, **values).model_dump(
            mode="python", exclude={"binding_id"}
        )
        return cls(binding_id=canonical_digest(expanded), **expanded)


class IsolatedAttackChainAdmission(DomainModel):
    """Exact, expiring admission for one private non-loopback fixture chain."""

    admission_id: Digest
    chain_plan_id: Digest
    graph_id: Digest
    fixture_ref: str = Field(pattern=r"^fixture:[a-zA-Z0-9._-]{1,200}$")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    scheme: str = Field(pattern=r"^https?$")
    allowed_peer_ips: Annotated[tuple[str, ...], Field(min_length=1, max_length=8)]
    action_bindings: Annotated[
        tuple[AttackActionHttpBinding, ...], Field(min_length=3, max_length=32)
    ]
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        normalized: list[str] = []
        for value in self.allowed_peer_ips:
            address = ipaddress.ip_address(value)
            if (
                address.version != 4
                or not address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
            ):
                raise ValueError("Attack Chain admission requires private non-loopback IPv4")
            normalized.append(str(address))
        if tuple(sorted(set(normalized))) != self.allowed_peer_ips:
            raise ValueError("Attack Chain peer IPs must be normalized, sorted, and unique")
        if self.host != self.host.lower():
            raise ValueError("Attack Chain admission host must be lowercase")
        if len({binding.action_id for binding in self.action_bindings}) != len(
            self.action_bindings
        ):
            raise ValueError("Attack Chain admission bindings must be unique")
        if self.admission_id != canonical_digest(
            self.model_dump(mode="python", exclude={"admission_id"})
        ):
            raise ValueError("Attack Chain admission content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> IsolatedAttackChainAdmission:
        expanded = cls.model_construct(admission_id="0" * 64, **values).model_dump(
            mode="python", exclude={"admission_id"}
        )
        return cls(admission_id=canonical_digest(expanded), **expanded)


class IsolatedLocalAttackChainAdapter:
    """Execute only sealed actions through a pinned, target-only Tool Broker."""

    def __init__(
        self,
        *,
        plan: AttackChainPlan,
        broker: ToolBroker,
        profile: SandboxProfile,
        admission: IsolatedAttackChainAdmission,
        evidence_store: EvidenceStore,
        connect_seconds: float = 2.0,
        read_seconds: float = 2.0,
    ) -> None:
        self.plan = AttackChainPlan.model_validate(plan.model_dump(mode="python"))
        self.broker = broker
        self.profile = SandboxProfile.model_validate(profile.model_dump(mode="python"))
        self.admission = IsolatedAttackChainAdmission.model_validate(
            admission.model_dump(mode="python")
        )
        self.evidence_store = evidence_store
        self.limits = HttpLimits(
            connect_seconds=connect_seconds,
            read_seconds=read_seconds,
            total_seconds=30,
            max_response_bytes=64 * 1024,
            max_redirects=0,
            max_requests=1,
        )
        self.calls = 0
        self._bindings = {item.action_id: item for item in self.admission.action_bindings}
        self._preflight_static()

    def execute(
        self,
        command: AttackActionCommand,
        action: AttackAction,
        *,
        approvals: tuple[ApprovalRequest, ...],
        now: datetime,
    ) -> AttackActionObservation:
        self.calls += 1
        if now >= self.admission.expires_at:
            return self._result(
                action, command, now, AttackActionOutcome.REJECTED, "admission_expired"
            )
        binding = self._bindings.get(action.action_id)
        url = self._url(action)
        if (
            command.chain_plan_id != self.plan.chain_plan_id
            or command.action_id != action.action_id
            or action not in self.plan.graph.actions
            or binding is None
            or binding.method is not _METHODS[action.kind]
            or binding.url_digest != url_digest(url)
        ):
            return self._result(
                action, command, now, AttackActionOutcome.REJECTED, "action_not_admitted"
            )
        cutoff = (
            self.plan.cleanup_deadline
            if action.kind is AttackActionKind.CLEANUP_TEST_SESSION
            else self.plan.deadline
        )
        remaining = (cutoff - now).total_seconds()
        if remaining <= 0:
            return self._result(
                action, command, now, AttackActionOutcome.TIMED_OUT, "chain_deadline_exceeded"
            )
        task = TaskEnvelope(
            engagement_id=self.broker.scope.engagement_id,
            target_id=self.plan.graph.target_id,
            target_version=self.plan.graph.graph_id,
            scope_id=self.broker.scope.scope_id,
            worker_role=WorkerRole.VALIDATOR,
            scope_version=self.broker.scope.version,
            policy_digest=PolicyEngine(self.broker.scope).policy_digest,
            sandbox_profile_digest=sandbox_profile_digest(self.profile),
            tool_registry_digest=self.broker.registry.digest,
            input_refs=(
                f"attack-chain:{self.plan.chain_plan_id}",
                f"attack-command:{command.command_id}",
                f"attack-action:{action.action_id}",
            ),
            allowed_tools=frozenset({"http.request"}),
            budget=TaskBudget(wall_seconds=max(1, int(remaining)), model_tokens=0, tool_calls=1),
            deadline=cutoff,
            idempotency_key=f"attack-task:{command.command_id}",
        )
        call = BrokerCall(
            task=task,
            profile=self.profile,
            tool_id="http.request",
            http=HttpRequestPlan(
                method=binding.method,
                url=url,
                test_class=action.test_class,
                headers=(),
                credential_ref=None,
                body_ref=None,
                body_bytes=0,
                follow_redirects=False,
                limits=self.limits.model_copy(
                    update={"total_seconds": min(30.0, max(0.001, remaining))}
                ),
            ),
            idempotency_key=f"attack-broker:{command.command_id}",
        )
        try:
            broker_result = self.broker.execute(call, now=now, approvals=approvals)
        except (ValueError, RuntimeError) as exc:
            raise AttackActionAdapterInterrupted(
                "trusted Attack Chain adapter interrupted"
            ) from exc
        if broker_result.status is BrokerStatus.COMPLETED:
            assert broker_result.http is not None
            output = broker_result.http
            if (
                output.final_url_digest != binding.url_digest
                or output.status_code != binding.expected_status_code
                or output.response_body_sha256 != binding.expected_content_sha256
                or output.peer_ip not in self.admission.allowed_peer_ips
                or not output.evidence_refs
                or not all(self.evidence_store.contains(item) for item in output.evidence_refs)
            ):
                return self._result(
                    action,
                    command,
                    broker_result.completed_at,
                    AttackActionOutcome.FAILED,
                    "response_attestation_failed",
                )
            return AttackActionObservation.create(
                command_id=command.command_id,
                action_id=action.action_id,
                outcome=AttackActionOutcome.SUCCEEDED,
                reason_code="admitted_http_action_succeeded",
                evidence_refs=output.evidence_refs,
                goal_reached=action.kind is AttackActionKind.VERIFY_OBJECTIVE,
                cleanup_complete=True,
                sensitive_data_redacted=True,
                observed_at=broker_result.completed_at,
            )
        outcome = {
            BrokerStatus.TIMED_OUT: AttackActionOutcome.TIMED_OUT,
            BrokerStatus.DENIED: AttackActionOutcome.REJECTED,
            BrokerStatus.APPROVAL_REQUIRED: AttackActionOutcome.REJECTED,
            BrokerStatus.FAILED: AttackActionOutcome.FAILED,
        }[broker_result.status]
        reason = {
            BrokerStatus.TIMED_OUT: "broker_timed_out",
            BrokerStatus.DENIED: "broker_denied",
            BrokerStatus.APPROVAL_REQUIRED: "broker_approval_required",
            BrokerStatus.FAILED: "broker_failed",
        }[broker_result.status]
        return self._result(action, command, broker_result.completed_at, outcome, reason)

    def _preflight_static(self) -> None:
        grants = self.profile.network_grants
        expected_actions = tuple(action.action_id for action in self.plan.graph.actions)
        scope_target_admitted = any(
            item.host == self.admission.host
            and self.admission.port in item.ports
            and self.admission.scheme in item.schemes
            for item in self.broker.scope.network_targets
        )
        if (
            self.admission.chain_plan_id != self.plan.chain_plan_id
            or self.admission.graph_id != self.plan.graph.graph_id
            or not scope_target_admitted
            or tuple(item.action_id for item in self.admission.action_bindings) != expected_actions
            or self.profile.kind is not SandboxProfileKind.VALIDATION
            or self.profile.network_mode is not NetworkMode.TARGET_ONLY
            or len(grants) != 1
            or grants[0].host != self.admission.host
            or grants[0].ports != {self.admission.port}
            or grants[0].schemes != {self.admission.scheme}
            or self.broker.allowed_resolved_ips != frozenset(self.admission.allowed_peer_ips)
            or self.admission.expires_at > self.plan.cleanup_deadline
        ):
            raise AttackChainRejected("isolated Attack Chain admission is invalid")
        for action, binding in zip(
            self.plan.graph.actions, self.admission.action_bindings, strict=True
        ):
            if binding.method is not _METHODS[action.kind] or binding.url_digest != url_digest(
                self._url(action)
            ):
                raise AttackChainRejected("isolated Attack Chain binding is invalid")

    def _url(self, action: AttackAction) -> str:
        default_port = 443 if self.admission.scheme == "https" else 80
        netloc = self.admission.host
        if self.admission.port != default_port:
            netloc = f"{netloc}:{self.admission.port}"
        return urlunsplit((self.admission.scheme, netloc, action.target_path, "", ""))

    @staticmethod
    def _result(
        action: AttackAction,
        command: AttackActionCommand,
        now: datetime,
        outcome: AttackActionOutcome,
        reason: str,
    ) -> AttackActionObservation:
        return AttackActionObservation.create(
            command_id=command.command_id,
            action_id=action.action_id,
            outcome=outcome,
            reason_code=reason,
            cleanup_complete=False,
            sensitive_data_redacted=True,
            observed_at=now,
        )
