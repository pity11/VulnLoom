"""Trusted, explicitly admitted HTTP HEAD adapter for isolated local fixtures."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Annotated, Self
from urllib.parse import urlsplit

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
from vulnloom.broker.registry import pinned_http_tool_registry
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkMode, SandboxProfile, sandbox_profile_digest

from .models import (
    AttackSurfaceSnapshot,
    Digest,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamFlowPlan,
    RedTeamReconAction,
    RedTeamReconObservation,
)
from .service import RedTeamAdapterInterrupted, RedTeamRejected


class IsolatedLocalReconAdmission(DomainModel):
    """Exact, expiring admission for a non-loopback private test fixture."""

    admission_id: Digest
    fixture_ref: str = Field(pattern=r"^fixture:[a-zA-Z0-9._-]{1,200}$")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    scheme: str = Field(pattern=r"^https?$")
    allowed_peer_ips: Annotated[tuple[str, ...], Field(min_length=1, max_length=8)]
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
                raise ValueError("local Recon admission requires private non-loopback IPv4")
            normalized.append(str(address))
        if tuple(sorted(set(normalized))) != self.allowed_peer_ips:
            raise ValueError("local Recon peer IPs must be normalized, sorted, and unique")
        if self.host != self.host.lower():
            raise ValueError("local Recon admission host must be lowercase")
        if self.admission_id != canonical_digest(
            self.model_dump(mode="python", exclude={"admission_id"})
        ):
            raise ValueError("local Recon admission content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> IsolatedLocalReconAdmission:
        expanded = cls.model_construct(admission_id="0" * 64, **values).model_dump(
            mode="python", exclude={"admission_id"}
        )
        return cls(admission_id=canonical_digest(expanded), **expanded)


class IsolatedLocalHttpReconAdapter:
    """Route one HEAD action through the pinned Broker under exact local admission."""

    def __init__(
        self,
        *,
        plan: RedTeamFlowPlan,
        broker: ToolBroker,
        profile: SandboxProfile,
        admission: IsolatedLocalReconAdmission,
        evidence_store: EvidenceStore,
        connect_seconds: float = 2.0,
        read_seconds: float = 2.0,
        max_redirects: int = 2,
    ):
        self.plan = RedTeamFlowPlan.model_validate(plan.model_dump(mode="python"))
        self.broker = broker
        self.profile = SandboxProfile.model_validate(profile.model_dump(mode="python"))
        self.admission = IsolatedLocalReconAdmission.model_validate(
            admission.model_dump(mode="python")
        )
        self.evidence_store = evidence_store
        try:
            limits = HttpLimits(
                connect_seconds=connect_seconds,
                read_seconds=read_seconds,
                total_seconds=120,
                max_response_bytes=64 * 1024,
                max_redirects=max_redirects,
                max_requests=max_redirects + 1,
            )
        except ValueError as exc:
            raise RedTeamRejected("isolated local Recon limits are invalid") from exc
        self.connect_seconds = limits.connect_seconds
        self.read_seconds = limits.read_seconds
        self.max_redirects = limits.max_redirects
        self.calls = 0
        self._preflight_static()

    def execute(
        self, action: RedTeamReconAction, *, now: datetime
    ) -> RedTeamReconObservation:
        self.calls += 1
        if now >= self.admission.expires_at:
            return self._rejected(action, now=now, reason="local_admission_expired")
        if action.plan_id != self.plan.plan_id or action.kind is not RedTeamActionKind.HTTP_HEAD:
            return self._rejected(action, now=now, reason="local_action_not_admitted")
        task = TaskEnvelope(
            engagement_id=self.broker.scope.engagement_id,
            target_id=self.plan.target.target_id,
            target_version=self.plan.plan_id,
            scope_id=self.broker.scope.scope_id,
            worker_role=WorkerRole.VALIDATOR,
            scope_version=self.broker.scope.version,
            policy_digest=PolicyEngine(self.broker.scope).policy_digest,
            sandbox_profile_digest=sandbox_profile_digest(self.profile),
            tool_registry_digest=self.broker.registry.digest,
            input_refs=(
                f"red-team-plan:{self.plan.plan_id}",
                f"red-team-action:{action.action_id}",
            ),
            allowed_tools=frozenset({"http.request"}),
            budget=TaskBudget(
                wall_seconds=max(1, int((action.deadline - now).total_seconds())),
                model_tokens=0,
                tool_calls=self.max_redirects + 1,
            ),
            deadline=action.deadline,
            idempotency_key=f"red-team-task:{action.action_id}",
        )
        call = BrokerCall(
            task=task,
            profile=self.profile,
            tool_id="http.request",
            http=HttpRequestPlan(
                method=HttpMethod.HEAD,
                url=action.target_url,
                test_class=action.test_class,
                follow_redirects=self.max_redirects > 0,
                limits=HttpLimits(
                    connect_seconds=self.connect_seconds,
                    read_seconds=self.read_seconds,
                    total_seconds=min(
                        120.0, max(0.001, (action.deadline - now).total_seconds())
                    ),
                    max_response_bytes=64 * 1024,
                    max_redirects=self.max_redirects,
                    max_requests=self.max_redirects + 1,
                ),
            ),
            idempotency_key=f"red-team-broker:{action.action_id}",
        )
        try:
            result = self.broker.execute(call, now=now)
        except (ValueError, RuntimeError) as exc:
            raise RedTeamAdapterInterrupted("trusted HTTP Recon adapter interrupted") from exc
        if result.status is BrokerStatus.COMPLETED:
            assert result.http is not None
            if not result.http.evidence_refs or not all(
                self.evidence_store.contains(item) for item in result.http.evidence_refs
            ):
                return self._observation(
                    action,
                    now=result.completed_at,
                    outcome=ReconOutcome.FAILED,
                    reason="evidence_integrity_failed",
                )
            surface = AttackSurfaceSnapshot.create(
                plan_id=self.plan.plan_id,
                action_id=action.action_id,
                target_id=self.plan.target.target_id,
                scope_id=self.broker.scope.scope_id,
                scope_version=self.broker.scope.version,
                requested_url_digest=url_digest(action.target_url),
                final_url_digest=result.http.final_url_digest,
                status_code=result.http.status_code,
                peer_ip=result.http.peer_ip,
                redirect_count=len(result.http.redirects),
                evidence_refs=result.http.evidence_refs,
                policy_record_digests=tuple(
                    canonical_digest(record.model_dump(mode="python"))
                    for record in result.policy_records
                ),
                captured_at=result.completed_at,
            )
            return RedTeamReconObservation.create(
                action_id=action.action_id,
                outcome=ReconOutcome.SUCCEEDED,
                status_code=result.http.status_code,
                reason_code="live_http_head_succeeded",
                cleanup_complete=True,
                sensitive_data_redacted=True,
                attack_surface=surface,
                observed_at=result.completed_at,
            )
        outcome = {
            BrokerStatus.DENIED: ReconOutcome.REJECTED,
            BrokerStatus.APPROVAL_REQUIRED: ReconOutcome.REJECTED,
            BrokerStatus.TIMED_OUT: ReconOutcome.TIMED_OUT,
            BrokerStatus.FAILED: ReconOutcome.FAILED,
        }[result.status]
        reason = result.error_codes[0] if result.error_codes else "broker_rejected"
        return self._observation(
            action,
            now=result.completed_at,
            outcome=outcome,
            reason=f"broker.{reason}",
        )

    def _preflight_static(self) -> None:
        parsed = urlsplit(self.plan.target.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        exact_grant = (
            len(self.profile.network_grants) == 1
            and self.profile.network_mode is NetworkMode.TARGET_ONLY
            and self.profile.network_grants[0].host == self.admission.host
            and self.profile.network_grants[0].ports == frozenset({self.admission.port})
            and self.profile.network_grants[0].schemes == frozenset({self.admission.scheme})
        )
        if (
            parsed.hostname != self.admission.host
            or port != self.admission.port
            or parsed.scheme != self.admission.scheme
            or not exact_grant
            or self.broker.registry.digest != pinned_http_tool_registry().digest
            or self.broker.allowed_resolved_ips != frozenset(self.admission.allowed_peer_ips)
        ):
            raise RedTeamRejected("isolated local Recon admission binding is invalid")

    @classmethod
    def _rejected(
        cls, action: RedTeamReconAction, *, now: datetime, reason: str
    ) -> RedTeamReconObservation:
        return cls._observation(
            action, now=now, outcome=ReconOutcome.REJECTED, reason=reason
        )

    @staticmethod
    def _observation(
        action: RedTeamReconAction,
        *,
        now: datetime,
        outcome: ReconOutcome,
        reason: str,
    ) -> RedTeamReconObservation:
        return RedTeamReconObservation.create(
            action_id=action.action_id,
            outcome=outcome,
            status_code=None,
            reason_code=reason,
            cleanup_complete=True,
            sensitive_data_redacted=True,
            observed_at=now,
        )
