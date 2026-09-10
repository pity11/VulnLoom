"""Trusted TLS identity adapter for an explicitly admitted isolated local fixture."""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from vulnloom.broker import (
    BrokerCall,
    BrokerStatus,
    TlsInspectionLimits,
    TlsInspectionPlan,
    ToolBroker,
    pinned_tls_tool_registry,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkMode, SandboxProfile, sandbox_profile_digest

from .live_http import IsolatedLocalReconAdmission
from .models import (
    ReconOutcome,
    RedTeamActionKind,
    RedTeamFlowPlan,
    RedTeamReconAction,
    RedTeamReconObservation,
    ServiceIdentitySnapshot,
    ServiceTlsVersion,
)
from .service import RedTeamAdapterInterrupted, RedTeamRejected


class IsolatedLocalTlsReconAdapter:
    """Route one TLS identity action through a pinned, verified Broker transport."""

    def __init__(
        self,
        *,
        plan: RedTeamFlowPlan,
        broker: ToolBroker,
        profile: SandboxProfile,
        admission: IsolatedLocalReconAdmission,
        evidence_store: EvidenceStore,
        connect_seconds: float = 2.0,
        handshake_seconds: float = 3.0,
    ):
        self.plan = RedTeamFlowPlan.model_validate(plan.model_dump(mode="python"))
        self.broker = broker
        self.profile = SandboxProfile.model_validate(profile.model_dump(mode="python"))
        self.admission = IsolatedLocalReconAdmission.model_validate(
            admission.model_dump(mode="python")
        )
        self.evidence_store = evidence_store
        try:
            limits = TlsInspectionLimits(
                connect_seconds=connect_seconds,
                handshake_seconds=handshake_seconds,
                total_seconds=60,
            )
        except ValueError as exc:
            raise RedTeamRejected("isolated local TLS limits are invalid") from exc
        self.connect_seconds = limits.connect_seconds
        self.handshake_seconds = limits.handshake_seconds
        self.calls = 0
        self._preflight_static()

    def execute(
        self, action: RedTeamReconAction, *, now: datetime
    ) -> RedTeamReconObservation:
        self.calls += 1
        if now >= self.admission.expires_at:
            return self._observation(
                action, now=now, outcome=ReconOutcome.REJECTED,
                reason="local_admission_expired"
            )
        if action.plan_id != self.plan.plan_id or action.kind is not RedTeamActionKind.TLS_INSPECT:
            return self._observation(
                action, now=now, outcome=ReconOutcome.REJECTED,
                reason="local_tls_action_not_admitted"
            )
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
            allowed_tools=frozenset({"tls.inspect"}),
            budget=TaskBudget(
                wall_seconds=max(1, int((action.deadline - now).total_seconds())),
                model_tokens=0,
                tool_calls=1,
            ),
            deadline=action.deadline,
            idempotency_key=f"red-team-tls-task:{action.action_id}",
        )
        call = BrokerCall(
            task=task,
            profile=self.profile,
            tool_id="tls.inspect",
            tls=TlsInspectionPlan(
                url=action.target_url,
                test_class=action.test_class,
                limits=TlsInspectionLimits(
                    connect_seconds=self.connect_seconds,
                    handshake_seconds=self.handshake_seconds,
                    total_seconds=min(
                        60.0, max(0.001, (action.deadline - now).total_seconds())
                    ),
                ),
            ),
            idempotency_key=f"red-team-tls-broker:{action.action_id}",
        )
        try:
            result = self.broker.execute(call, now=now)
        except (ValueError, RuntimeError) as exc:
            raise RedTeamAdapterInterrupted("trusted TLS Recon adapter interrupted") from exc
        if result.status is BrokerStatus.COMPLETED:
            assert result.tls is not None
            if not all(self.evidence_store.contains(item) for item in result.tls.evidence_refs):
                return self._observation(
                    action, now=result.completed_at, outcome=ReconOutcome.FAILED,
                    reason="evidence_integrity_failed"
                )
            identity = ServiceIdentitySnapshot.create(
                plan_id=self.plan.plan_id,
                action_id=action.action_id,
                target_id=self.plan.target.target_id,
                scope_id=self.broker.scope.scope_id,
                scope_version=self.broker.scope.version,
                endpoint_url_digest=result.tls.endpoint_url_digest,
                peer_ip=result.tls.peer_ip,
                tls_version=ServiceTlsVersion(result.tls.tls_version.value),
                cipher_suite=result.tls.cipher_suite,
                cipher_bits=result.tls.cipher_bits,
                leaf_certificate_sha256=result.tls.leaf_certificate_sha256,
                evidence_refs=result.tls.evidence_refs,
                policy_record_digests=tuple(
                    canonical_digest(record.model_dump(mode="python"))
                    for record in result.policy_records
                ),
                captured_at=result.completed_at,
            )
            return RedTeamReconObservation.create(
                action_id=action.action_id,
                outcome=ReconOutcome.SUCCEEDED,
                status_code=None,
                reason_code="live_tls_identity_succeeded",
                cleanup_complete=True,
                sensitive_data_redacted=True,
                service_identity=identity,
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
            action, now=result.completed_at, outcome=outcome, reason=f"broker.{reason}"
        )

    def _preflight_static(self) -> None:
        parsed = urlsplit(self.plan.target.url)
        port = parsed.port or 443
        exact_grant = (
            len(self.profile.network_grants) == 1
            and self.profile.network_mode is NetworkMode.TARGET_ONLY
            and self.profile.network_grants[0].host == self.admission.host
            and self.profile.network_grants[0].ports == frozenset({self.admission.port})
            and self.profile.network_grants[0].schemes == frozenset({"https"})
        )
        if (
            parsed.scheme != "https"
            or self.admission.scheme != "https"
            or parsed.hostname != self.admission.host
            or port != self.admission.port
            or not exact_grant
            or self.broker.registry.digest != pinned_tls_tool_registry().digest
            or self.broker.allowed_resolved_ips
            != frozenset(self.admission.allowed_peer_ips)
        ):
            raise RedTeamRejected("isolated local TLS admission binding is invalid")

    @staticmethod
    def _observation(action, *, now, outcome, reason):
        return RedTeamReconObservation.create(
            action_id=action.action_id,
            outcome=outcome,
            status_code=None,
            reason_code=reason,
            cleanup_complete=True,
            sensitive_data_redacted=True,
            observed_at=now,
        )
