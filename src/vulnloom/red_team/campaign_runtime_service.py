"""Fail-closed B5.4 fan-in for isolated A4 Campaign runtime evidence."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    Scope,
    ScopeState,
)
from vulnloom.runners.hostile_worker import (
    HostileWorkerQualificationOutcome,
    HostileWorkerQualificationPlan,
    HostileWorkerQualificationStatus,
)
from vulnloom.runners.models import (
    MountKind,
    NetworkMode,
    SandboxProfile,
    SandboxProfileKind,
    sandbox_profile_digest,
)
from vulnloom.runners.resource_pressure import (
    ResourcePressureQualificationOutcome,
    ResourcePressureQualificationPlan,
    ResourcePressureQualificationStatus,
)

from .adaptive_runtime_models import RuntimeAssuranceLevel
from .campaign_models import (
    GoalDrivenCampaignPlan,
    GoalDrivenCampaignQualificationOutcome,
)
from .campaign_runtime_models import (
    REQUIRED_CAMPAIGN_RUNTIME_STOP_PROBES,
    CampaignPhaseRuntimeObservation,
    CampaignRuntimeQualificationLimits,
    CampaignRuntimeQualificationOutcome,
    CampaignRuntimeQualificationPlan,
    CampaignStopRuntimeObservation,
)
from .campaign_runtime_store import CampaignRuntimeQualificationStore


class CampaignRuntimeQualificationRejected(ValueError):
    pass


class CampaignRuntimeQualificationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CampaignRuntimeQualificationTimedOut(
                "Campaign Runtime Qualification timed out"
            )


class CampaignRuntimeQualificationService:
    def __init__(
        self,
        *,
        store: CampaignRuntimeQualificationStore,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        campaign_plan: GoalDrivenCampaignPlan,
        campaign_outcome: GoalDrivenCampaignQualificationOutcome,
        hostile_plan: HostileWorkerQualificationPlan,
        hostile_outcome: HostileWorkerQualificationOutcome,
        resource_plan: ResourcePressureQualificationPlan,
        resource_outcome: ResourcePressureQualificationOutcome,
        profile: SandboxProfile,
        scope: Scope,
        limits: CampaignRuntimeQualificationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CampaignRuntimeQualificationPlan:
        self._inputs(
            campaign_plan=campaign_plan,
            campaign_outcome=campaign_outcome,
            hostile_plan=hostile_plan,
            hostile_outcome=hostile_outcome,
            resource_plan=resource_plan,
            resource_outcome=resource_outcome,
            profile=profile,
            scope=scope,
            now=now,
        )
        stop_at = min(deadline, campaign_plan.deadline, scope.valid_until)
        if not now < stop_at:
            raise CampaignRuntimeQualificationRejected(
                "Campaign Runtime Qualification deadline is invalid"
            )
        return CampaignRuntimeQualificationPlan.create(
            campaign_plan_id=campaign_plan.campaign_plan_id,
            campaign_plan_digest=canonical_digest(
                campaign_plan.model_dump(mode="python")
            ),
            campaign_outcome_id=campaign_outcome.outcome_id,
            campaign_outcome_digest=canonical_digest(
                campaign_outcome.model_dump(mode="python")
            ),
            goal_id=campaign_plan.goal.goal_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            target_set_digest=canonical_digest(campaign_plan.target_ids),
            phase_graph_digest=canonical_digest(
                tuple(item.model_dump(mode="python") for item in campaign_plan.phases)
            ),
            required_phase_ids=tuple(item.phase_id for item in campaign_plan.phases),
            image_digest=profile.image_digest,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            hostile_worker_plan_id=hostile_plan.plan_id,
            hostile_worker_outcome_id=hostile_outcome.outcome_id,
            hostile_worker_outcome_digest=canonical_digest(
                hostile_outcome.model_dump(mode="python")
            ),
            resource_pressure_plan_id=resource_plan.plan_id,
            resource_pressure_outcome_id=resource_outcome.outcome_id,
            resource_pressure_outcome_digest=canonical_digest(
                resource_outcome.model_dump(mode="python")
            ),
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: CampaignRuntimeQualificationPlan,
        *,
        campaign_plan: GoalDrivenCampaignPlan,
        campaign_outcome: GoalDrivenCampaignQualificationOutcome,
        hostile_plan: HostileWorkerQualificationPlan,
        hostile_outcome: HostileWorkerQualificationOutcome,
        resource_plan: ResourcePressureQualificationPlan,
        resource_outcome: ResourcePressureQualificationOutcome,
        profile: SandboxProfile,
        phase_observations: tuple[CampaignPhaseRuntimeObservation, ...],
        stop_observations: tuple[CampaignStopRuntimeObservation, ...],
        approvals: tuple[ApprovalRequest, ...],
        scope: Scope,
        now: datetime,
    ) -> CampaignRuntimeQualificationOutcome:
        authoritative = CampaignRuntimeQualificationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        phases, stops, approvals = self._evidence(
            phase_observations, stop_observations, approvals
        )
        self._binding(
            authoritative,
            campaign_plan=campaign_plan,
            campaign_outcome=campaign_outcome,
            hostile_plan=hostile_plan,
            hostile_outcome=hostile_outcome,
            resource_plan=resource_plan,
            resource_outcome=resource_outcome,
            profile=profile,
            phase_observations=phases,
            stop_observations=stops,
            approvals=approvals,
            scope=scope,
            now=now,
        )
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        return self._complete(
            authoritative,
            campaign_outcome,
            phases,
            stops,
            claim.attempt,
            now,
        )

    def recover(
        self,
        plan: CampaignRuntimeQualificationPlan,
        *,
        inputs: dict[str, object],
        phase_observations: tuple[CampaignPhaseRuntimeObservation, ...],
        stop_observations: tuple[CampaignStopRuntimeObservation, ...],
        approvals: tuple[ApprovalRequest, ...],
        scope: Scope,
        now: datetime,
    ) -> CampaignRuntimeQualificationOutcome:
        authoritative = CampaignRuntimeQualificationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        phases, stops, approvals = self._evidence(
            phase_observations, stop_observations, approvals
        )
        self._binding(
            authoritative,
            phase_observations=phases,
            stop_observations=stops,
            approvals=approvals,
            scope=scope,
            now=now,
            **inputs,
        )
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            inputs["campaign_outcome"],
            phases,
            stops,
            claim.attempt,
            now,
        )

    def _complete(
        self,
        plan: CampaignRuntimeQualificationPlan,
        campaign_outcome: GoalDrivenCampaignQualificationOutcome,
        phases: tuple[CampaignPhaseRuntimeObservation, ...],
        stops: tuple[CampaignStopRuntimeObservation, ...],
        attempt: int,
        now: datetime,
    ) -> CampaignRuntimeQualificationOutcome:
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        assurance = (
            RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            if campaign_outcome.minimum_assurance_level
            is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            and all(
                item.assurance_level is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
                for item in (*phases, *stops)
            )
            else RuntimeAssuranceLevel.LOCAL_DOCKER
        )
        outcome = CampaignRuntimeQualificationOutcome.create(
            runtime_plan_id=plan.runtime_plan_id,
            campaign_plan_id=plan.campaign_plan_id,
            campaign_outcome_id=plan.campaign_outcome_id,
            phase_observation_ids=tuple(item.observation_id for item in phases),
            stop_observation_ids=tuple(
                item.observation_id for item in sorted(stops, key=lambda item: item.kind)
            ),
            assurance_level=assurance,
            attempt=attempt,
            completed_at=now,
            production_campaign_runtime_admitted=(
                assurance is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            ),
        )
        deadline.check()
        self.store.complete(plan, outcome)
        return outcome

    def _binding(
        self,
        plan: CampaignRuntimeQualificationPlan,
        *,
        campaign_plan: GoalDrivenCampaignPlan,
        campaign_outcome: GoalDrivenCampaignQualificationOutcome,
        hostile_plan: HostileWorkerQualificationPlan,
        hostile_outcome: HostileWorkerQualificationOutcome,
        resource_plan: ResourcePressureQualificationPlan,
        resource_outcome: ResourcePressureQualificationOutcome,
        profile: SandboxProfile,
        phase_observations: tuple[CampaignPhaseRuntimeObservation, ...],
        stop_observations: tuple[CampaignStopRuntimeObservation, ...],
        approvals: tuple[ApprovalRequest, ...],
        scope: Scope,
        now: datetime,
    ) -> None:
        if not plan.created_at <= now < plan.deadline:
            raise CampaignRuntimeQualificationRejected(
                "Campaign Runtime Qualification Plan is not active"
            )
        self._inputs(
            campaign_plan=campaign_plan,
            campaign_outcome=campaign_outcome,
            hostile_plan=hostile_plan,
            hostile_outcome=hostile_outcome,
            resource_plan=resource_plan,
            resource_outcome=resource_outcome,
            profile=profile,
            scope=scope,
            now=now,
        )
        expected = (
            plan.campaign_plan_id == campaign_plan.campaign_plan_id
            and plan.campaign_plan_digest
            == canonical_digest(campaign_plan.model_dump(mode="python"))
            and plan.campaign_outcome_id == campaign_outcome.outcome_id
            and plan.campaign_outcome_digest
            == canonical_digest(campaign_outcome.model_dump(mode="python"))
            and plan.goal_id == campaign_plan.goal.goal_id
            and plan.scope_id == scope.scope_id
            and plan.scope_version == scope.version
            and plan.target_set_digest == canonical_digest(campaign_plan.target_ids)
            and plan.phase_graph_digest
            == canonical_digest(
                tuple(item.model_dump(mode="python") for item in campaign_plan.phases)
            )
            and plan.required_phase_ids
            == tuple(item.phase_id for item in campaign_plan.phases)
            and plan.image_digest == profile.image_digest
            and plan.sandbox_profile_digest == sandbox_profile_digest(profile)
            and plan.hostile_worker_plan_id == hostile_plan.plan_id
            and plan.hostile_worker_outcome_id == hostile_outcome.outcome_id
            and plan.hostile_worker_outcome_digest
            == canonical_digest(hostile_outcome.model_dump(mode="python"))
            and plan.resource_pressure_plan_id == resource_plan.plan_id
            and plan.resource_pressure_outcome_id == resource_outcome.outcome_id
            and plan.resource_pressure_outcome_digest
            == canonical_digest(resource_outcome.model_dump(mode="python"))
        )
        if not expected:
            raise CampaignRuntimeQualificationRejected(
                "Campaign Runtime Qualification sealed binding drifted"
            )
        by_approval = {item.approval_id: item for item in approvals}
        if len(by_approval) != len(approvals) or len(approvals) != len(campaign_plan.phases):
            raise CampaignRuntimeQualificationRejected(
                "Campaign Phase Admission set is invalid"
            )
        if len(phase_observations) != len(campaign_plan.phases):
            raise CampaignRuntimeQualificationRejected(
                "Campaign Phase Runtime sequence is incomplete"
            )
        previous_time: datetime | None = None
        for phase, observation in zip(
            campaign_plan.phases, phase_observations, strict=True
        ):
            approval = by_approval.get(observation.approval_id)
            if (
                observation.runtime_plan_id != plan.runtime_plan_id
                or observation.campaign_plan_id != plan.campaign_plan_id
                or observation.campaign_outcome_id != plan.campaign_outcome_id
                or observation.phase_id != phase.phase_id
                or observation.phase_kind is not phase.kind
                or observation.ordinal != phase.ordinal
                or observation.prerequisite_phase_ids != phase.prerequisite_phase_ids
                or observation.image_digest != plan.image_digest
                or observation.sandbox_profile_digest
                != plan.sandbox_profile_digest
                or not plan.created_at <= observation.observed_at <= now
                or (previous_time is not None and observation.observed_at <= previous_time)
                or approval is None
                or approval.engagement_id != scope.engagement_id
                or approval.target_id is not None
                or approval.decided_at is None
                or approval.decided_at > observation.observed_at
                or not approval.is_valid_for(
                    action=ApprovalAction.ADVANCE_CAMPAIGN_PHASE,
                    digest=phase.phase_id,
                    now=observation.observed_at,
                )
                or observation.approval_digest != approval.action_digest
            ):
                raise CampaignRuntimeQualificationRejected(
                    "Campaign Phase Runtime provenance or admission drifted"
                )
            previous_time = observation.observed_at
        by_kind = {item.kind: item for item in stop_observations}
        if (
            len(by_kind) != len(stop_observations)
            or set(by_kind) != REQUIRED_CAMPAIGN_RUNTIME_STOP_PROBES
        ):
            raise CampaignRuntimeQualificationRejected(
                "Campaign Runtime stop evidence is incomplete"
            )
        for observation in stop_observations:
            if (
                observation.runtime_plan_id != plan.runtime_plan_id
                or observation.campaign_plan_id != plan.campaign_plan_id
                or observation.campaign_outcome_id != plan.campaign_outcome_id
                or observation.image_digest != plan.image_digest
                or observation.sandbox_profile_digest
                != plan.sandbox_profile_digest
                or not plan.created_at <= observation.observed_at <= now
            ):
                raise CampaignRuntimeQualificationRejected(
                    "Campaign Runtime stop provenance or cleanup drifted"
                )

    @staticmethod
    def _evidence(phase_observations, stop_observations, approvals):
        try:
            phases = tuple(
                CampaignPhaseRuntimeObservation.model_validate(
                    item.model_dump(mode="python")
                )
                for item in phase_observations
            )
            stops = tuple(
                CampaignStopRuntimeObservation.model_validate(
                    item.model_dump(mode="python")
                )
                for item in stop_observations
            )
            authoritative_approvals = tuple(
                ApprovalRequest.model_validate(item.model_dump(mode="python"))
                for item in approvals
            )
        except (AttributeError, ValueError) as exc:
            raise CampaignRuntimeQualificationRejected(
                "Campaign Runtime evidence is not authoritative"
            ) from exc
        return phases, stops, authoritative_approvals

    @staticmethod
    def _inputs(
        *,
        campaign_plan,
        campaign_outcome,
        hostile_plan,
        hostile_outcome,
        resource_plan,
        resource_outcome,
        profile,
        scope,
        now,
    ) -> None:
        try:
            campaign_plan = GoalDrivenCampaignPlan.model_validate(
                campaign_plan.model_dump(mode="python")
            )
            campaign_outcome = GoalDrivenCampaignQualificationOutcome.model_validate(
                campaign_outcome.model_dump(mode="python")
            )
            hostile_plan = HostileWorkerQualificationPlan.model_validate(
                hostile_plan.model_dump(mode="python")
            )
            hostile_outcome = HostileWorkerQualificationOutcome.model_validate(
                hostile_outcome.model_dump(mode="python")
            )
            resource_plan = ResourcePressureQualificationPlan.model_validate(
                resource_plan.model_dump(mode="python")
            )
            resource_outcome = ResourcePressureQualificationOutcome.model_validate(
                resource_outcome.model_dump(mode="python")
            )
            profile = SandboxProfile.model_validate(profile.model_dump(mode="python"))
            scope = Scope.model_validate(scope.model_dump(mode="python"))
        except (AttributeError, ValueError) as exc:
            raise CampaignRuntimeQualificationRejected(
                "Campaign Runtime Qualification prerequisite is not authoritative"
            ) from exc
        evidence_mount = next(
            (item for item in profile.mounts if item.kind is MountKind.EVIDENCE), None
        )
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or campaign_plan.scope_id != scope.scope_id
            or campaign_plan.scope_version != scope.version
            or campaign_outcome.campaign_plan_id != campaign_plan.campaign_plan_id
            or campaign_outcome.goal_id != campaign_plan.goal.goal_id
            or campaign_outcome.flow_binding_ids
            != tuple(item.binding_id for item in campaign_plan.flow_bindings)
            or campaign_outcome.target_ids != campaign_plan.target_ids
            or not campaign_outcome.qualified
            or campaign_outcome.campaign_started
            or hostile_outcome.plan_id != hostile_plan.plan_id
            or hostile_outcome.status is not HostileWorkerQualificationStatus.ADMITTED
            or resource_outcome.plan_id != resource_plan.plan_id
            or resource_outcome.status
            is not ResourcePressureQualificationStatus.ADMITTED
            or hostile_plan.image_digest != profile.image_digest
            or resource_plan.image_digest != profile.image_digest
            or {item.sandbox_profile_digest for item in hostile_plan.probes}
            != {sandbox_profile_digest(profile)}
            or {item.sandbox_profile_digest for item in resource_plan.probes}
            != {sandbox_profile_digest(profile)}
            or profile.kind is not SandboxProfileKind.POST_EXPLOITATION
            or profile.network_mode is not NetworkMode.NONE
            or profile.execute_target_code
            or evidence_mount is None
            or evidence_mount.object_id != campaign_outcome.outcome_id
            or not evidence_mount.read_only
        ):
            raise CampaignRuntimeQualificationRejected(
                "Campaign Runtime Qualification prerequisite is not authoritative"
            )
