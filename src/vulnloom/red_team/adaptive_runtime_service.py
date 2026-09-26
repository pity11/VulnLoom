"""Fail-closed fan-in for B5.2 isolated A3 runtime qualification."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, ScopeState
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

from .adaptive_qualification_models import (
    AdaptiveFlowQualificationOutcome,
    AdaptiveFlowQualificationPlan,
)
from .adaptive_runtime_models import (
    REQUIRED_ADAPTIVE_RUNTIME_PROBES,
    AdaptiveRuntimeProbeObservation,
    AdaptiveRuntimeQualificationLimits,
    AdaptiveRuntimeQualificationOutcome,
    AdaptiveRuntimeQualificationPlan,
    RuntimeAssuranceLevel,
)
from .adaptive_runtime_store import AdaptiveRuntimeQualificationStore


class AdaptiveRuntimeQualificationRejected(ValueError):
    pass


class AdaptiveRuntimeQualificationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise AdaptiveRuntimeQualificationTimedOut(
                "Adaptive Runtime Qualification timed out"
            )


class AdaptiveRuntimeQualificationService:
    def __init__(
        self,
        *,
        store: AdaptiveRuntimeQualificationStore,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        adaptive_plan: AdaptiveFlowQualificationPlan,
        adaptive_outcome: AdaptiveFlowQualificationOutcome,
        hostile_plan: HostileWorkerQualificationPlan,
        hostile_outcome: HostileWorkerQualificationOutcome,
        resource_plan: ResourcePressureQualificationPlan,
        resource_outcome: ResourcePressureQualificationOutcome,
        profile: SandboxProfile,
        scope: Scope,
        limits: AdaptiveRuntimeQualificationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AdaptiveRuntimeQualificationPlan:
        self._inputs(
            adaptive_plan=adaptive_plan,
            adaptive_outcome=adaptive_outcome,
            hostile_plan=hostile_plan,
            hostile_outcome=hostile_outcome,
            resource_plan=resource_plan,
            resource_outcome=resource_outcome,
            profile=profile,
            scope=scope,
            now=now,
        )
        stop_at = min(deadline, adaptive_plan.deadline, scope.valid_until)
        if not now < stop_at:
            raise AdaptiveRuntimeQualificationRejected(
                "Adaptive Runtime Qualification deadline is invalid"
            )
        return AdaptiveRuntimeQualificationPlan.create(
            adaptive_plan_id=adaptive_plan.plan_id,
            adaptive_outcome_id=adaptive_outcome.outcome_id,
            adaptive_outcome_digest=canonical_digest(
                adaptive_outcome.model_dump(mode="python")
            ),
            flow_plan_id=adaptive_outcome.flow_plan_id,
            coverage_ledger_id=adaptive_outcome.coverage_ledger.ledger_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
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
        plan: AdaptiveRuntimeQualificationPlan,
        *,
        adaptive_plan: AdaptiveFlowQualificationPlan,
        adaptive_outcome: AdaptiveFlowQualificationOutcome,
        hostile_plan: HostileWorkerQualificationPlan,
        hostile_outcome: HostileWorkerQualificationOutcome,
        resource_plan: ResourcePressureQualificationPlan,
        resource_outcome: ResourcePressureQualificationOutcome,
        profile: SandboxProfile,
        observations: tuple[AdaptiveRuntimeProbeObservation, ...],
        scope: Scope,
        now: datetime,
    ) -> AdaptiveRuntimeQualificationOutcome:
        authoritative = AdaptiveRuntimeQualificationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        observations = self._observations(observations)
        self._binding(
            authoritative,
            adaptive_plan=adaptive_plan,
            adaptive_outcome=adaptive_outcome,
            hostile_plan=hostile_plan,
            hostile_outcome=hostile_outcome,
            resource_plan=resource_plan,
            resource_outcome=resource_outcome,
            profile=profile,
            observations=observations,
            scope=scope,
            now=now,
        )
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        return self._complete(authoritative, observations, claim.attempt, now)

    def recover(self, plan, *, inputs, observations, scope, now):
        authoritative = AdaptiveRuntimeQualificationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        observations = self._observations(observations)
        self._binding(
            authoritative,
            observations=observations,
            scope=scope,
            now=now,
            **inputs,
        )
        claim = self.store.recover(authoritative, now=now)
        return self._complete(authoritative, observations, claim.attempt, now)

    def _complete(self, plan, observations, attempt, now):
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        ordered = tuple(sorted(observations, key=lambda item: item.kind.value))
        assurance = (
            RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            if all(
                item.assurance_level is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
                for item in ordered
            )
            else RuntimeAssuranceLevel.LOCAL_DOCKER
        )
        outcome = AdaptiveRuntimeQualificationOutcome.create(
            plan_id=plan.plan_id,
            adaptive_outcome_id=plan.adaptive_outcome_id,
            flow_plan_id=plan.flow_plan_id,
            coverage_ledger_id=plan.coverage_ledger_id,
            probe_observation_ids=tuple(item.observation_id for item in ordered),
            assurance_level=assurance,
            attempt=attempt,
            completed_at=now,
            production_runner_admitted=(
                assurance is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            ),
        )
        deadline.check()
        self.store.complete(plan, outcome)
        return outcome

    def _binding(self, plan, *, observations, scope, now, **inputs):
        if not plan.created_at <= now < plan.deadline:
            raise AdaptiveRuntimeQualificationRejected(
                "Adaptive Runtime Qualification Plan is not active"
            )
        self._inputs(scope=scope, now=now, **inputs)
        adaptive_plan = inputs["adaptive_plan"]
        adaptive_outcome = inputs["adaptive_outcome"]
        hostile_plan = inputs["hostile_plan"]
        hostile_outcome = inputs["hostile_outcome"]
        resource_plan = inputs["resource_plan"]
        resource_outcome = inputs["resource_outcome"]
        profile = inputs["profile"]
        expected = (
            plan.adaptive_plan_id == adaptive_plan.plan_id
            and plan.adaptive_outcome_id == adaptive_outcome.outcome_id
            and plan.adaptive_outcome_digest
            == canonical_digest(adaptive_outcome.model_dump(mode="python"))
            and plan.flow_plan_id == adaptive_outcome.flow_plan_id
            and plan.coverage_ledger_id == adaptive_outcome.coverage_ledger.ledger_id
            and plan.scope_id == scope.scope_id
            and plan.scope_version == scope.version
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
        by_kind = {item.kind: item for item in observations}
        if (
            not expected
            or len(by_kind) != len(observations)
            or set(by_kind) != REQUIRED_ADAPTIVE_RUNTIME_PROBES
        ):
            raise AdaptiveRuntimeQualificationRejected(
                "Adaptive Runtime Qualification sealed binding drifted"
            )
        for item in observations:
            if (
                item.plan_id != plan.plan_id
                or item.adaptive_outcome_id != plan.adaptive_outcome_id
                or item.coverage_ledger_id != plan.coverage_ledger_id
                or item.image_digest != plan.image_digest
                or item.sandbox_profile_digest != plan.sandbox_profile_digest
                or not item.cleanup_verified
                or not item.container_absent
            ):
                raise AdaptiveRuntimeQualificationRejected(
                    "Adaptive Runtime Probe provenance or cleanup drifted"
                )

    @staticmethod
    def _observations(observations):
        try:
            return tuple(
                AdaptiveRuntimeProbeObservation.model_validate(
                    item.model_dump(mode="python")
                )
                for item in observations
            )
        except ValueError as exc:
            raise AdaptiveRuntimeQualificationRejected(
                "Adaptive Runtime Probe provenance or cleanup drifted"
            ) from exc

    @staticmethod
    def _inputs(
        *,
        adaptive_plan,
        adaptive_outcome,
        hostile_plan,
        hostile_outcome,
        resource_plan,
        resource_outcome,
        profile,
        scope,
        now,
    ):
        try:
            adaptive_plan = AdaptiveFlowQualificationPlan.model_validate(
                adaptive_plan.model_dump(mode="python")
            )
            adaptive_outcome = AdaptiveFlowQualificationOutcome.model_validate(
                adaptive_outcome.model_dump(mode="python")
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
        except ValueError as exc:
            raise AdaptiveRuntimeQualificationRejected(
                "Adaptive Runtime Qualification prerequisite is not authoritative"
            ) from exc
        evidence_mount = next(
            (item for item in profile.mounts if item.kind is MountKind.EVIDENCE), None
        )
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or adaptive_plan.scope_id != scope.scope_id
            or adaptive_plan.scope_version != scope.version
            or adaptive_outcome.plan_id != adaptive_plan.plan_id
            or adaptive_outcome.flow_plan_id != adaptive_plan.flow_plan_id
            or adaptive_outcome.coverage_ledger.flow_plan_id
            != adaptive_outcome.flow_plan_id
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
            or evidence_mount.object_id != adaptive_outcome.coverage_ledger.ledger_id
            or not evidence_mount.read_only
        ):
            raise AdaptiveRuntimeQualificationRejected(
                "Adaptive Runtime Qualification prerequisite is not authoritative"
            )
