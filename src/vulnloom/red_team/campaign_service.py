"""Fail-closed B5.3 qualification for finite A4 Campaign plans."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, ScopeState

from .adaptive_qualification_models import (
    AdaptiveFlowQualificationOutcome,
    AdaptiveFlowQualificationPlan,
)
from .adaptive_runtime_models import (
    AdaptiveRuntimeQualificationOutcome,
    AdaptiveRuntimeQualificationPlan,
    RuntimeAssuranceLevel,
)
from .campaign_models import (
    CampaignBudget,
    CampaignFlowQualificationBinding,
    CampaignGoal,
    CampaignPhase,
    CampaignQualificationLimits,
    CampaignStopConditions,
    GoalDrivenCampaignPlan,
    GoalDrivenCampaignQualificationOutcome,
)
from .campaign_store import CampaignQualificationStore


class CampaignQualificationRejected(ValueError):
    pass


class CampaignQualificationTimedOut(TimeoutError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignFlowQualificationSource:
    adaptive_plan: AdaptiveFlowQualificationPlan
    adaptive_outcome: AdaptiveFlowQualificationOutcome
    runtime_plan: AdaptiveRuntimeQualificationPlan
    runtime_outcome: AdaptiveRuntimeQualificationOutcome


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CampaignQualificationTimedOut("Campaign Qualification timed out")


class GoalDrivenCampaignQualificationService:
    def __init__(
        self,
        *,
        store: CampaignQualificationStore,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        goal: CampaignGoal,
        sources: tuple[CampaignFlowQualificationSource, ...],
        phases: tuple[CampaignPhase, ...],
        budget: CampaignBudget,
        stop_conditions: CampaignStopConditions,
        scope: Scope,
        limits: CampaignQualificationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> GoalDrivenCampaignPlan:
        self._scope(scope, now)
        bindings = tuple(
            sorted(
                (self._source(item, scope=scope, now=now) for item in sources),
                key=lambda item: item.flow_plan_id,
            )
        )
        stop_at = min(deadline, scope.valid_until)
        if not now < stop_at:
            raise CampaignQualificationRejected(
                "Campaign Qualification deadline is invalid"
            )
        try:
            return GoalDrivenCampaignPlan.create(
                goal=CampaignGoal.model_validate(goal.model_dump(mode="python")),
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_ids=tuple(sorted({item.target_id for item in bindings}, key=str)),
                flow_bindings=bindings,
                phases=tuple(
                    CampaignPhase.model_validate(item.model_dump(mode="python"))
                    for item in phases
                ),
                budget=CampaignBudget.model_validate(budget.model_dump(mode="python")),
                stop_conditions=CampaignStopConditions.model_validate(
                    stop_conditions.model_dump(mode="python")
                ),
                limits=limits,
                created_at=now,
                deadline=stop_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise CampaignQualificationRejected(
                "Goal-driven Campaign Plan could not be sealed"
            ) from exc

    def execute(
        self,
        plan: GoalDrivenCampaignPlan,
        *,
        sources: tuple[CampaignFlowQualificationSource, ...],
        scope: Scope,
        now: datetime,
    ) -> GoalDrivenCampaignQualificationOutcome:
        authoritative = GoalDrivenCampaignPlan.model_validate(
            plan.model_dump(mode="python")
        )
        bindings = self._binding(authoritative, sources=sources, scope=scope, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        return self._complete(authoritative, bindings, claim.attempt, now)

    def recover(
        self,
        plan: GoalDrivenCampaignPlan,
        *,
        sources: tuple[CampaignFlowQualificationSource, ...],
        scope: Scope,
        now: datetime,
    ) -> GoalDrivenCampaignQualificationOutcome:
        authoritative = GoalDrivenCampaignPlan.model_validate(
            plan.model_dump(mode="python")
        )
        bindings = self._binding(authoritative, sources=sources, scope=scope, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(authoritative, bindings, claim.attempt, now)

    def _complete(
        self,
        plan: GoalDrivenCampaignPlan,
        bindings: tuple[CampaignFlowQualificationBinding, ...],
        attempt: int,
        now: datetime,
    ) -> GoalDrivenCampaignQualificationOutcome:
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        assurance = (
            RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            if all(
                item.assurance_level is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
                for item in bindings
            )
            else RuntimeAssuranceLevel.LOCAL_DOCKER
        )
        outcome = GoalDrivenCampaignQualificationOutcome.create(
            campaign_plan_id=plan.campaign_plan_id,
            goal_id=plan.goal.goal_id,
            flow_binding_ids=tuple(item.binding_id for item in bindings),
            target_ids=plan.target_ids,
            minimum_assurance_level=assurance,
            attempt=attempt,
            completed_at=now,
        )
        deadline.check()
        self.store.complete(plan, outcome)
        return outcome

    def _binding(
        self,
        plan: GoalDrivenCampaignPlan,
        *,
        sources: tuple[CampaignFlowQualificationSource, ...],
        scope: Scope,
        now: datetime,
    ) -> tuple[CampaignFlowQualificationBinding, ...]:
        if not plan.created_at <= now < plan.deadline:
            raise CampaignQualificationRejected(
                "Campaign Qualification Plan is not active"
            )
        self._scope(scope, now)
        bindings = tuple(
            sorted(
                (self._source(item, scope=scope, now=now) for item in sources),
                key=lambda item: item.flow_plan_id,
            )
        )
        if (
            plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.flow_bindings != bindings
            or plan.target_ids
            != tuple(sorted({item.target_id for item in bindings}, key=str))
        ):
            raise CampaignQualificationRejected(
                "Campaign Qualification sealed Flow set drifted"
            )
        return bindings

    @staticmethod
    def _source(
        source: CampaignFlowQualificationSource, *, scope: Scope, now: datetime
    ) -> CampaignFlowQualificationBinding:
        try:
            adaptive_plan = AdaptiveFlowQualificationPlan.model_validate(
                source.adaptive_plan.model_dump(mode="python")
            )
            adaptive_outcome = AdaptiveFlowQualificationOutcome.model_validate(
                source.adaptive_outcome.model_dump(mode="python")
            )
            runtime_plan = AdaptiveRuntimeQualificationPlan.model_validate(
                source.runtime_plan.model_dump(mode="python")
            )
            runtime_outcome = AdaptiveRuntimeQualificationOutcome.model_validate(
                source.runtime_outcome.model_dump(mode="python")
            )
        except (AttributeError, ValueError) as exc:
            raise CampaignQualificationRejected(
                "Campaign Flow qualification source is invalid"
            ) from exc
        if (
            adaptive_plan.scope_id != scope.scope_id
            or adaptive_plan.scope_version != scope.version
            or adaptive_outcome.plan_id != adaptive_plan.plan_id
            or adaptive_outcome.flow_plan_id != adaptive_plan.flow_plan_id
            or adaptive_outcome.coverage_ledger.flow_plan_id
            != adaptive_plan.flow_plan_id
            or runtime_plan.adaptive_plan_id != adaptive_plan.plan_id
            or runtime_plan.adaptive_outcome_id != adaptive_outcome.outcome_id
            or runtime_plan.adaptive_outcome_digest
            != canonical_digest(adaptive_outcome.model_dump(mode="python"))
            or runtime_plan.flow_plan_id != adaptive_plan.flow_plan_id
            or runtime_plan.coverage_ledger_id
            != adaptive_outcome.coverage_ledger.ledger_id
            or runtime_plan.scope_id != scope.scope_id
            or runtime_plan.scope_version != scope.version
            or runtime_outcome.plan_id != runtime_plan.plan_id
            or runtime_outcome.adaptive_outcome_id != adaptive_outcome.outcome_id
            or runtime_outcome.flow_plan_id != adaptive_plan.flow_plan_id
            or runtime_outcome.coverage_ledger_id
            != adaptive_outcome.coverage_ledger.ledger_id
            or not runtime_outcome.isolated_lab_qualified
            or runtime_outcome.execution_authority_granted
            or runtime_outcome.campaign_qualified
            or adaptive_outcome.completed_at > runtime_outcome.completed_at
            or runtime_outcome.completed_at > now
        ):
            raise CampaignQualificationRejected(
                "Campaign Flow qualification provenance drifted"
            )
        return CampaignFlowQualificationBinding.create(
            flow_plan_id=adaptive_plan.flow_plan_id,
            target_id=adaptive_plan.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            adaptive_plan_id=adaptive_plan.plan_id,
            adaptive_outcome_id=adaptive_outcome.outcome_id,
            coverage_ledger_id=adaptive_outcome.coverage_ledger.ledger_id,
            runtime_plan_id=runtime_plan.plan_id,
            runtime_outcome_id=runtime_outcome.outcome_id,
            runtime_outcome_digest=canonical_digest(
                runtime_outcome.model_dump(mode="python")
            ),
            assurance_level=runtime_outcome.assurance_level,
        )

    @staticmethod
    def _scope(scope: Scope, now: datetime) -> None:
        try:
            authoritative = Scope.model_validate(scope.model_dump(mode="python"))
        except ValueError as exc:
            raise CampaignQualificationRejected(
                "Campaign Qualification Scope is invalid"
            ) from exc
        if (
            authoritative.state is not ScopeState.APPROVED
            or not authoritative.valid_from <= now < authoritative.valid_until
        ):
            raise CampaignQualificationRejected(
                "Campaign Qualification requires current approved Scope"
            )
