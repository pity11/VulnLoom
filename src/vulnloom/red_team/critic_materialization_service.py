"""Trusted offline materializer for independent Critic Assertions."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .critic_materialization_models import (
    CRITIC_ASSERTION_RULESET_DIGEST,
    CriticAssertionMaterialization,
    CriticAssertionMaterializationLimits,
    CriticAssertionMaterializationOutcome,
    CriticAssertionMaterializationPlan,
    CriticEvidenceReview,
)
from .critic_materialization_store import CriticAssertionMaterializationStore
from .evidence_requirement_models import (
    EvidenceAssertion,
    EvidenceRequirementStage,
    VulnerabilityEvidenceRequirement,
)
from .replay_validation_models import (
    EvidenceReplayValidationOutcome,
    EvidenceReplayValidationPlan,
)


class EvidenceReplayValidationSource(Protocol):
    def plan(self, plan_id: str) -> EvidenceReplayValidationPlan: ...

    def outcome(self, plan_id: str) -> EvidenceReplayValidationOutcome: ...


class CriticAssertionMaterializationRejected(ValueError):
    pass


class CriticAssertionMaterializationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CriticAssertionMaterializationTimedOut(
                "Critic Assertion materialization timed out"
            )


class CriticAssertionMaterializationService:
    def __init__(
        self,
        *,
        replay_validation_source: EvidenceReplayValidationSource,
        store: CriticAssertionMaterializationStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.replay_validation_source = replay_validation_source
        self.store = store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        replay_validation_plan_id: str,
        review: CriticEvidenceReview,
        scope: Scope,
        limits: CriticAssertionMaterializationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CriticAssertionMaterializationPlan:
        replay_plan, replay_outcome = self._source(
            replay_validation_plan_id, scope=scope, now=now
        )
        self._review(
            review,
            replay_plan=replay_plan,
            replay_outcome=replay_outcome,
            limits=limits,
            now=now,
        )
        stop_at = min(deadline, scope.valid_until)
        if stop_at <= now:
            raise CriticAssertionMaterializationRejected(
                "Critic Assertion materialization deadline is invalid"
            )
        validation = replay_outcome.validation
        validation_producers = {item.producer_ref for item in validation.assertions}
        if len(validation_producers) != 1:
            raise CriticAssertionMaterializationRejected(
                "Replay Validation producer binding is invalid"
            )
        return CriticAssertionMaterializationPlan.create(
            requirement_id=replay_plan.requirement_id,
            replay_validation_plan_id=replay_plan.plan_id,
            replay_validation_id=validation.validation_id,
            validation_context_id=replay_plan.plan_id,
            validation_producer_ref=validation_producers.pop(),
            validation_evidence_refs=validation.evidence_refs,
            review=review,
            target_id=replay_plan.target_id,
            target_version=replay_plan.target_version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            ruleset_digest=CRITIC_ASSERTION_RULESET_DIGEST,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: CriticAssertionMaterializationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> CriticAssertionMaterializationOutcome:
        authoritative = CriticAssertionMaterializationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        materialization = self._materialize(authoritative, scope=scope, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            if claim.outcome is None or claim.outcome.materialization != materialization:
                raise CriticAssertionMaterializationRejected(
                    "completed Critic Assertion materialization outcome drifted"
                )
            return claim.outcome
        return self._complete(
            authoritative,
            materialization,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def recover(
        self,
        plan: CriticAssertionMaterializationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> CriticAssertionMaterializationOutcome:
        authoritative = CriticAssertionMaterializationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        materialization = self._materialize(authoritative, scope=scope, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            materialization,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def _complete(self, plan, materialization, *, attempt, scope, now):
        self._binding(plan, scope=scope, now=now)
        outcome = CriticAssertionMaterializationOutcome(
            plan_id=plan.plan_id,
            materialization=materialization,
            attempt=attempt,
        )
        self.store.complete(outcome, completed_at=now)
        return outcome

    def _materialize(self, plan, *, scope, now):
        self._binding(plan, scope=scope, now=now)
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        assertions = tuple(
            sorted(
                (
                    EvidenceAssertion.create(
                        requirement_id=plan.requirement_id,
                        stage=EvidenceRequirementStage.CRITIC,
                        fact=conclusion.fact,
                        verdict=conclusion.verdict,
                        evidence_refs=conclusion.evidence_refs,
                        producer_ref=plan.review.producer_ref,
                        context_id=plan.plan_id,
                        observed_at=plan.review.reviewed_at,
                    )
                    for conclusion in plan.review.conclusions
                ),
                key=lambda item: item.assertion_id,
            )
        )
        deadline.check()
        refs = tuple(
            sorted({ref for assertion in assertions for ref in assertion.evidence_refs})
        )
        return CriticAssertionMaterialization.create(
            plan_id=plan.plan_id,
            requirement_id=plan.requirement_id,
            replay_validation_id=plan.replay_validation_id,
            review_id=plan.review.review_id,
            evidence_refs=refs,
            assertions=assertions,
            ruleset_digest=plan.ruleset_digest,
            materialized_at=plan.created_at,
        )

    def _binding(self, plan, *, scope, now):
        if (
            not plan.created_at <= now < plan.deadline
            or plan.ruleset_digest != CRITIC_ASSERTION_RULESET_DIGEST
        ):
            raise CriticAssertionMaterializationRejected(
                "Critic Assertion materialization plan is not active"
            )
        replay_plan, replay_outcome = self._source(
            plan.replay_validation_plan_id, scope=scope, now=now
        )
        validation = replay_outcome.validation
        validation_producers = {item.producer_ref for item in validation.assertions}
        if (
            plan.requirement_id != replay_plan.requirement_id
            or plan.replay_validation_id != validation.validation_id
            or plan.validation_context_id != replay_plan.plan_id
            or validation_producers != {plan.validation_producer_ref}
            or plan.validation_evidence_refs != validation.evidence_refs
            or plan.target_id != replay_plan.target_id
            or plan.target_version != replay_plan.target_version
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
        ):
            raise CriticAssertionMaterializationRejected(
                "Critic Assertion materialization binding drifted"
            )
        self._review(
            plan.review,
            replay_plan=replay_plan,
            replay_outcome=replay_outcome,
            limits=plan.limits,
            now=now,
        )
        return replay_plan, replay_outcome

    def _source(self, plan_id, *, scope, now):
        self._scope(scope, now=now)
        try:
            plan = self.replay_validation_source.plan(plan_id)
            outcome = self.replay_validation_source.outcome(plan_id)
        except (KeyError, RuntimeError, ValueError) as exc:
            raise CriticAssertionMaterializationRejected(
                "completed Replay Validation source is unavailable"
            ) from exc
        validation = outcome.validation
        if (
            outcome.plan_id != plan.plan_id
            or validation.plan_id != plan.plan_id
            or validation.requirement_id != plan.requirement_id
            or validation.baseline_materialization_id
            != plan.baseline_materialization_id
            or validation.current_materialization_id
            != plan.current_materialization_id
            or validation.requested_url_digest != plan.requested_url_digest
            or validation.evidence_refs != plan.evidence_refs
            or plan.requirement_id
            != VulnerabilityEvidenceRequirement.create().requirement_id
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or not outcome.cleanup_complete
        ):
            raise CriticAssertionMaterializationRejected(
                "Replay Validation source binding is invalid"
            )
        self._verify_evidence(validation.evidence_refs)
        return plan, outcome

    def _review(self, review, *, replay_plan, replay_outcome, limits, now):
        validation = replay_outcome.validation
        critic_refs = tuple(
            sorted(
                {
                    ref
                    for conclusion in review.conclusions
                    for ref in conclusion.evidence_refs
                }
            )
        )
        if (
            review.requirement_id != replay_plan.requirement_id
            or review.target_id != replay_plan.target_id
            or review.target_version != replay_plan.target_version
            or review.scope_id != replay_plan.scope_id
            or review.scope_version != replay_plan.scope_version
            or review.review_context_id == replay_plan.plan_id
            or review.producer_ref
            in {item.producer_ref for item in validation.assertions}
            or not set(critic_refs).isdisjoint(validation.evidence_refs)
            or not validation.validated_at < review.reviewed_at <= now
            or len(critic_refs) > limits.max_evidence_refs
        ):
            raise CriticAssertionMaterializationRejected(
                "Critic Evidence Review is not independent and compatible"
            )
        self._verify_evidence(critic_refs)

    @staticmethod
    def _scope(scope: Scope, *, now: datetime) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
        ):
            raise CriticAssertionMaterializationRejected(
                "Critic Assertion materialization requires a current read-only approved Scope"
            )

    def _verify_evidence(self, refs) -> None:
        if not refs or not all(self.evidence_store.contains(ref) for ref in refs):
            raise CriticAssertionMaterializationRejected(
                "Critic Assertion materialization Evidence integrity check failed"
            )
