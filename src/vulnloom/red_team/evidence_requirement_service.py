"""Trusted offline reducer for vulnerability Evidence Requirements."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .evidence_requirement_models import (
    EvidenceAssertion,
    EvidenceAssessment,
    EvidenceAssessmentLimits,
    EvidenceAssessmentOutcome,
    EvidenceAssessmentPlan,
    EvidenceAssessmentVerdict,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
    VulnerabilityEvidenceRequirement,
)
from .evidence_requirement_store import EvidenceAssessmentStore


class EvidenceAssessmentRejected(ValueError):
    pass


class EvidenceAssessmentTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise EvidenceAssessmentTimedOut("Evidence Assessment timed out")


class EvidenceAssessmentService:
    def __init__(
        self,
        *,
        store: EvidenceAssessmentStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.store = store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    @staticmethod
    def requirement() -> VulnerabilityEvidenceRequirement:
        return VulnerabilityEvidenceRequirement.create()

    def prepare(
        self,
        *,
        target_id: UUID,
        target_version: str,
        scope: Scope,
        assertions: tuple[EvidenceAssertion, ...],
        limits: EvidenceAssessmentLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> EvidenceAssessmentPlan:
        self._scope(scope, now=now)
        requirement = self.requirement()
        stop_at = min(deadline, scope.valid_until)
        if stop_at <= now:
            raise EvidenceAssessmentRejected(
                "Evidence Assessment deadline is invalid"
            )
        canonical = tuple(sorted(assertions, key=lambda item: item.assertion_id))
        self._assertions(requirement, canonical, limits=limits, now=now)
        return EvidenceAssessmentPlan.create(
            requirement=requirement,
            target_id=target_id,
            target_version=target_version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            assertions=canonical,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self, plan: EvidenceAssessmentPlan, *, scope: Scope, now: datetime
    ) -> EvidenceAssessmentOutcome:
        authoritative = EvidenceAssessmentPlan.model_validate(
            plan.model_dump(mode="python")
        )
        assessment = self._assess(authoritative, scope=scope, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            if claim.outcome is None or claim.outcome.assessment != assessment:
                raise EvidenceAssessmentRejected(
                    "completed Evidence Assessment outcome drifted"
                )
            return claim.outcome
        return self._complete(
            authoritative,
            assessment,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def recover(
        self, plan: EvidenceAssessmentPlan, *, scope: Scope, now: datetime
    ) -> EvidenceAssessmentOutcome:
        authoritative = EvidenceAssessmentPlan.model_validate(
            plan.model_dump(mode="python")
        )
        assessment = self._assess(authoritative, scope=scope, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            assessment,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def _complete(self, plan, assessment, *, attempt, scope, now):
        self._binding(plan, scope=scope, now=now)
        self._verify_evidence(plan.assertions)
        outcome = EvidenceAssessmentOutcome(
            plan_id=plan.plan_id,
            assessment=assessment,
            attempt=attempt,
        )
        self.store.complete(outcome, completed_at=now)
        return outcome

    def _assess(self, plan, *, scope, now):
        self._binding(plan, scope=scope, now=now)
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        self._assertions(
            plan.requirement,
            plan.assertions,
            limits=plan.limits,
            now=now,
            deadline=deadline,
        )
        by_fact = {item.fact: item for item in plan.assertions}
        required_positive = (
            *plan.requirement.observation_facts,
            *plan.requirement.validation_facts,
        )
        satisfied: set[EvidenceFactKind] = set()
        counterevidence: set[EvidenceFactKind] = set()
        unresolved: set[EvidenceFactKind] = set()

        for fact in required_positive:
            deadline.check()
            assertion = by_fact.get(fact)
            if assertion is None or assertion.verdict is EvidenceFactVerdict.INCONCLUSIVE:
                unresolved.add(fact)
            elif assertion.verdict is EvidenceFactVerdict.SUPPORTED:
                satisfied.add(fact)
            else:
                counterevidence.add(fact)

        for fact in plan.requirement.counterevidence_facts:
            deadline.check()
            assertion = by_fact.get(fact)
            if assertion is None or assertion.verdict is EvidenceFactVerdict.INCONCLUSIVE:
                unresolved.add(fact)
            elif assertion.verdict is EvidenceFactVerdict.REFUTED:
                satisfied.add(fact)
            else:
                counterevidence.add(fact)

        cleanup_satisfied = True
        for fact in plan.requirement.cleanup_facts:
            deadline.check()
            assertion = by_fact.get(fact)
            if assertion is not None and assertion.verdict is EvidenceFactVerdict.SUPPORTED:
                satisfied.add(fact)
            else:
                cleanup_satisfied = False
                unresolved.add(fact)

        if counterevidence:
            verdict = EvidenceAssessmentVerdict.NEGATIVE
        elif unresolved:
            verdict = EvidenceAssessmentVerdict.INCONCLUSIVE
        else:
            verdict = EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
        evidence_refs = tuple(
            sorted(
                {
                    ref
                    for assertion in plan.assertions
                    for ref in assertion.evidence_refs
                }
            )
        )
        deadline.check()
        return EvidenceAssessment.create(
            plan_id=plan.plan_id,
            requirement_id=plan.requirement.requirement_id,
            verdict=verdict,
            satisfied_facts=tuple(sorted(satisfied, key=lambda item: item.value)),
            counterevidence_facts=tuple(
                sorted(counterevidence, key=lambda item: item.value)
            ),
            unresolved_facts=tuple(sorted(unresolved, key=lambda item: item.value)),
            evidence_refs=evidence_refs,
            cleanup_requirement_satisfied=cleanup_satisfied,
            candidate_proposal_eligible=(
                verdict is EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
            ),
            assessed_at=plan.created_at,
        )

    def _binding(self, plan, *, scope, now):
        self._scope(scope, now=now)
        if (
            not plan.created_at <= now < plan.deadline
            or plan.requirement != self.requirement()
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
        ):
            raise EvidenceAssessmentRejected("Evidence Assessment binding drifted")

    @staticmethod
    def _scope(scope: Scope, *, now: datetime) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
        ):
            raise EvidenceAssessmentRejected(
                "Evidence Assessment requires a current read-only approved Scope"
            )

    def _assertions(
        self,
        requirement,
        assertions,
        *,
        limits,
        now,
        deadline=None,
    ):
        if len(assertions) > limits.max_assertions:
            raise EvidenceAssessmentRejected("Evidence Assertion budget exceeded")
        if len({item.assertion_id for item in assertions}) != len(assertions):
            raise EvidenceAssessmentRejected("Evidence Assertions must be unique")
        facts = tuple(item.fact for item in assertions)
        if len(set(facts)) != len(facts):
            raise EvidenceAssessmentRejected(
                "Evidence Assessment repeats a required fact"
            )
        allowed = {
            *requirement.observation_facts,
            *requirement.validation_facts,
            *requirement.counterevidence_facts,
            *requirement.cleanup_facts,
        }
        if any(
            item.requirement_id != requirement.requirement_id
            or item.fact not in allowed
            or item.observed_at > now
            for item in assertions
        ):
            raise EvidenceAssessmentRejected(
                "Evidence Assertion provenance is invalid"
            )
        evidence_refs = {
            ref for assertion in assertions for ref in assertion.evidence_refs
        }
        if len(evidence_refs) > limits.max_evidence_refs:
            raise EvidenceAssessmentRejected("Evidence reference budget exceeded")
        validation = tuple(
            item
            for item in assertions
            if item.stage is EvidenceRequirementStage.VALIDATION
        )
        critic = tuple(
            item
            for item in assertions
            if item.stage is EvidenceRequirementStage.CRITIC
        )
        if validation and critic:
            validation_contexts = {item.context_id for item in validation}
            critic_contexts = {item.context_id for item in critic}
            validation_producers = {item.producer_ref for item in validation}
            critic_producers = {item.producer_ref for item in critic}
            if (
                len(validation_contexts) != 1
                or len(critic_contexts) != 1
                or len(validation_producers) != 1
                or len(critic_producers) != 1
                or not validation_contexts.isdisjoint(critic_contexts)
                or not validation_producers.isdisjoint(critic_producers)
                or not {
                    ref for item in validation for ref in item.evidence_refs
                }.isdisjoint({ref for item in critic for ref in item.evidence_refs})
            ):
                raise EvidenceAssessmentRejected(
                    "Critic Evidence must be independent from Validation"
                )
        if deadline is not None:
            deadline.check()
        self._verify_evidence(assertions)

    def _verify_evidence(self, assertions) -> None:
        if not all(
            self.evidence_store.contains(ref)
            for assertion in assertions
            for ref in assertion.evidence_refs
        ):
            raise EvidenceAssessmentRejected("Evidence integrity check failed")
