"""Human-gated B5.7 admission to Campaign Candidate Validation."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    CandidateState,
    Scope,
    ScopeState,
)

from .campaign_candidate_models import (
    CampaignCandidateIntakeOutcome,
    CampaignCandidateIntakePlan,
)
from .campaign_candidate_state_machine import admit_campaign_candidate_validation
from .campaign_candidate_validation_models import (
    REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS,
    CampaignCandidateLifecycleCheckpoint,
    CampaignCandidateValidationIntakeLimits,
    CampaignCandidateValidationIntakeOutcome,
    CampaignCandidateValidationIntakePlan,
)
from .campaign_candidate_validation_store import (
    CampaignCandidateValidationIntakeStore,
)


class CampaignCandidateIntakeSource(Protocol):
    def plan(self, plan_id: str) -> CampaignCandidateIntakePlan: ...

    def outcome(self, plan_id: str) -> CampaignCandidateIntakeOutcome: ...


class CampaignCandidateValidationIntakeRejected(ValueError):
    pass


class CampaignCandidateValidationIntakeTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CampaignCandidateValidationIntakeTimedOut(
                "Campaign Candidate Validation Intake timed out"
            )


class CampaignCandidateValidationIntakeService:
    def __init__(
        self,
        *,
        candidate_source: CampaignCandidateIntakeSource,
        store: CampaignCandidateValidationIntakeStore,
        monotonic: Callable[[], float] = time.monotonic,
        after_claim: Callable[[], None] | None = None,
    ) -> None:
        self.candidate_source = candidate_source
        self.store = store
        self.monotonic = monotonic
        self.after_claim = after_claim

    def prepare(
        self,
        *,
        candidate_intake_plan_id: str,
        scope: Scope,
        limits: CampaignCandidateValidationIntakeLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CampaignCandidateValidationIntakePlan:
        candidate_plan, candidate_outcome = self._read(candidate_intake_plan_id)
        self._validate_source(candidate_plan, candidate_outcome, scope=scope, now=now)
        stop_at = min(deadline, scope.valid_until)
        if not now < stop_at:
            raise CampaignCandidateValidationIntakeRejected(
                "Campaign Candidate Validation Intake deadline is invalid"
            )
        candidate = candidate_outcome.candidate
        context_digest = canonical_digest(
            {
                "candidate_id": candidate.candidate_id,
                "candidate_digest": candidate.candidate_digest,
                "scope_id": scope.scope_id,
                "scope_version": scope.version,
                "required_fresh_facts": REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS,
                "contract": "campaign-candidate-fresh-validation-v1",
            }
        )
        return CampaignCandidateValidationIntakePlan.create(
            candidate_intake_plan_id=candidate_plan.intake_plan_id,
            candidate_intake_plan_digest=canonical_digest(candidate_plan.model_dump(mode="python")),
            candidate_intake_outcome_id=candidate_outcome.outcome_id,
            candidate_intake_outcome_digest=canonical_digest(
                candidate_outcome.model_dump(mode="python")
            ),
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate.candidate_digest,
            target_id=candidate.target_id,
            target_version=candidate.target_version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            vulnerability_class=candidate.vulnerability_class,
            cwe=candidate.cwe,
            prior_campaign_evidence_refs=candidate.evidence_refs,
            validation_context_digest=context_digest,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: CampaignCandidateValidationIntakePlan,
        *,
        approval: ApprovalRequest,
        scope: Scope,
        now: datetime,
    ) -> CampaignCandidateValidationIntakeOutcome:
        authoritative = CampaignCandidateValidationIntakePlan.model_validate(
            plan.model_dump(mode="python")
        )
        source_plan, source_outcome = self._read(authoritative.candidate_intake_plan_id)
        self._validate_source(source_plan, source_outcome, scope=scope, now=now)
        self._validate_plan(authoritative, source_plan, source_outcome)
        if not authoritative.created_at <= now < authoritative.deadline:
            raise CampaignCandidateValidationIntakeTimedOut(
                "Campaign Candidate Validation Intake Plan is not active"
            )
        if (
            approval.engagement_id != scope.engagement_id
            or approval.target_id != authoritative.target_id
            or approval.policy_version != scope.version
            or approval.expected_side_effects != ("queue campaign candidate validation",)
            or approval.decided_at is None
            or not authoritative.created_at <= approval.decided_at <= now < approval.expires_at
            or not approval.is_valid_for(
                action=ApprovalAction.QUEUE_CAMPAIGN_CANDIDATE_VALIDATION,
                digest=authoritative.validation_intake_plan_id,
                now=now,
            )
        ):
            raise CampaignCandidateValidationIntakeRejected(
                "Campaign Candidate Validation Intake Approval is invalid"
            )
        deadline = _Deadline(authoritative.limits.timeout_seconds, self.monotonic)
        deadline.check()
        claim = self.store.claim(authoritative, now=now)
        if claim.outcome is not None:
            return claim.outcome
        if self.after_claim is not None:
            self.after_claim()
        state = admit_campaign_candidate_validation(source_outcome.candidate.state)
        if state is not CandidateState.VALIDATION_PENDING:
            raise CampaignCandidateValidationIntakeRejected(
                "Campaign Candidate lifecycle transition is invalid"
            )
        checkpoint = CampaignCandidateLifecycleCheckpoint.create(
            validation_intake_plan_id=authoritative.validation_intake_plan_id,
            candidate_id=authoritative.candidate_id,
            candidate_digest=authoritative.candidate_digest,
            approval_id=approval.approval_id,
            approval_digest=approval.action_digest,
            validation_context_digest=authoritative.validation_context_digest,
            prior_campaign_evidence_refs=authoritative.prior_campaign_evidence_refs,
            required_fresh_facts=authoritative.required_fresh_facts,
            recorded_at=approval.decided_at,
        )
        deadline.check()
        outcome = CampaignCandidateValidationIntakeOutcome.create(
            validation_intake_plan_id=authoritative.validation_intake_plan_id,
            checkpoint=checkpoint,
            attempt=claim.attempt,
            completed_at=now,
        )
        deadline.check()
        self.store.complete(authoritative, outcome)
        return outcome

    def _read(self, candidate_intake_plan_id):
        try:
            return (
                self.candidate_source.plan(candidate_intake_plan_id),
                self.candidate_source.outcome(candidate_intake_plan_id),
            )
        except (KeyError, LookupError) as exc:
            raise CampaignCandidateValidationIntakeRejected(
                "Campaign Candidate authoritative source is unavailable"
            ) from exc

    @staticmethod
    def _validate_source(candidate_plan, candidate_outcome, *, scope, now):
        candidate = candidate_outcome.candidate
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
            or candidate.scope_id != scope.scope_id
            or candidate.scope_version != scope.version
        ):
            raise CampaignCandidateValidationIntakeRejected(
                "Campaign Candidate Validation Intake requires a current approved Scope"
            )
        if (
            candidate_outcome.intake_plan_id != candidate_plan.intake_plan_id
            or candidate.candidate_id != candidate_plan.candidate_id
            or candidate.target_id != candidate_plan.target_id
            or candidate.target_version != candidate_plan.target_version
            or candidate.vulnerability_class != candidate_plan.vulnerability_class
            or candidate.cwe != candidate_plan.cwe
            or candidate.evidence_refs != candidate_plan.evidence_refs
            or candidate.state is not CandidateState.PROPOSED
            or not candidate.validation_required
            or not candidate.independent_critic_required
            or candidate.prior_campaign_evidence_is_validation_run
            or candidate.finding_authorized
            or candidate.submission_authorized
            or not candidate_outcome.candidate_created
            or candidate_outcome.validation_started
            or candidate_outcome.finding_created
            or not candidate_outcome.cleanup_complete
        ):
            raise CampaignCandidateValidationIntakeRejected(
                "Campaign Candidate source binding is invalid"
            )

    @staticmethod
    def _validate_plan(plan, candidate_plan, candidate_outcome):
        candidate = candidate_outcome.candidate
        expected = {
            "candidate_intake_plan_digest": canonical_digest(
                candidate_plan.model_dump(mode="python")
            ),
            "candidate_intake_outcome_id": candidate_outcome.outcome_id,
            "candidate_intake_outcome_digest": canonical_digest(
                candidate_outcome.model_dump(mode="python")
            ),
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate.candidate_digest,
            "target_id": candidate.target_id,
            "target_version": candidate.target_version,
            "scope_id": candidate.scope_id,
            "scope_version": candidate.scope_version,
            "vulnerability_class": candidate.vulnerability_class,
            "cwe": candidate.cwe,
            "prior_campaign_evidence_refs": candidate.evidence_refs,
        }
        if any(getattr(plan, key) != value for key, value in expected.items()):
            raise CampaignCandidateValidationIntakeRejected(
                "Campaign Candidate Validation Intake Plan source binding drifted"
            )
