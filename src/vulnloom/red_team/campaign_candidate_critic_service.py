"""Human-gated B5.9 admission to independent Campaign Candidate Critic review."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.critic.models import CRITIC_RULESET_DIGEST
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    CandidateState,
    Scope,
    ScopeState,
    ValidationResult,
)

from .campaign_candidate_critic_models import (
    REQUIRED_CAMPAIGN_CRITIC_ANGLES,
    CampaignCandidateCriticIntakeCheckpoint,
    CampaignCandidateCriticIntakeLimits,
    CampaignCandidateCriticIntakeOutcome,
    CampaignCandidateCriticIntakePlan,
    CampaignCandidateCriticLifecycleState,
)
from .campaign_candidate_critic_store import CampaignCandidateCriticIntakeStore
from .campaign_candidate_execution_models import (
    CampaignCandidateValidationCompletionCheckpoint,
    CampaignCandidateValidationExecutionOutcome,
    CampaignCandidateValidationExecutionPlan,
)
from .campaign_candidate_state_machine import admit_campaign_candidate_critic
from .campaign_candidate_validation_models import REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS


class CampaignCandidateValidationExecutionSource(Protocol):
    def plan(self, plan_id: str) -> CampaignCandidateValidationExecutionPlan: ...

    def outcome(self, plan_id: str) -> CampaignCandidateValidationExecutionOutcome: ...

    def checkpoint(self, candidate_id) -> CampaignCandidateValidationCompletionCheckpoint: ...


class CampaignCandidateCriticIntakeRejected(ValueError):
    pass


class CampaignCandidateCriticIntakeTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CampaignCandidateCriticIntakeTimedOut(
                "Campaign Candidate Critic Intake timed out"
            )


class CampaignCandidateCriticIntakeService:
    def __init__(
        self,
        *,
        validation_source: CampaignCandidateValidationExecutionSource,
        store: CampaignCandidateCriticIntakeStore,
        monotonic: Callable[[], float] = time.monotonic,
        after_claim: Callable[[], None] | None = None,
    ) -> None:
        self.validation_source = validation_source
        self.store = store
        self.monotonic = monotonic
        self.after_claim = after_claim

    def prepare(
        self,
        *,
        validation_execution_plan_id: str,
        review_producer_digest: str,
        scope: Scope,
        limits: CampaignCandidateCriticIntakeLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CampaignCandidateCriticIntakePlan:
        validation_plan, validation_outcome, checkpoint = self._read(validation_execution_plan_id)
        self._validate_source(validation_plan, validation_outcome, checkpoint, scope=scope, now=now)
        validation_producer_digest = self._validation_producer_digest(validation_plan)
        if validation_producer_digest == review_producer_digest:
            raise CampaignCandidateCriticIntakeRejected(
                "Campaign Candidate Critic producer must be independent"
            )
        stop_at = min(deadline, scope.valid_until)
        if not now < stop_at:
            raise CampaignCandidateCriticIntakeRejected(
                "Campaign Candidate Critic Intake deadline is invalid"
            )
        review_context_digest = canonical_digest(
            {
                "candidate_id": validation_plan.candidate_id,
                "candidate_digest": validation_plan.candidate_digest,
                "validation_run_id": validation_outcome.validation_run.run_id,
                "validation_run_digest": canonical_digest(
                    validation_outcome.validation_run.model_dump(mode="python")
                ),
                "evidence_bundle_id": validation_outcome.evidence_bundle.bundle_id,
                "evidence_bundle_digest": canonical_digest(
                    validation_outcome.evidence_bundle.model_dump(mode="python")
                ),
                "validation_context_digest": validation_plan.validation_context_digest,
                "validation_producer_digest": validation_producer_digest,
                "review_producer_digest": review_producer_digest,
                "required_counterevidence_angles": REQUIRED_CAMPAIGN_CRITIC_ANGLES,
                "ruleset_digest": CRITIC_RULESET_DIGEST,
                "contract": "campaign-candidate-independent-critic-v1",
            }
        )
        return CampaignCandidateCriticIntakePlan.create(
            validation_execution_plan_id=validation_plan.execution_plan_id,
            validation_execution_plan_digest=canonical_digest(
                validation_plan.model_dump(mode="python")
            ),
            validation_execution_outcome_id=validation_outcome.outcome_id,
            validation_execution_outcome_digest=canonical_digest(
                validation_outcome.model_dump(mode="python")
            ),
            validation_checkpoint_id=checkpoint.checkpoint_id,
            validation_checkpoint_digest=canonical_digest(checkpoint.model_dump(mode="python")),
            candidate_id=validation_plan.candidate_id,
            candidate_digest=validation_plan.candidate_digest,
            target_id=validation_plan.target_id,
            target_version=validation_plan.target_version,
            scope_id=validation_plan.scope_id,
            scope_version=validation_plan.scope_version,
            validation_run_id=validation_outcome.validation_run.run_id,
            validation_run_digest=canonical_digest(
                validation_outcome.validation_run.model_dump(mode="python")
            ),
            evidence_bundle_id=validation_outcome.evidence_bundle.bundle_id,
            evidence_bundle_digest=canonical_digest(
                validation_outcome.evidence_bundle.model_dump(mode="python")
            ),
            fresh_fact_ids=tuple(sorted(item.fact_id for item in validation_outcome.fresh_facts)),
            validation_context_digest=validation_plan.validation_context_digest,
            review_context_digest=review_context_digest,
            validation_producer_digest=validation_producer_digest,
            review_producer_digest=review_producer_digest,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: CampaignCandidateCriticIntakePlan,
        *,
        approval: ApprovalRequest,
        scope: Scope,
        now: datetime,
    ) -> CampaignCandidateCriticIntakeOutcome:
        authoritative = CampaignCandidateCriticIntakePlan.model_validate(
            plan.model_dump(mode="python")
        )
        validation_plan, validation_outcome, checkpoint = self._read(
            authoritative.validation_execution_plan_id
        )
        self._validate_source(validation_plan, validation_outcome, checkpoint, scope=scope, now=now)
        self._validate_plan(authoritative, validation_plan, validation_outcome, checkpoint)
        if not authoritative.created_at <= now < authoritative.deadline:
            raise CampaignCandidateCriticIntakeTimedOut(
                "Campaign Candidate Critic Intake Plan is not active"
            )
        if (
            approval.engagement_id != scope.engagement_id
            or approval.target_id != authoritative.target_id
            or approval.policy_version != scope.version
            or approval.expected_side_effects != ("queue independent campaign candidate critic",)
            or approval.decided_at is None
            or not authoritative.created_at <= approval.decided_at <= now < approval.expires_at
            or not approval.is_valid_for(
                action=ApprovalAction.QUEUE_CAMPAIGN_CANDIDATE_CRITIC,
                digest=authoritative.critic_intake_plan_id,
                now=now,
            )
        ):
            raise CampaignCandidateCriticIntakeRejected(
                "Campaign Candidate Critic Intake Approval is invalid"
            )
        deadline = _Deadline(authoritative.limits.timeout_seconds, self.monotonic)
        deadline.check()
        claim = self.store.claim(authoritative, now=now)
        if claim.outcome is not None:
            return claim.outcome
        if self.after_claim is not None:
            self.after_claim()
        critic_state = admit_campaign_candidate_critic(checkpoint.state)
        if critic_state is not CampaignCandidateCriticLifecycleState.PENDING:
            raise CampaignCandidateCriticIntakeRejected(
                "Campaign Candidate Critic lifecycle admission is invalid"
            )
        intake_checkpoint = CampaignCandidateCriticIntakeCheckpoint.create(
            critic_intake_plan_id=authoritative.critic_intake_plan_id,
            candidate_id=authoritative.candidate_id,
            candidate_digest=authoritative.candidate_digest,
            approval_id=approval.approval_id,
            approval_digest=approval.action_digest,
            validation_run_id=authoritative.validation_run_id,
            validation_run_digest=authoritative.validation_run_digest,
            evidence_bundle_id=authoritative.evidence_bundle_id,
            evidence_bundle_digest=authoritative.evidence_bundle_digest,
            validation_context_digest=authoritative.validation_context_digest,
            review_context_digest=authoritative.review_context_digest,
            required_counterevidence_angles=authoritative.required_counterevidence_angles,
            recorded_at=approval.decided_at,
        )
        deadline.check()
        outcome = CampaignCandidateCriticIntakeOutcome.create(
            critic_intake_plan_id=authoritative.critic_intake_plan_id,
            checkpoint=intake_checkpoint,
            attempt=claim.attempt,
            completed_at=now,
        )
        deadline.check()
        self.store.complete(authoritative, outcome)
        return outcome

    def _read(self, plan_id):
        try:
            plan = self.validation_source.plan(plan_id)
            outcome = self.validation_source.outcome(plan_id)
            checkpoint = self.validation_source.checkpoint(plan.candidate_id)
            return plan, outcome, checkpoint
        except (KeyError, LookupError) as exc:
            raise CampaignCandidateCriticIntakeRejected(
                "Campaign Candidate validation source is unavailable"
            ) from exc

    @staticmethod
    def _validation_producer_digest(validation_plan):
        return canonical_digest(
            {
                "primary_request_digest": validation_plan.primary_request_digest,
                "replay_request_digest": validation_plan.replay_request_digest,
                "image_digest": validation_plan.primary_request.profile.image_digest,
                "role": "validator",
            }
        )

    @staticmethod
    def _validate_source(plan, outcome, checkpoint, *, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or outcome.execution_plan_id != plan.execution_plan_id
            or outcome.checkpoint != checkpoint
            or checkpoint.candidate_id != plan.candidate_id
            or checkpoint.candidate_digest != plan.candidate_digest
            or checkpoint.state is not CandidateState.VALIDATED
            or checkpoint.validation_context_digest != plan.validation_context_digest
            or outcome.validation_run.result is not ValidationResult.REPRODUCED
            or outcome.validation_run.candidate_id != plan.candidate_id
            or outcome.validation_run.run_id != checkpoint.validation_run_id
            or canonical_digest(outcome.validation_run.model_dump(mode="python"))
            != checkpoint.validation_run_digest
            or outcome.evidence_bundle.bundle_id != checkpoint.evidence_bundle_id
            or canonical_digest(outcome.evidence_bundle.model_dump(mode="python"))
            != checkpoint.evidence_bundle_digest
            or outcome.validation_run.evidence_refs != outcome.fresh_evidence_refs
            or outcome.evidence_bundle.evidence_refs != outcome.fresh_evidence_refs
            or {item.fact for item in outcome.fresh_facts}
            != set(REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS)
            or any(
                item.execution_plan_id != plan.execution_plan_id
                or item.candidate_id != plan.candidate_id
                or item.validation_context_digest != plan.validation_context_digest
                or not set(item.evidence_refs) <= set(outcome.fresh_evidence_refs)
                for item in outcome.fresh_facts
            )
            or not outcome.validation_reproduced
            or not outcome.critic_required
            or outcome.critic_completed
            or outcome.finding_created
            or outcome.submission_authorized
            or not outcome.cleanup_complete
        ):
            raise CampaignCandidateCriticIntakeRejected(
                "Campaign Candidate validation source binding is invalid"
            )

    @staticmethod
    def _validate_plan(plan, validation_plan, validation_outcome, checkpoint):
        expected = {
            "validation_execution_plan_digest": canonical_digest(
                validation_plan.model_dump(mode="python")
            ),
            "validation_execution_outcome_id": validation_outcome.outcome_id,
            "validation_execution_outcome_digest": canonical_digest(
                validation_outcome.model_dump(mode="python")
            ),
            "validation_checkpoint_id": checkpoint.checkpoint_id,
            "validation_checkpoint_digest": canonical_digest(checkpoint.model_dump(mode="python")),
            "candidate_id": validation_plan.candidate_id,
            "candidate_digest": validation_plan.candidate_digest,
            "target_id": validation_plan.target_id,
            "target_version": validation_plan.target_version,
            "scope_id": validation_plan.scope_id,
            "scope_version": validation_plan.scope_version,
            "validation_run_id": validation_outcome.validation_run.run_id,
            "validation_run_digest": canonical_digest(
                validation_outcome.validation_run.model_dump(mode="python")
            ),
            "evidence_bundle_id": validation_outcome.evidence_bundle.bundle_id,
            "evidence_bundle_digest": canonical_digest(
                validation_outcome.evidence_bundle.model_dump(mode="python")
            ),
            "fresh_fact_ids": tuple(
                sorted(item.fact_id for item in validation_outcome.fresh_facts)
            ),
            "validation_context_digest": validation_plan.validation_context_digest,
            "validation_producer_digest": (
                CampaignCandidateCriticIntakeService._validation_producer_digest(validation_plan)
            ),
        }
        if any(getattr(plan, key) != value for key, value in expected.items()):
            raise CampaignCandidateCriticIntakeRejected(
                "Campaign Candidate Critic Intake Plan source binding drifted"
            )
