"""Approval-gated deterministic Candidate-to-Finding promotion."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.critic import AgentCriticOutcomeBindingPlan, domain_object_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    ScopeState,
)
from vulnloom.domain.state_machine import TransitionRejected, promote_candidate

from .intake import AgentFindingIntakeRejected, AgentFindingIntakeService
from .intake_models import (
    AgentFindingIntakeDecision,
    AgentFindingIntakePlan,
    AgentFindingIntakeReason,
    agent_finding_intake_record_digest,
)
from .models import FindingDuplicateCheck, FindingPromotionPlan, finding_promotion_plan_digest
from .promotion_models import (
    FINDING_PROMOTION_SIDE_EFFECTS,
    FindingPromotionApprovalAction,
    FindingPromotionExecutionPlan,
    FindingPromotionOutcome,
    finding_promotion_execution_plan_digest,
)
from .promotion_store import FindingPromotionStore


class FindingPromotionRejected(ValueError):
    pass


class FindingPromotionTimedOut(TimeoutError):
    pass


class FindingPromotionService:
    """Consumes accepted Intake plus an exact human Approval; never invokes an Agent or tool."""

    def __init__(self, *, intake_service: AgentFindingIntakeService, store: FindingPromotionStore):
        self.intake_service = intake_service
        self.store = store
        self.scope = intake_service.scope

    def prepare(
        self,
        *,
        intake_plan: AgentFindingIntakePlan,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        promotion_plan: FindingPromotionPlan,
        duplicate_check: FindingDuplicateCheck,
        approval: ApprovalRequest,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> FindingPromotionExecutionPlan:
        record, candidate, _run, _bundle, _review = self._load(
            intake_plan=intake_plan,
            critic_binding_plan=critic_binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=now,
        )
        if (
            not now
            < deadline
            <= min(
                self.scope.valid_until,
                intake_plan.decision_deadline,
                record.expires_at,
                promotion_plan.deadline,
                duplicate_check.expires_at,
                approval.expires_at,
            )
        ):
            raise FindingPromotionRejected("Finding promotion deadline exceeds active authority")
        action = self.approval_action(record=record, promotion_plan=promotion_plan)
        values = {
            "approval_action_id": action.action_id,
            "approval_id": approval.approval_id,
            "approval_digest": domain_object_digest(approval),
            "intake_plan_id": intake_plan.intake_plan_id,
            "intake_record_id": record.record_id,
            "intake_record_digest": agent_finding_intake_record_digest(record),
            "promotion_plan_id": promotion_plan.promotion_plan_id,
            "promotion_plan_digest": finding_promotion_plan_digest(promotion_plan),
            "candidate_id": candidate.candidate_id,
            "candidate_digest": domain_object_digest(candidate),
            "finding_id": promotion_plan.finding_id,
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        return FindingPromotionExecutionPlan.create(**values)

    def execute(
        self,
        plan: FindingPromotionExecutionPlan,
        *,
        intake_plan: AgentFindingIntakePlan,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        promotion_plan: FindingPromotionPlan,
        duplicate_check: FindingDuplicateCheck,
        approval: ApprovalRequest,
        now: datetime,
    ) -> FindingPromotionOutcome:
        try:
            FindingPromotionExecutionPlan.model_validate(plan)
        except ValidationError as exc:
            raise FindingPromotionRejected("Finding promotion execution plan drifted") from exc
        if now < plan.created_at or now >= plan.deadline:
            raise FindingPromotionTimedOut("Finding promotion is outside its execution window")
        # Re-read current authority and all authoritative completed checkpoints immediately
        # before the state transition. This also rejects a superseded duplicate proof.
        record, candidate, run, bundle, review = self._load(
            intake_plan=intake_plan,
            critic_binding_plan=critic_binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=now,
        )
        expected = self.prepare(
            intake_plan=intake_plan,
            critic_binding_plan=critic_binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan or plan.execution_plan_id != finding_promotion_execution_plan_digest(
            plan
        ):
            raise FindingPromotionRejected("Finding promotion execution plan drifted")
        try:
            promoted, finding = promote_candidate(
                candidate,
                scope=self.scope,
                now=now,
                root_cause=promotion_plan.root_cause,
                affected_versions=promotion_plan.affected_versions,
                impact=promotion_plan.impact,
                severity_assessment=promotion_plan.severity_assessment,
                validation_runs=(run,),
                evidence_bundle=bundle,
                critic_review=review,
                duplicate_checked=True,
                finding_id=promotion_plan.finding_id,
            )
        except TransitionRejected as exc:
            raise FindingPromotionRejected("Finding promotion state transition rejected") from exc
        values = {
            "execution_plan_id": plan.execution_plan_id,
            "approval_action_id": plan.approval_action_id,
            "approval_id": plan.approval_id,
            "approval_digest": plan.approval_digest,
            "intake_record_id": record.record_id,
            "promotion_plan_id": promotion_plan.promotion_plan_id,
            "promotion_plan_digest": finding_promotion_plan_digest(promotion_plan),
            "source_candidate_digest": domain_object_digest(candidate),
            "promoted_candidate": promoted,
            "promoted_candidate_digest": domain_object_digest(promoted),
            "finding": finding,
            "finding_digest": domain_object_digest(finding),
            "completed_at": now,
        }
        partial = FindingPromotionOutcome.model_construct(outcome_id="0" * 64, **values)
        outcome = FindingPromotionOutcome(
            outcome_id=canonical_digest(partial.model_dump(mode="python", exclude={"outcome_id"})),
            **values,
        )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        self.store.complete(outcome)
        return outcome

    def approval_action(self, *, record, promotion_plan) -> FindingPromotionApprovalAction:
        return FindingPromotionApprovalAction.create(
            engagement_id=self.scope.engagement_id,
            target_id=self._candidate_target_id(promotion_plan),
            intake_record_id=record.record_id,
            intake_record_digest=agent_finding_intake_record_digest(record),
            promotion_plan_id=promotion_plan.promotion_plan_id,
            promotion_plan_digest=finding_promotion_plan_digest(promotion_plan),
            candidate_id=promotion_plan.candidate_id,
            candidate_digest=promotion_plan.candidate_digest,
            finding_id=promotion_plan.finding_id,
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            expected_side_effects=FINDING_PROMOTION_SIDE_EFFECTS,
        )

    def _candidate_target_id(self, promotion_plan: FindingPromotionPlan):
        binding = self.intake_service.critic_binding_store.load_completed(
            promotion_plan.critic_outcome_binding_plan_id
        )
        _, outcome = self.intake_service.critic_store.load_completed(binding.critic_plan_id)
        return outcome.candidate.target_id

    def _load(
        self,
        *,
        intake_plan,
        critic_binding_plan,
        promotion_plan,
        duplicate_check,
        approval,
        now,
    ):
        try:
            AgentFindingIntakePlan.model_validate(intake_plan)
            ApprovalRequest.model_validate(approval)
            record = self.intake_service.store.load_completed(intake_plan.intake_plan_id)
            _binding, validation_outcome, critic_outcome = self.intake_service.load_authoritative(
                critic_binding_plan, promotion_plan, duplicate_check, now
            )
        except (ValueError, RuntimeError, AgentFindingIntakeRejected) as exc:
            raise FindingPromotionRejected(
                "Finding promotion authoritative input unavailable"
            ) from exc
        candidate = critic_outcome.candidate
        bundle = validation_outcome.evidence_bundle
        run = validation_outcome.validation_run
        review = critic_outcome.review
        action = self.approval_action(record=record, promotion_plan=promotion_plan)
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or record.decision is not AgentFindingIntakeDecision.ACCEPT
            or record.reason_code is not AgentFindingIntakeReason.HUMAN_ACCEPTED_EXACT_PROMOTION
            or not record.decided_at <= now < record.expires_at
            or record.intake_plan_id != intake_plan.intake_plan_id
            or record.critic_outcome_binding_id != intake_plan.critic_outcome_binding_id
            or record.promotion_plan_id != promotion_plan.promotion_plan_id
            or record.promotion_plan_digest != finding_promotion_plan_digest(promotion_plan)
            or record.candidate_id != candidate.candidate_id
            or record.finding_id != promotion_plan.finding_id
            or candidate.state is not CandidateState.CRITIC_REVIEWED
            or bundle is None
            or approval.status is not ApprovalStatus.GRANTED
            or approval.action is not ApprovalAction.MUTATE_TARGET_STATE
            or approval.action_digest != action.action_id
            or approval.engagement_id != self.scope.engagement_id
            or approval.target_id != candidate.target_id
            or approval.policy_version != self.scope.version
            or approval.expected_side_effects != FINDING_PROMOTION_SIDE_EFFECTS
            or approval.decided_by is None
            or approval.decided_at is None
            or not record.decided_at <= approval.decided_at <= now < approval.expires_at
        ):
            raise FindingPromotionRejected("Finding promotion Intake or Approval drifted")
        return record, candidate, run, bundle, review
