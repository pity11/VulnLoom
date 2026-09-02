"""Trusted human Intake for an exact Finding promotion plan; never promotes."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.critic import (
    AgentCriticOutcomeBindingPlan,
    AgentCriticOutcomeBindingStore,
    CriticStore,
    agent_critic_outcome_binding_digest,
    agent_critic_outcome_binding_plan_digest,
    domain_object_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    Scope,
    ScopeState,
    ValidationResult,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.validation import AgentValidationOutcomeBindingStore, ValidationStore

from .duplicate_store import FindingDuplicateCheckStore
from .intake_models import (
    AgentFindingIntakeCommand,
    AgentFindingIntakePlan,
    AgentFindingIntakeRecord,
    agent_finding_intake_command_digest,
    agent_finding_intake_plan_digest,
)
from .intake_store import AgentFindingIntakeStore
from .models import (
    DuplicateCheckResult,
    FindingDuplicateCheck,
    FindingPromotionPlan,
    finding_duplicate_check_digest,
    finding_promotion_plan_digest,
)


class AgentFindingIntakeRejected(ValueError):
    pass


class AgentFindingIntakeTimedOut(TimeoutError):
    pass


class AgentFindingIntakeService:
    """Records a human choice without importing or invoking Candidate promotion."""

    def __init__(
        self,
        *,
        scope: Scope,
        critic_binding_store: AgentCriticOutcomeBindingStore,
        validation_binding_store: AgentValidationOutcomeBindingStore,
        validation_store: ValidationStore,
        critic_store: CriticStore,
        evidence_store: EvidenceStore,
        duplicate_check_store: FindingDuplicateCheckStore,
        store: AgentFindingIntakeStore,
    ):
        self.scope = scope
        self.critic_binding_store = critic_binding_store
        self.validation_binding_store = validation_binding_store
        self.validation_store = validation_store
        self.critic_store = critic_store
        self.evidence_store = evidence_store
        self.duplicate_check_store = duplicate_check_store
        self.store = store

    def prepare(
        self,
        *,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        promotion_plan: FindingPromotionPlan,
        duplicate_check: FindingDuplicateCheck,
        now: datetime,
        decision_deadline: datetime,
        idempotency_key: str,
    ) -> AgentFindingIntakePlan:
        binding, validation_outcome, critic_outcome = self._load(
            critic_binding_plan, promotion_plan, duplicate_check, now
        )
        evidence_bundle = validation_outcome.evidence_bundle
        assert evidence_bundle is not None
        if (
            not now
            < decision_deadline
            <= min(self.scope.valid_until, promotion_plan.deadline, duplicate_check.expires_at)
        ):
            raise AgentFindingIntakeRejected("Finding Intake deadline exceeds active authority")
        values = {
            "critic_outcome_binding_plan_id": critic_binding_plan.binding_plan_id,
            "critic_outcome_binding_id": binding.binding_id,
            "critic_outcome_binding_digest": agent_critic_outcome_binding_digest(binding),
            "promotion_plan_id": promotion_plan.promotion_plan_id,
            "promotion_plan_digest": finding_promotion_plan_digest(promotion_plan),
            "duplicate_check_id": duplicate_check.check_id,
            "duplicate_check_digest": finding_duplicate_check_digest(duplicate_check),
            "candidate_id": critic_outcome.candidate.candidate_id,
            "candidate_digest": domain_object_digest(critic_outcome.candidate),
            "finding_id": promotion_plan.finding_id,
            "validation_run_ids_digest": canonical_digest(promotion_plan.validation_run_ids),
            "evidence_bundle_id": evidence_bundle.bundle_id,
            "evidence_bundle_digest": domain_object_digest(evidence_bundle),
            "critic_review_id": critic_outcome.review.review_id,
            "critic_review_digest": domain_object_digest(critic_outcome.review),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "decision_deadline": decision_deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentFindingIntakePlan.create(**values)

    def decide(
        self,
        plan: AgentFindingIntakePlan,
        command: AgentFindingIntakeCommand,
        *,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        promotion_plan: FindingPromotionPlan,
        duplicate_check: FindingDuplicateCheck,
        now: datetime,
    ) -> AgentFindingIntakeRecord:
        try:
            AgentFindingIntakePlan.model_validate(plan)
            AgentFindingIntakeCommand.model_validate(command)
        except ValidationError as exc:
            raise AgentFindingIntakeRejected("Finding Intake boundary validation failed") from exc
        if now < plan.created_at or now >= plan.decision_deadline:
            raise AgentFindingIntakeTimedOut("Finding Intake decision is outside its window")
        expected = self.prepare(
            critic_binding_plan=critic_binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            now=plan.created_at,
            decision_deadline=plan.decision_deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentFindingIntakeRejected("Finding Intake plan drifted")
        if (
            command.command_id != agent_finding_intake_command_digest(command)
            or command.intake_plan_id != plan.intake_plan_id
            or command.intake_plan_digest != agent_finding_intake_plan_digest(plan)
            or command.critic_outcome_binding_id != plan.critic_outcome_binding_id
            or command.promotion_plan_id != plan.promotion_plan_id
            or command.promotion_plan_digest != plan.promotion_plan_digest
            or command.candidate_id != plan.candidate_id
            or command.finding_id != plan.finding_id
            or not plan.created_at <= command.decided_at < plan.decision_deadline
            or command.decided_at > now
        ):
            raise AgentFindingIntakeRejected("Finding Intake command drifted")
        claim = self.store.claim(plan, command, now=now)
        if not claim.created:
            assert claim.record is not None
            return claim.record
        values = {
            "intake_plan_id": plan.intake_plan_id,
            "command_id": command.command_id,
            "critic_outcome_binding_id": plan.critic_outcome_binding_id,
            "promotion_plan_id": plan.promotion_plan_id,
            "promotion_plan_digest": plan.promotion_plan_digest,
            "duplicate_check_id": plan.duplicate_check_id,
            "candidate_id": plan.candidate_id,
            "finding_id": plan.finding_id,
            "evidence_bundle_id": plan.evidence_bundle_id,
            "critic_review_id": plan.critic_review_id,
            "scope_id": plan.scope_id,
            "scope_version": plan.scope_version,
            "decision": command.decision,
            "reason_code": command.reason_code,
            "reviewer": command.reviewer,
            "decided_at": command.decided_at,
            "expires_at": plan.decision_deadline,
        }
        record = AgentFindingIntakeRecord(record_id=canonical_digest(values), **values)
        self.store.complete(record)
        return record

    def _load(self, binding_plan, promotion_plan, duplicate_check, now):
        try:
            stored_duplicate_check = self.duplicate_check_store.load_current(
                duplicate_check.check_id
            )
            binding = self.critic_binding_store.load_completed(binding_plan.binding_plan_id)
            validation_binding = self.validation_binding_store.load_completed_by_binding_id(
                binding.outcome_binding_id
            )
            _, validation_outcome = self.validation_store.load_completed(
                validation_binding.validation_plan_id
            )
            critic_plan, critic_outcome = self.critic_store.load_completed(binding.critic_plan_id)
        except (ValueError, RuntimeError) as exc:
            raise AgentFindingIntakeRejected(
                "Finding Intake authoritative input unavailable"
            ) from exc
        evidence_bundle = validation_outcome.evidence_bundle
        candidate = critic_outcome.candidate
        review = critic_outcome.review
        run = validation_outcome.validation_run
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or binding_plan.binding_plan_id
            != agent_critic_outcome_binding_plan_digest(binding_plan)
            or binding.binding_plan_id != binding_plan.binding_plan_id
            or binding.binding_id != promotion_plan.critic_outcome_binding_id
            or agent_critic_outcome_binding_digest(binding)
            != promotion_plan.critic_outcome_binding_digest
            or binding.verdict is not CriticVerdict.ACCEPTED
            or binding.final_candidate_state is not CandidateState.CRITIC_REVIEWED
            or binding.critic_outcome_digest != domain_object_digest(critic_outcome)
            or binding.critic_review_id != review.review_id
            or binding.critic_review_digest != domain_object_digest(review)
            or binding.final_candidate_digest != domain_object_digest(candidate)
            or candidate.state is not CandidateState.CRITIC_REVIEWED
            or review.verdict is not CriticVerdict.ACCEPTED
            or review.candidate_id != candidate.candidate_id
            or critic_plan.plan_id != binding.critic_plan_id
            or critic_outcome.plan_id != critic_plan.plan_id
            or validation_binding.binding_id != binding.outcome_binding_id
            or validation_binding.final_candidate_state is not CandidateState.VALIDATED
            or validation_binding.validation_outcome_digest
            != canonical_digest(validation_outcome.model_dump(mode="python"))
            or run.result is not ValidationResult.REPRODUCED
            or run.run_id != binding.validation_run_id
            or run.run_id != review.validation_run_id
            or evidence_bundle is None
            or evidence_bundle.bundle_id != binding.evidence_bundle_id
            or evidence_bundle.bundle_id != review.evidence_bundle_id
            or not evidence_bundle.evidence_refs
            or any(not self.evidence_store.contains(ref) for ref in evidence_bundle.evidence_refs)
            or duplicate_check.check_id != finding_duplicate_check_digest(duplicate_check)
            or stored_duplicate_check != duplicate_check
            or duplicate_check.result is not DuplicateCheckResult.CLEAR
            or not duplicate_check.checked_at <= now < duplicate_check.expires_at
            or duplicate_check.candidate_id != candidate.candidate_id
            or duplicate_check.candidate_digest != domain_object_digest(candidate)
            or duplicate_check.target_version_digest != canonical_digest(candidate.target_version)
            or duplicate_check.scope_id != self.scope.scope_id
            or duplicate_check.scope_version != self.scope.version
            or promotion_plan.promotion_plan_id != finding_promotion_plan_digest(promotion_plan)
            or not promotion_plan.created_at <= now < promotion_plan.deadline
            or promotion_plan.critic_outcome_binding_plan_id != binding_plan.binding_plan_id
            or promotion_plan.critic_outcome_binding_id != binding.binding_id
            or promotion_plan.candidate_id != candidate.candidate_id
            or promotion_plan.candidate_digest != domain_object_digest(candidate)
            or promotion_plan.validation_run_ids != (run.run_id,)
            or promotion_plan.validation_run_digests != (domain_object_digest(run),)
            or promotion_plan.evidence_bundle_id != evidence_bundle.bundle_id
            or promotion_plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or promotion_plan.critic_review_id != review.review_id
            or promotion_plan.critic_review_digest != domain_object_digest(review)
            or promotion_plan.duplicate_check_id != duplicate_check.check_id
            or promotion_plan.duplicate_check_digest
            != finding_duplicate_check_digest(duplicate_check)
            or promotion_plan.scope_id != self.scope.scope_id
            or promotion_plan.scope_version != self.scope.version
        ):
            raise AgentFindingIntakeRejected("Finding Intake provenance drifted")
        return binding, validation_outcome, critic_outcome
