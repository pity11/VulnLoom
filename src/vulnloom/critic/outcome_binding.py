"""Read-only provenance binding for an already completed Critic outcome."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    Scope,
    ScopeState,
    ValidationResult,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.validation import (
    AgentValidationOutcomeBindingStore,
    ValidationStore,
    agent_validation_outcome_binding_digest,
    candidate_content_digest,
)

from .intake_models import (
    AgentCriticIntakeDecision,
    AgentCriticIntakePlan,
    agent_critic_intake_plan_digest,
    agent_critic_intake_record_digest,
)
from .intake_store import AgentCriticIntakeStore
from .models import CounterevidenceDisposition, critic_plan_digest, domain_object_digest
from .outcome_binding_models import AgentCriticOutcomeBinding, AgentCriticOutcomeBindingPlan
from .outcome_binding_store import AgentCriticOutcomeBindingStore
from .store import CriticStore


class AgentCriticOutcomeBindingRejected(ValueError):
    pass


class AgentCriticOutcomeBindingService:
    """Binds sealed completed state; it never invokes Critic or changes a Candidate."""

    def __init__(
        self,
        *,
        scope: Scope,
        critic_intake_store: AgentCriticIntakeStore,
        outcome_binding_store: AgentValidationOutcomeBindingStore,
        validation_store: ValidationStore,
        critic_store: CriticStore,
        evidence_store: EvidenceStore,
        binding_store: AgentCriticOutcomeBindingStore,
    ):
        self.scope = scope
        self.critic_intake_store = critic_intake_store
        self.outcome_binding_store = outcome_binding_store
        self.validation_store = validation_store
        self.critic_store = critic_store
        self.evidence_store = evidence_store
        self.binding_store = binding_store

    def prepare(
        self,
        *,
        critic_intake_plan: AgentCriticIntakePlan,
        now: datetime,
        idempotency_key: str,
    ) -> AgentCriticOutcomeBindingPlan:
        record, binding, validation_outcome, critic_plan, critic_outcome = self._load(
            critic_intake_plan, now
        )
        evidence_bundle = validation_outcome.evidence_bundle
        assert evidence_bundle is not None
        values = {
            "critic_intake_plan_id": critic_intake_plan.intake_plan_id,
            "critic_intake_record_id": record.record_id,
            "critic_intake_record_digest": agent_critic_intake_record_digest(record),
            "outcome_binding_id": binding.binding_id,
            "outcome_binding_digest": agent_validation_outcome_binding_digest(binding),
            "candidate_id": validation_outcome.candidate.candidate_id,
            "validated_candidate_digest": candidate_content_digest(validation_outcome.candidate),
            "validation_run_id": validation_outcome.validation_run.run_id,
            "validation_run_digest": domain_object_digest(validation_outcome.validation_run),
            "evidence_bundle_id": evidence_bundle.bundle_id,
            "evidence_bundle_digest": domain_object_digest(evidence_bundle),
            "critic_plan_id": critic_plan.plan_id,
            "critic_plan_digest": critic_plan_digest(critic_plan),
            "critic_outcome_digest": domain_object_digest(critic_outcome),
            "critic_review_id": critic_outcome.review.review_id,
            "critic_review_digest": domain_object_digest(critic_outcome.review),
            "verdict": critic_outcome.review.verdict,
            "final_candidate_state": critic_outcome.candidate.state,
            "final_candidate_digest": candidate_content_digest(critic_outcome.candidate),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "deadline": min(now + timedelta(seconds=60), record.expires_at, self.scope.valid_until),
            "idempotency_key": idempotency_key,
        }
        return AgentCriticOutcomeBindingPlan.create(**values)

    def execute(
        self,
        plan: AgentCriticOutcomeBindingPlan,
        *,
        critic_intake_plan: AgentCriticIntakePlan,
        now: datetime,
    ) -> AgentCriticOutcomeBinding:
        if now < plan.created_at or now >= plan.deadline:
            raise AgentCriticOutcomeBindingRejected("Critic outcome binding deadline expired")
        record, binding, validation_outcome, critic_plan, critic_outcome = self._load(
            critic_intake_plan, now
        )
        expected = self.prepare(
            critic_intake_plan=critic_intake_plan,
            now=plan.created_at,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentCriticOutcomeBindingRejected("Critic outcome binding plan drifted")
        claim = self.binding_store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            return claim.binding
        values = {
            "binding_plan_id": plan.binding_plan_id,
            "critic_intake_record_id": record.record_id,
            "outcome_binding_id": binding.binding_id,
            "candidate_id": validation_outcome.candidate.candidate_id,
            "validated_candidate_digest": candidate_content_digest(validation_outcome.candidate),
            "validation_run_id": validation_outcome.validation_run.run_id,
            "evidence_bundle_id": validation_outcome.evidence_bundle.bundle_id,
            "critic_plan_id": critic_plan.plan_id,
            "critic_outcome_digest": domain_object_digest(critic_outcome),
            "critic_review_id": critic_outcome.review.review_id,
            "critic_review_digest": domain_object_digest(critic_outcome.review),
            "verdict": critic_outcome.review.verdict,
            "final_candidate_state": critic_outcome.candidate.state,
            "final_candidate_digest": candidate_content_digest(critic_outcome.candidate),
            "completed_at": now,
        }
        result = AgentCriticOutcomeBinding(binding_id=canonical_digest(values), **values)
        self.binding_store.complete(result)
        return result

    def _load(self, intake_plan: AgentCriticIntakePlan, now: datetime):
        try:
            record = self.critic_intake_store.load_completed(intake_plan.intake_plan_id)
            binding = self.outcome_binding_store.load_completed(intake_plan.outcome_binding_plan_id)
            _, validation_outcome = self.validation_store.load_completed(binding.validation_plan_id)
            critic_plan, critic_outcome = self.critic_store.load_completed(
                intake_plan.critic_plan_id
            )
        except (ValueError, RuntimeError) as exc:
            raise AgentCriticOutcomeBindingRejected(
                "authoritative Critic binding input unavailable"
            ) from exc

        evidence_bundle = validation_outcome.evidence_bundle
        review = critic_outcome.review
        expected_state = {
            CriticVerdict.ACCEPTED: CandidateState.CRITIC_REVIEWED,
            CriticVerdict.REJECTED: CandidateState.REJECTED,
            CriticVerdict.INCONCLUSIVE: CandidateState.VALIDATED,
        }[review.verdict]
        confirmed_refs = tuple(
            dict.fromkeys(
                ref
                for assessment in critic_plan.assessments
                if assessment.disposition is CounterevidenceDisposition.CONFIRMED
                for ref in assessment.evidence_refs
            )
        )
        expected_verdict = (
            CriticVerdict.REJECTED
            if confirmed_refs
            else CriticVerdict.INCONCLUSIVE
            if any(
                item.disposition is CounterevidenceDisposition.INCONCLUSIVE
                for item in critic_plan.assessments
            )
            else CriticVerdict.ACCEPTED
        )
        expected_rationale = {
            CriticVerdict.ACCEPTED: "all_counterevidence_angles_ruled_out",
            CriticVerdict.REJECTED: "counterevidence_confirmed",
            CriticVerdict.INCONCLUSIVE: "counterevidence_review_inconclusive",
        }[expected_verdict]
        base_candidate = validation_outcome.candidate
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or intake_plan.intake_plan_id != agent_critic_intake_plan_digest(intake_plan)
            or record.decision is not AgentCriticIntakeDecision.ACCEPT
            or now >= record.expires_at
            or record.intake_plan_id != intake_plan.intake_plan_id
            or record.outcome_binding_id != binding.binding_id
            or record.critic_plan_id != critic_plan.plan_id
            or record.critic_plan_digest != critic_plan_digest(critic_plan)
            or record.candidate_id != base_candidate.candidate_id
            or record.validation_run_id != validation_outcome.validation_run.run_id
            or evidence_bundle is None
            or record.evidence_bundle_id != evidence_bundle.bundle_id
            or record.scope_id != self.scope.scope_id
            or record.scope_version != self.scope.version
            or binding.binding_plan_id != intake_plan.outcome_binding_plan_id
            or binding.binding_id != intake_plan.outcome_binding_id
            or agent_validation_outcome_binding_digest(binding)
            != intake_plan.outcome_binding_digest
            or binding.validation_outcome_digest
            != canonical_digest(validation_outcome.model_dump(mode="python"))
            or intake_plan.validated_candidate_digest != candidate_content_digest(base_candidate)
            or intake_plan.validation_outcome_digest != binding.validation_outcome_digest
            or intake_plan.validation_run_id != validation_outcome.validation_run.run_id
            or intake_plan.validation_run_digest
            != domain_object_digest(validation_outcome.validation_run)
            or intake_plan.evidence_bundle_id != evidence_bundle.bundle_id
            or intake_plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or intake_plan.critic_plan_id != critic_plan.plan_id
            or intake_plan.critic_plan_digest != critic_plan_digest(critic_plan)
            or intake_plan.scope_id != self.scope.scope_id
            or intake_plan.scope_version != self.scope.version
            or binding.final_candidate_state is not CandidateState.VALIDATED
            or binding.final_candidate_digest != candidate_content_digest(base_candidate)
            or base_candidate.state is not CandidateState.VALIDATED
            or validation_outcome.validation_run.result is not ValidationResult.REPRODUCED
            or validation_outcome.validation_run.candidate_id != base_candidate.candidate_id
            or validation_outcome.validation_run.evidence_refs != evidence_bundle.evidence_refs
            or evidence_bundle.candidate_id != base_candidate.candidate_id
            or critic_plan.candidate_id != base_candidate.candidate_id
            or critic_plan.candidate_digest != domain_object_digest(base_candidate)
            or critic_plan.validation_run_id != validation_outcome.validation_run.run_id
            or critic_plan.validation_run_digest
            != domain_object_digest(validation_outcome.validation_run)
            or critic_plan.evidence_bundle_id != evidence_bundle.bundle_id
            or critic_plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or critic_plan.scope_id != self.scope.scope_id
            or critic_plan.scope_version != self.scope.version
            or critic_outcome.plan_id != critic_plan.plan_id
            or not critic_plan.created_at <= critic_outcome.completed_at < critic_plan.deadline
            or critic_outcome.completed_at < record.decided_at
            or critic_outcome.completed_at > now
            or review.plan_id != critic_plan.plan_id
            or review.review_id
            != uuid5(NAMESPACE_URL, f"vulnloom:critic-review:{critic_plan.plan_id}")
            or review.candidate_id != base_candidate.candidate_id
            or review.validation_run_id != validation_outcome.validation_run.run_id
            or review.evidence_bundle_id != evidence_bundle.bundle_id
            or review.validation_context_id != critic_plan.validation_context_id
            or review.review_context_id != critic_plan.review_context_id
            or review.ruleset_digest != critic_plan.ruleset_digest
            or review.reviewed_at != critic_outcome.completed_at
            or review.verdict is not expected_verdict
            or review.counterevidence_refs != confirmed_refs
            or review.rationale_code != expected_rationale
            or critic_outcome.candidate.state is not expected_state
            or critic_outcome.candidate.model_copy(update={"state": CandidateState.VALIDATED})
            != base_candidate
            or any(
                not self.evidence_store.contains(ref)
                for ref in (
                    *evidence_bundle.evidence_refs,
                    *(ref for item in critic_plan.assessments for ref in item.evidence_refs),
                    *review.counterevidence_refs,
                )
            )
        ):
            raise AgentCriticOutcomeBindingRejected("Critic outcome provenance drifted")
        return record, binding, validation_outcome, critic_plan, critic_outcome
