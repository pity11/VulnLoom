"""Trusted human Intake that binds, but never executes, an exact CriticPlan."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.agent_runtime import AgentSessionAuditArtifact, AgentSessionAuditArtifactStore
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, Scope, ScopeState, ValidationResult
from vulnloom.evidence import EvidenceStore
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.validation import (
    AgentValidationOutcomeBindingPlan,
    AgentValidationOutcomeBindingStore,
    ValidationStore,
    agent_validation_outcome_binding_digest,
    agent_validation_outcome_binding_plan_digest,
    candidate_content_digest,
)

from .intake_models import (
    AgentCriticIntakeCommand,
    AgentCriticIntakePlan,
    AgentCriticIntakeRecord,
    agent_critic_intake_command_digest,
    agent_critic_intake_plan_digest,
)
from .intake_store import AgentCriticIntakeStore
from .models import CriticPlan, critic_plan_digest, domain_object_digest


class AgentCriticIntakeRejected(ValueError):
    pass


class AgentCriticIntakeTimedOut(TimeoutError):
    pass


class AgentCriticIntakeService:
    def __init__(
        self,
        *,
        scope: Scope,
        audit_store: AgentSessionAuditArtifactStore,
        candidate_store: CandidateSetStore,
        outcome_binding_store: AgentValidationOutcomeBindingStore,
        validation_store: ValidationStore,
        evidence_store: EvidenceStore,
        store: AgentCriticIntakeStore,
    ):
        self.scope = scope
        self.audit_store = audit_store
        self.candidate_store = candidate_store
        self.outcome_binding_store = outcome_binding_store
        self.validation_store = validation_store
        self.evidence_store = evidence_store
        self.store = store

    def prepare(
        self,
        *,
        outcome_binding_plan: AgentValidationOutcomeBindingPlan,
        audit_artifact: AgentSessionAuditArtifact,
        critic_plan: CriticPlan,
        now: datetime,
        decision_deadline: datetime,
        idempotency_key: str,
    ) -> AgentCriticIntakePlan:
        loaded = self._load(outcome_binding_plan, audit_artifact, critic_plan, now)
        binding, bundle, candidate_set, proposed, outcome = loaded
        if not now < decision_deadline <= min(self.scope.valid_until, critic_plan.deadline):
            raise AgentCriticIntakeRejected("Critic Intake deadline exceeds active authority")
        evidence_bundle = outcome.evidence_bundle
        assert evidence_bundle is not None
        values = {
            "outcome_binding_plan_id": outcome_binding_plan.binding_plan_id,
            "outcome_binding_id": binding.binding_id,
            "outcome_binding_digest": agent_validation_outcome_binding_digest(binding),
            "audit_bundle_id": bundle.bundle_id,
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_set_digest": candidate_set_digest(candidate_set),
            "candidate_id": proposed.candidate_id,
            "proposed_candidate_digest": candidate_content_digest(proposed),
            "validated_candidate_digest": candidate_content_digest(outcome.candidate),
            "target_id": proposed.target_id,
            "target_version_digest": canonical_digest(proposed.target_version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "validation_plan_id": binding.validation_plan_id,
            "validation_outcome_digest": binding.validation_outcome_digest,
            "validation_run_id": outcome.validation_run.run_id,
            "validation_run_digest": domain_object_digest(outcome.validation_run),
            "evidence_bundle_id": evidence_bundle.bundle_id,
            "evidence_bundle_digest": domain_object_digest(evidence_bundle),
            "critic_plan_id": critic_plan.plan_id,
            "critic_plan_digest": critic_plan_digest(critic_plan),
            "created_at": now,
            "decision_deadline": decision_deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentCriticIntakePlan.create(**values)

    def decide(
        self,
        plan: AgentCriticIntakePlan,
        command: AgentCriticIntakeCommand,
        *,
        outcome_binding_plan: AgentValidationOutcomeBindingPlan,
        audit_artifact: AgentSessionAuditArtifact,
        critic_plan: CriticPlan,
        now: datetime,
    ) -> AgentCriticIntakeRecord:
        try:
            AgentCriticIntakePlan.model_validate(plan)
            AgentCriticIntakeCommand.model_validate(command)
        except ValidationError as exc:
            raise AgentCriticIntakeRejected("Critic Intake boundary validation failed") from exc
        if now < plan.created_at or now >= plan.decision_deadline:
            raise AgentCriticIntakeTimedOut("Critic Intake decision is outside its window")
        expected = self.prepare(
            outcome_binding_plan=outcome_binding_plan,
            audit_artifact=audit_artifact,
            critic_plan=critic_plan,
            now=plan.created_at,
            decision_deadline=plan.decision_deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentCriticIntakeRejected("Critic Intake plan drifted")
        if (
            command.command_id != agent_critic_intake_command_digest(command)
            or command.intake_plan_id != plan.intake_plan_id
            or command.intake_plan_digest != agent_critic_intake_plan_digest(plan)
            or command.outcome_binding_id != plan.outcome_binding_id
            or command.candidate_id != plan.candidate_id
            or command.critic_plan_id != plan.critic_plan_id
            or command.critic_plan_digest != plan.critic_plan_digest
            or not plan.created_at <= command.decided_at < plan.decision_deadline
            or command.decided_at > now
        ):
            raise AgentCriticIntakeRejected("Critic Intake command drifted")
        claim = self.store.claim(plan, command, now=now)
        if not claim.created:
            assert claim.record is not None
            return claim.record
        values = {
            "intake_plan_id": plan.intake_plan_id,
            "command_id": command.command_id,
            "outcome_binding_id": plan.outcome_binding_id,
            "audit_bundle_id": plan.audit_bundle_id,
            "candidate_id": plan.candidate_id,
            "validation_run_id": plan.validation_run_id,
            "evidence_bundle_id": plan.evidence_bundle_id,
            "critic_plan_id": plan.critic_plan_id,
            "critic_plan_digest": plan.critic_plan_digest,
            "scope_id": plan.scope_id,
            "scope_version": plan.scope_version,
            "decision": command.decision,
            "reason_code": command.reason_code,
            "reviewer": command.reviewer,
            "decided_at": command.decided_at,
            "expires_at": plan.decision_deadline,
        }
        record = AgentCriticIntakeRecord(record_id=canonical_digest(values), **values)
        self.store.complete(record)
        return record

    def _load(self, binding_plan, artifact, critic_plan, now):
        try:
            binding = self.outcome_binding_store.load_completed(binding_plan.binding_plan_id)
            audit_bundle = self.audit_store.read_bundle(artifact)
            candidate_set = self.candidate_store.load(binding_plan.candidate_set_id)
            validation_plan, outcome = self.validation_store.load_completed(
                binding.validation_plan_id
            )
        except (ValueError, RuntimeError) as exc:
            raise AgentCriticIntakeRejected(
                "Critic Intake authoritative input unavailable"
            ) from exc
        matches = tuple(
            c for c in candidate_set.candidates if c.candidate_id == binding.candidate_id
        )
        if len(matches) != 1:
            raise AgentCriticIntakeRejected("Critic Intake Candidate unavailable")
        proposed = matches[0]
        evidence_bundle = outcome.evidence_bundle
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or binding_plan.binding_plan_id
            != agent_validation_outcome_binding_plan_digest(binding_plan)
            or binding.binding_plan_id != binding_plan.binding_plan_id
            or binding.audit_bundle_id != audit_bundle.bundle_id
            or binding.candidate_id != proposed.candidate_id
            or binding.candidate_digest != candidate_content_digest(proposed)
            or binding.validation_plan_id != validation_plan.plan_id
            or binding.validation_outcome_digest
            != canonical_digest(outcome.model_dump(mode="python"))
            or binding.validation_run_id != outcome.validation_run.run_id
            or binding.result is not ValidationResult.REPRODUCED
            or binding.final_candidate_state is not CandidateState.VALIDATED
            or proposed.state is not CandidateState.PROPOSED
            or outcome.candidate.state is not CandidateState.VALIDATED
            or outcome.candidate.model_copy(update={"state": CandidateState.PROPOSED}) != proposed
            or evidence_bundle is None
            or not evidence_bundle.evidence_refs
            or binding.evidence_bundle_id != evidence_bundle.bundle_id
            or binding.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or tuple(sorted(binding.evidence_refs))
            != tuple(sorted(evidence_bundle.evidence_refs))
        ):
            raise AgentCriticIntakeRejected("Critic Intake provenance drifted")
        assessment_refs = tuple(
            ref for assessment in critic_plan.assessments for ref in assessment.evidence_refs
        )
        if (
            critic_plan.plan_id != critic_plan_digest(critic_plan)
            or critic_plan.candidate_id != outcome.candidate.candidate_id
            or critic_plan.candidate_digest != domain_object_digest(outcome.candidate)
            or critic_plan.validation_run_id != outcome.validation_run.run_id
            or critic_plan.validation_run_digest != domain_object_digest(outcome.validation_run)
            or critic_plan.evidence_bundle_id != evidence_bundle.bundle_id
            or critic_plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or critic_plan.scope_id != self.scope.scope_id
            or critic_plan.scope_version != self.scope.version
            or critic_plan.created_at > now
            or now >= critic_plan.deadline
            or not set(assessment_refs) <= set(evidence_bundle.evidence_refs)
            or any(
                not self.evidence_store.contains(ref)
                for ref in (*evidence_bundle.evidence_refs, *assessment_refs)
            )
        ):
            raise AgentCriticIntakeRejected("Critic Intake provenance drifted")
        return binding, audit_bundle, candidate_set, proposed, outcome
