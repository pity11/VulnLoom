"""Read-only provenance binding for an already completed Validation outcome."""

from __future__ import annotations

from datetime import datetime, timedelta

from vulnloom.agent_runtime import AgentSessionAuditArtifact, AgentSessionAuditArtifactStore
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, Scope, ScopeState, ValidationResult
from vulnloom.evidence import EvidenceStore
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest

from .intake_models import AgentValidationIntakeDecision, agent_validation_intake_record_digest
from .intake_store import AgentValidationIntakeStore
from .models import ValidationPlan, candidate_content_digest, validation_plan_digest
from .outcome_binding_models import (
    AgentValidationOutcomeBinding,
    AgentValidationOutcomeBindingPlan,
)
from .outcome_binding_store import AgentValidationOutcomeBindingStore
from .store import ValidationStore


class AgentValidationOutcomeBindingRejected(ValueError):
    pass


class AgentValidationOutcomeBindingService:
    def __init__(
        self,
        *,
        scope: Scope,
        audit_store: AgentSessionAuditArtifactStore,
        candidate_store: CandidateSetStore,
        intake_store: AgentValidationIntakeStore,
        validation_store: ValidationStore,
        evidence_store: EvidenceStore,
        binding_store: AgentValidationOutcomeBindingStore,
    ):
        self.scope = scope
        self.audit_store = audit_store
        self.candidate_store = candidate_store
        self.intake_store = intake_store
        self.validation_store = validation_store
        self.evidence_store = evidence_store
        self.binding_store = binding_store

    def prepare(
        self,
        *,
        intake_plan_id: str,
        audit_artifact: AgentSessionAuditArtifact,
        candidate_set_id: str,
        candidate_id,
        validation_plan: ValidationPlan,
        now: datetime,
        idempotency_key: str,
    ) -> AgentValidationOutcomeBindingPlan:
        record, bundle, candidate_set, candidate, stored_plan, outcome = self._load(
            intake_plan_id,
            audit_artifact,
            candidate_set_id,
            candidate_id,
            validation_plan,
            now,
        )
        values = {
            "intake_plan_id": record.intake_plan_id,
            "intake_record_id": record.record_id,
            "intake_record_digest": agent_validation_intake_record_digest(record),
            "audit_bundle_id": bundle.bundle_id,
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_set_digest": candidate_set_digest(candidate_set),
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "target_id": candidate.target_id,
            "target_version_digest": canonical_digest(candidate.target_version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "validation_plan_id": stored_plan.plan_id,
            "validation_plan_digest": validation_plan_digest(stored_plan),
            "validation_outcome_digest": canonical_digest(outcome.model_dump(mode="python")),
            "validation_run_id": outcome.validation_run.run_id,
            "result": outcome.verdict.result,
            "evidence_refs": tuple(sorted(outcome.verdict.evidence_refs)),
            "created_at": now,
            "deadline": now + timedelta(seconds=60),
            "idempotency_key": idempotency_key,
        }
        return AgentValidationOutcomeBindingPlan.create(**values)

    def execute(
        self,
        plan: AgentValidationOutcomeBindingPlan,
        *,
        audit_artifact: AgentSessionAuditArtifact,
        validation_plan: ValidationPlan,
        now: datetime,
    ) -> AgentValidationOutcomeBinding:
        if now >= plan.deadline:
            raise AgentValidationOutcomeBindingRejected("outcome binding deadline expired")
        record, _, _, candidate, stored_plan, outcome = self._load(
            plan.intake_plan_id,
            audit_artifact,
            plan.candidate_set_id,
            plan.candidate_id,
            validation_plan,
            now,
        )
        expected = self.prepare(
            intake_plan_id=plan.intake_plan_id,
            audit_artifact=audit_artifact,
            candidate_set_id=plan.candidate_set_id,
            candidate_id=plan.candidate_id,
            validation_plan=validation_plan,
            now=plan.created_at,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentValidationOutcomeBindingRejected("outcome binding plan drifted")
        claim = self.binding_store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            return claim.binding
        evidence_bundle = outcome.evidence_bundle
        values = {
            "binding_plan_id": plan.binding_plan_id,
            "intake_record_id": record.record_id,
            "audit_bundle_id": plan.audit_bundle_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "validation_plan_id": stored_plan.plan_id,
            "validation_outcome_digest": plan.validation_outcome_digest,
            "validation_run_id": outcome.validation_run.run_id,
            "result": outcome.verdict.result,
            "final_candidate_state": outcome.candidate.state,
            "final_candidate_digest": candidate_content_digest(outcome.candidate),
            "evidence_bundle_id": None if evidence_bundle is None else evidence_bundle.bundle_id,
            "evidence_bundle_digest": None
            if evidence_bundle is None
            else canonical_digest(evidence_bundle.model_dump(mode="python")),
            "evidence_refs": tuple(sorted(outcome.verdict.evidence_refs)),
            "completed_at": now,
        }
        binding = AgentValidationOutcomeBinding(binding_id=canonical_digest(values), **values)
        self.binding_store.complete(binding)
        return binding

    def _load(self, intake_plan_id, artifact, candidate_set_id, candidate_id, validation_plan, now):
        try:
            record = self.intake_store.load_completed(intake_plan_id)
            bundle = self.audit_store.read_bundle(artifact)
            candidate_set = self.candidate_store.load(candidate_set_id)
            stored_plan, outcome = self.validation_store.load_completed(validation_plan.plan_id)
        except (ValueError, RuntimeError) as exc:
            raise AgentValidationOutcomeBindingRejected(
                "authoritative binding input unavailable"
            ) from exc
        candidates = tuple(
            item for item in candidate_set.candidates if item.candidate_id == candidate_id
        )
        if len(candidates) != 1:
            raise AgentValidationOutcomeBindingRejected("Candidate binding is unavailable")
        candidate = candidates[0]
        refs = tuple(sorted(outcome.verdict.evidence_refs))
        expected_state = (
            CandidateState.VALIDATED
            if outcome.verdict.result is ValidationResult.REPRODUCED
            else CandidateState.INCONCLUSIVE
        )
        evidence_bundle = outcome.evidence_bundle
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or record.decision is not AgentValidationIntakeDecision.ACCEPT
            or now >= record.expires_at
            or record.audit_bundle_id != bundle.bundle_id
            or record.target_id != candidate.target_id
            or record.target_version_digest != canonical_digest(candidate.target_version)
            or record.scope_id != self.scope.scope_id
            or record.scope_version != self.scope.version
            or record.candidate_set_id != candidate_set.candidate_set_id
            or record.candidate_id != candidate.candidate_id
            or record.candidate_digest != candidate_content_digest(candidate)
            or record.validation_plan_id != validation_plan.plan_id
            or record.validation_plan_digest != validation_plan_digest(validation_plan)
            or stored_plan != validation_plan
            or candidate.state is not CandidateState.PROPOSED
            or candidate_set.target_id != candidate.target_id
            or candidate_set.target_version != candidate.target_version
            or candidate_set.scope_id != self.scope.scope_id
            or candidate_set.scope_version != self.scope.version
            or bundle.target_id != candidate.target_id
            or bundle.target_version_digest != canonical_digest(candidate.target_version)
            or bundle.scope_id != self.scope.scope_id
            or bundle.scope_version != self.scope.version
            or outcome.plan_id != stored_plan.plan_id
            or outcome.candidate.candidate_id != candidate.candidate_id
            or outcome.candidate.target_id != candidate.target_id
            or outcome.candidate.target_version != candidate.target_version
            or outcome.candidate.scope_id != self.scope.scope_id
            or outcome.candidate.scope_version != self.scope.version
            or outcome.candidate.state is not expected_state
            or outcome.validation_run.candidate_id != candidate.candidate_id
            or outcome.validation_run.target_version != candidate.target_version
            or outcome.validation_run.scope_version != self.scope.version
            or outcome.validation_run.result is not outcome.verdict.result
            or tuple(sorted(outcome.validation_run.evidence_refs)) != refs
            or (
                evidence_bundle is not None
                and (
                    evidence_bundle.candidate_id != candidate.candidate_id
                    or tuple(sorted(evidence_bundle.evidence_refs)) != refs
                )
            )
            or (refs and evidence_bundle is None)
            or any(not self.evidence_store.contains(ref) for ref in refs)
        ):
            raise AgentValidationOutcomeBindingRejected("Validation outcome provenance drifted")
        return record, bundle, candidate_set, candidate, stored_plan, outcome
