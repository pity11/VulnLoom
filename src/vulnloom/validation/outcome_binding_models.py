"""Digest-only provenance binding from accepted Intake to completed Validation."""

from __future__ import annotations

from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, DomainModel, ValidationResult
from vulnloom.runners.models import Digest


class AgentValidationOutcomeBindingPlan(DomainModel):
    binding_plan_id: Digest
    intake_plan_id: Digest
    intake_record_id: Digest
    intake_record_digest: Digest
    audit_bundle_id: Digest
    candidate_set_id: Digest
    candidate_set_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    validation_plan_id: Digest
    validation_plan_digest: Digest
    validation_outcome_digest: Digest
    validation_run_id: UUID
    result: ValidationResult
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=256)] = ()
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_plan(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Agent Validation outcome binding window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent Validation outcome binding idempotency key contains NUL")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("Agent Validation outcome Evidence refs must be unique and sorted")
        if self.binding_plan_id != agent_validation_outcome_binding_plan_digest(self):
            raise ValueError("Agent Validation outcome binding plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentValidationOutcomeBindingPlan:
        return cls(binding_plan_id=canonical_digest(values), **values)


def agent_validation_outcome_binding_plan_digest(
    plan: AgentValidationOutcomeBindingPlan,
) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"binding_plan_id"}))


class AgentValidationOutcomeBinding(DomainModel):
    binding_id: Digest
    binding_plan_id: Digest
    intake_record_id: Digest
    audit_bundle_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    validation_plan_id: Digest
    validation_outcome_digest: Digest
    validation_run_id: UUID
    result: ValidationResult
    final_candidate_state: CandidateState
    final_candidate_digest: Digest
    evidence_bundle_id: UUID | None = None
    evidence_bundle_digest: Digest | None = None
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=256)] = ()
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_binding(self) -> Self:
        if (self.evidence_bundle_id is None) != (self.evidence_bundle_digest is None):
            raise ValueError("Agent Validation Evidence bundle binding is incomplete")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("Agent Validation binding Evidence refs must be unique and sorted")
        expected = (
            CandidateState.VALIDATED
            if self.result is ValidationResult.REPRODUCED
            else CandidateState.INCONCLUSIVE
        )
        if self.final_candidate_state is not expected:
            raise ValueError("Agent Validation final Candidate state does not match result")
        if self.binding_id != agent_validation_outcome_binding_digest(self):
            raise ValueError("Agent Validation outcome binding digest mismatch")
        return self


def agent_validation_outcome_binding_digest(binding: AgentValidationOutcomeBinding) -> str:
    return canonical_digest(binding.model_dump(mode="python", exclude={"binding_id"}))
