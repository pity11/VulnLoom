"""Sealed Approval boundary for executing one M9.8-bound ValidationPlan."""

from __future__ import annotations

from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, DomainModel, ValidationResult
from vulnloom.runners.models import Digest

PILOT_VALIDATION_EFFECTS = ("validation:run", "candidate:validation_result")


class PilotValidationApprovalAction(DomainModel):
    action_id: Digest
    engagement_id: UUID
    target_id: UUID
    pilot_intake_plan_id: Digest
    pilot_intake_binding_id: Digest
    pilot_intake_binding_digest: Digest
    intake_record_id: Digest
    intake_record_digest: Digest
    validation_plan_id: Digest
    validation_plan_digest: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    expected_side_effects: tuple[str, ...] = PILOT_VALIDATION_EFFECTS

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.expected_side_effects != PILOT_VALIDATION_EFFECTS:
            raise ValueError("pilot Validation effects drifted")
        if self.action_id != pilot_validation_approval_action_digest(self):
            raise ValueError("pilot Validation Approval action digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> PilotValidationApprovalAction:
        return cls(action_id=canonical_digest(values), **values)


def pilot_validation_approval_action_digest(action: PilotValidationApprovalAction) -> str:
    return canonical_digest(action.model_dump(mode="python", exclude={"action_id"}))


class PilotValidationExecutionPlan(DomainModel):
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    pilot_intake_plan_id: Digest
    pilot_intake_binding_id: Digest
    pilot_intake_binding_digest: Digest
    intake_record_id: Digest
    validation_plan_id: Digest
    validation_plan_digest: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("pilot Validation execution window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("pilot Validation execution key contains NUL")
        if self.execution_plan_id != pilot_validation_execution_plan_digest(self):
            raise ValueError("pilot Validation execution plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> PilotValidationExecutionPlan:
        return cls(execution_plan_id=canonical_digest(values), **values)


def pilot_validation_execution_plan_digest(plan: PilotValidationExecutionPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"execution_plan_id"}))


class PilotValidationExecutionBinding(DomainModel):
    binding_id: Digest
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    pilot_intake_binding_id: Digest
    intake_record_id: Digest
    validation_plan_id: Digest
    validation_outcome_digest: Digest
    validation_run_id: UUID
    candidate_id: UUID
    source_candidate_digest: Digest
    final_candidate_state: CandidateState
    final_candidate_digest: Digest
    result: ValidationResult
    evidence_bundle_id: UUID | None = None
    evidence_bundle_digest: Digest | None = None
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=256)] = ()
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (self.evidence_bundle_id is None) != (self.evidence_bundle_digest is None):
            raise ValueError("pilot Validation Evidence binding is incomplete")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("pilot Validation Evidence refs must be unique and sorted")
        expected = (
            CandidateState.VALIDATED
            if self.result is ValidationResult.REPRODUCED
            else CandidateState.INCONCLUSIVE
        )
        if self.final_candidate_state is not expected:
            raise ValueError("pilot Validation final Candidate state is invalid")
        if self.binding_id != pilot_validation_execution_binding_digest(self):
            raise ValueError("pilot Validation execution binding digest mismatch")
        return self


def pilot_validation_execution_binding_digest(
    binding: PilotValidationExecutionBinding,
) -> str:
    return canonical_digest(binding.model_dump(mode="python", exclude={"binding_id"}))
