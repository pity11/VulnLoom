"""Digest-only Intake contracts from an accepted Recommendation selection."""

from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class CandidateRecommendationValidationIntakePlan(DomainModel):
    plan_id: Digest
    selection_record_id: Digest
    selection_record_digest: Digest
    admission_record_id: Digest
    recommendation_id: Digest
    generation_outcome_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    validation_plan_id: Digest
    validation_plan_digest: Digest
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Recommendation Validation Intake window is invalid")
        if self.plan_id != candidate_recommendation_validation_intake_plan_digest(self):
            raise ValueError("Recommendation Validation Intake plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        return cls(plan_id=canonical_digest(values), **values)


def candidate_recommendation_validation_intake_plan_digest(plan):
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class CandidateRecommendationValidationIntakeRecord(DomainModel):
    record_id: Digest
    plan_id: Digest
    selection_record_id: Digest
    selection_record_digest: Digest
    admission_record_id: Digest
    recommendation_id: Digest
    generation_outcome_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    validation_plan_id: Digest
    validation_plan_digest: Digest
    selected_by: str = Field(pattern=r"^[A-Za-z0-9_.:@-]{1,128}$")
    selected_at: AwareDatetime
    completed_at: AwareDatetime
    candidate_unchanged: Literal[True] = True
    validation_executed: Literal[False] = False
    requires_run_validation_approval: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.completed_at < self.selected_at:
            raise ValueError("Recommendation Validation Intake record time is invalid")
        if self.record_id != candidate_recommendation_validation_intake_record_digest(self):
            raise ValueError("Recommendation Validation Intake record digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault("candidate_unchanged", True)
        values.setdefault("validation_executed", False)
        values.setdefault("requires_run_validation_approval", True)
        return cls(record_id=canonical_digest(values), **values)


def candidate_recommendation_validation_intake_record_digest(record):
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
