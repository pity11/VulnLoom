"""Digest-only binding from a pilot selection to an M8.1 Intake decision."""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class PilotValidationIntakePlan(DomainModel):
    plan_id: Digest
    selection_record_id: Digest
    selection_record_digest: Digest
    selection_readiness_plan_id: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    intake_command_id: Digest
    intake_command_digest: Digest
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
            raise ValueError("pilot Validation Intake window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("pilot Validation Intake key contains NUL")
        if self.plan_id != pilot_validation_intake_plan_digest(self):
            raise ValueError("pilot Validation Intake plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> PilotValidationIntakePlan:
        return cls(plan_id=canonical_digest(values), **values)


def pilot_validation_intake_plan_digest(plan: PilotValidationIntakePlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class PilotValidationIntakeBinding(DomainModel):
    binding_id: Digest
    plan_id: Digest
    selection_record_id: Digest
    intake_record_id: Digest
    intake_record_digest: Digest
    validation_plan_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.binding_id != pilot_validation_intake_binding_digest(self):
            raise ValueError("pilot Validation Intake binding content digest mismatch")
        return self


def pilot_validation_intake_binding_digest(binding: PilotValidationIntakeBinding) -> str:
    return canonical_digest(binding.model_dump(mode="python", exclude={"binding_id"}))
