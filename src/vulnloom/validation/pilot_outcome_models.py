"""Digest-only handoff from M9.9 execution to M8.2 outcome provenance."""

from typing import Self

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class PilotValidationOutcomePlan(DomainModel):
    plan_id: Digest
    execution_plan_id: Digest
    execution_plan_digest: Digest
    execution_binding_id: Digest
    execution_binding_digest: Digest
    outcome_binding_plan_id: Digest
    outcome_binding_plan_digest: Digest
    validation_plan_id: Digest
    validation_outcome_digest: Digest
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline or "\x00" in self.idempotency_key:
            raise ValueError("pilot outcome window or key is invalid")
        if self.plan_id != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"})):
            raise ValueError("pilot outcome plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        return cls(plan_id=canonical_digest(values), **values)


class PilotValidationOutcomeBinding(DomainModel):
    binding_id: Digest
    plan_id: Digest
    execution_binding_id: Digest
    outcome_binding_plan_id: Digest
    outcome_binding_id: Digest
    outcome_binding_digest: Digest
    validation_plan_id: Digest
    validation_outcome_digest: Digest
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.binding_id != canonical_digest(
            self.model_dump(mode="python", exclude={"binding_id"})
        ):
            raise ValueError("pilot outcome binding digest mismatch")
        return self
