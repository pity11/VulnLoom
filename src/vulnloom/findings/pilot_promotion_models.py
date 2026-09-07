"""Sealed digest-only pilot Finding promotion provenance."""

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class PilotFindingPromotionPlan(DomainModel):
    plan_id: Digest
    pilot_intake_plan_id: Digest
    pilot_intake_plan_digest: Digest
    pilot_intake_binding_id: Digest
    pilot_intake_binding_digest: Digest
    execution_plan_id: Digest
    execution_plan_digest: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    intake_record_id: Digest
    promotion_plan_id: Digest
    duplicate_check_id: Digest
    finding_id: UUID
    candidate_id: UUID
    candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline or "\x00" in self.idempotency_key:
            raise ValueError("pilot Finding promotion window or key invalid")
        if self.plan_id != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"})):
            raise ValueError("pilot Finding promotion plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        return cls(plan_id=canonical_digest(values), **values)


class PilotFindingPromotionBinding(DomainModel):
    binding_id: Digest
    plan_id: Digest
    pilot_intake_binding_id: Digest
    execution_plan_id: Digest
    approval_id: UUID
    approval_digest: Digest
    intake_record_id: Digest
    promotion_plan_id: Digest
    finding_id: UUID
    candidate_id: UUID
    candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    outcome_id: Digest
    outcome_digest: Digest
    promoted_candidate_digest: Digest
    finding_digest: Digest
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.binding_id != canonical_digest(
            self.model_dump(mode="python", exclude={"binding_id"})
        ):
            raise ValueError("pilot Finding promotion binding digest mismatch")
        return self
