"""Sealed, digest-only pilot handoff to an independently selected M8.3 CriticPlan."""

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class PilotCriticIntakePlan(DomainModel):
    plan_id: Digest
    pilot_outcome_plan_id: Digest
    pilot_outcome_plan_digest: Digest
    pilot_outcome_binding_id: Digest
    pilot_outcome_binding_digest: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    command_id: Digest
    command_digest: Digest
    critic_plan_id: Digest
    critic_plan_digest: Digest
    candidate_id: UUID
    validated_candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline or "\x00" in self.idempotency_key:
            raise ValueError("pilot Critic Intake window or key is invalid")
        if self.plan_id != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"})):
            raise ValueError("pilot Critic Intake plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        return cls(plan_id=canonical_digest(values), **values)


class PilotCriticIntakeBinding(DomainModel):
    binding_id: Digest
    plan_id: Digest
    pilot_outcome_binding_id: Digest
    intake_plan_id: Digest
    intake_record_id: Digest
    intake_record_digest: Digest
    command_id: Digest
    critic_plan_id: Digest
    candidate_id: UUID
    validated_candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.binding_id != canonical_digest(
            self.model_dump(mode="python", exclude={"binding_id"})
        ):
            raise ValueError("pilot Critic Intake binding digest mismatch")
        return self
