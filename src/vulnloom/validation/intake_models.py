"""Digest-only contracts for human review of an exact ValidationPlan."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class AgentValidationIntakeDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"


class AgentValidationIntakeReason(StrEnum):
    HUMAN_ACCEPTED_EXACT_PLAN = "human_accepted_exact_plan"
    HUMAN_REJECTED = "human_rejected"
    HUMAN_DEFERRED = "human_deferred"


_DECISION_REASONS = {
    AgentValidationIntakeDecision.ACCEPT: AgentValidationIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
    AgentValidationIntakeDecision.REJECT: AgentValidationIntakeReason.HUMAN_REJECTED,
    AgentValidationIntakeDecision.DEFER: AgentValidationIntakeReason.HUMAN_DEFERRED,
}


class AgentValidationIntakePlan(DomainModel):
    intake_plan_id: Digest
    audit_bundle_id: Digest
    audit_bundle_digest: Digest
    audit_artifact_digest: Digest
    recommendation_id: Digest
    recommendation_digest: Digest
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
    created_at: AwareDatetime
    decision_deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_plan(self) -> Self:
        if not self.created_at < self.decision_deadline:
            raise ValueError("Agent Validation Intake decision window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent Validation Intake idempotency key contains NUL")
        if self.intake_plan_id != agent_validation_intake_plan_digest(self):
            raise ValueError("Agent Validation Intake plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentValidationIntakePlan:
        return cls(intake_plan_id=canonical_digest(values), **values)


def agent_validation_intake_plan_digest(plan: AgentValidationIntakePlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"intake_plan_id"}))


class AgentValidationIntakeCommand(DomainModel):
    command_id: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    audit_bundle_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    validation_plan_id: Digest
    validation_plan_digest: Digest
    decision: AgentValidationIntakeDecision
    reason_code: AgentValidationIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_command(self) -> Self:
        if self.reason_code is not _DECISION_REASONS[self.decision]:
            raise ValueError("Agent Validation Intake reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Agent Validation Intake reviewer contains NUL")
        if self.command_id != agent_validation_intake_command_digest(self):
            raise ValueError("Agent Validation Intake command content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentValidationIntakeCommand:
        return cls(command_id=canonical_digest(values), **values)


def agent_validation_intake_command_digest(command: AgentValidationIntakeCommand) -> str:
    return canonical_digest(command.model_dump(mode="python", exclude={"command_id"}))


class AgentValidationIntakeRecord(DomainModel):
    record_id: Digest
    intake_plan_id: Digest
    command_id: Digest
    audit_bundle_id: Digest
    recommendation_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    validation_plan_id: Digest
    validation_plan_digest: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    decision: AgentValidationIntakeDecision
    reason_code: AgentValidationIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_record(self) -> Self:
        if self.reason_code is not _DECISION_REASONS[self.decision]:
            raise ValueError("Agent Validation Intake record reason does not match decision")
        if not self.decided_at < self.expires_at:
            raise ValueError("Agent Validation Intake record is already expired")
        if self.record_id != agent_validation_intake_record_digest(self):
            raise ValueError("Agent Validation Intake record content digest mismatch")
        return self


def agent_validation_intake_record_digest(record: AgentValidationIntakeRecord) -> str:
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
