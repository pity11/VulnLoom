"""Digest-only contracts for human Finding promotion selection."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class AgentFindingIntakeDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"


class AgentFindingIntakeReason(StrEnum):
    HUMAN_ACCEPTED_EXACT_PROMOTION = "human_accepted_exact_promotion"
    HUMAN_REJECTED = "human_rejected"
    HUMAN_DEFERRED = "human_deferred"


_REASONS = {
    AgentFindingIntakeDecision.ACCEPT: AgentFindingIntakeReason.HUMAN_ACCEPTED_EXACT_PROMOTION,
    AgentFindingIntakeDecision.REJECT: AgentFindingIntakeReason.HUMAN_REJECTED,
    AgentFindingIntakeDecision.DEFER: AgentFindingIntakeReason.HUMAN_DEFERRED,
}


class AgentFindingIntakePlan(DomainModel):
    intake_plan_id: Digest
    critic_outcome_binding_plan_id: Digest
    critic_outcome_binding_id: Digest
    critic_outcome_binding_digest: Digest
    promotion_plan_id: Digest
    promotion_plan_digest: Digest
    duplicate_check_id: Digest
    duplicate_check_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    finding_id: UUID
    validation_run_ids_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    critic_review_id: UUID
    critic_review_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    decision_deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.decision_deadline:
            raise ValueError("Finding Intake decision window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Finding Intake idempotency key contains NUL")
        if self.intake_plan_id != agent_finding_intake_plan_digest(self):
            raise ValueError("Finding Intake plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentFindingIntakePlan:
        return cls(intake_plan_id=canonical_digest(values), **values)


def agent_finding_intake_plan_digest(plan: AgentFindingIntakePlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"intake_plan_id"}))


class AgentFindingIntakeCommand(DomainModel):
    command_id: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    critic_outcome_binding_id: Digest
    promotion_plan_id: Digest
    promotion_plan_digest: Digest
    candidate_id: UUID
    finding_id: UUID
    decision: AgentFindingIntakeDecision
    reason_code: AgentFindingIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Finding Intake reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Finding Intake reviewer contains NUL")
        if self.command_id != agent_finding_intake_command_digest(self):
            raise ValueError("Finding Intake command digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentFindingIntakeCommand:
        return cls(command_id=canonical_digest(values), **values)


def agent_finding_intake_command_digest(command: AgentFindingIntakeCommand) -> str:
    return canonical_digest(command.model_dump(mode="python", exclude={"command_id"}))


class AgentFindingIntakeRecord(DomainModel):
    record_id: Digest
    intake_plan_id: Digest
    command_id: Digest
    critic_outcome_binding_id: Digest
    promotion_plan_id: Digest
    promotion_plan_digest: Digest
    duplicate_check_id: Digest
    candidate_id: UUID
    finding_id: UUID
    evidence_bundle_id: UUID
    critic_review_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    decision: AgentFindingIntakeDecision
    reason_code: AgentFindingIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Finding Intake record reason does not match decision")
        if not self.decided_at < self.expires_at:
            raise ValueError("Finding Intake record is already expired")
        if self.record_id != agent_finding_intake_record_digest(self):
            raise ValueError("Finding Intake record digest mismatch")
        return self


def agent_finding_intake_record_digest(record: AgentFindingIntakeRecord) -> str:
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
