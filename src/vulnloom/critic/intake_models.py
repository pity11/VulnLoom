"""Digest-only contracts for human selection of an exact CriticPlan."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class AgentCriticIntakeDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"


class AgentCriticIntakeReason(StrEnum):
    HUMAN_ACCEPTED_EXACT_PLAN = "human_accepted_exact_plan"
    HUMAN_REJECTED = "human_rejected"
    HUMAN_DEFERRED = "human_deferred"


_REASONS = {
    AgentCriticIntakeDecision.ACCEPT: AgentCriticIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
    AgentCriticIntakeDecision.REJECT: AgentCriticIntakeReason.HUMAN_REJECTED,
    AgentCriticIntakeDecision.DEFER: AgentCriticIntakeReason.HUMAN_DEFERRED,
}


class AgentCriticIntakePlan(DomainModel):
    intake_plan_id: Digest
    outcome_binding_plan_id: Digest
    outcome_binding_id: Digest
    outcome_binding_digest: Digest
    audit_bundle_id: Digest
    candidate_set_id: Digest
    candidate_set_digest: Digest
    candidate_id: UUID
    proposed_candidate_digest: Digest
    validated_candidate_digest: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    validation_plan_id: Digest
    validation_outcome_digest: Digest
    validation_run_id: UUID
    validation_run_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    critic_plan_id: Digest
    critic_plan_digest: Digest
    created_at: AwareDatetime
    decision_deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.decision_deadline:
            raise ValueError("Agent Critic Intake decision window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent Critic Intake idempotency key contains NUL")
        if self.intake_plan_id != agent_critic_intake_plan_digest(self):
            raise ValueError("Agent Critic Intake plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentCriticIntakePlan:
        return cls(intake_plan_id=canonical_digest(values), **values)


def agent_critic_intake_plan_digest(plan: AgentCriticIntakePlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"intake_plan_id"}))


class AgentCriticIntakeCommand(DomainModel):
    command_id: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    outcome_binding_id: Digest
    candidate_id: UUID
    critic_plan_id: Digest
    critic_plan_digest: Digest
    decision: AgentCriticIntakeDecision
    reason_code: AgentCriticIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Agent Critic Intake reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Agent Critic Intake reviewer contains NUL")
        if self.command_id != agent_critic_intake_command_digest(self):
            raise ValueError("Agent Critic Intake command digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentCriticIntakeCommand:
        return cls(command_id=canonical_digest(values), **values)


def agent_critic_intake_command_digest(command: AgentCriticIntakeCommand) -> str:
    return canonical_digest(command.model_dump(mode="python", exclude={"command_id"}))


class AgentCriticIntakeRecord(DomainModel):
    record_id: Digest
    intake_plan_id: Digest
    command_id: Digest
    outcome_binding_id: Digest
    audit_bundle_id: Digest
    candidate_id: UUID
    validation_run_id: UUID
    evidence_bundle_id: UUID
    critic_plan_id: Digest
    critic_plan_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    decision: AgentCriticIntakeDecision
    reason_code: AgentCriticIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Agent Critic Intake record reason does not match decision")
        if not self.decided_at < self.expires_at:
            raise ValueError("Agent Critic Intake record is already expired")
        if self.record_id != agent_critic_intake_record_digest(self):
            raise ValueError("Agent Critic Intake record digest mismatch")
        return self


def agent_critic_intake_record_digest(record: AgentCriticIntakeRecord) -> str:
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
