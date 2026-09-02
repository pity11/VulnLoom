"""Digest-only contracts for human selection of an exact ReportDraftPlan."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, ReportChannel

from .models import Digest


class AgentReportIntakeDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"


class AgentReportIntakeReason(StrEnum):
    HUMAN_ACCEPTED_EXACT_DRAFT = "human_accepted_exact_draft"
    HUMAN_REJECTED = "human_rejected"
    HUMAN_DEFERRED = "human_deferred"


_REASONS = {
    AgentReportIntakeDecision.ACCEPT: AgentReportIntakeReason.HUMAN_ACCEPTED_EXACT_DRAFT,
    AgentReportIntakeDecision.REJECT: AgentReportIntakeReason.HUMAN_REJECTED,
    AgentReportIntakeDecision.DEFER: AgentReportIntakeReason.HUMAN_DEFERRED,
}


class AgentReportIntakePlan(DomainModel):
    intake_plan_id: Digest
    finding_promotion_execution_plan_id: Digest
    finding_promotion_outcome_id: Digest
    finding_promotion_outcome_digest: Digest
    report_draft_plan_id: Digest
    report_draft_plan_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    finding_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    channel: ReportChannel
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    decision_deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.decision_deadline:
            raise ValueError("Report Intake decision window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Report Intake idempotency key contains NUL")
        if self.intake_plan_id != agent_report_intake_plan_digest(self):
            raise ValueError("Report Intake plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportIntakePlan:
        return cls(intake_plan_id=canonical_digest(values), **values)


def agent_report_intake_plan_digest(plan: AgentReportIntakePlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"intake_plan_id"}))


class AgentReportIntakeCommand(DomainModel):
    command_id: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    finding_promotion_outcome_id: Digest
    report_draft_plan_id: Digest
    report_draft_plan_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    decision: AgentReportIntakeDecision
    reason_code: AgentReportIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Report Intake reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Report Intake reviewer contains NUL")
        if self.command_id != agent_report_intake_command_digest(self):
            raise ValueError("Report Intake command digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportIntakeCommand:
        return cls(command_id=canonical_digest(values), **values)


def agent_report_intake_command_digest(command: AgentReportIntakeCommand) -> str:
    return canonical_digest(command.model_dump(mode="python", exclude={"command_id"}))


class AgentReportIntakeRecord(DomainModel):
    record_id: Digest
    intake_plan_id: Digest
    command_id: Digest
    finding_promotion_outcome_id: Digest
    finding_promotion_outcome_digest: Digest
    report_draft_plan_id: Digest
    report_draft_plan_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    candidate_id: UUID
    evidence_bundle_id: UUID
    channel: ReportChannel
    scope_id: UUID
    scope_version: int = Field(ge=1)
    decision: AgentReportIntakeDecision
    reason_code: AgentReportIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Report Intake record reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Report Intake reviewer contains NUL")
        if not self.decided_at < self.expires_at:
            raise ValueError("Report Intake record is already expired")
        if self.record_id != agent_report_intake_record_digest(self):
            raise ValueError("Report Intake record digest mismatch")
        return self


def agent_report_intake_record_digest(record: AgentReportIntakeRecord) -> str:
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
