"""Digest-only contracts for human selection of an exact local Report export plan."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, ReportChannel, ReportReviewStatus

from .models import Digest


class AgentReportExportIntakeDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"


class AgentReportExportIntakeReason(StrEnum):
    HUMAN_ACCEPTED_EXACT_EXPORT = "human_accepted_exact_export"
    HUMAN_REJECTED = "human_rejected"
    HUMAN_DEFERRED = "human_deferred"


_REASONS = {
    AgentReportExportIntakeDecision.ACCEPT: (
        AgentReportExportIntakeReason.HUMAN_ACCEPTED_EXACT_EXPORT
    ),
    AgentReportExportIntakeDecision.REJECT: AgentReportExportIntakeReason.HUMAN_REJECTED,
    AgentReportExportIntakeDecision.DEFER: AgentReportExportIntakeReason.HUMAN_DEFERRED,
}


class AgentReportExportIntakePlan(DomainModel):
    intake_plan_id: Digest
    review_execution_plan_id: Digest
    review_execution_plan_digest: Digest
    review_outcome_binding_id: Digest
    review_outcome_binding_digest: Digest
    report_review_outcome_digest: Digest
    report_export_plan_id: Digest
    report_export_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    review_id: UUID
    review_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    candidate_id: UUID
    evidence_bundle_id: UUID
    channel: ReportChannel
    review_status: ReportReviewStatus
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    decision_deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.review_status is not ReportReviewStatus.HUMAN_APPROVED:
            raise ValueError("Report export Intake requires a human-approved Report")
        if not self.created_at < self.decision_deadline:
            raise ValueError("Report export Intake decision window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Report export Intake key contains NUL")
        if self.intake_plan_id != agent_report_export_intake_plan_digest(self):
            raise ValueError("Report export Intake plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportExportIntakePlan:
        return cls(intake_plan_id=canonical_digest(values), **values)


def agent_report_export_intake_plan_digest(plan: AgentReportExportIntakePlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"intake_plan_id"}))


class AgentReportExportIntakeCommand(DomainModel):
    command_id: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    review_outcome_binding_id: Digest
    report_export_plan_id: Digest
    report_export_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    decision: AgentReportExportIntakeDecision
    reason_code: AgentReportExportIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Report export Intake reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Report export Intake reviewer contains NUL")
        if self.command_id != agent_report_export_intake_command_digest(self):
            raise ValueError("Report export Intake command digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportExportIntakeCommand:
        return cls(command_id=canonical_digest(values), **values)


def agent_report_export_intake_command_digest(
    command: AgentReportExportIntakeCommand,
) -> str:
    return canonical_digest(command.model_dump(mode="python", exclude={"command_id"}))


class AgentReportExportIntakeRecord(DomainModel):
    record_id: Digest
    intake_plan_id: Digest
    command_id: Digest
    review_execution_plan_id: Digest
    review_outcome_binding_id: Digest
    review_outcome_binding_digest: Digest
    report_export_plan_id: Digest
    report_export_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    review_id: UUID
    review_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    candidate_id: UUID
    evidence_bundle_id: UUID
    channel: ReportChannel
    scope_id: UUID
    scope_version: int = Field(ge=1)
    decision: AgentReportExportIntakeDecision
    reason_code: AgentReportExportIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Report export Intake record reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Report export Intake reviewer contains NUL")
        if not self.decided_at < self.expires_at:
            raise ValueError("Report export Intake record is already expired")
        if self.record_id != agent_report_export_intake_record_digest(self):
            raise ValueError("Report export Intake record digest mismatch")
        return self


def agent_report_export_intake_record_digest(
    record: AgentReportExportIntakeRecord,
) -> str:
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
