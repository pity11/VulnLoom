"""Digest-only contracts for human selection of an exact Report review plan."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, ReportChannel, ReportReviewStatus

from .models import Digest


class AgentReportReviewIntakeDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"


class AgentReportReviewIntakeReason(StrEnum):
    HUMAN_ACCEPTED_EXACT_REVIEW = "human_accepted_exact_review"
    HUMAN_REJECTED = "human_rejected"
    HUMAN_DEFERRED = "human_deferred"


_REASONS = {
    AgentReportReviewIntakeDecision.ACCEPT: (
        AgentReportReviewIntakeReason.HUMAN_ACCEPTED_EXACT_REVIEW
    ),
    AgentReportReviewIntakeDecision.REJECT: AgentReportReviewIntakeReason.HUMAN_REJECTED,
    AgentReportReviewIntakeDecision.DEFER: AgentReportReviewIntakeReason.HUMAN_DEFERRED,
}


class AgentReportReviewIntakePlan(DomainModel):
    intake_plan_id: Digest
    draft_execution_plan_id: Digest
    draft_execution_plan_digest: Digest
    draft_outcome_binding_id: Digest
    draft_outcome_binding_digest: Digest
    report_outcome_digest: Digest
    report_review_plan_id: Digest
    report_review_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    candidate_id: UUID
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    evidence_catalog_digest: Digest
    channel: ReportChannel
    review_status: ReportReviewStatus
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    decision_deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.review_status is not ReportReviewStatus.DRAFT:
            raise ValueError("Report review Intake requires a draft Report")
        if not self.created_at < self.decision_deadline:
            raise ValueError("Report review Intake decision window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Report review Intake key contains NUL")
        if self.intake_plan_id != agent_report_review_intake_plan_digest(self):
            raise ValueError("Report review Intake plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportReviewIntakePlan:
        return cls(intake_plan_id=canonical_digest(values), **values)


def agent_report_review_intake_plan_digest(plan: AgentReportReviewIntakePlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"intake_plan_id"}))


class AgentReportReviewIntakeCommand(DomainModel):
    command_id: Digest
    intake_plan_id: Digest
    intake_plan_digest: Digest
    draft_outcome_binding_id: Digest
    report_review_plan_id: Digest
    report_review_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    decision: AgentReportReviewIntakeDecision
    reason_code: AgentReportReviewIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Report review Intake reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Report review Intake reviewer contains NUL")
        if self.command_id != agent_report_review_intake_command_digest(self):
            raise ValueError("Report review Intake command digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportReviewIntakeCommand:
        return cls(command_id=canonical_digest(values), **values)


def agent_report_review_intake_command_digest(
    command: AgentReportReviewIntakeCommand,
) -> str:
    return canonical_digest(command.model_dump(mode="python", exclude={"command_id"}))


class AgentReportReviewIntakeRecord(DomainModel):
    record_id: Digest
    intake_plan_id: Digest
    command_id: Digest
    draft_execution_plan_id: Digest
    draft_outcome_binding_id: Digest
    draft_outcome_binding_digest: Digest
    report_review_plan_id: Digest
    report_review_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    candidate_id: UUID
    evidence_bundle_id: UUID
    channel: ReportChannel
    scope_id: UUID
    scope_version: int = Field(ge=1)
    decision: AgentReportReviewIntakeDecision
    reason_code: AgentReportReviewIntakeReason
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_code is not _REASONS[self.decision]:
            raise ValueError("Report review Intake record reason does not match decision")
        if "\x00" in self.reviewer:
            raise ValueError("Report review Intake reviewer contains NUL")
        if not self.decided_at < self.expires_at:
            raise ValueError("Report review Intake record is already expired")
        if self.record_id != agent_report_review_intake_record_digest(self):
            raise ValueError("Report review Intake record digest mismatch")
        return self


def agent_report_review_intake_record_digest(
    record: AgentReportReviewIntakeRecord,
) -> str:
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
