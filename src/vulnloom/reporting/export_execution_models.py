"""Approval-gated contracts for deterministic local Report export execution."""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, ReportReviewStatus

from .models import Digest

REPORT_EXPORT_EFFECTS = ("report:exported", "report_artifact:created")


class ReportExportApprovalAction(DomainModel):
    action_id: Digest
    engagement_id: UUID
    export_intake_record_id: Digest
    export_intake_record_digest: Digest
    review_execution_plan_id: Digest
    review_outcome_binding_id: Digest
    report_export_plan_id: Digest
    report_export_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    review_id: UUID
    review_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    expected_side_effects: tuple[str, ...] = REPORT_EXPORT_EFFECTS

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.expected_side_effects != REPORT_EXPORT_EFFECTS:
            raise ValueError("Report export Approval effects do not match local export")
        if self.action_id != report_export_approval_action_digest(self):
            raise ValueError("Report export Approval action digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> ReportExportApprovalAction:
        return cls(action_id=canonical_digest(values), **values)


def report_export_approval_action_digest(action: ReportExportApprovalAction) -> str:
    return canonical_digest(action.model_dump(mode="python", exclude={"action_id"}))


class AgentReportExportExecutionPlan(DomainModel):
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    export_intake_plan_id: Digest
    export_intake_record_id: Digest
    export_intake_record_digest: Digest
    review_execution_plan_id: Digest
    review_outcome_binding_id: Digest
    report_export_plan_id: Digest
    report_export_plan_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    review_id: UUID
    review_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Report export execution window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Report export execution key contains NUL")
        if self.execution_plan_id != agent_report_export_execution_plan_digest(self):
            raise ValueError("Report export execution plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportExportExecutionPlan:
        return cls(execution_plan_id=canonical_digest(values), **values)


def agent_report_export_execution_plan_digest(
    plan: AgentReportExportExecutionPlan,
) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"execution_plan_id"}))


class AgentReportExportOutcomeBinding(DomainModel):
    binding_id: Digest
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    export_intake_record_id: Digest
    report_export_plan_id: Digest
    report_export_outcome_digest: Digest
    report_id: UUID
    source_report_digest: Digest
    exported_report_digest: Digest
    exported_artifact_digest: Digest
    review_id: UUID
    review_digest: Digest
    resulting_status: ReportReviewStatus
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.resulting_status is not ReportReviewStatus.EXPORTED:
            raise ValueError("Report export binding must describe an exported Report")
        if self.binding_id != agent_report_export_outcome_binding_digest(self):
            raise ValueError("Report export outcome binding digest mismatch")
        return self


def agent_report_export_outcome_binding_digest(
    binding: AgentReportExportOutcomeBinding,
) -> str:
    return canonical_digest(binding.model_dump(mode="python", exclude={"binding_id"}))
