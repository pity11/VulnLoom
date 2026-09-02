"""Approval-gated contracts for deterministic Report review execution."""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, ReportReviewStatus

from .models import Digest
from .state_machine import ReviewDecisionKind

REPORT_REVIEW_EFFECTS = {
    ReviewDecisionKind.APPROVE: ("report:human_approved",),
    ReviewDecisionKind.REQUEST_CHANGES: ("report:changes_requested",),
    ReviewDecisionKind.REJECT: ("report:rejected",),
}


class ReportReviewApprovalAction(DomainModel):
    action_id: Digest
    engagement_id: UUID
    review_intake_record_id: Digest
    review_intake_record_digest: Digest
    report_review_plan_id: Digest
    report_review_plan_digest: Digest
    report_review_command_id: Digest
    report_review_command_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    decision: ReviewDecisionKind
    scope_id: UUID
    scope_version: int = Field(ge=1)
    expected_side_effects: tuple[str, ...]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.expected_side_effects != REPORT_REVIEW_EFFECTS[self.decision]:
            raise ValueError("Report review Approval effects do not match decision")
        if self.action_id != report_review_approval_action_digest(self):
            raise ValueError("Report review Approval action digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> ReportReviewApprovalAction:
        return cls(action_id=canonical_digest(values), **values)


def report_review_approval_action_digest(action: ReportReviewApprovalAction) -> str:
    return canonical_digest(action.model_dump(mode="python", exclude={"action_id"}))


class AgentReportReviewExecutionPlan(DomainModel):
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    review_intake_plan_id: Digest
    review_intake_record_id: Digest
    review_intake_record_digest: Digest
    draft_execution_plan_id: Digest
    draft_outcome_binding_id: Digest
    report_review_plan_id: Digest
    report_review_plan_digest: Digest
    report_review_command_id: Digest
    report_review_command_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    decision: ReviewDecisionKind
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Report review execution window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Report review execution key contains NUL")
        if self.execution_plan_id != agent_report_review_execution_plan_digest(self):
            raise ValueError("Report review execution plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportReviewExecutionPlan:
        return cls(execution_plan_id=canonical_digest(values), **values)


def agent_report_review_execution_plan_digest(
    plan: AgentReportReviewExecutionPlan,
) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"execution_plan_id"}))


class AgentReportReviewOutcomeBinding(DomainModel):
    binding_id: Digest
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    review_intake_record_id: Digest
    report_review_plan_id: Digest
    report_review_command_id: Digest
    report_review_outcome_digest: Digest
    report_id: UUID
    source_report_digest: Digest
    resulting_report_digest: Digest
    resulting_artifact_digest: Digest
    review_id: UUID
    review_digest: Digest
    decision: ReviewDecisionKind
    resulting_status: ReportReviewStatus
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = {
            ReviewDecisionKind.APPROVE: ReportReviewStatus.HUMAN_APPROVED,
            ReviewDecisionKind.REQUEST_CHANGES: ReportReviewStatus.CHANGES_REQUESTED,
            ReviewDecisionKind.REJECT: ReportReviewStatus.REJECTED,
        }[self.decision]
        if self.resulting_status is not expected:
            raise ValueError("Report review binding decision and status disagree")
        if self.binding_id != agent_report_review_outcome_binding_digest(self):
            raise ValueError("Report review outcome binding digest mismatch")
        return self


def agent_report_review_outcome_binding_digest(
    binding: AgentReportReviewOutcomeBinding,
) -> str:
    return canonical_digest(binding.model_dump(mode="python", exclude={"binding_id"}))
