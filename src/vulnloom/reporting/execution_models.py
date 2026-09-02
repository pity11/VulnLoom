"""Digest-only contracts for accepted Report Intake execution and result binding."""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, ReportChannel, ReportReviewStatus

from .models import Digest


class AgentReportDraftExecutionPlan(DomainModel):
    execution_plan_id: Digest
    report_intake_plan_id: Digest
    report_intake_record_id: Digest
    report_intake_record_digest: Digest
    finding_promotion_execution_plan_id: Digest
    finding_promotion_outcome_id: Digest
    finding_promotion_outcome_digest: Digest
    report_draft_plan_id: Digest
    report_draft_plan_digest: Digest
    evidence_catalog_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    candidate_id: UUID
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    channel: ReportChannel
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Report draft execution window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Report draft execution key contains NUL")
        if self.execution_plan_id != agent_report_draft_execution_plan_digest(self):
            raise ValueError("Report draft execution plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentReportDraftExecutionPlan:
        return cls(execution_plan_id=canonical_digest(values), **values)


def agent_report_draft_execution_plan_digest(plan: AgentReportDraftExecutionPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"execution_plan_id"}))


class AgentReportDraftOutcomeBinding(DomainModel):
    binding_id: Digest
    execution_plan_id: Digest
    report_intake_record_id: Digest
    finding_promotion_outcome_id: Digest
    report_draft_plan_id: Digest
    report_draft_plan_digest: Digest
    report_outcome_digest: Digest
    report_id: UUID
    report_digest: Digest
    artifact_digest: Digest
    report_family_id: UUID
    report_version: int = Field(ge=1)
    finding_id: UUID
    candidate_id: UUID
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    channel: ReportChannel
    review_status: ReportReviewStatus
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.review_status is not ReportReviewStatus.DRAFT:
            raise ValueError("Report draft binding must remain in draft review state")
        if self.binding_id != agent_report_draft_outcome_binding_digest(self):
            raise ValueError("Report draft outcome binding digest mismatch")
        return self


def agent_report_draft_outcome_binding_digest(
    binding: AgentReportDraftOutcomeBinding,
) -> str:
    return canonical_digest(binding.model_dump(mode="python", exclude={"binding_id"}))
