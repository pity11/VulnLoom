"""Sealed human-review and local-export protocol objects."""

from __future__ import annotations

from datetime import datetime
from typing import Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, Report, ReportReviewStatus

from .models import Digest, ReportArtifact
from .state_machine import ReviewDecisionKind


class ReportReviewPlan(DomainModel):
    plan_id: Digest
    report_id: UUID
    report_family_id: UUID
    report_version: int = Field(ge=1)
    report_digest: Digest
    artifact_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    reviewer: str = Field(min_length=1, max_length=256)
    diff_id: Digest | None = None
    created_at: AwareDatetime
    deadline: AwareDatetime
    approval_expires_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_review_request(self) -> Self:
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("ReportReviewPlan content digest mismatch")
        if not self.created_at < self.deadline <= self.approval_expires_at:
            raise ValueError("Report review and approval validity windows are invalid")
        if (self.report_version == 1) != (self.diff_id is None):
            raise ValueError("revised Reports require an exact diff binding")
        return self

    @classmethod
    def create(
        cls,
        *,
        report: Report,
        artifact: ReportArtifact,
        evidence_bundle_digest: str,
        reviewer: str,
        diff_id: str | None,
        created_at: datetime,
        deadline: datetime,
        approval_expires_at: datetime,
        idempotency_key: str,
    ) -> ReportReviewPlan:
        from .models import domain_object_digest

        values = {
            "report_id": report.report_id,
            "report_family_id": report.report_family_id,
            "report_version": report.version,
            "report_digest": domain_object_digest(report),
            "artifact_digest": domain_object_digest(artifact),
            "evidence_bundle_id": report.evidence_bundle_id,
            "evidence_bundle_digest": evidence_bundle_digest,
            "scope_id": report.scope_id,
            "scope_version": report.scope_version,
            "reviewer": reviewer,
            "diff_id": diff_id,
            "created_at": created_at,
            "deadline": deadline,
            "approval_expires_at": approval_expires_at,
            "idempotency_key": idempotency_key,
        }
        return cls(plan_id=canonical_digest(values), **values)


class ReportReviewCommand(DomainModel):
    command_id: Digest
    plan_id: Digest
    report_id: UUID
    report_digest: Digest
    reviewer: str = Field(min_length=1, max_length=256)
    decision: ReviewDecisionKind
    rationale_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def content_address_is_valid(self) -> Self:
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("ReportReviewCommand content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        plan_id: str,
        report_id: UUID,
        report_digest: str,
        reviewer: str,
        decision: ReviewDecisionKind,
        rationale_code: str,
        decided_at: datetime,
    ) -> ReportReviewCommand:
        values = {
            "plan_id": plan_id,
            "report_id": report_id,
            "report_digest": report_digest,
            "reviewer": reviewer,
            "decision": decision,
            "rationale_code": rationale_code,
            "decided_at": decided_at,
        }
        return cls(command_id=canonical_digest(values), **values)


class ReportReviewRecord(DomainModel):
    review_id: UUID
    plan_id: Digest
    command_id: Digest
    report_id: UUID
    report_family_id: UUID
    report_version: int = Field(ge=1)
    reviewed_report_digest: Digest
    resulting_report_digest: Digest
    reviewer: str = Field(min_length=1, max_length=256)
    decision: ReviewDecisionKind
    rationale_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    diff_id: Digest | None = None
    decided_at: AwareDatetime
    expires_at: AwareDatetime
    resulting_status: ReportReviewStatus

    @model_validator(mode="after")
    def identity_and_status_are_valid(self) -> Self:
        expected = uuid5(NAMESPACE_URL, f"vulnloom:report-review:{self.command_id}")
        if self.review_id != expected:
            raise ValueError("Report review identity does not match its command")
        expected_status = {
            ReviewDecisionKind.APPROVE: ReportReviewStatus.HUMAN_APPROVED,
            ReviewDecisionKind.REQUEST_CHANGES: ReportReviewStatus.CHANGES_REQUESTED,
            ReviewDecisionKind.REJECT: ReportReviewStatus.REJECTED,
        }[self.decision]
        if self.resulting_status is not expected_status:
            raise ValueError("Report review decision and resulting status disagree")
        if self.expires_at <= self.decided_at:
            raise ValueError("Report review approval must expire after its decision")
        return self


class ReportReviewOutcome(DomainModel):
    plan_id: Digest
    report: Report
    artifact: ReportArtifact
    review: ReportReviewRecord
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def bindings_are_consistent(self) -> Self:
        from .models import domain_object_digest

        if (
            self.plan_id != self.review.plan_id
            or self.report.report_id != self.review.report_id
            or self.report.review_status is not self.review.resulting_status
            or domain_object_digest(self.report) != self.review.resulting_report_digest
            or self.artifact.report_digest != domain_object_digest(self.report)
        ):
            raise ValueError("ReportReviewOutcome bindings are inconsistent")
        return self


class ReportExportPlan(DomainModel):
    plan_id: Digest
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
    def content_address_is_valid(self) -> Self:
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("ReportExportPlan content digest mismatch")
        if self.deadline <= self.created_at:
            raise ValueError("ReportExportPlan deadline must be after creation")
        return self

    @classmethod
    def create(
        cls,
        *,
        report: Report,
        artifact: ReportArtifact,
        review: ReportReviewRecord,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> ReportExportPlan:
        from .models import domain_object_digest

        values = {
            "report_id": report.report_id,
            "report_digest": domain_object_digest(report),
            "artifact_digest": domain_object_digest(artifact),
            "review_id": review.review_id,
            "review_digest": domain_object_digest(review),
            "scope_id": report.scope_id,
            "scope_version": report.scope_version,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        return cls(plan_id=canonical_digest(values), **values)


class ReportExportOutcome(DomainModel):
    plan_id: Digest
    report: Report
    artifact: ReportArtifact
    review: ReportReviewRecord
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def bindings_are_consistent(self) -> Self:
        from .models import domain_object_digest

        if (
            self.report.review_status is not ReportReviewStatus.EXPORTED
            or self.report.report_id != self.review.report_id
            or self.review.resulting_status is not ReportReviewStatus.HUMAN_APPROVED
            or self.artifact.report_digest != domain_object_digest(self.report)
        ):
            raise ValueError("ReportExportOutcome bindings are inconsistent")
        return self
