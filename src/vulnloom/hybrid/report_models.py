"""Sealed contracts for Hybrid Evidence-backed local report drafting."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, ReportReviewStatus
from vulnloom.reporting import ReportOutcome

from .models import Digest


class HybridReportState(StrEnum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class HybridReportPlan(DomainModel):
    plan_id: Digest
    hybrid_finding_plan_id: Digest
    hybrid_finding_outcome_digest: Digest
    hybrid_chain_id: Digest
    hybrid_chain_digest: Digest
    report_draft_plan_id: Digest
    report_draft_plan_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    max_attempts: int = Field(default=3, ge=1, le=3)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Hybrid Report window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Hybrid Report idempotency key contains NUL")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("Hybrid Report plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> HybridReportPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class HybridReportOutcome(DomainModel):
    plan_id: Digest
    state: HybridReportState
    attempt: int = Field(ge=1, le=3)
    hybrid_finding_plan_id: Digest
    hybrid_chain_id: Digest
    report_draft_plan_id: Digest
    report_outcome: ReportOutcome | None = None
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        completed = self.state is HybridReportState.COMPLETED
        if completed != (self.report_outcome is not None):
            raise ValueError("Only completed Hybrid Report outcomes contain a Report")
        if self.report_outcome is not None and (
            self.report_outcome.plan_id != self.report_draft_plan_id
            or self.report_outcome.report.review_status is not ReportReviewStatus.DRAFT
        ):
            raise ValueError("Hybrid Report outcome is not an exact local draft")
        if not self.cleanup_complete:
            raise ValueError("Hybrid Report outcome requires proven cleanup")
        return self
