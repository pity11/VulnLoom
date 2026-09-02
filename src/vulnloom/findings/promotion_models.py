"""Sealed contracts for Approval-gated deterministic Finding promotion."""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Candidate, CandidateState, DomainModel, Finding
from vulnloom.runners.models import Digest

FINDING_PROMOTION_SIDE_EFFECTS = ("candidate:promoted", "finding:created")


class FindingPromotionApprovalAction(DomainModel):
    action_id: Digest
    engagement_id: UUID
    target_id: UUID
    intake_record_id: Digest
    intake_record_digest: Digest
    promotion_plan_id: Digest
    promotion_plan_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    finding_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    expected_side_effects: tuple[str, ...] = FINDING_PROMOTION_SIDE_EFFECTS

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.expected_side_effects != FINDING_PROMOTION_SIDE_EFFECTS:
            raise ValueError("Finding promotion side effects drifted")
        if self.action_id != finding_promotion_approval_action_digest(self):
            raise ValueError("Finding promotion approval action digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> FindingPromotionApprovalAction:
        return cls(action_id=canonical_digest(values), **values)


def finding_promotion_approval_action_digest(action: FindingPromotionApprovalAction) -> str:
    return canonical_digest(action.model_dump(mode="python", exclude={"action_id"}))


class FindingPromotionExecutionPlan(DomainModel):
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    intake_plan_id: Digest
    intake_record_id: Digest
    intake_record_digest: Digest
    promotion_plan_id: Digest
    promotion_plan_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    finding_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Finding promotion execution window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Finding promotion execution key contains NUL")
        if self.execution_plan_id != finding_promotion_execution_plan_digest(self):
            raise ValueError("Finding promotion execution plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> FindingPromotionExecutionPlan:
        return cls(execution_plan_id=canonical_digest(values), **values)


def finding_promotion_execution_plan_digest(plan: FindingPromotionExecutionPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"execution_plan_id"}))


class FindingPromotionOutcome(DomainModel):
    outcome_id: Digest
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    intake_record_id: Digest
    promotion_plan_id: Digest
    promotion_plan_digest: Digest
    source_candidate_digest: Digest
    promoted_candidate: Candidate
    promoted_candidate_digest: Digest
    finding: Finding
    finding_digest: Digest
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.promoted_candidate.state is not CandidateState.PROMOTED:
            raise ValueError("Finding promotion outcome Candidate is not promoted")
        if self.finding.candidate_id != self.promoted_candidate.candidate_id:
            raise ValueError("Finding promotion outcome Candidate drifted")
        if self.finding.state != "verified" or not self.finding.validation_run_ids:
            raise ValueError("Finding promotion outcome is not verified")
        if (
            canonical_digest(self.promoted_candidate.model_dump(mode="python"))
            != self.promoted_candidate_digest
        ):
            raise ValueError("Promoted Candidate digest mismatch")
        if canonical_digest(self.finding.model_dump(mode="python")) != self.finding_digest:
            raise ValueError("Finding digest mismatch")
        if self.outcome_id != finding_promotion_outcome_digest(self):
            raise ValueError("Finding promotion outcome digest mismatch")
        return self


def finding_promotion_outcome_digest(outcome: FindingPromotionOutcome) -> str:
    return canonical_digest(outcome.model_dump(mode="python", exclude={"outcome_id"}))
