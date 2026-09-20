"""Sealed contracts for approval-gated Hybrid Finding promotion."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Candidate, CandidateState, DomainModel, Finding

from .models import Digest

HYBRID_FINDING_SIDE_EFFECTS = ("candidate:promoted", "hybrid_finding:created")


class HybridFindingState(StrEnum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class HybridFindingPromotionPlan(DomainModel):
    plan_id: Digest
    hybrid_chain_id: Digest
    hybrid_chain_digest: Digest
    critic_plan_id: Digest
    critic_outcome_digest: Digest
    duplicate_check_id: Digest
    duplicate_check_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    finding_id: UUID
    root_cause: str = Field(min_length=1, max_length=8192)
    affected_versions: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    impact: str = Field(min_length=1, max_length=8192)
    severity_assessment: Annotated[dict[str, str | float], Field(min_length=1, max_length=32)]
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    max_attempts: int = Field(default=3, ge=1, le=3)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Hybrid Finding promotion window is invalid")
        if any(not version or "\x00" in version for version in self.affected_versions):
            raise ValueError("Hybrid Finding affected version is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Hybrid Finding idempotency key contains NUL")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("Hybrid Finding promotion plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> HybridFindingPromotionPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


def hybrid_finding_approval_digest(plan: HybridFindingPromotionPlan) -> str:
    return canonical_digest(
        {
            "action": "mutate_target_state",
            "plan_id": plan.plan_id,
            "hybrid_chain_id": plan.hybrid_chain_id,
            "finding_id": plan.finding_id,
            "expected_side_effects": HYBRID_FINDING_SIDE_EFFECTS,
        }
    )


class HybridFindingPromotionOutcome(DomainModel):
    plan_id: Digest
    state: HybridFindingState
    attempt: int = Field(ge=1, le=3)
    hybrid_chain_id: Digest
    approval_id: UUID | None = None
    approval_digest: Digest | None = None
    source_candidate_digest: Digest | None = None
    promoted_candidate: Candidate | None = None
    finding: Finding | None = None
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        completed = self.state is HybridFindingState.COMPLETED
        if (self.approval_id is None) != (self.approval_digest is None):
            raise ValueError("Hybrid Finding Approval receipt is incomplete")
        if completed != all(
            value is not None
            for value in (
                self.source_candidate_digest,
                self.promoted_candidate,
                self.finding,
            )
        ):
            raise ValueError("Only completed Hybrid Finding outcomes contain a Finding")
        if completed:
            if self.approval_id is None:
                raise ValueError("Completed Hybrid Finding requires an Approval receipt")
            assert self.promoted_candidate is not None and self.finding is not None
            if (
                self.promoted_candidate.state is not CandidateState.PROMOTED
                or self.finding.candidate_id != self.promoted_candidate.candidate_id
                or self.finding.state != "verified"
            ):
                raise ValueError("Hybrid Finding outcome is not a verified promotion")
        if not self.cleanup_complete:
            raise ValueError("Hybrid Finding outcome requires proven cleanup")
        return self
