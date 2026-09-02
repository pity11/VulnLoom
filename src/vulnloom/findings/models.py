"""Sealed trusted-control-plane inputs for human Finding promotion selection."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class DuplicateCheckResult(StrEnum):
    CLEAR = "clear"
    DUPLICATE = "duplicate"


class FindingDuplicateCheck(DomainModel):
    check_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    result: DuplicateCheckResult
    duplicate_family_id: UUID | None = None
    checked_by: str = Field(min_length=1, max_length=256)
    checked_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.checked_at < self.expires_at:
            raise ValueError("Finding duplicate check window is invalid")
        if (self.result is DuplicateCheckResult.DUPLICATE) != (
            self.duplicate_family_id is not None
        ):
            raise ValueError("Finding duplicate check result is inconsistent")
        if "\x00" in self.checked_by:
            raise ValueError("Finding duplicate reviewer contains NUL")
        if self.check_id != finding_duplicate_check_digest(self):
            raise ValueError("Finding duplicate check digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> FindingDuplicateCheck:
        return cls(check_id=canonical_digest(values), **values)


def finding_duplicate_check_digest(check: FindingDuplicateCheck) -> str:
    return canonical_digest(check.model_dump(mode="python", exclude={"check_id"}))


class FindingPromotionPlan(DomainModel):
    promotion_plan_id: Digest
    critic_outcome_binding_plan_id: Digest
    critic_outcome_binding_id: Digest
    critic_outcome_binding_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    validation_run_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    validation_run_digests: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=32)]
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    critic_review_id: UUID
    critic_review_digest: Digest
    duplicate_check_id: Digest
    duplicate_check_digest: Digest
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

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Finding promotion plan window is invalid")
        if len(self.validation_run_ids) != len(self.validation_run_digests):
            raise ValueError("Finding promotion ValidationRun bindings are incomplete")
        if len(set(self.validation_run_ids)) != len(self.validation_run_ids):
            raise ValueError("Finding promotion ValidationRun IDs must be unique")
        if any(not item or "\x00" in item for item in self.affected_versions):
            raise ValueError("Finding affected version is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Finding promotion idempotency key contains NUL")
        if self.promotion_plan_id != finding_promotion_plan_digest(self):
            raise ValueError("Finding promotion plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> FindingPromotionPlan:
        return cls(promotion_plan_id=canonical_digest(values), **values)


def finding_promotion_plan_digest(plan: FindingPromotionPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"promotion_plan_id"}))
