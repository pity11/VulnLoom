"""Content-addressed human decisions over admitted Candidate recommendations."""

from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class CandidateRecommendationSelectionDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"


class CandidateRecommendationSelectionCommand(DomainModel):
    command_id: Digest
    admission_plan_id: Digest
    admission_record_id: Digest
    admission_record_digest: Digest
    recommendation_id: Digest
    recommendation_digest: Digest
    generation_plan_id: Digest
    generation_outcome_id: Digest
    generation_outcome_digest: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    scope_digest: Digest
    decision: CandidateRecommendationSelectionDecision
    reviewer_id: str = Field(pattern=r"^[a-zA-Z0-9_.:@-]{1,128}$")
    decided_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not 0 < (self.expires_at - self.decided_at).total_seconds() <= 300:
            raise ValueError("recommendation selection window is invalid")
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("recommendation selection command digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        return cls(command_id=canonical_digest(values), **values)


class CandidateRecommendationSelectionRecord(DomainModel):
    record_id: Digest
    command_id: Digest
    admission_plan_id: Digest
    admission_record_id: Digest
    admission_record_digest: Digest
    recommendation_id: Digest
    generation_plan_id: Digest
    generation_outcome_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    decision: CandidateRecommendationSelectionDecision
    reviewer_id: str = Field(pattern=r"^[a-zA-Z0-9_.:@-]{1,128}$")
    decided_at: AwareDatetime
    recorded_at: AwareDatetime
    candidate_unchanged: Literal[True] = True
    requires_separate_validation_approval: Literal[True] = True
    eligible_for_validation_intake: bool

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.recorded_at < self.decided_at:
            raise ValueError("recommendation selection record time is invalid")
        if self.eligible_for_validation_intake != (
            self.decision is CandidateRecommendationSelectionDecision.ACCEPT
        ):
            raise ValueError("recommendation selection eligibility mismatch")
        if self.record_id != canonical_digest(
            self.model_dump(mode="python", exclude={"record_id"})
        ):
            raise ValueError("recommendation selection record digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault("candidate_unchanged", True)
        values.setdefault("requires_separate_validation_approval", True)
        values.setdefault(
            "eligible_for_validation_intake",
            values.get("decision") in {CandidateRecommendationSelectionDecision.ACCEPT, "accept"},
        )
        return cls(record_id=canonical_digest(values), **values)
