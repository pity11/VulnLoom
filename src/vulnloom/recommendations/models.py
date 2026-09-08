"""Typed advisory model output bound to an existing deterministic Candidate."""

import unicodedata
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_serializer, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, SourceLocation
from vulnloom.evidence import Redactor
from vulnloom.runners.models import Digest


class RecommendationPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


CANDIDATE_RECOMMENDATION_PROTOCOL_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.candidate-recommendation",
        "version": 1,
        "authority": "advisory-only",
        "candidate_fields": "immutable",
        "requires_human_selection": True,
    }
)


def _safe_text(value: str) -> bool:
    return (
        value == value.strip()
        and bool(value)
        and Redactor().text(value) == value
        and not any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)
    )


class CandidateRecommendation(DomainModel):
    recommendation_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    supporting_signal_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=16)]
    cited_locations: Annotated[tuple[SourceLocation, ...], Field(min_length=1, max_length=8)]
    priority: RecommendationPriority
    rationale: str = Field(min_length=1, max_length=600)
    review_questions: Annotated[tuple[str, ...], Field(max_length=3)] = ()
    producer_protocol: Literal["candidate-recommendation-v1"] = "candidate-recommendation-v1"
    producer_protocol_digest: Digest = CANDIDATE_RECOMMENDATION_PROTOCOL_DIGEST
    producer_result_id: Digest
    producer_plan_id: Digest
    producer_receipt_digest: Digest
    created_at: AwareDatetime
    requires_human_review: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.supporting_signal_ids != tuple(sorted(set(self.supporting_signal_ids))):
            raise ValueError("recommendation signals must be unique and ordered")
        if self.producer_protocol_digest != CANDIDATE_RECOMMENDATION_PROTOCOL_DIGEST:
            raise ValueError("recommendation producer protocol mismatch")
        location_keys = tuple((item.path, item.line, item.symbol) for item in self.cited_locations)
        if location_keys != tuple(dict.fromkeys(location_keys)):
            raise ValueError("recommendation locations must be unique")
        if not _safe_text(self.rationale) or any(
            not _safe_text(item) for item in self.review_questions
        ):
            raise ValueError("recommendation text is not safe for ordinary storage")
        if self.recommendation_id != canonical_digest(
            self.model_dump(mode="python", exclude={"recommendation_id"})
        ):
            raise ValueError("recommendation digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault("requires_human_review", True)
        partial = cls.model_construct(recommendation_id="0" * 64, **values)
        digest = canonical_digest(partial.model_dump(mode="python", exclude={"recommendation_id"}))
        return cls(recommendation_id=digest, **values)


class CandidateRecommendationAdmissionPlan(DomainModel):
    plan_id: Digest
    recommendation_id: Digest
    recommendation_digest: Digest
    producer_result_id: Digest
    producer_result_digest: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    scope_digest: Digest
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    generation_plan_id: Digest | None = None
    generation_outcome_id: Digest | None = None
    generation_outcome_digest: Digest | None = None

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not 0 < (self.deadline - self.created_at).total_seconds() <= 300:
            raise ValueError("recommendation admission window invalid")
        generation_binding = (
            self.generation_plan_id,
            self.generation_outcome_id,
            self.generation_outcome_digest,
        )
        if any(generation_binding) and not all(generation_binding):
            raise ValueError("recommendation generation binding is incomplete")
        if "\x00" in self.idempotency_key or self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"}, exclude_none=True)
        ):
            raise ValueError("recommendation admission plan mismatch")
        return self

    @model_serializer(mode="wrap")
    def omit_absent_generation_binding(self, handler):
        result = handler(self)
        if self.generation_plan_id is None:
            result.pop("generation_plan_id", None)
            result.pop("generation_outcome_id", None)
            result.pop("generation_outcome_digest", None)
        return result

    @classmethod
    def create(cls, **values):
        return cls(
            plan_id=canonical_digest(
                {key: value for key, value in values.items() if value is not None}
            ),
            **values,
        )


class CandidateRecommendationRecord(DomainModel):
    record_id: Digest
    plan_id: Digest
    recommendation_id: Digest
    recommendation_digest: Digest
    producer_result_id: Digest
    producer_result_digest: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    admitted_at: AwareDatetime
    generation_plan_id: Digest | None = None
    generation_outcome_id: Digest | None = None
    generation_outcome_digest: Digest | None = None
    candidate_unchanged: Literal[True] = True
    requires_human_selection: Literal[True] = True
    producer_content_binding_verified: bool = False
    eligible_for_validation_intake: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        generation_binding = (
            self.generation_plan_id,
            self.generation_outcome_id,
            self.generation_outcome_digest,
        )
        if any(generation_binding) != all(
            generation_binding
        ) or self.producer_content_binding_verified != all(generation_binding):
            raise ValueError("recommendation record generation binding mismatch")
        if self.record_id != canonical_digest(
            self.model_dump(mode="python", exclude={"record_id"}, exclude_none=True)
        ):
            raise ValueError("recommendation admission record mismatch")
        return self

    @model_serializer(mode="wrap")
    def omit_absent_generation_binding(self, handler):
        result = handler(self)
        if self.generation_plan_id is None:
            result.pop("generation_plan_id", None)
            result.pop("generation_outcome_id", None)
            result.pop("generation_outcome_digest", None)
        return result

    @classmethod
    def create(cls, **values):
        values.setdefault("candidate_unchanged", True)
        values.setdefault("requires_human_selection", True)
        values.setdefault("producer_content_binding_verified", False)
        values.setdefault("eligible_for_validation_intake", False)
        return cls(
            record_id=canonical_digest(
                {key: value for key, value in values.items() if value is not None}
            ),
            **values,
        )
