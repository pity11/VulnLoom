"""Sealed minimal Candidate projection and model-generation outcome."""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.analyzers.models import SignalKind
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .models import CandidateRecommendation, RecommendationPriority, _safe_text


def _sealed(cls, field, values):
    partial = cls.model_construct(**{field: "0" * 64}, **values)
    digest = canonical_digest(partial.model_dump(mode="python", exclude={field}))
    return cls(**{field: digest}, **values)


class CandidateLocationProjection(DomainModel):
    index: int = Field(ge=0, le=31)
    path_digest: Digest
    line: int = Field(ge=1, le=1_000_000)


class CandidateSignalProjection(DomainModel):
    signal_id: Digest
    kind: SignalKind
    rule_digest: Digest
    confidence: float = Field(ge=0, le=1)


class CandidateRecommendationProjection(DomainModel):
    projection_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    candidate_confidence: float = Field(ge=0, le=1)
    locations: Annotated[
        tuple[CandidateLocationProjection, ...], Field(min_length=1, max_length=32)
    ]
    signals: Annotated[tuple[CandidateSignalProjection, ...], Field(min_length=1, max_length=16)]
    disclosure_profile: Literal["digests-lines-static-signals-v1"] = (
        "digests-lines-static-signals-v1"
    )

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if tuple(item.index for item in self.locations) != tuple(range(len(self.locations))):
            raise ValueError("projection location indexes must be contiguous")
        if tuple(item.signal_id for item in self.signals) != tuple(
            sorted(item.signal_id for item in self.signals)
        ):
            raise ValueError("projection signals must be ordered")
        if self.projection_id != canonical_digest(
            self.model_dump(mode="python", exclude={"projection_id"})
        ):
            raise ValueError("Candidate projection digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault("disclosure_profile", "digests-lines-static-signals-v1")
        return _sealed(cls, "projection_id", values)


class CandidateRecommendationResponse(DomainModel):
    projection_id: Digest
    priority: RecommendationPriority
    rationale: str = Field(min_length=1, max_length=600)
    review_questions: Annotated[tuple[str, ...], Field(max_length=3)] = ()
    cited_location_indexes: Annotated[tuple[int, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def safe(self) -> Self:
        if self.cited_location_indexes != tuple(sorted(set(self.cited_location_indexes))):
            raise ValueError("response location indexes must be ordered and unique")
        if not _safe_text(self.rationale) or any(
            not _safe_text(item) for item in self.review_questions
        ):
            raise ValueError("recommendation response text is unsafe")
        return self

    def require_projection(self, projection: CandidateRecommendationProjection) -> None:
        indexes = {item.index for item in projection.locations}
        if (
            self.projection_id != projection.projection_id
            or not set(self.cited_location_indexes) <= indexes
        ):
            raise ValueError("recommendation response projection binding rejected")


class CandidateRecommendationGenerationOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    status: Literal["recommendation_ready", "rejected", "timed_out"]
    projection_id: Digest
    transport: ProviderProbeResult
    response: CandidateRecommendationResponse | None = None
    recommendation: CandidateRecommendation | None = None
    producer_content_binding_verified: bool
    eligible_for_validation_intake: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = (
            "recommendation_ready" if self.transport.status == "passed" else self.transport.status
        )
        ready = self.status == "recommendation_ready"
        if (
            self.status != expected
            or self.plan_id != self.transport.plan_id
            or (ready and (self.response is None or self.recommendation is None))
            or (not ready and (self.response is not None or self.recommendation is not None))
        ):
            raise ValueError("generation outcome transport binding mismatch")
        if ready and (
            self.response.projection_id != self.projection_id
            or self.transport.response_model is None
            or self.transport.input_tokens + self.transport.output_tokens > 8192
            or self.recommendation.producer_result_id != self.transport.result_id
            or self.recommendation.producer_plan_id != self.plan_id
            or self.recommendation.producer_receipt_digest != self.transport.receipt_digest
            or self.recommendation.priority != self.response.priority
            or self.recommendation.rationale != self.response.rationale
            or self.recommendation.review_questions != self.response.review_questions
            or not self.producer_content_binding_verified
            or not self.recommendation.requires_human_review
        ):
            raise ValueError("generation outcome recommendation binding mismatch")
        if self.outcome_id != canonical_digest(
            self.model_dump(mode="python", exclude={"outcome_id"})
        ):
            raise ValueError("generation outcome digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault(
            "producer_content_binding_verified",
            values.get("status") == "recommendation_ready",
        )
        values.setdefault("eligible_for_validation_intake", False)
        return _sealed(cls, "outcome_id", values)
