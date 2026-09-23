"""Contracts for materializing independent counterevidence Assertions."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .evidence_requirement_models import (
    EvidenceAssertion,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
)
from .models import Digest


class CriticAssertionMaterializationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


CRITIC_FACTS = (
    EvidenceFactKind.ACCESS_CONTROL_ENFORCED,
    EvidenceFactKind.PUBLIC_BY_DESIGN,
    EvidenceFactKind.SYNTHETIC_OR_PLACEHOLDER_DATA,
    EvidenceFactKind.ENVIRONMENT_OR_VERSION_MISMATCH,
)

CRITIC_ASSERTION_RULESET_DIGEST = canonical_digest(
    {
        "ruleset": "independent-counterevidence-assertions-v1",
        "facts": CRITIC_FACTS,
        "producer": "critic:counterevidence-review-v1",
        "request_execution_authorized": False,
    }
)


class CriticEvidenceConclusion(DomainModel):
    fact: EvidenceFactKind
    verdict: EvidenceFactVerdict
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.fact not in CRITIC_FACTS or self.evidence_refs != tuple(
            sorted(set(self.evidence_refs))
        ):
            raise ValueError("Critic Evidence conclusion binding is invalid")
        return self


class CriticEvidenceReview(DomainModel):
    review_id: Digest
    requirement_id: Digest
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    review_context_id: Digest
    producer_ref: Literal["critic:counterevidence-review-v1"] = (
        "critic:counterevidence-review-v1"
    )
    conclusions: Annotated[
        tuple[CriticEvidenceConclusion, ...], Field(min_length=4, max_length=4)
    ]
    reviewed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        facts = tuple(item.fact for item in self.conclusions)
        if (
            facts != tuple(sorted(set(facts), key=lambda item: item.value))
            or set(facts) != set(CRITIC_FACTS)
            or self.review_id
            != canonical_digest(self.model_dump(mode="python", exclude={"review_id"}))
        ):
            raise ValueError("Critic Evidence Review binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CriticEvidenceReview:
        conclusions = tuple(
            sorted(values["conclusions"], key=lambda item: item.fact.value)  # type: ignore[index,union-attr]
        )
        expanded = cls.model_construct(
            review_id="0" * 64,
            **(values | {"conclusions": conclusions}),
        ).model_dump(mode="python", exclude={"review_id"})
        return cls(review_id=canonical_digest(expanded), **expanded)


class CriticAssertionMaterializationLimits(DomainModel):
    max_evidence_refs: int = Field(default=16, ge=1, le=32)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CriticAssertionMaterializationPlan(DomainModel):
    plan_id: Digest
    requirement_id: Digest
    replay_validation_plan_id: Digest
    replay_validation_id: Digest
    validation_context_id: Digest
    validation_producer_ref: Literal["validator:sealed-get-replay-v1"]
    validation_evidence_refs: Annotated[
        tuple[Digest, ...], Field(min_length=2, max_length=2)
    ]
    review: CriticEvidenceReview
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    ruleset_digest: Literal[CRITIC_ASSERTION_RULESET_DIGEST] = (
        CRITIC_ASSERTION_RULESET_DIGEST
    )
    limits: CriticAssertionMaterializationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        critic_refs = {
            ref for conclusion in self.review.conclusions for ref in conclusion.evidence_refs
        }
        if (
            self.deadline <= self.created_at
            or self.validation_context_id == self.review.review_context_id
            or self.validation_producer_ref == self.review.producer_ref
            or self.validation_evidence_refs
            != tuple(sorted(set(self.validation_evidence_refs)))
            or not critic_refs.isdisjoint(self.validation_evidence_refs)
            or len(critic_refs) > self.limits.max_evidence_refs
            or self.requirement_id != self.review.requirement_id
            or self.target_id != self.review.target_id
            or self.target_version != self.review.target_version
            or self.scope_id != self.review.scope_id
            or self.scope_version != self.review.scope_version
            or self.ruleset_digest != CRITIC_ASSERTION_RULESET_DIGEST
            or self.plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Critic Assertion Materialization Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CriticAssertionMaterializationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class CriticAssertionMaterialization(DomainModel):
    materialization_id: Digest
    plan_id: Digest
    requirement_id: Digest
    replay_validation_id: Digest
    review_id: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=32)]
    assertions: Annotated[tuple[EvidenceAssertion, ...], Field(min_length=4, max_length=4)]
    ruleset_digest: Literal[CRITIC_ASSERTION_RULESET_DIGEST]
    review_executed: Literal[False] = False
    request_execution_authorized: Literal[False] = False
    candidate_proposal_eligible: Literal[False] = False
    finding_authorized: Literal[False] = False
    materialized_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        assertions = {item.fact: item for item in self.assertions}
        if (
            tuple(item.assertion_id for item in self.assertions)
            != tuple(sorted({item.assertion_id for item in self.assertions}))
            or set(assertions) != set(CRITIC_FACTS)
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or any(
                item.requirement_id != self.requirement_id
                or item.stage is not EvidenceRequirementStage.CRITIC
                or item.context_id != self.plan_id
                or item.producer_ref != "critic:counterevidence-review-v1"
                or not set(item.evidence_refs) <= set(self.evidence_refs)
                for item in self.assertions
            )
            or set(self.evidence_refs)
            != {ref for item in self.assertions for ref in item.evidence_refs}
            or self.ruleset_digest != CRITIC_ASSERTION_RULESET_DIGEST
            or self.review_executed
            or self.request_execution_authorized
            or self.candidate_proposal_eligible
            or self.finding_authorized
            or self.materialization_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"materialization_id"})
            )
        ):
            raise ValueError("Critic Assertion Materialization binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CriticAssertionMaterialization:
        expanded = cls.model_construct(
            materialization_id="0" * 64, **values
        ).model_dump(mode="python", exclude={"materialization_id"})
        return cls(materialization_id=canonical_digest(expanded), **expanded)


class CriticAssertionMaterializationOutcome(DomainModel):
    plan_id: Digest
    materialization: CriticAssertionMaterialization
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.materialization.plan_id != self.plan_id:
            raise ValueError("Critic Assertion Materialization Outcome binding is invalid")
        return self
