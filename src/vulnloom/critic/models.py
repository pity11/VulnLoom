"""Sealed contracts for deterministic, independent counterevidence review."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    DETERMINISTIC_CRITIC_RULESET_DIGEST,
    Candidate,
    CriticReview,
    DomainModel,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CounterevidenceAngle(StrEnum):
    SECURITY_CONTROL = "security_control"
    REACHABILITY = "reachability"
    ENVIRONMENT_PARITY = "environment_parity"
    VERSION_BINDING = "version_binding"


class CounterevidenceDisposition(StrEnum):
    RULED_OUT = "ruled_out"
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"


REQUIRED_ANGLES = frozenset(CounterevidenceAngle)
CRITIC_RULESET_DIGEST = DETERMINISTIC_CRITIC_RULESET_DIGEST


class CounterevidenceAssessment(DomainModel):
    angle: CounterevidenceAngle
    disposition: CounterevidenceDisposition
    evidence_refs: tuple[Digest, ...] = ()
    rationale_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")

    @model_validator(mode="after")
    def conclusive_assessment_has_evidence(self) -> Self:
        if (
            self.disposition is not CounterevidenceDisposition.INCONCLUSIVE
            and not self.evidence_refs
        ):
            raise ValueError("a conclusive counterevidence assessment requires Evidence")
        return self


class CriticPlan(DomainModel):
    plan_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    validation_run_id: UUID
    validation_run_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    validation_context_id: Digest
    review_context_id: Digest
    validation_producer: str = Field(min_length=1, max_length=256)
    review_producer: str = Field(min_length=1, max_length=256)
    assessments: tuple[CounterevidenceAssessment, ...]
    ruleset_digest: Digest = CRITIC_RULESET_DIGEST
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_independent_review(self) -> Self:
        if self.plan_id != critic_plan_digest(self):
            raise ValueError("CriticPlan content digest mismatch")
        if self.ruleset_digest != CRITIC_RULESET_DIGEST:
            raise ValueError("CriticPlan uses an unknown deterministic ruleset")
        if self.validation_context_id == self.review_context_id:
            raise ValueError("Critic context must be independent from validation")
        if self.validation_producer == self.review_producer:
            raise ValueError("Critic producer must be independent from validation")
        if self.deadline <= self.created_at:
            raise ValueError("CriticPlan deadline must be after creation")
        angles = tuple(item.angle for item in self.assessments)
        if len(angles) != len(REQUIRED_ANGLES) or frozenset(angles) != REQUIRED_ANGLES:
            raise ValueError("CriticPlan must assess every required counterevidence angle once")
        return self

    @classmethod
    def create(
        cls,
        *,
        candidate_id: UUID,
        candidate_digest: str,
        validation_run_id: UUID,
        validation_run_digest: str,
        evidence_bundle_id: UUID,
        evidence_bundle_digest: str,
        scope_id: UUID,
        scope_version: int,
        validation_context_id: str,
        review_context_id: str,
        validation_producer: str,
        review_producer: str,
        assessments: tuple[CounterevidenceAssessment, ...],
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CriticPlan:
        values = {
            "candidate_id": candidate_id,
            "candidate_digest": candidate_digest,
            "validation_run_id": validation_run_id,
            "validation_run_digest": validation_run_digest,
            "evidence_bundle_id": evidence_bundle_id,
            "evidence_bundle_digest": evidence_bundle_digest,
            "scope_id": scope_id,
            "scope_version": scope_version,
            "validation_context_id": validation_context_id,
            "review_context_id": review_context_id,
            "validation_producer": validation_producer,
            "review_producer": review_producer,
            "assessments": assessments,
            "ruleset_digest": CRITIC_RULESET_DIGEST,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "assessments": tuple(item.model_dump(mode="python") for item in assessments),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def critic_plan_digest(plan: CriticPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


def domain_object_digest(value: DomainModel) -> str:
    return canonical_digest(value.model_dump(mode="python"))


class CriticOutcome(DomainModel):
    plan_id: Digest
    candidate: Candidate
    review: CriticReview
    completed_at: AwareDatetime
