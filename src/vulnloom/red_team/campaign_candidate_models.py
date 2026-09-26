"""B5.6 contracts for human-gated Campaign Candidate materialization."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, DomainModel

from .evidence_requirement_models import VulnerabilityClass
from .models import Digest


class CampaignCandidateIntakeState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignCandidateIntakeLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CampaignCandidateIntakePlan(DomainModel):
    intake_plan_id: Digest
    orchestration_plan_id: Digest
    orchestration_plan_digest: Digest
    orchestration_outcome_digest: Digest
    closure_id: Digest
    assessment_plan_id: Digest
    assessment_plan_digest: Digest
    assessment_id: Digest
    assessment_outcome_digest: Digest
    candidate_id: UUID
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    vulnerability_class: VulnerabilityClass
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    hypothesis_digest: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    duplicate_fingerprint: Digest
    limits: CampaignCandidateIntakeLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    human_approval_required: Literal[True] = True
    validation_execution_requested: Literal[False] = False
    finding_creation_requested: Literal[False] = False
    submission_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_candidate_id = uuid5(
            NAMESPACE_URL, f"vulnloom:campaign-candidate:{self.closure_id}"
        )
        expected_fingerprint = canonical_digest(
            {
                "target_id": self.target_id,
                "target_version": self.target_version,
                "vulnerability_class": self.vulnerability_class,
                "cwe": self.cwe,
            }
        )
        if (
            self.candidate_id != expected_candidate_id
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or self.duplicate_fingerprint != expected_fingerprint
            or not self.created_at < self.deadline
            or not self.human_approval_required
            or self.validation_execution_requested
            or self.finding_creation_requested
            or self.submission_requested
            or self.intake_plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"intake_plan_id"}))
        ):
            raise ValueError("Campaign Candidate Intake Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateIntakePlan:
        expanded = cls.model_construct(intake_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"intake_plan_id"}
        )
        return cls(intake_plan_id=canonical_digest(expanded), **expanded)


class CampaignCandidate(DomainModel):
    candidate_digest: Digest
    candidate_id: UUID
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    vulnerability_class: VulnerabilityClass
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    hypothesis_digest: Digest
    duplicate_fingerprint: Digest
    orchestration_plan_id: Digest
    closure_id: Digest
    assessment_id: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    state: Literal[CandidateState.PROPOSED] = CandidateState.PROPOSED
    validation_required: Literal[True] = True
    independent_critic_required: Literal[True] = True
    prior_campaign_evidence_is_validation_run: Literal[False] = False
    finding_authorized: Literal[False] = False
    submission_authorized: Literal[False] = False
    created_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.candidate_id
            != uuid5(NAMESPACE_URL, f"vulnloom:campaign-candidate:{self.closure_id}")
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or self.state is not CandidateState.PROPOSED
            or not self.validation_required
            or not self.independent_critic_required
            or self.prior_campaign_evidence_is_validation_run
            or self.finding_authorized
            or self.submission_authorized
            or self.candidate_digest
            != canonical_digest(self.model_dump(mode="python", exclude={"candidate_digest"}))
        ):
            raise ValueError("Campaign Candidate binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidate:
        expanded = cls.model_construct(candidate_digest="0" * 64, **values).model_dump(
            mode="python", exclude={"candidate_digest"}
        )
        return cls(candidate_digest=canonical_digest(expanded), **expanded)


class CampaignCandidateIntakeOutcome(DomainModel):
    outcome_id: Digest
    intake_plan_id: Digest
    approval_id: UUID
    candidate: CampaignCandidate
    attempt: int = Field(ge=1, le=3)
    candidate_created: Literal[True] = True
    validation_started: Literal[False] = False
    finding_created: Literal[False] = False
    submission_started: Literal[False] = False
    cleanup_complete: Literal[True] = True
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.candidate_created
            or self.validation_started
            or self.finding_created
            or self.submission_started
            or not self.cleanup_complete
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Campaign Candidate Intake Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateIntakeOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
