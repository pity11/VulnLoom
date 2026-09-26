"""B5.7 contracts for Campaign Candidate Validation Intake."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, DomainModel

from .evidence_requirement_models import EvidenceFactKind, VulnerabilityClass
from .models import Digest

REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS = (
    EvidenceFactKind.SEALED_GET_SUCCEEDED,
    EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
    EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
    EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
    EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
)


class CampaignCandidateValidationIntakeState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignCandidateValidationIntakeLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CampaignCandidateValidationIntakePlan(DomainModel):
    validation_intake_plan_id: Digest
    candidate_intake_plan_id: Digest
    candidate_intake_plan_digest: Digest
    candidate_intake_outcome_id: Digest
    candidate_intake_outcome_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    vulnerability_class: VulnerabilityClass
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    initial_candidate_state: Literal[CandidateState.PROPOSED] = CandidateState.PROPOSED
    requested_candidate_state: Literal[CandidateState.VALIDATION_PENDING] = (
        CandidateState.VALIDATION_PENDING
    )
    prior_campaign_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    required_fresh_facts: tuple[EvidenceFactKind, ...] = REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
    validation_context_digest: Digest
    limits: CampaignCandidateValidationIntakeLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    human_approval_required: Literal[True] = True
    prior_campaign_evidence_accepted_as_validation: Literal[False] = False
    validation_execution_requested: Literal[False] = False
    critic_bypass_requested: Literal[False] = False
    finding_creation_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_context = canonical_digest(
            {
                "candidate_id": self.candidate_id,
                "candidate_digest": self.candidate_digest,
                "scope_id": self.scope_id,
                "scope_version": self.scope_version,
                "required_fresh_facts": self.required_fresh_facts,
                "contract": "campaign-candidate-fresh-validation-v1",
            }
        )
        if (
            self.initial_candidate_state is not CandidateState.PROPOSED
            or self.requested_candidate_state is not CandidateState.VALIDATION_PENDING
            or self.prior_campaign_evidence_refs
            != tuple(sorted(set(self.prior_campaign_evidence_refs)))
            or self.required_fresh_facts != REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
            or self.validation_context_digest != expected_context
            or not self.created_at < self.deadline
            or not self.human_approval_required
            or self.prior_campaign_evidence_accepted_as_validation
            or self.validation_execution_requested
            or self.critic_bypass_requested
            or self.finding_creation_requested
            or self.validation_intake_plan_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"validation_intake_plan_id"})
            )
        ):
            raise ValueError("Campaign Candidate Validation Intake Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateValidationIntakePlan:
        expanded = cls.model_construct(validation_intake_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"validation_intake_plan_id"}
        )
        return cls(validation_intake_plan_id=canonical_digest(expanded), **expanded)


class CampaignCandidateLifecycleCheckpoint(DomainModel):
    checkpoint_id: Digest
    validation_intake_plan_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    previous_state: Literal[CandidateState.PROPOSED] = CandidateState.PROPOSED
    state: Literal[CandidateState.VALIDATION_PENDING] = CandidateState.VALIDATION_PENDING
    approval_id: UUID
    approval_digest: Digest
    validation_context_digest: Digest
    prior_campaign_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    required_fresh_facts: tuple[EvidenceFactKind, ...]
    prior_campaign_evidence_accepted_as_validation: Literal[False] = False
    validation_started: Literal[False] = False
    critic_completed: Literal[False] = False
    finding_created: Literal[False] = False
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.previous_state is not CandidateState.PROPOSED
            or self.state is not CandidateState.VALIDATION_PENDING
            or self.approval_digest != self.validation_intake_plan_id
            or self.prior_campaign_evidence_refs
            != tuple(sorted(set(self.prior_campaign_evidence_refs)))
            or self.required_fresh_facts != REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
            or self.prior_campaign_evidence_accepted_as_validation
            or self.validation_started
            or self.critic_completed
            or self.finding_created
            or self.checkpoint_id
            != canonical_digest(self.model_dump(mode="python", exclude={"checkpoint_id"}))
        ):
            raise ValueError("Campaign Candidate Lifecycle Checkpoint binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateLifecycleCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **expanded)


class CampaignCandidateValidationIntakeOutcome(DomainModel):
    outcome_id: Digest
    validation_intake_plan_id: Digest
    checkpoint: CampaignCandidateLifecycleCheckpoint
    attempt: int = Field(ge=1, le=3)
    validation_admitted: Literal[True] = True
    validation_started: Literal[False] = False
    validation_run_created: Literal[False] = False
    critic_completed: Literal[False] = False
    finding_created: Literal[False] = False
    cleanup_complete: Literal[True] = True
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.checkpoint.validation_intake_plan_id != self.validation_intake_plan_id
            or not self.validation_admitted
            or self.validation_started
            or self.validation_run_created
            or self.critic_completed
            or self.finding_created
            or not self.cleanup_complete
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Campaign Candidate Validation Intake Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateValidationIntakeOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
