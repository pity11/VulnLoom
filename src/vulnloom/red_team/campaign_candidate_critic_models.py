"""B5.9 contracts for independent Campaign Candidate Critic Intake."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.critic.models import CRITIC_RULESET_DIGEST, REQUIRED_ANGLES, CounterevidenceAngle
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, DomainModel

from .models import Digest

REQUIRED_CAMPAIGN_CRITIC_ANGLES = tuple(sorted(REQUIRED_ANGLES, key=str))


class CampaignCandidateCriticLifecycleState(StrEnum):
    PENDING = "pending"


class CampaignCandidateCriticIntakeState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignCandidateCriticIntakeLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CampaignCandidateCriticIntakePlan(DomainModel):
    critic_intake_plan_id: Digest
    validation_execution_plan_id: Digest
    validation_execution_plan_digest: Digest
    validation_execution_outcome_id: Digest
    validation_execution_outcome_digest: Digest
    validation_checkpoint_id: Digest
    validation_checkpoint_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    validation_run_id: UUID
    validation_run_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    fresh_fact_ids: Annotated[tuple[Digest, ...], Field(min_length=5, max_length=5)]
    validation_context_digest: Digest
    review_context_digest: Digest
    validation_producer_digest: Digest
    review_producer_digest: Digest
    required_counterevidence_angles: tuple[CounterevidenceAngle, ...] = (
        REQUIRED_CAMPAIGN_CRITIC_ANGLES
    )
    ruleset_digest: Literal[CRITIC_RULESET_DIGEST] = CRITIC_RULESET_DIGEST
    limits: CampaignCandidateCriticIntakeLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    human_approval_required: Literal[True] = True
    validation_evidence_accepted_as_counterevidence: Literal[False] = False
    critic_execution_requested: Literal[False] = False
    finding_creation_requested: Literal[False] = False
    submission_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_review_context = canonical_digest(
            {
                "candidate_id": self.candidate_id,
                "candidate_digest": self.candidate_digest,
                "validation_run_id": self.validation_run_id,
                "validation_run_digest": self.validation_run_digest,
                "evidence_bundle_id": self.evidence_bundle_id,
                "evidence_bundle_digest": self.evidence_bundle_digest,
                "validation_context_digest": self.validation_context_digest,
                "validation_producer_digest": self.validation_producer_digest,
                "review_producer_digest": self.review_producer_digest,
                "required_counterevidence_angles": self.required_counterevidence_angles,
                "ruleset_digest": self.ruleset_digest,
                "contract": "campaign-candidate-independent-critic-v1",
            }
        )
        if (
            self.fresh_fact_ids != tuple(sorted(set(self.fresh_fact_ids)))
            or self.required_counterevidence_angles != REQUIRED_CAMPAIGN_CRITIC_ANGLES
            or self.validation_context_digest == self.review_context_digest
            or self.validation_producer_digest == self.review_producer_digest
            or self.review_context_digest != expected_review_context
            or not self.created_at < self.deadline
            or not self.human_approval_required
            or self.validation_evidence_accepted_as_counterevidence
            or self.critic_execution_requested
            or self.finding_creation_requested
            or self.submission_requested
            or self.critic_intake_plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"critic_intake_plan_id"}))
        ):
            raise ValueError("Campaign Candidate Critic Intake Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateCriticIntakePlan:
        expanded = cls.model_construct(critic_intake_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"critic_intake_plan_id"}
        )
        return cls(critic_intake_plan_id=canonical_digest(expanded), **expanded)


class CampaignCandidateCriticIntakeCheckpoint(DomainModel):
    checkpoint_id: Digest
    critic_intake_plan_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    candidate_state: Literal[CandidateState.VALIDATED] = CandidateState.VALIDATED
    critic_state: Literal[CampaignCandidateCriticLifecycleState.PENDING] = (
        CampaignCandidateCriticLifecycleState.PENDING
    )
    approval_id: UUID
    approval_digest: Digest
    validation_run_id: UUID
    validation_run_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    validation_context_digest: Digest
    review_context_digest: Digest
    required_counterevidence_angles: tuple[CounterevidenceAngle, ...]
    validation_evidence_accepted_as_counterevidence: Literal[False] = False
    critic_started: Literal[False] = False
    critic_completed: Literal[False] = False
    finding_created: Literal[False] = False
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.candidate_state is not CandidateState.VALIDATED
            or self.critic_state is not CampaignCandidateCriticLifecycleState.PENDING
            or self.approval_digest != self.critic_intake_plan_id
            or self.validation_context_digest == self.review_context_digest
            or self.required_counterevidence_angles != REQUIRED_CAMPAIGN_CRITIC_ANGLES
            or self.validation_evidence_accepted_as_counterevidence
            or self.critic_started
            or self.critic_completed
            or self.finding_created
            or self.checkpoint_id
            != canonical_digest(self.model_dump(mode="python", exclude={"checkpoint_id"}))
        ):
            raise ValueError("Campaign Candidate Critic Intake Checkpoint binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateCriticIntakeCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **expanded)


class CampaignCandidateCriticIntakeOutcome(DomainModel):
    outcome_id: Digest
    critic_intake_plan_id: Digest
    checkpoint: CampaignCandidateCriticIntakeCheckpoint
    attempt: int = Field(ge=1, le=3)
    critic_admitted: Literal[True] = True
    critic_started: Literal[False] = False
    critic_review_created: Literal[False] = False
    finding_created: Literal[False] = False
    submission_authorized: Literal[False] = False
    cleanup_complete: Literal[True] = True
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.checkpoint.critic_intake_plan_id != self.critic_intake_plan_id
            or not self.critic_admitted
            or self.critic_started
            or self.critic_review_created
            or self.finding_created
            or self.submission_authorized
            or not self.cleanup_complete
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Campaign Candidate Critic Intake Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateCriticIntakeOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
