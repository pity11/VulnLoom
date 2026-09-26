"""B5.10 contracts for isolated Campaign Candidate Critic execution."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.critic.models import (
    CounterevidenceAngle,
    CounterevidenceAssessment,
    CounterevidenceDisposition,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, CriticReview, CriticVerdict, DomainModel
from vulnloom.runners.models import (
    Digest,
    MountKind,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    run_request_digest,
)

from .campaign_candidate_critic_models import REQUIRED_CAMPAIGN_CRITIC_ANGLES

CAMPAIGN_CANDIDATE_CRITIC_OUTPUT_CONTRACT = "campaign-candidate-critic-output-v1"


class CampaignCandidateCriticExecutionState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignCandidateCriticExecutionLimits(DomainModel):
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CampaignCandidateCriticWorkerOutput(DomainModel):
    contract: Literal[CAMPAIGN_CANDIDATE_CRITIC_OUTPUT_CONTRACT] = (
        CAMPAIGN_CANDIDATE_CRITIC_OUTPUT_CONTRACT
    )
    candidate_id: UUID
    review_context_digest: Digest
    review_producer_digest: Digest
    assessments: Annotated[tuple[CounterevidenceAssessment, ...], Field(min_length=4, max_length=4)]
    raw_values_retained: Literal[False] = False
    target_locator_retained: Literal[False] = False
    credential_material_retained: Literal[False] = False
    candidate_decision_requested: Literal[False] = False
    finding_creation_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            tuple(item.angle for item in self.assessments) != REQUIRED_CAMPAIGN_CRITIC_ANGLES
            or any(not item.evidence_refs for item in self.assessments)
            or self.raw_values_retained
            or self.target_locator_retained
            or self.credential_material_retained
            or self.candidate_decision_requested
            or self.finding_creation_requested
        ):
            raise ValueError("Campaign Candidate Critic Worker output is invalid")
        return self


class CampaignCandidateCriticExecutionPlan(DomainModel):
    execution_plan_id: Digest
    critic_intake_plan_id: Digest
    critic_intake_plan_digest: Digest
    critic_intake_outcome_id: Digest
    critic_intake_outcome_digest: Digest
    intake_checkpoint_id: Digest
    intake_checkpoint_digest: Digest
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
    validation_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=2)]
    validation_context_digest: Digest
    review_context_digest: Digest
    validation_producer_digest: Digest
    review_producer_digest: Digest
    required_counterevidence_angles: tuple[CounterevidenceAngle, ...] = (
        REQUIRED_CAMPAIGN_CRITIC_ANGLES
    )
    request_digest: Digest
    request: SandboxRunRequest
    limits: CampaignCandidateCriticExecutionLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    human_approval_required: Literal[True] = True
    finding_creation_requested: Literal[False] = False
    submission_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        evidence_mounts = tuple(
            m.object_id for m in self.request.profile.mounts if m.kind is MountKind.EVIDENCE
        )
        if (
            self.fresh_fact_ids != tuple(sorted(set(self.fresh_fact_ids)))
            or self.validation_evidence_refs != tuple(sorted(set(self.validation_evidence_refs)))
            or self.required_counterevidence_angles != REQUIRED_CAMPAIGN_CRITIC_ANGLES
            or self.validation_context_digest == self.review_context_digest
            or self.validation_producer_digest == self.review_producer_digest
            or len(evidence_mounts) != 1
            or evidence_mounts[0] in self.validation_evidence_refs
            or self.request_digest != run_request_digest(self.request)
            or not self.created_at < self.deadline
            or not self.human_approval_required
            or self.finding_creation_requested
            or self.submission_requested
            or self.execution_plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"execution_plan_id"}))
        ):
            raise ValueError("Campaign Candidate Critic Execution Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateCriticExecutionPlan:
        expanded = cls.model_construct(execution_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"execution_plan_id"}
        )
        return cls(execution_plan_id=canonical_digest(expanded), **expanded)


class CampaignCandidateCounterevidenceFact(DomainModel):
    fact_id: Digest
    execution_plan_id: Digest
    candidate_id: UUID
    review_context_digest: Digest
    review_producer_digest: Digest
    angle: CounterevidenceAngle
    disposition: CounterevidenceDisposition
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=4)]
    rationale_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.evidence_refs != tuple(
            sorted(set(self.evidence_refs))
        ) or self.fact_id != canonical_digest(self.model_dump(mode="python", exclude={"fact_id"})):
            raise ValueError("Campaign Candidate counterevidence Fact binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateCounterevidenceFact:
        expanded = cls.model_construct(fact_id="0" * 64, **values).model_dump(
            mode="python", exclude={"fact_id"}
        )
        return cls(fact_id=canonical_digest(expanded), **expanded)


class CampaignCandidateCriticCompletionCheckpoint(DomainModel):
    checkpoint_id: Digest
    execution_plan_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    previous_candidate_state: Literal[CandidateState.VALIDATED] = CandidateState.VALIDATED
    candidate_state: CandidateState
    critic_state: Literal[CampaignCandidateCriticExecutionState.COMPLETED] = (
        CampaignCandidateCriticExecutionState.COMPLETED
    )
    approval_id: UUID
    approval_digest: Digest
    critic_review_id: UUID
    critic_review_digest: Digest
    counterevidence_fact_ids: Annotated[tuple[Digest, ...], Field(min_length=4, max_length=4)]
    cleanup_complete: Literal[True] = True
    finding_created: Literal[False] = False
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.candidate_state
            not in {
                CandidateState.CRITIC_REVIEWED,
                CandidateState.REJECTED,
                CandidateState.VALIDATED,
            }
            or self.approval_digest != self.execution_plan_id
            or self.critic_review_id
            != uuid5(NAMESPACE_URL, f"vulnloom:critic-review:{self.execution_plan_id}")
            or self.counterevidence_fact_ids != tuple(sorted(set(self.counterevidence_fact_ids)))
            or not self.cleanup_complete
            or self.finding_created
            or self.checkpoint_id
            != canonical_digest(self.model_dump(mode="python", exclude={"checkpoint_id"}))
        ):
            raise ValueError("Campaign Candidate Critic completion checkpoint is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateCriticCompletionCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **expanded)


class CampaignCandidateCriticExecutionOutcome(DomainModel):
    outcome_id: Digest
    execution_plan_id: Digest
    result: SandboxRunResult
    counterevidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=4)]
    counterevidence_facts: Annotated[
        tuple[CampaignCandidateCounterevidenceFact, ...], Field(min_length=4, max_length=4)
    ]
    review: CriticReview
    checkpoint: CampaignCandidateCriticCompletionCheckpoint
    attempt: int = Field(ge=1, le=3)
    critic_completed: Literal[True] = True
    finding_created: Literal[False] = False
    finding_promotion_required: Literal[True] = True
    submission_authorized: Literal[False] = False
    cleanup_complete: Literal[True] = True
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_state = {
            CriticVerdict.ACCEPTED: CandidateState.CRITIC_REVIEWED,
            CriticVerdict.REJECTED: CandidateState.REJECTED,
            CriticVerdict.INCONCLUSIVE: CandidateState.VALIDATED,
        }[self.review.verdict]
        if (
            self.result.status is not SandboxRunStatus.COMPLETED
            or not self.result.cleanup.complete
            or len(self.result.outputs) != 1
            or self.counterevidence_refs != tuple(sorted(set(self.counterevidence_refs)))
            or {f.angle for f in self.counterevidence_facts} != set(REQUIRED_CAMPAIGN_CRITIC_ANGLES)
            or any(
                f.execution_plan_id != self.execution_plan_id
                or f.candidate_id != self.review.candidate_id
                or not set(f.evidence_refs) <= set(self.counterevidence_refs)
                for f in self.counterevidence_facts
            )
            or self.checkpoint.candidate_state is not expected_state
            or self.checkpoint.critic_review_digest
            != canonical_digest(self.review.model_dump(mode="python"))
            or self.checkpoint.counterevidence_fact_ids
            != tuple(sorted(f.fact_id for f in self.counterevidence_facts))
            or not self.critic_completed
            or self.finding_created
            or not self.finding_promotion_required
            or self.submission_authorized
            or not self.cleanup_complete
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Campaign Candidate Critic Execution Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateCriticExecutionOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
