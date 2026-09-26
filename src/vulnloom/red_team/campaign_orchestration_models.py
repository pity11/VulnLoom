"""Sealed B5.5 contracts for bounded Campaign orchestration and Evidence closure."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, DomainModel
from vulnloom.workflows import AutonomyLevel

from .campaign_models import CampaignPhaseKind
from .evidence_requirement_models import EvidenceAssessmentVerdict
from .models import Digest


class CampaignEvidenceClosureDisposition(StrEnum):
    UNRESOLVED_CANDIDATE = "unresolved_candidate"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class CampaignOrchestrationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignOrchestrationLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


def campaign_phase_admission_digest(
    orchestration_plan_id: Digest, phase_id: Digest, ordinal: int
) -> Digest:
    return canonical_digest(
        {
            "contract": "campaign-orchestration-phase-admission-v1",
            "orchestration_plan_id": orchestration_plan_id,
            "phase_id": phase_id,
            "ordinal": ordinal,
        }
    )


class CampaignOrchestrationPlan(DomainModel):
    orchestration_plan_id: Digest
    campaign_plan_id: Digest
    campaign_plan_digest: Digest
    campaign_outcome_id: Digest
    campaign_outcome_digest: Digest
    runtime_plan_id: Digest
    runtime_plan_digest: Digest
    runtime_outcome_id: Digest
    runtime_outcome_digest: Digest
    goal_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=16)]
    target_set_digest: Digest
    phase_ids: Annotated[tuple[Digest, ...], Field(min_length=6, max_length=6)]
    phase_graph_digest: Digest
    evidence_assessment_plan_id: Digest
    evidence_assessment_plan_digest: Digest
    evidence_assessment_id: Digest
    evidence_assessment_outcome_digest: Digest
    evidence_requirement_id: Digest
    evidence_target_id: UUID
    evidence_target_version: str = Field(min_length=1, max_length=256)
    limits: CampaignOrchestrationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    requested_autonomy: Literal[AutonomyLevel.GOAL_DRIVEN_CAMPAIGN] = (
        AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    )
    action_execution_requested: Literal[False] = False
    dynamic_target_expansion_requested: Literal[False] = False
    credential_access_requested: Literal[False] = False
    submission_requested: Literal[False] = False
    candidate_creation_requested: Literal[False] = False
    finding_creation_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.target_ids != tuple(sorted(set(self.target_ids), key=str))
            or self.target_set_digest != canonical_digest(self.target_ids)
            or len(set(self.phase_ids)) != 6
            or self.evidence_target_id not in self.target_ids
            or not self.created_at < self.deadline
            or any(
                (
                    self.action_execution_requested,
                    self.dynamic_target_expansion_requested,
                    self.credential_access_requested,
                    self.submission_requested,
                    self.candidate_creation_requested,
                    self.finding_creation_requested,
                )
            )
            or self.orchestration_plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"orchestration_plan_id"}))
        ):
            raise ValueError("Campaign Orchestration Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignOrchestrationPlan:
        expanded = cls.model_construct(orchestration_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"orchestration_plan_id"}
        )
        return cls(orchestration_plan_id=canonical_digest(expanded), **expanded)


class CampaignPhaseCheckpoint(DomainModel):
    checkpoint_id: Digest
    orchestration_plan_id: Digest
    phase_id: Digest
    phase_kind: CampaignPhaseKind
    ordinal: int = Field(ge=1, le=6)
    approval_id: UUID
    approval_action: Literal[ApprovalAction.ADVANCE_CAMPAIGN_PHASE] = (
        ApprovalAction.ADVANCE_CAMPAIGN_PHASE
    )
    approval_digest: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=32)]
    target_set_unchanged: Literal[True] = True
    no_action_executed: Literal[True] = True
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.approval_digest
            != campaign_phase_admission_digest(
                self.orchestration_plan_id, self.phase_id, self.ordinal
            )
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or not self.target_set_unchanged
            or not self.no_action_executed
            or self.checkpoint_id
            != canonical_digest(self.model_dump(mode="python", exclude={"checkpoint_id"}))
        ):
            raise ValueError("Campaign Phase Checkpoint binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignPhaseCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **expanded)


class CampaignEvidenceClosure(DomainModel):
    closure_id: Digest
    orchestration_plan_id: Digest
    campaign_plan_id: Digest
    runtime_outcome_id: Digest
    evidence_assessment_id: Digest
    evidence_requirement_id: Digest
    disposition: CampaignEvidenceClosureDisposition
    assessment_verdict: EvidenceAssessmentVerdict
    phase_checkpoint_ids: Annotated[tuple[Digest, ...], Field(min_length=6, max_length=6)]
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    cleanup_complete: Literal[True] = True
    unresolved_candidate_recorded: bool
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False
    action_execution_authority_granted: Literal[False] = False
    submission_granted: Literal[False] = False
    closed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = {
            EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE: (
                CampaignEvidenceClosureDisposition.UNRESOLVED_CANDIDATE,
                True,
            ),
            EvidenceAssessmentVerdict.NEGATIVE: (
                CampaignEvidenceClosureDisposition.REFUTED,
                False,
            ),
            EvidenceAssessmentVerdict.INCONCLUSIVE: (
                CampaignEvidenceClosureDisposition.INCONCLUSIVE,
                False,
            ),
        }[self.assessment_verdict]
        if (
            (self.disposition, self.unresolved_candidate_recorded) != expected
            or len(set(self.phase_checkpoint_ids)) != 6
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or not self.cleanup_complete
            or self.candidate_created
            or self.finding_created
            or self.action_execution_authority_granted
            or self.submission_granted
            or self.closure_id
            != canonical_digest(self.model_dump(mode="python", exclude={"closure_id"}))
        ):
            raise ValueError("Campaign Evidence Closure binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignEvidenceClosure:
        expanded = cls.model_construct(closure_id="0" * 64, **values).model_dump(
            mode="python", exclude={"closure_id"}
        )
        return cls(closure_id=canonical_digest(expanded), **expanded)


class CampaignOrchestrationOutcome(DomainModel):
    orchestration_plan_id: Digest
    closure: CampaignEvidenceClosure
    attempt: int = Field(ge=1, le=3)
    campaign_started: Literal[True] = True
    campaign_completed: Literal[True] = True
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if (
            self.closure.orchestration_plan_id != self.orchestration_plan_id
            or not self.campaign_started
            or not self.campaign_completed
            or not self.cleanup_complete
        ):
            raise ValueError("Campaign Orchestration Outcome binding is invalid")
        return self
