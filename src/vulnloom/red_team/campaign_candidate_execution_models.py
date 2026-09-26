"""B5.8 contracts for isolated Campaign Candidate validation execution."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    DomainModel,
    EvidenceBundle,
    ValidationResult,
    ValidationRun,
)
from vulnloom.runners.models import (
    Digest,
    MountKind,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    run_request_digest,
)

from .campaign_candidate_validation_models import REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
from .evidence_requirement_models import EvidenceFactKind, EvidenceFactVerdict, VulnerabilityClass

CAMPAIGN_CANDIDATE_VALIDATION_OUTPUT_CONTRACT = "campaign-candidate-validation-output-v1"


class CampaignCandidateValidationExecutionRole(StrEnum):
    PRIMARY = "primary"
    REPLAY = "replay"


_ROLE_FACTS = {
    CampaignCandidateValidationExecutionRole.PRIMARY: (
        EvidenceFactKind.SEALED_GET_SUCCEEDED,
        EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
        EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
        EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
    ),
    CampaignCandidateValidationExecutionRole.REPLAY: (
        EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
        EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
    ),
}


class CampaignCandidateValidationExecutionState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignCandidateValidationExecutionLimits(DomainModel):
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CampaignCandidateValidationWorkerOutput(DomainModel):
    contract: Literal[CAMPAIGN_CANDIDATE_VALIDATION_OUTPUT_CONTRACT] = (
        CAMPAIGN_CANDIDATE_VALIDATION_OUTPUT_CONTRACT
    )
    candidate_id: UUID
    validation_context_digest: Digest
    role: CampaignCandidateValidationExecutionRole
    response_fingerprint: Digest
    facts: tuple[EvidenceFactKind, ...]
    raw_values_retained: Literal[False] = False
    target_locator_retained: Literal[False] = False
    credential_material_retained: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.facts != _ROLE_FACTS[self.role]
            or self.raw_values_retained
            or self.target_locator_retained
            or self.credential_material_retained
        ):
            raise ValueError("Campaign Candidate validation Worker output is invalid")
        return self


class CampaignCandidateValidationExecutionPlan(DomainModel):
    execution_plan_id: Digest
    validation_intake_plan_id: Digest
    validation_intake_plan_digest: Digest
    validation_intake_outcome_id: Digest
    validation_intake_outcome_digest: Digest
    lifecycle_checkpoint_id: Digest
    lifecycle_checkpoint_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    vulnerability_class: VulnerabilityClass
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    validation_context_digest: Digest
    required_fresh_facts: tuple[EvidenceFactKind, ...] = REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
    prior_campaign_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    primary_request_digest: Digest
    primary_request: SandboxRunRequest
    replay_request_digest: Digest
    replay_request: SandboxRunRequest
    limits: CampaignCandidateValidationExecutionLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    human_approval_required: Literal[True] = True
    network_execution_requested: Literal[False] = False
    credential_access_requested: Literal[False] = False
    critic_bypass_requested: Literal[False] = False
    finding_creation_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        primary_snapshots = tuple(
            item.object_id
            for item in self.primary_request.profile.mounts
            if item.kind is MountKind.SNAPSHOT
        )
        replay_snapshots = tuple(
            item.object_id
            for item in self.replay_request.profile.mounts
            if item.kind is MountKind.SNAPSHOT
        )
        if (
            self.required_fresh_facts != REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
            or self.prior_campaign_evidence_refs
            != tuple(sorted(set(self.prior_campaign_evidence_refs)))
            or self.primary_request.run_id == self.replay_request.run_id
            or self.primary_request.task.task_id == self.replay_request.task.task_id
            or self.primary_request.idempotency_key == self.replay_request.idempotency_key
            or self.primary_request.profile.image_digest != self.replay_request.profile.image_digest
            or self.primary_request.task.policy_digest != self.replay_request.task.policy_digest
            or len(primary_snapshots) != 1
            or len(replay_snapshots) != 1
            or primary_snapshots == replay_snapshots
            or bool(
                set((*primary_snapshots, *replay_snapshots))
                & set(self.prior_campaign_evidence_refs)
            )
            or self.primary_request_digest != run_request_digest(self.primary_request)
            or self.replay_request_digest != run_request_digest(self.replay_request)
            or not self.created_at < self.deadline
            or not self.human_approval_required
            or self.network_execution_requested
            or self.credential_access_requested
            or self.critic_bypass_requested
            or self.finding_creation_requested
            or self.execution_plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"execution_plan_id"}))
        ):
            raise ValueError("Campaign Candidate Validation Execution Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateValidationExecutionPlan:
        expanded = cls.model_construct(execution_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"execution_plan_id"}
        )
        return cls(execution_plan_id=canonical_digest(expanded), **expanded)


class CampaignCandidateFreshEvidenceFact(DomainModel):
    fact_id: Digest
    execution_plan_id: Digest
    candidate_id: UUID
    validation_context_digest: Digest
    fact: EvidenceFactKind
    verdict: Literal[EvidenceFactVerdict.SUPPORTED] = EvidenceFactVerdict.SUPPORTED
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=2)]
    producer_roles: Annotated[
        tuple[CampaignCandidateValidationExecutionRole, ...], Field(min_length=1, max_length=2)
    ]
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        primary_only = {
            EvidenceFactKind.SEALED_GET_SUCCEEDED,
            EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
            EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
        }
        both_runs = {
            EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
        }
        if (
            self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or self.producer_roles != tuple(sorted(set(self.producer_roles), key=str))
            or len(self.evidence_refs) != len(self.producer_roles)
            or (
                self.fact in primary_only
                and self.producer_roles != (CampaignCandidateValidationExecutionRole.PRIMARY,)
            )
            or (
                self.fact in both_runs
                and self.producer_roles
                != tuple(sorted(CampaignCandidateValidationExecutionRole, key=str))
            )
            or self.fact_id != canonical_digest(self.model_dump(mode="python", exclude={"fact_id"}))
        ):
            raise ValueError("Campaign Candidate fresh Evidence Fact binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateFreshEvidenceFact:
        expanded = cls.model_construct(fact_id="0" * 64, **values).model_dump(
            mode="python", exclude={"fact_id"}
        )
        return cls(fact_id=canonical_digest(expanded), **expanded)


class CampaignCandidateValidationCompletionCheckpoint(DomainModel):
    checkpoint_id: Digest
    execution_plan_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    validation_context_digest: Digest
    previous_state: Literal[CandidateState.VALIDATION_PENDING] = CandidateState.VALIDATION_PENDING
    state: Literal[CandidateState.VALIDATED] = CandidateState.VALIDATED
    approval_id: UUID
    approval_digest: Digest
    validation_run_id: UUID
    validation_run_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    fresh_fact_ids: Annotated[tuple[Digest, ...], Field(min_length=5, max_length=5)]
    validation_started: Literal[True] = True
    validation_completed: Literal[True] = True
    critic_completed: Literal[False] = False
    finding_created: Literal[False] = False
    cleanup_complete: Literal[True] = True
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.previous_state is not CandidateState.VALIDATION_PENDING
            or self.state is not CandidateState.VALIDATED
            or self.approval_digest != self.execution_plan_id
            or self.fresh_fact_ids != tuple(sorted(set(self.fresh_fact_ids)))
            or not self.validation_started
            or not self.validation_completed
            or self.critic_completed
            or self.finding_created
            or not self.cleanup_complete
            or self.checkpoint_id
            != canonical_digest(self.model_dump(mode="python", exclude={"checkpoint_id"}))
        ):
            raise ValueError("Campaign Candidate Validation completion checkpoint is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateValidationCompletionCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **expanded)


class CampaignCandidateValidationExecutionOutcome(DomainModel):
    outcome_id: Digest
    execution_plan_id: Digest
    primary_result: SandboxRunResult
    replay_result: SandboxRunResult
    fresh_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=2)]
    fresh_facts: Annotated[
        tuple[CampaignCandidateFreshEvidenceFact, ...], Field(min_length=5, max_length=5)
    ]
    validation_run: ValidationRun
    evidence_bundle: EvidenceBundle
    checkpoint: CampaignCandidateValidationCompletionCheckpoint
    attempt: int = Field(ge=1, le=3)
    validation_reproduced: Literal[True] = True
    critic_required: Literal[True] = True
    critic_completed: Literal[False] = False
    finding_created: Literal[False] = False
    submission_authorized: Literal[False] = False
    cleanup_complete: Literal[True] = True
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if len(self.primary_result.outputs) != 1 or len(self.replay_result.outputs) != 1:
            raise ValueError("Campaign Candidate validation requires two exact outputs")
        output_refs = tuple(
            sorted(
                (
                    self.primary_result.outputs[0].object_id,
                    self.replay_result.outputs[0].object_id,
                )
            )
        )
        refs = self.fresh_evidence_refs
        if (
            {item.fact for item in self.fresh_facts}
            != set(REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS)
            or tuple(item.fact_id for item in self.fresh_facts)
            != tuple(sorted({item.fact_id for item in self.fresh_facts}))
            or self.validation_run.result is not ValidationResult.REPRODUCED
            or self.primary_result.status is not SandboxRunStatus.COMPLETED
            or self.replay_result.status is not SandboxRunStatus.COMPLETED
            or not self.primary_result.cleanup.complete
            or not self.replay_result.cleanup.complete
            or len(set(output_refs)) != 2
            or refs != tuple(sorted(set(refs)))
            or self.validation_run.evidence_refs != refs
            or any(
                item.execution_plan_id != self.execution_plan_id
                or item.candidate_id != self.validation_run.candidate_id
                or not set(item.evidence_refs) <= set(refs)
                for item in self.fresh_facts
            )
            or len({item.validation_context_digest for item in self.fresh_facts}) != 1
            or self.evidence_bundle.candidate_id != self.validation_run.candidate_id
            or self.evidence_bundle.evidence_refs != refs
            or self.checkpoint.execution_plan_id != self.execution_plan_id
            or self.checkpoint.candidate_id != self.validation_run.candidate_id
            or any(
                item.validation_context_digest != self.checkpoint.validation_context_digest
                for item in self.fresh_facts
            )
            or self.checkpoint.validation_run_id != self.validation_run.run_id
            or self.checkpoint.validation_run_digest
            != canonical_digest(self.validation_run.model_dump(mode="python"))
            or self.checkpoint.evidence_bundle_id != self.evidence_bundle.bundle_id
            or self.checkpoint.evidence_bundle_digest
            != canonical_digest(self.evidence_bundle.model_dump(mode="python"))
            or self.checkpoint.fresh_fact_ids
            != tuple(sorted(item.fact_id for item in self.fresh_facts))
            or not self.validation_reproduced
            or not self.critic_required
            or self.critic_completed
            or self.finding_created
            or self.submission_authorized
            or not self.cleanup_complete
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Campaign Candidate Validation Execution Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignCandidateValidationExecutionOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
