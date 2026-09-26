"""Sealed B5.3 contracts for A4 Goal-driven Campaign qualification."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest
from vulnloom.workflows import AutonomyLevel

from .adaptive_runtime_models import RuntimeAssuranceLevel


class CampaignGoalKind(StrEnum):
    COVERAGE_COMPLETION = "coverage_completion"
    EVIDENCE_REQUIREMENT_SATISFACTION = "evidence_requirement_satisfaction"


class CampaignPhaseKind(StrEnum):
    SCOPE_CONFIRMATION = "scope_confirmation"
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"
    CRITIC_REVIEW = "critic_review"
    CLEANUP_CONFIRMATION = "cleanup_confirmation"


REQUIRED_CAMPAIGN_PHASES = tuple(CampaignPhaseKind)


class CampaignQualificationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignGoal(DomainModel):
    goal_id: Digest
    kind: CampaignGoalKind
    statement_digest: Digest
    required_evidence_classes: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.required_evidence_classes
            != tuple(sorted(set(self.required_evidence_classes)))
            or any(
                not item
                or len(item) > 128
                or not item.replace("_", "").replace("-", "").isalnum()
                for item in self.required_evidence_classes
            )
            or self.goal_id
            != canonical_digest(self.model_dump(mode="python", exclude={"goal_id"}))
        ):
            raise ValueError("Campaign Goal binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignGoal:
        expanded = cls.model_construct(goal_id="0" * 64, **values).model_dump(
            mode="python", exclude={"goal_id"}
        )
        return cls(goal_id=canonical_digest(expanded), **expanded)


class CampaignPhase(DomainModel):
    phase_id: Digest
    ordinal: int = Field(ge=1, le=16)
    kind: CampaignPhaseKind
    prerequisite_phase_ids: Annotated[tuple[Digest, ...], Field(max_length=8)] = ()
    max_flow_materializations: int = Field(ge=1, le=16)
    max_actions: int = Field(ge=1, le=128)
    wall_seconds: int = Field(ge=1, le=86_400)
    transition_requires_operator_approval: Literal[True] = True
    execution_authority_granted: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            len(set(self.prerequisite_phase_ids)) != len(self.prerequisite_phase_ids)
            or not self.transition_requires_operator_approval
            or self.execution_authority_granted
            or self.phase_id
            != canonical_digest(self.model_dump(mode="python", exclude={"phase_id"}))
        ):
            raise ValueError("Campaign Phase binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignPhase:
        expanded = cls.model_construct(phase_id="0" * 64, **values).model_dump(
            mode="python", exclude={"phase_id"}
        )
        return cls(phase_id=canonical_digest(expanded), **expanded)


class CampaignBudget(DomainModel):
    max_flow_materializations: int = Field(ge=6, le=64)
    max_actions: int = Field(ge=6, le=512)
    wall_seconds: int = Field(ge=60, le=86_400)
    max_consecutive_failures: int = Field(ge=1, le=5)


class CampaignStopConditions(DomainModel):
    stop_on_scope_revocation: Literal[True] = True
    stop_on_budget_exhaustion: Literal[True] = True
    stop_on_deadline: Literal[True] = True
    stop_on_cleanup_failure: Literal[True] = True
    stop_on_consecutive_failures: Literal[True] = True
    stop_on_goal_reached: Literal[True] = True


class CampaignQualificationLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CampaignFlowQualificationBinding(DomainModel):
    binding_id: Digest
    flow_plan_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    adaptive_plan_id: Digest
    adaptive_outcome_id: Digest
    coverage_ledger_id: Digest
    runtime_plan_id: Digest
    runtime_outcome_id: Digest
    runtime_outcome_digest: Digest
    assurance_level: RuntimeAssuranceLevel
    isolated_lab_qualified: Literal[True] = True
    cleanup_complete: Literal[True] = True
    execution_authority_granted: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.isolated_lab_qualified
            or not self.cleanup_complete
            or self.execution_authority_granted
            or self.binding_id
            != canonical_digest(self.model_dump(mode="python", exclude={"binding_id"}))
        ):
            raise ValueError("Campaign Flow Qualification binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignFlowQualificationBinding:
        expanded = cls.model_construct(binding_id="0" * 64, **values).model_dump(
            mode="python", exclude={"binding_id"}
        )
        return cls(binding_id=canonical_digest(expanded), **expanded)


class GoalDrivenCampaignPlan(DomainModel):
    campaign_plan_id: Digest
    goal: CampaignGoal
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=16)]
    flow_bindings: Annotated[
        tuple[CampaignFlowQualificationBinding, ...], Field(min_length=2, max_length=16)
    ]
    phases: Annotated[tuple[CampaignPhase, ...], Field(min_length=6, max_length=6)]
    budget: CampaignBudget
    stop_conditions: CampaignStopConditions
    limits: CampaignQualificationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    requested_autonomy: Literal[
        AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    ] = AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    execution_authority_requested: Literal[False] = False
    dynamic_target_expansion_requested: Literal[False] = False
    credential_access_requested: Literal[False] = False
    submission_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        target_ids = tuple(sorted({item.target_id for item in self.flow_bindings}, key=str))
        if (
            self.target_ids != target_ids
            or tuple(item.flow_plan_id for item in self.flow_bindings)
            != tuple(sorted({item.flow_plan_id for item in self.flow_bindings}))
            or len({item.binding_id for item in self.flow_bindings})
            != len(self.flow_bindings)
            or any(
                item.scope_id != self.scope_id or item.scope_version != self.scope_version
                for item in self.flow_bindings
            )
            or tuple(item.ordinal for item in self.phases)
            != tuple(range(1, len(self.phases) + 1))
            or tuple(item.kind for item in self.phases) != REQUIRED_CAMPAIGN_PHASES
            or not self.created_at < self.deadline
            or self.execution_authority_requested
            or self.dynamic_target_expansion_requested
            or self.credential_access_requested
            or self.submission_requested
        ):
            raise ValueError("Goal-driven Campaign Plan binding is invalid")
        prior: set[str] = set()
        for index, phase in enumerate(self.phases):
            if (
                (index == 0 and phase.prerequisite_phase_ids)
                or (index > 0 and not phase.prerequisite_phase_ids)
                or not set(phase.prerequisite_phase_ids) <= prior
            ):
                raise ValueError("Campaign Phase Graph topology is invalid")
            prior.add(phase.phase_id)
        if (
            self.phases[-1].prerequisite_phase_ids
            != (self.phases[-2].phase_id,)
            or sum(item.max_flow_materializations for item in self.phases)
            > self.budget.max_flow_materializations
            or sum(item.max_actions for item in self.phases) > self.budget.max_actions
            or sum(item.wall_seconds for item in self.phases) > self.budget.wall_seconds
            or len(self.flow_bindings) > self.budget.max_flow_materializations
            or self.campaign_plan_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"campaign_plan_id"})
            )
        ):
            raise ValueError("Goal-driven Campaign budget or digest is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> GoalDrivenCampaignPlan:
        expanded = cls.model_construct(campaign_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"campaign_plan_id"}
        )
        return cls(campaign_plan_id=canonical_digest(expanded), **expanded)


class GoalDrivenCampaignQualificationOutcome(DomainModel):
    outcome_id: Digest
    campaign_plan_id: Digest
    goal_id: Digest
    flow_binding_ids: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=16)]
    target_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=16)]
    minimum_assurance_level: RuntimeAssuranceLevel
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    qualified_autonomy: Literal[
        AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    ] = AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    qualified: Literal[True] = True
    campaign_started: Literal[False] = False
    execution_authority_granted: Literal[False] = False
    dynamic_target_expansion_granted: Literal[False] = False
    credential_access_granted: Literal[False] = False
    submission_granted: Literal[False] = False
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            len(set(self.flow_binding_ids)) != len(self.flow_binding_ids)
            or self.target_ids != tuple(sorted(set(self.target_ids), key=str))
            or not self.qualified
            or self.campaign_started
            or self.execution_authority_granted
            or self.dynamic_target_expansion_granted
            or self.credential_access_granted
            or self.submission_granted
            or self.candidate_created
            or self.finding_created
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Goal-driven Campaign Qualification Outcome is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> GoalDrivenCampaignQualificationOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
