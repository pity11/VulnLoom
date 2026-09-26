"""Sealed B5.1 contracts for offline A3 Adaptive Flow qualification."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.workflows import AutonomyLevel

from .models import Digest, ReconOutcome, RedTeamActionKind


class AdaptiveQualificationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class AdaptiveQualificationLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)
    minimum_replan_rounds: Literal[2] = 2
    maximum_replan_rounds: int = Field(default=16, ge=2, le=32)


class AdaptiveFlowQualificationPlan(DomainModel):
    plan_id: Digest
    flow_plan_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    target_url_digest: Digest
    final_checkpoint_id: Digest
    replan_execution_receipt_ids: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=32)]
    limits: AdaptiveQualificationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    requested_autonomy: Literal[AutonomyLevel.ADAPTIVE_FLOW] = AutonomyLevel.ADAPTIVE_FLOW
    campaign_qualification_requested: Literal[False] = False
    execution_authority_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            len(set(self.replan_execution_receipt_ids))
            != len(self.replan_execution_receipt_ids)
            or len(self.replan_execution_receipt_ids) < self.limits.minimum_replan_rounds
            or len(self.replan_execution_receipt_ids) > self.limits.maximum_replan_rounds
            or not self.created_at < self.deadline
            or self.campaign_qualification_requested
            or self.execution_authority_requested
            or self.plan_id != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Adaptive Flow Qualification Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AdaptiveFlowQualificationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class AdaptiveRoundCoverage(DomainModel):
    coverage_id: Digest
    ordinal: int = Field(ge=1, le=32)
    execution_receipt_id: Digest
    admission_id: Digest
    source_checkpoint_id: Digest
    result_checkpoint_id: Digest
    source_observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1)]
    produced_observation_id: Digest
    action_id: Digest
    action_kind: RedTeamActionKind
    test_class: str = Field(min_length=1, max_length=128)
    outcome: Literal[ReconOutcome.SUCCEEDED] = ReconOutcome.SUCCEEDED
    exact_approval_proven: Literal[True] = True
    cleanup_proven: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            tuple(sorted(set(self.source_observation_ids))) != self.source_observation_ids
            or not self.exact_approval_proven
            or not self.cleanup_proven
            or self.coverage_id
            != canonical_digest(self.model_dump(mode="python", exclude={"coverage_id"}))
        ):
            raise ValueError("Adaptive Round Coverage binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AdaptiveRoundCoverage:
        expanded = cls.model_construct(coverage_id="0" * 64, **values).model_dump(
            mode="python", exclude={"coverage_id"}
        )
        return cls(coverage_id=canonical_digest(expanded), **expanded)


class AdaptiveCoverageLedger(DomainModel):
    ledger_id: Digest
    flow_plan_id: Digest
    final_checkpoint_id: Digest
    rounds: Annotated[tuple[AdaptiveRoundCoverage, ...], Field(min_length=2, max_length=32)]
    covered_action_kinds: Annotated[tuple[RedTeamActionKind, ...], Field(min_length=1)]
    covered_test_classes: Annotated[tuple[str, ...], Field(min_length=1)]
    source_observation_count: int = Field(ge=1)
    produced_observation_count: int = Field(ge=2)
    bounded_target_count: Literal[1] = 1
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            tuple(item.ordinal for item in self.rounds)
            != tuple(range(1, len(self.rounds) + 1))
            or self.covered_action_kinds
            != tuple(sorted({item.action_kind for item in self.rounds}, key=str))
            or self.covered_test_classes
            != tuple(sorted({item.test_class for item in self.rounds}))
            or self.produced_observation_count != len(self.rounds)
            or not self.cleanup_complete
            or self.ledger_id
            != canonical_digest(self.model_dump(mode="python", exclude={"ledger_id"}))
        ):
            raise ValueError("Adaptive Coverage Ledger binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AdaptiveCoverageLedger:
        expanded = cls.model_construct(ledger_id="0" * 64, **values).model_dump(
            mode="python", exclude={"ledger_id"}
        )
        return cls(ledger_id=canonical_digest(expanded), **expanded)


class AdaptiveFlowQualificationOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    flow_plan_id: Digest
    coverage_ledger: AdaptiveCoverageLedger
    qualified_autonomy: Literal[AutonomyLevel.ADAPTIVE_FLOW] = AutonomyLevel.ADAPTIVE_FLOW
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    qualified: Literal[True] = True
    campaign_qualified: Literal[False] = False
    execution_authority_granted: Literal[False] = False
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.coverage_ledger.flow_plan_id != self.flow_plan_id
            or not self.qualified
            or self.campaign_qualified
            or self.execution_authority_granted
            or self.candidate_created
            or self.finding_created
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Adaptive Flow Qualification Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AdaptiveFlowQualificationOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
