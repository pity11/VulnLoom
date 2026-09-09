"""Typed Build/Harness/Fuzz/Sanitizer/PoV execution contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    Candidate,
    DomainModel,
    EvidenceBundle,
    ValidationRun,
)
from vulnloom.runners import SandboxProfile, SandboxRunRequest, SandboxRunResult, validation_profile

from .models import Digest


class SourceExecutionStage(StrEnum):
    BUILD = "build"
    HARNESS = "harness"
    FUZZ = "fuzz"
    SANITIZER = "sanitizer"
    POV_REPLAY = "pov_replay"


SOURCE_EXECUTION_STAGES = tuple(SourceExecutionStage)
SOURCE_EXECUTION_TOOLS = {
    SourceExecutionStage.BUILD: "source.build",
    SourceExecutionStage.HARNESS: "source.harness",
    SourceExecutionStage.FUZZ: "source.fuzz",
    SourceExecutionStage.SANITIZER: "source.sanitizer",
    SourceExecutionStage.POV_REPLAY: "source.pov_replay",
}


def source_execution_profile(*, image_digest: str, snapshot_id: str) -> SandboxProfile:
    values = validation_profile(
        image_digest=image_digest, snapshot_id=snapshot_id
    ).model_dump(mode="python")
    values["allowed_tools"] = frozenset(SOURCE_EXECUTION_TOOLS.values())
    return SandboxProfile.model_validate(values)


class SourceExecutionStep(DomainModel):
    stage: SourceExecutionStage
    request: SandboxRunRequest


class SourceExecutionPlan(DomainModel):
    plan_id: Digest
    investigation_plan_id: Digest
    investigation_checkpoint_id: Digest
    index_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_version: str = Field(min_length=1)
    steps: Annotated[tuple[SourceExecutionStep, ...], Field(min_length=5, max_length=5)]
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if tuple(item.stage for item in self.steps) != SOURCE_EXECUTION_STAGES:
            raise ValueError("SourceExecutionPlan requires the fixed five-stage chain")
        if self.deadline <= self.created_at:
            raise ValueError("SourceExecutionPlan deadline must be after creation")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("SourceExecutionPlan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourceExecutionPlan:
        digest_values = dict(values)
        digest_values["steps"] = tuple(
            item.model_dump(mode="python") for item in values["steps"]  # type: ignore[union-attr]
        )
        return cls(plan_id=canonical_digest(digest_values), **values)


def source_execution_approval_digest(plan: SourceExecutionPlan) -> str:
    return canonical_digest(
        {"action": ApprovalAction.RUN_UNTRUSTED_BUILD, "plan_id": plan.plan_id}
    )


class SourceExecutionStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class SourceExecutionOutcome(DomainModel):
    plan_id: Digest
    status: SourceExecutionStatus
    executed_stages: tuple[SourceExecutionStage, ...]
    runner_results: tuple[SandboxRunResult, ...]
    evidence_refs: tuple[Digest, ...]
    reproducible_pov: bool = False
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if len(self.executed_stages) != len(self.runner_results):
            raise ValueError("Source execution stage/result binding is incomplete")
        if tuple(dict.fromkeys(self.evidence_refs)) != self.evidence_refs:
            raise ValueError("Source execution Evidence references must be unique")
        expected = SOURCE_EXECUTION_STAGES[: len(self.executed_stages)]
        if self.executed_stages != expected:
            raise ValueError("Source execution results are out of order")
        if self.reproducible_pov != (
            self.status is SourceExecutionStatus.COMPLETED
            and self.executed_stages == SOURCE_EXECUTION_STAGES
            and bool(self.runner_results[-1].evidence_refs)
        ):
            raise ValueError("Source execution PoV reproduction claim is invalid")
        return self


class SourceValidationBinding(DomainModel):
    binding_id: Digest
    execution_plan_id: Digest
    execution_outcome_digest: Digest
    source_candidate_digest: Digest
    validated_candidate: Candidate
    validation_run: ValidationRun
    evidence_bundle: EvidenceBundle
    bound_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.binding_id != canonical_digest(
            self.model_dump(mode="python", exclude={"binding_id"})
        ):
            raise ValueError("SourceValidationBinding content digest mismatch")
        return self
