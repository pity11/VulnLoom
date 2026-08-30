"""Typed protocol crossing the trusted Control Plane / Worker boundary."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field

from .models import DomainModel


class WorkerRole(StrEnum):
    SCOPE_INTERPRETER = "scope_interpreter"
    SOURCE_MAPPER = "source_mapper"
    HYPOTHESIS = "hypothesis"
    VALIDATOR = "validator"
    CRITIC = "critic"
    REPORTER = "reporter"


class WorkerStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    FAILED = "failed"


class TaskBudget(DomainModel):
    wall_seconds: int = Field(gt=0, le=86_400)
    model_tokens: int = Field(ge=0)
    tool_calls: int = Field(ge=0)


class TaskEnvelope(DomainModel):
    task_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    target_id: UUID
    target_version: str = Field(min_length=1)
    scope_id: UUID
    worker_role: WorkerRole
    scope_version: int = Field(ge=1)
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sandbox_profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_refs: tuple[str, ...]
    allowed_tools: frozenset[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]]
    budget: TaskBudget
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1)


class WorkerClaim(DomainModel):
    statement: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = ()


class WorkerResult(DomainModel):
    task_id: UUID
    worker_role: WorkerRole
    status: WorkerStatus
    confidence: float = Field(ge=0, le=1)
    claims: tuple[WorkerClaim, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    candidate_refs: tuple[UUID, ...] = ()
    checkpoint_ref: str | None = None
    budget_used: TaskBudget
    policy_decision_refs: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
