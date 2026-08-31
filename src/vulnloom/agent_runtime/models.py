"""Typed, secret-free contracts for the offline Agent Runtime boundary."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskEnvelope, WorkerRole
from vulnloom.runners.models import (
    Digest,
    ToolId,
    ToolInvocation,
    WorkingDirectory,
    invocation_digest,
)

AGENT_DECISION_SCHEMA_DIGEST = canonical_digest(
    {"contract": "vulnloom.agent-decision", "version": 1, "raw_text_persisted": False}
)


class AgentAdapterKind(StrEnum):
    OFFLINE_REPLAY = "offline_replay"


class AgentDecisionKind(StrEnum):
    PROPOSE_TOOL = "propose_tool"
    COMPLETE = "complete"
    BLOCKED = "blocked"


class AgentRunStatus(StrEnum):
    TOOL_PROPOSED = "tool_proposed"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class AgentModelRegistration(DomainModel):
    registration_id: Digest
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    model: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
    adapter_kind: AgentAdapterKind = AgentAdapterKind.OFFLINE_REPLAY
    adapter_digest: Digest
    supported_roles: Annotated[tuple[WorkerRole, ...], Field(min_length=1)]
    max_output_tokens: int = Field(gt=0, le=65_536)

    @model_validator(mode="after")
    def sealed_offline_registration(self) -> Self:
        expected_roles = tuple(sorted(set(self.supported_roles), key=lambda item: item.value))
        if self.supported_roles != expected_roles:
            raise ValueError("Agent model roles must be unique and sorted")
        if self.registration_id != agent_model_registration_digest(self):
            raise ValueError("Agent model registration content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        model: str,
        adapter_digest: str,
        supported_roles: tuple[WorkerRole, ...],
        max_output_tokens: int,
    ) -> AgentModelRegistration:
        roles = tuple(sorted(set(supported_roles), key=lambda item: item.value))
        values = {
            "provider_id": provider_id,
            "model": model,
            "adapter_kind": AgentAdapterKind.OFFLINE_REPLAY,
            "adapter_digest": adapter_digest,
            "supported_roles": roles,
            "max_output_tokens": max_output_tokens,
        }
        return cls(registration_id=canonical_digest(values), **values)


def agent_model_registration_digest(registration: AgentModelRegistration) -> str:
    return canonical_digest(registration.model_dump(mode="python", exclude={"registration_id"}))


class AgentRunLimits(DomainModel):
    max_steps: int = Field(default=2, ge=1, le=8)
    max_output_tokens_per_step: int = Field(default=4096, gt=0, le=65_536)
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)


class AgentRunPlan(DomainModel):
    plan_id: Digest
    task: TaskEnvelope
    task_digest: Digest
    model_registration_id: Digest
    model_registration_digest: Digest
    context_digest: Digest
    decision_schema_digest: Digest = AGENT_DECISION_SCHEMA_DIGEST
    limits: AgentRunLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Agent run deadline must be after creation")
        if self.task_digest != canonical_digest(self.task.model_dump(mode="python")):
            raise ValueError("Agent task digest mismatch")
        if self.context_digest != canonical_digest(self.task.input_refs):
            raise ValueError("Agent context digest mismatch")
        if self.decision_schema_digest != AGENT_DECISION_SCHEMA_DIGEST:
            raise ValueError("Agent decision schema is not trusted")
        if self.plan_id != agent_run_plan_digest(self):
            raise ValueError("Agent run plan content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        task: TaskEnvelope,
        registration: AgentModelRegistration,
        limits: AgentRunLimits,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AgentRunPlan:
        if task.worker_role not in registration.supported_roles:
            raise ValueError("Agent model registration does not support the Worker role")
        if task.budget.model_tokens <= 0:
            raise ValueError("Agent task requires a positive model token budget")
        if limits.max_output_tokens_per_step > registration.max_output_tokens:
            raise ValueError("Agent step output limit exceeds the model registration")
        values = {
            "task": task,
            "task_digest": canonical_digest(task.model_dump(mode="python")),
            "model_registration_id": registration.registration_id,
            "model_registration_digest": canonical_digest(
                registration.model_dump(mode="python")
            ),
            "context_digest": canonical_digest(task.input_refs),
            "decision_schema_digest": AGENT_DECISION_SCHEMA_DIGEST,
            "limits": limits,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "task": task.model_dump(mode="python"),
            "limits": limits.model_dump(mode="python"),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def agent_run_plan_digest(plan: AgentRunPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class AgentToolCallPayload(DomainModel):
    tool_id: ToolId
    arguments: Annotated[tuple[str, ...], Field(max_length=128)] = ()
    working_directory: WorkingDirectory


class AgentDecisionPayload(DomainModel):
    kind: AgentDecisionKind
    tool_call: AgentToolCallPayload | None = None
    summary_digest: Digest | None = None
    supporting_ref_digests: Annotated[tuple[Digest, ...], Field(max_length=1024)] = ()

    @model_validator(mode="after")
    def exact_shape(self) -> Self:
        if self.supporting_ref_digests != tuple(sorted(set(self.supporting_ref_digests))):
            raise ValueError("Agent supporting references must be unique and sorted")
        if self.kind is AgentDecisionKind.PROPOSE_TOOL:
            if self.tool_call is None or self.summary_digest is not None:
                raise ValueError("tool proposal requires only one typed tool call")
        elif self.tool_call is not None or self.summary_digest is None:
            raise ValueError("terminal Agent decision requires only a summary digest")
        return self


class AgentToolIntent(DomainModel):
    tool_id: ToolId
    invocation_digest: Digest
    argument_digests: tuple[Digest, ...]
    working_directory: WorkingDirectory

    @classmethod
    def from_payload(cls, payload: AgentToolCallPayload) -> AgentToolIntent:
        invocation = ToolInvocation(
            tool_id=payload.tool_id,
            arguments=payload.arguments,
            working_directory=payload.working_directory,
        )
        return cls(
            tool_id=payload.tool_id,
            invocation_digest=invocation_digest(invocation),
            argument_digests=tuple(canonical_digest(item) for item in payload.arguments),
            working_directory=payload.working_directory,
        )


class AgentStepRequest(DomainModel):
    request_id: Digest
    plan_id: Digest
    task_id: UUID
    step: int = Field(ge=1, le=8)
    worker_role: WorkerRole
    context_digest: Digest
    allowed_tools: frozenset[ToolId]
    decision_schema_digest: Digest
    remaining_model_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0, le=65_536)

    @model_validator(mode="after")
    def sealed_request(self) -> Self:
        expected = canonical_digest(
            self.model_dump(mode="python", exclude={"request_id"})
        )
        if self.request_id != expected:
            raise ValueError("Agent step request content digest mismatch")
        return self

    @classmethod
    def create(
        cls, *, plan: AgentRunPlan, step: int, remaining_model_tokens: int
    ) -> AgentStepRequest:
        values = {
            "plan_id": plan.plan_id,
            "task_id": plan.task.task_id,
            "step": step,
            "worker_role": plan.task.worker_role,
            "context_digest": plan.context_digest,
            "allowed_tools": plan.task.allowed_tools,
            "decision_schema_digest": plan.decision_schema_digest,
            "remaining_model_tokens": remaining_model_tokens,
            "max_output_tokens": min(
                plan.limits.max_output_tokens_per_step, remaining_model_tokens
            ),
        }
        return cls(request_id=canonical_digest(values), **values)


class AgentModelReply(DomainModel):
    structured_output: dict[str, object]
    provider_id: str
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_seconds: float = Field(ge=0, le=600)


class AgentCleanupReport(DomainModel):
    model_request_released: bool
    raw_response_discarded: bool
    no_tool_executed: bool

    @property
    def complete(self) -> bool:
        return all(
            (self.model_request_released, self.raw_response_discarded, self.no_tool_executed)
        )


class AgentRunOutcome(DomainModel):
    plan_id: Digest
    task_id: UUID
    model_registration_id: Digest
    status: AgentRunStatus
    steps: int = Field(ge=1, le=8)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    tool_intent: AgentToolIntent | None = None
    summary_digest: Digest | None = None
    supporting_ref_digests: tuple[Digest, ...] = ()
    error_codes: tuple[str, ...] = ()
    cleanup: AgentCleanupReport
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape_and_cleanup(self) -> Self:
        if not self.cleanup.complete:
            raise ValueError("Agent run requires complete logical cleanup")
        if self.supporting_ref_digests != tuple(sorted(set(self.supporting_ref_digests))):
            raise ValueError("Agent outcome supporting references must be unique and sorted")
        if self.status is AgentRunStatus.TOOL_PROPOSED:
            if self.tool_intent is None or self.summary_digest is not None or self.error_codes:
                raise ValueError("tool-proposed Agent outcome shape mismatch")
        elif self.status in {AgentRunStatus.COMPLETED, AgentRunStatus.BLOCKED}:
            if self.tool_intent is not None or self.summary_digest is None or self.error_codes:
                raise ValueError("terminal Agent outcome shape mismatch")
        elif (
            self.tool_intent is not None
            or self.summary_digest is not None
            or not self.error_codes
        ):
            raise ValueError("failed Agent outcome requires only stable error codes")
        return self
