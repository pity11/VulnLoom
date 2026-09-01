"""Sealed contracts for one Observation-fed Agent continuation."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import WorkerRole
from vulnloom.runners.models import Digest

from .context import AgentContextSnapshot
from .models import AgentRunOutcome, AgentRunPlan, AgentRunStatus
from .tool_handoff_models import (
    AgentToolHandoffOutcome,
    AgentToolHandoffStatus,
    agent_tool_handoff_outcome_digest,
)


class AgentContinuationStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class AgentContinuationBudgetLedger(DomainModel):
    original_model_tokens: int = Field(gt=0)
    consumed_model_tokens: int = Field(ge=0)
    remaining_model_tokens: int = Field(gt=0)
    consumed_agent_steps: int = Field(ge=1, le=8)
    consumed_tool_calls: int = Field(ge=1)
    remaining_wall_seconds: int = Field(gt=0, le=86_400)

    @model_validator(mode="after")
    def exact_remainder(self) -> Self:
        if (
            self.consumed_model_tokens >= self.original_model_tokens
            or self.remaining_model_tokens
            != self.original_model_tokens - self.consumed_model_tokens
        ):
            raise ValueError("Agent continuation model budget remainder mismatch")
        return self


class AgentContinuationCleanup(DomainModel):
    evidence_buffers_released: bool
    context_reverified: bool
    raw_provider_response_absent: bool
    no_tool_executed: bool
    no_vulnloom_domain_state_changed: bool

    @property
    def complete(self) -> bool:
        return all(
            (
                self.evidence_buffers_released,
                self.context_reverified,
                self.raw_provider_response_absent,
                self.no_tool_executed,
                self.no_vulnloom_domain_state_changed,
            )
        )


class AgentContinuationPlan(DomainModel):
    continuation_id: Digest
    root_plan: AgentRunPlan
    root_plan_digest: Digest
    root_outcome: AgentRunOutcome
    root_outcome_digest: Digest
    handoff_outcome: AgentToolHandoffOutcome
    handoff_outcome_digest: Digest
    observation_id: Digest
    context_snapshot: AgentContextSnapshot
    continuation_plan: AgentRunPlan
    continuation_plan_digest: Digest
    budget: AgentContinuationBudgetLedger
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_continuation(self) -> Self:
        root_task = self.root_plan.task
        continuation_task = self.continuation_plan.task
        observation = self.handoff_outcome.observation
        if self.root_plan_digest != canonical_digest(
            self.root_plan.model_dump(mode="python")
        ):
            raise ValueError("Agent continuation root plan digest mismatch")
        if self.root_outcome_digest != canonical_digest(
            self.root_outcome.model_dump(mode="python")
        ):
            raise ValueError("Agent continuation root outcome digest mismatch")
        if self.handoff_outcome_digest != agent_tool_handoff_outcome_digest(
            self.handoff_outcome
        ):
            raise ValueError("Agent continuation handoff outcome digest mismatch")
        if self.continuation_plan_digest != canonical_digest(
            self.continuation_plan.model_dump(mode="python")
        ):
            raise ValueError("Agent continuation run plan digest mismatch")
        if (
            root_task.worker_role is not WorkerRole.VALIDATOR
            or self.root_outcome.plan_id != self.root_plan.plan_id
            or self.root_outcome.task_id != root_task.task_id
            or self.root_outcome.status is not AgentRunStatus.TOOL_PROPOSED
            or self.root_outcome.tool_intent is None
            or not self.root_outcome.cleanup.complete
            or not self.root_outcome.cleanup.no_tool_executed
        ):
            raise ValueError("Agent continuation requires a clean Validator tool proposal")
        if (
            self.handoff_outcome.status is not AgentToolHandoffStatus.COMPLETED
            or observation is None
            or not self.handoff_outcome.cleanup.complete
            or self.handoff_outcome.agent_plan_id != self.root_plan.plan_id
            or self.handoff_outcome.agent_outcome_digest != self.root_outcome_digest
            or self.observation_id != observation.observation_id
        ):
            raise ValueError("Agent continuation requires the matching completed handoff")
        if (
            observation.task_id != root_task.task_id
            or observation.target_id != root_task.target_id
            or observation.target_version != root_task.target_version
            or observation.scope_id != root_task.scope_id
            or observation.scope_version != root_task.scope_version
        ):
            raise ValueError("Agent continuation Observation authority binding mismatch")
        inherited = (
            continuation_task.engagement_id == root_task.engagement_id
            and continuation_task.target_id == root_task.target_id
            and continuation_task.target_version == root_task.target_version
            and continuation_task.scope_id == root_task.scope_id
            and continuation_task.scope_version == root_task.scope_version
            and continuation_task.policy_digest == root_task.policy_digest
            and continuation_task.sandbox_profile_digest
            == root_task.sandbox_profile_digest
            and continuation_task.tool_registry_digest == root_task.tool_registry_digest
            and continuation_task.worker_role is WorkerRole.VALIDATOR
            and continuation_task.deadline == root_task.deadline
        )
        if not inherited or continuation_task.task_id == root_task.task_id:
            raise ValueError("Agent continuation Task authority binding mismatch")
        if (
            continuation_task.input_refs != agent_continuation_input_refs(
                self.observation_id, observation.evidence_refs
            )
            or continuation_task.allowed_tools
            or continuation_task.budget.tool_calls != 0
        ):
            raise ValueError("Agent continuation Task is not observation-only")
        consumed = self.root_outcome.input_tokens + self.root_outcome.output_tokens
        if (
            self.budget.original_model_tokens != root_task.budget.model_tokens
            or self.budget.consumed_model_tokens != consumed
            or self.budget.consumed_agent_steps != self.root_outcome.steps
            or self.budget.consumed_tool_calls
            != self.handoff_outcome.broker_result.tool_calls_used
            or self.budget.consumed_tool_calls > root_task.budget.tool_calls
            or continuation_task.budget.model_tokens != self.budget.remaining_model_tokens
            or continuation_task.budget.wall_seconds != self.budget.remaining_wall_seconds
            or self.budget.remaining_wall_seconds > root_task.budget.wall_seconds
            or self.budget.remaining_wall_seconds
            > int(
                (
                    min(self.root_plan.deadline, root_task.deadline)
                    - self.created_at
                ).total_seconds()
            )
        ):
            raise ValueError("Agent continuation cumulative budget binding mismatch")
        if (
            self.continuation_plan.model_registration_id
            != self.root_plan.model_registration_id
            or self.continuation_plan.model_registration_digest
            != self.root_plan.model_registration_digest
            or self.continuation_plan.limits.max_steps != 1
            or self.continuation_plan.limits.timeout_seconds
            > self.budget.remaining_wall_seconds
            or self.continuation_plan.deadline != self.root_plan.deadline
            or self.continuation_plan.created_at != self.created_at
            or self.deadline != self.continuation_plan.deadline
        ):
            raise ValueError("Agent continuation run authority binding mismatch")
        if not self.created_at < self.deadline:
            raise ValueError("Agent continuation validity window is invalid")
        self.context_snapshot.assert_for_task(continuation_task)
        if self.continuation_plan.context_snapshot_id != self.context_snapshot.snapshot_id:
            raise ValueError("Agent continuation context binding mismatch")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent continuation idempotency key contains NUL")
        if self.continuation_id != agent_continuation_plan_digest(self):
            raise ValueError("Agent continuation content digest mismatch")
        return self


def agent_continuation_plan_digest(plan: AgentContinuationPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"continuation_id"}))


def agent_continuation_input_refs(
    observation_id: str, evidence_refs: tuple[str, ...]
) -> tuple[str, ...]:
    return (f"agent-observation:{observation_id}",) + tuple(
        f"evidence:{item}" for item in evidence_refs
    )


class AgentContinuationOutcome(DomainModel):
    outcome_id: Digest
    continuation_id: Digest
    root_plan_id: Digest
    observation_id: Digest
    continuation_plan_id: Digest
    status: AgentContinuationStatus
    agent_outcome: AgentRunOutcome
    cleanup: AgentContinuationCleanup
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        expected = AgentContinuationStatus(self.agent_outcome.status.value)
        if self.status is not expected:
            raise ValueError("Agent continuation and Agent run statuses do not match")
        if self.agent_outcome.plan_id != self.continuation_plan_id:
            raise ValueError("Agent continuation run outcome binding mismatch")
        if self.agent_outcome.tool_intent is not None:
            raise ValueError("Agent continuation cannot emit a tool intent")
        if not self.cleanup.complete or not self.agent_outcome.cleanup.complete:
            raise ValueError("Agent continuation cleanup is incomplete")
        if self.outcome_id != agent_continuation_outcome_digest(self):
            raise ValueError("Agent continuation outcome content digest mismatch")
        return self


def agent_continuation_outcome_digest(outcome: AgentContinuationOutcome) -> str:
    return canonical_digest(outcome.model_dump(mode="python", exclude={"outcome_id"}))
