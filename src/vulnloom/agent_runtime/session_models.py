"""Sealed contracts for one fixed, two-tool Agent session."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.broker.models import (
    BrokerCall,
    HttpMethod,
    HttpRequestPlan,
    broker_call_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskEnvelope, WorkerRole
from vulnloom.runners.models import Digest, SandboxProfile, ToolId

from .context import AgentContextSnapshot
from .continuation_models import AgentContinuationOutcome
from .models import AgentRunOutcome, AgentRunPlan, AgentRunStatus
from .tool_handoff_models import (
    AgentToolHandoffOutcome,
    AgentToolHandoffStatus,
    agent_broker_call_commitment,
    agent_tool_handoff_outcome_digest,
    agent_tool_intent_for_broker_call,
)


class AgentSessionStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class AgentSessionLimits(DomainModel):
    max_tool_rounds: int = Field(default=2, ge=2, le=2)
    max_provider_turns: int = Field(default=3, ge=3, le=3)
    max_authorized_calls_per_round: int = Field(default=8, ge=1, le=8)


class AgentSessionCallTemplate(DomainModel):
    template_id: Digest
    profile: SandboxProfile
    tool_id: ToolId
    http: HttpRequestPlan
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_read_only_template(self) -> Self:
        if self.http.method not in {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS}:
            raise ValueError("Agent session call templates must remain read-only")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent session call template idempotency key contains NUL")
        if self.template_id != agent_session_call_template_digest(self):
            raise ValueError("Agent session call template content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        profile: SandboxProfile,
        tool_id: str,
        http: HttpRequestPlan,
        idempotency_key: str,
    ) -> AgentSessionCallTemplate:
        values = {
            "profile": profile,
            "tool_id": tool_id,
            "http": http,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "profile": profile.model_dump(mode="python"),
            "http": http.model_dump(mode="python"),
        }
        return cls(template_id=canonical_digest(digest_values), **values)


def agent_session_call_template_digest(template: AgentSessionCallTemplate) -> str:
    return canonical_digest(template.model_dump(mode="python", exclude={"template_id"}))


class AgentAuthorizedCallOption(DomainModel):
    call_commitment: Digest
    broker_call_digest: Digest
    broker_call: BrokerCall

    @model_validator(mode="after")
    def exact_call(self) -> Self:
        if self.call_commitment != agent_broker_call_commitment(self.broker_call):
            raise ValueError("Agent authorized call commitment mismatch")
        if self.broker_call_digest != broker_call_digest(self.broker_call):
            raise ValueError("Agent authorized Broker call digest mismatch")
        if self.broker_call.http.method not in {
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
        }:
            raise ValueError("Agent authorized Broker call must remain read-only")
        return self


class AgentAuthorizedCallSet(DomainModel):
    call_set_id: Digest
    round_index: int = Field(default=2, ge=2, le=2)
    task_id: UUID
    task_digest: Digest
    options: Annotated[tuple[AgentAuthorizedCallOption, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def sealed_call_set(self) -> Self:
        commitments = tuple(item.call_commitment for item in self.options)
        if commitments != tuple(sorted(set(commitments))):
            raise ValueError("Agent authorized call commitments must be unique and sorted")
        for option in self.options:
            if (
                option.broker_call.task.task_id != self.task_id
                or canonical_digest(option.broker_call.task.model_dump(mode="python"))
                != self.task_digest
            ):
                raise ValueError("Agent authorized call Task binding mismatch")
        if self.call_set_id != agent_authorized_call_set_digest(self):
            raise ValueError("Agent authorized call set content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        task: TaskEnvelope,
        templates: tuple[AgentSessionCallTemplate, ...],
    ) -> AgentAuthorizedCallSet:
        options = []
        for template in templates:
            call = BrokerCall(
                task=task,
                profile=template.profile,
                tool_id=template.tool_id,
                http=template.http,
                idempotency_key=template.idempotency_key,
            )
            options.append(
                AgentAuthorizedCallOption(
                    call_commitment=agent_broker_call_commitment(call),
                    broker_call_digest=broker_call_digest(call),
                    broker_call=call,
                )
            )
        ordered = tuple(sorted(options, key=lambda item: item.call_commitment))
        values = {
            "round_index": 2,
            "task_id": task.task_id,
            "task_digest": canonical_digest(task.model_dump(mode="python")),
            "options": ordered,
        }
        digest_values = {
            **values,
            "options": tuple(item.model_dump(mode="python") for item in ordered),
        }
        return cls(call_set_id=canonical_digest(digest_values), **values)


def agent_authorized_call_set_digest(call_set: AgentAuthorizedCallSet) -> str:
    return canonical_digest(call_set.model_dump(mode="python", exclude={"call_set_id"}))


class AgentSessionBudgetLedger(DomainModel):
    original_model_tokens: int = Field(gt=0)
    original_tool_calls: int = Field(ge=2, le=2)
    consumed_model_tokens: int = Field(ge=0)
    remaining_model_tokens: int = Field(ge=0)
    consumed_agent_steps: int = Field(ge=1, le=24)
    consumed_tool_calls: int = Field(ge=1, le=2)
    remaining_tool_calls: int = Field(ge=0)
    provider_attempts: int = Field(ge=1, le=3)
    broker_attempts: int = Field(ge=1, le=3)
    remaining_wall_seconds: int = Field(ge=0, le=86_400)

    @model_validator(mode="after")
    def exact_remainders(self) -> Self:
        if self.consumed_model_tokens > self.original_model_tokens or (
            self.remaining_model_tokens
            != self.original_model_tokens - self.consumed_model_tokens
        ):
            raise ValueError("Agent session model budget remainder mismatch")
        if self.consumed_tool_calls > self.original_tool_calls or (
            self.remaining_tool_calls
            != self.original_tool_calls - self.consumed_tool_calls
        ):
            raise ValueError("Agent session tool budget remainder mismatch")
        return self


class AgentSessionCleanup(DomainModel):
    evidence_buffers_released: bool
    context_reverified: bool
    raw_provider_responses_absent: bool
    broker_authorization_enforced: bool
    no_vulnloom_domain_state_changed: bool

    @property
    def complete(self) -> bool:
        return all(self.model_dump(mode="python").values())


class AgentSessionPlan(DomainModel):
    session_id: Digest
    root_plan: AgentRunPlan
    root_plan_digest: Digest
    root_outcome: AgentRunOutcome
    root_outcome_digest: Digest
    first_handoff_outcome: AgentToolHandoffOutcome
    first_handoff_outcome_digest: Digest
    first_observation_id: Digest
    context_snapshot: AgentContextSnapshot
    round_plan: AgentRunPlan
    round_plan_digest: Digest
    authorized_calls: AgentAuthorizedCallSet
    budget: AgentSessionBudgetLedger
    limits: AgentSessionLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_session(self) -> Self:
        root_task = self.root_plan.task
        round_task = self.round_plan.task
        observation = self.first_handoff_outcome.observation
        if self.root_plan_digest != canonical_digest(self.root_plan.model_dump(mode="python")):
            raise ValueError("Agent session root plan digest mismatch")
        if self.root_outcome_digest != canonical_digest(
            self.root_outcome.model_dump(mode="python")
        ):
            raise ValueError("Agent session root outcome digest mismatch")
        if self.first_handoff_outcome_digest != agent_tool_handoff_outcome_digest(
            self.first_handoff_outcome
        ):
            raise ValueError("Agent session first handoff digest mismatch")
        if self.round_plan_digest != canonical_digest(self.round_plan.model_dump(mode="python")):
            raise ValueError("Agent session round plan digest mismatch")
        if (
            root_task.worker_role is not WorkerRole.VALIDATOR
            or self.root_outcome.status is not AgentRunStatus.TOOL_PROPOSED
            or self.root_outcome.plan_id != self.root_plan.plan_id
            or self.root_outcome.tool_intent is None
            or not self.root_outcome.cleanup.complete
            or self.first_handoff_outcome.status is not AgentToolHandoffStatus.COMPLETED
            or observation is None
            or not self.first_handoff_outcome.cleanup.complete
            or self.first_handoff_outcome.agent_plan_id != self.root_plan.plan_id
            or self.first_handoff_outcome.agent_outcome_digest != self.root_outcome_digest
            or self.first_observation_id != observation.observation_id
            or observation.task_id != root_task.task_id
            or observation.target_id != root_task.target_id
            or observation.target_version != root_task.target_version
            or observation.scope_id != root_task.scope_id
            or observation.scope_version != root_task.scope_version
        ):
            raise ValueError("Agent session requires one authoritative completed tool round")
        inherited = (
            round_task.engagement_id == root_task.engagement_id
            and round_task.target_id == root_task.target_id
            and round_task.target_version == root_task.target_version
            and round_task.scope_id == root_task.scope_id
            and round_task.scope_version == root_task.scope_version
            and round_task.policy_digest == root_task.policy_digest
            and round_task.sandbox_profile_digest == root_task.sandbox_profile_digest
            and round_task.tool_registry_digest == root_task.tool_registry_digest
            and round_task.worker_role is WorkerRole.VALIDATOR
            and round_task.deadline == root_task.deadline
            and round_task.task_id != root_task.task_id
        )
        if not inherited:
            raise ValueError("Agent session round Task authority binding mismatch")
        expected_refs = (f"agent-observation:{observation.observation_id}",) + tuple(
            f"evidence:{item}" for item in observation.evidence_refs
        )
        if (
            round_task.input_refs != expected_refs
            or round_task.budget.tool_calls != 1
            or self.authorized_calls.task_id != round_task.task_id
            or self.authorized_calls.task_digest
            != canonical_digest(round_task.model_dump(mode="python"))
            or self.round_plan.authorized_call_set_id != self.authorized_calls.call_set_id
            or self.round_plan.authorized_call_commitments
            != tuple(item.call_commitment for item in self.authorized_calls.options)
        ):
            raise ValueError("Agent session authorized round binding mismatch")
        for option in self.authorized_calls.options:
            if (
                option.broker_call.tool_id not in round_task.allowed_tools
                or agent_tool_intent_for_broker_call(option.broker_call)
                == self.root_outcome.tool_intent
            ):
                raise ValueError("Agent session call is unauthorized or repeats the first round")
        consumed = self.root_outcome.input_tokens + self.root_outcome.output_tokens
        if (
            self.budget.original_model_tokens != root_task.budget.model_tokens
            or self.budget.original_tool_calls != root_task.budget.tool_calls
            or self.budget.consumed_model_tokens != consumed
            or self.budget.remaining_model_tokens != round_task.budget.model_tokens
            or self.budget.consumed_agent_steps != self.root_outcome.steps
            or self.budget.consumed_tool_calls
            != self.first_handoff_outcome.broker_result.tool_calls_used
            or self.budget.remaining_tool_calls < 1
            or self.budget.provider_attempts != 1
            or self.budget.broker_attempts != 1
            or round_task.budget.wall_seconds != self.budget.remaining_wall_seconds
        ):
            raise ValueError("Agent session cumulative budget binding mismatch")
        if (
            self.round_plan.model_registration_id != self.root_plan.model_registration_id
            or self.round_plan.model_registration_digest
            != self.root_plan.model_registration_digest
            or self.round_plan.limits.max_steps != 1
            or self.round_plan.context_snapshot_id != self.context_snapshot.snapshot_id
            or self.round_plan.deadline
            != min(self.root_plan.deadline, root_task.deadline)
            or self.deadline != min(self.root_plan.deadline, root_task.deadline)
            or self.created_at != self.round_plan.created_at
            or len(self.authorized_calls.options)
            > self.limits.max_authorized_calls_per_round
            or not self.created_at < self.deadline
        ):
            raise ValueError("Agent session execution binding mismatch")
        self.context_snapshot.assert_for_task(round_task)
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent session idempotency key contains NUL")
        if self.session_id != agent_session_plan_digest(self):
            raise ValueError("Agent session content digest mismatch")
        return self


def agent_session_plan_digest(plan: AgentSessionPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"session_id"}))


class AgentSessionOutcome(DomainModel):
    outcome_id: Digest
    session_id: Digest
    root_plan_id: Digest
    first_observation_id: Digest
    round_plan_id: Digest
    authorized_call_set_id: Digest
    status: AgentSessionStatus
    round_agent_outcome: AgentRunOutcome
    selected_call_commitment: Digest | None = None
    selected_broker_call_digest: Digest | None = None
    approval_handoff_outcome: AgentToolHandoffOutcome | None = None
    second_handoff_outcome: AgentToolHandoffOutcome | None = None
    terminal_continuation: AgentContinuationOutcome | None = None
    budget: AgentSessionBudgetLedger
    cleanup: AgentSessionCleanup
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        if self.round_agent_outcome.plan_id != self.round_plan_id:
            raise ValueError("Agent session round outcome binding mismatch")
        if (self.selected_call_commitment is None) != (
            self.selected_broker_call_digest is None
        ):
            raise ValueError("Agent session selected call binding is incomplete")
        if not self.cleanup.complete or not self.round_agent_outcome.cleanup.complete:
            raise ValueError("Agent session cleanup is incomplete")
        if self.second_handoff_outcome is None:
            if self.terminal_continuation is not None:
                raise ValueError("Agent session terminal continuation requires a handoff")
            if self.round_agent_outcome.status is AgentRunStatus.TOOL_PROPOSED:
                if self.status is not AgentSessionStatus.FAILED:
                    raise ValueError("Unmatched Agent session tool proposal must fail")
            elif self.status.value != self.round_agent_outcome.status.value:
                raise ValueError("Agent session terminal status mismatch")
        else:
            handoff = self.second_handoff_outcome
            commitment_handoff = self.approval_handoff_outcome or handoff
            if (
                self.round_agent_outcome.status is not AgentRunStatus.TOOL_PROPOSED
                or self.selected_call_commitment is None
                or self.selected_broker_call_digest
                != commitment_handoff.broker_call_digest
                or handoff.agent_plan_id != self.round_plan_id
            ):
                raise ValueError("Agent session second handoff binding mismatch")
            if handoff.status is AgentToolHandoffStatus.COMPLETED:
                if (
                    handoff.observation is None
                    or handoff.observation.observation_id == self.first_observation_id
                    or self.terminal_continuation is None
                    or self.status.value != self.terminal_continuation.status.value
                ):
                    raise ValueError("Agent session terminal continuation binding mismatch")
            elif (
                self.terminal_continuation is not None
                or self.status.value != handoff.status.value
            ):
                raise ValueError("Agent session non-completed handoff status mismatch")
        if self.approval_handoff_outcome is not None:
            approval_handoff = self.approval_handoff_outcome
            if (
                approval_handoff.status
                is not AgentToolHandoffStatus.APPROVAL_REQUIRED
                or approval_handoff.attempt != 1
                or self.second_handoff_outcome is None
                or self.second_handoff_outcome.attempt != 2
                or approval_handoff.agent_outcome_digest
                != self.second_handoff_outcome.agent_outcome_digest
            ):
                raise ValueError("Agent session Approval retry chain mismatch")
        outcomes = [self.round_agent_outcome]
        if self.terminal_continuation is not None:
            outcomes.append(self.terminal_continuation.agent_outcome)
        expected_tokens = sum(item.input_tokens + item.output_tokens for item in outcomes)
        if self.budget.provider_attempts != 1 + len(outcomes):
            raise ValueError("Agent session provider attempt ledger mismatch")
        if self.budget.broker_attempts != 1 + int(
            self.second_handoff_outcome is not None
        ) + int(self.approval_handoff_outcome is not None):
            raise ValueError("Agent session Broker attempt ledger mismatch")
        if self.outcome_id != agent_session_outcome_digest(self):
            raise ValueError("Agent session outcome content digest mismatch")
        if expected_tokens > self.budget.consumed_model_tokens:
            raise ValueError("Agent session consumed token ledger is incomplete")
        return self


def agent_session_outcome_digest(outcome: AgentSessionOutcome) -> str:
    return canonical_digest(outcome.model_dump(mode="python", exclude={"outcome_id"}))
