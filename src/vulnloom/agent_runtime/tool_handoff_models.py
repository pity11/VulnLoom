"""Typed Agent-tool handoff contracts for the trusted Tool Broker boundary."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.broker.models import BrokerCall, BrokerResult, BrokerStatus, broker_call_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import WorkerRole
from vulnloom.runners.models import Digest, ToolInvocation, WorkingDirectory, invocation_digest

from .models import AgentRunOutcome, AgentRunPlan, AgentRunStatus, AgentToolIntent


class AgentToolHandoffStatus(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class AgentToolHandoffLimits(DomainModel):
    max_attempts: int = Field(default=2, ge=2, le=2)
    timeout_seconds: float = Field(default=60.0, gt=0, le=120)


class AgentToolObservation(DomainModel):
    observation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    handoff_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_id: UUID
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    tool_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    broker_result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status_code: int = Field(ge=100, le=599)
    final_url_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_bytes: int = Field(ge=0, le=20 * 1024 * 1024)
    response_body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=64)]
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_observation(self) -> Self:
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("Agent tool Observation evidence refs must be unique and sorted")
        if self.observation_id != agent_tool_observation_digest(self):
            raise ValueError("Agent tool Observation content digest mismatch")
        return self


def agent_tool_observation_digest(observation: AgentToolObservation) -> str:
    return canonical_digest(observation.model_dump(mode="python", exclude={"observation_id"}))


class AgentToolHandoffCleanup(DomainModel):
    raw_agent_arguments_absent: bool
    raw_tool_response_absent: bool
    authorization_enforced: bool
    no_vulnloom_domain_state_changed: bool

    @property
    def complete(self) -> bool:
        return all(
            (
                self.raw_agent_arguments_absent,
                self.raw_tool_response_absent,
                self.authorization_enforced,
                self.no_vulnloom_domain_state_changed,
            )
        )


class AgentToolHandoffPlan(DomainModel):
    handoff_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_plan: AgentRunPlan
    agent_plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_outcome_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    broker_call: BrokerCall
    broker_call_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    call_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_intent_invocation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    attempt: int = Field(default=1, ge=1, le=2)
    previous_handoff_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    limits: AgentToolHandoffLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_handoff(self) -> Self:
        expected_intent = agent_tool_intent_for_broker_call(self.broker_call)
        if self.agent_plan_digest != canonical_digest(
            self.agent_plan.model_dump(mode="python")
        ):
            raise ValueError("Agent handoff plan digest mismatch")
        if self.broker_call_digest != broker_call_digest(self.broker_call):
            raise ValueError("Agent handoff Broker call digest mismatch")
        if self.call_commitment != agent_broker_call_commitment(self.broker_call):
            raise ValueError("Agent handoff call commitment mismatch")
        if self.expected_intent_invocation_digest != expected_intent.invocation_digest:
            raise ValueError("Agent handoff intent commitment mismatch")
        if self.broker_call.task != self.agent_plan.task:
            raise ValueError("Agent handoff Broker task does not match the Agent plan")
        if self.agent_plan.task.worker_role is not WorkerRole.VALIDATOR:
            raise ValueError("Agent tool handoff is restricted to Validator Workers")
        if self.broker_call.tool_id not in self.agent_plan.task.allowed_tools:
            raise ValueError("Agent handoff tool is not allowed by the Agent task")
        if not self.created_at < self.deadline <= self.agent_plan.task.deadline:
            raise ValueError("Agent handoff validity window is invalid")
        if (self.attempt == 1) != (self.previous_handoff_id is None):
            raise ValueError("Agent handoff retry chain shape mismatch")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent handoff idempotency key contains NUL")
        if self.handoff_id != agent_tool_handoff_plan_digest(self):
            raise ValueError("Agent tool handoff content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        agent_plan: AgentRunPlan,
        agent_outcome: AgentRunOutcome,
        broker_call: BrokerCall,
        limits: AgentToolHandoffLimits,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
        attempt: int = 1,
        previous_handoff_id: str | None = None,
    ) -> AgentToolHandoffPlan:
        if (
            agent_outcome.plan_id != agent_plan.plan_id
            or agent_outcome.task_id != agent_plan.task.task_id
            or agent_outcome.status is not AgentRunStatus.TOOL_PROPOSED
            or agent_outcome.tool_intent is None
        ):
            raise ValueError("Agent handoff requires a matching tool-proposed outcome")
        expected_intent = agent_tool_intent_for_broker_call(broker_call)
        values = {
            "agent_plan": agent_plan,
            "agent_plan_digest": canonical_digest(agent_plan.model_dump(mode="python")),
            "agent_outcome_digest": canonical_digest(agent_outcome.model_dump(mode="python")),
            "broker_call": broker_call,
            "broker_call_digest": broker_call_digest(broker_call),
            "call_commitment": agent_broker_call_commitment(broker_call),
            "expected_intent_invocation_digest": expected_intent.invocation_digest,
            "attempt": attempt,
            "previous_handoff_id": previous_handoff_id,
            "limits": limits,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "agent_plan": agent_plan.model_dump(mode="python"),
            "broker_call": broker_call.model_dump(mode="python"),
            "limits": limits.model_dump(mode="python"),
        }
        return cls(handoff_id=canonical_digest(digest_values), **values)


def agent_tool_handoff_plan_digest(plan: AgentToolHandoffPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"handoff_id"}))


class AgentToolHandoffOutcome(DomainModel):
    outcome_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    handoff_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_plan_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_outcome_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    broker_call_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    attempt: int = Field(ge=1, le=2)
    status: AgentToolHandoffStatus
    broker_result: BrokerResult
    observation: AgentToolObservation | None = None
    cleanup: AgentToolHandoffCleanup
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        expected_status = AgentToolHandoffStatus(self.broker_result.status.value)
        if self.status is not expected_status:
            raise ValueError("Agent handoff and Broker statuses do not match")
        if (self.status is AgentToolHandoffStatus.COMPLETED) != (
            self.observation is not None
        ):
            raise ValueError("completed Agent handoff requires exactly one Observation")
        if not self.cleanup.complete:
            raise ValueError("Agent tool handoff cleanup is incomplete")
        if self.observation is not None and self.observation.handoff_id != self.handoff_id:
            raise ValueError("Agent tool Observation handoff binding mismatch")
        if self.broker_result.call_digest != self.broker_call_digest:
            raise ValueError("Agent handoff Broker result call binding mismatch")
        if self.observation is not None:
            assert self.broker_result.http is not None
            if (
                self.observation.task_id != self.broker_result.task_id
                or self.observation.tool_id != self.broker_result.tool_id
                or self.observation.broker_result_digest
                != canonical_digest(self.broker_result.model_dump(mode="python"))
                or self.observation.status_code != self.broker_result.http.status_code
                or self.observation.final_url_digest
                != self.broker_result.http.final_url_digest
                or self.observation.response_bytes != self.broker_result.http.response_bytes
                or self.observation.response_body_sha256
                != self.broker_result.http.response_body_sha256
                or self.observation.evidence_refs
                != tuple(sorted(set(self.broker_result.http.evidence_refs)))
            ):
                raise ValueError("Agent tool Observation Broker result binding mismatch")
        if self.outcome_id != agent_tool_handoff_outcome_digest(self):
            raise ValueError("Agent tool handoff outcome content digest mismatch")
        return self


def agent_tool_handoff_outcome_digest(outcome: AgentToolHandoffOutcome) -> str:
    return canonical_digest(outcome.model_dump(mode="python", exclude={"outcome_id"}))


def agent_broker_call_commitment(call: BrokerCall) -> str:
    return canonical_digest(
        {
            "contract": "vulnloom.agent-broker-call.v1",
            "task": call.task.model_dump(mode="python"),
            "profile": call.profile.model_dump(mode="python"),
            "tool_id": call.tool_id,
            "http": call.http.model_dump(mode="python"),
        }
    )


def agent_tool_intent_for_broker_call(call: BrokerCall) -> AgentToolIntent:
    commitment = agent_broker_call_commitment(call)
    invocation = ToolInvocation(
        tool_id=call.tool_id,
        arguments=(commitment,),
        working_directory=WorkingDirectory.SOURCE,
    )
    return AgentToolIntent(
        tool_id=call.tool_id,
        invocation_digest=invocation_digest(invocation),
        argument_digests=(canonical_digest(commitment),),
        working_directory=WorkingDirectory.SOURCE,
    )


def agent_tool_observation_from_result(
    *,
    plan: AgentToolHandoffPlan,
    result: BrokerResult,
    observed_at: datetime,
) -> AgentToolObservation:
    if result.status is not BrokerStatus.COMPLETED or result.http is None:
        raise ValueError("only a completed Broker result can become an Agent tool Observation")
    values = {
        "handoff_id": plan.handoff_id,
        "task_id": plan.agent_plan.task.task_id,
        "target_id": plan.agent_plan.task.target_id,
        "target_version": plan.agent_plan.task.target_version,
        "scope_id": plan.agent_plan.task.scope_id,
        "scope_version": plan.agent_plan.task.scope_version,
        "tool_id": result.tool_id,
        "broker_result_digest": canonical_digest(result.model_dump(mode="python")),
        "status_code": result.http.status_code,
        "final_url_digest": result.http.final_url_digest,
        "response_bytes": result.http.response_bytes,
        "response_body_sha256": result.http.response_body_sha256,
        "evidence_refs": tuple(sorted(set(result.http.evidence_refs))),
        "observed_at": observed_at,
    }
    return AgentToolObservation(observation_id=canonical_digest(values), **values)
