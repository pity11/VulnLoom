"""Fail-closed Agent tool-intent dispatch through the trusted Tool Broker."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.broker import BrokerRejected, ToolBroker
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalRequest

from .models import AgentRunStatus
from .store import AgentRunRecoveryRequired, AgentRunStore
from .tool_handoff_models import (
    AgentToolHandoffCleanup,
    AgentToolHandoffOutcome,
    AgentToolHandoffPlan,
    AgentToolHandoffStatus,
    agent_tool_intent_for_broker_call,
    agent_tool_observation_from_result,
)
from .tool_handoff_store import AgentToolHandoffStore


class AgentToolHandoffRejected(ValueError):
    pass


class AgentToolHandoffTimedOut(TimeoutError):
    pass


class AgentToolHandoffService:
    def __init__(
        self,
        *,
        agent_store: AgentRunStore,
        handoff_store: AgentToolHandoffStore,
        broker: ToolBroker,
    ):
        self.agent_store = agent_store
        self.handoff_store = handoff_store
        self.broker = broker

    def execute(
        self,
        plan: AgentToolHandoffPlan,
        *,
        now: datetime,
        approvals: tuple[ApprovalRequest, ...] = (),
    ) -> AgentToolHandoffOutcome:
        plan = self._preflight(plan, now=now)
        claim = self.handoff_store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        try:
            result = self.broker.execute(
                plan.broker_call,
                now=now,
                approvals=approvals,
            )
        except BrokerRejected as exc:
            raise AgentToolHandoffRejected(
                "Tool Broker rejected a previously validated handoff"
            ) from exc
        status = AgentToolHandoffStatus(result.status.value)
        observation = (
            agent_tool_observation_from_result(plan=plan, result=result, observed_at=now)
            if status is AgentToolHandoffStatus.COMPLETED
            else None
        )
        values = {
            "handoff_id": plan.handoff_id,
            "agent_plan_id": plan.agent_plan.plan_id,
            "agent_outcome_digest": plan.agent_outcome_digest,
            "broker_call_digest": plan.broker_call_digest,
            "attempt": plan.attempt,
            "status": status,
            "broker_result": result,
            "observation": observation,
            "cleanup": AgentToolHandoffCleanup(
                raw_agent_arguments_absent=True,
                raw_tool_response_absent=True,
                authorization_enforced=True,
                no_vulnloom_domain_state_changed=True,
            ),
            "completed_at": now,
        }
        digest_values = {
            **values,
            "broker_result": result.model_dump(mode="python"),
            "observation": (
                None if observation is None else observation.model_dump(mode="python")
            ),
            "cleanup": values["cleanup"].model_dump(mode="python"),
        }
        outcome = AgentToolHandoffOutcome(
            outcome_id=canonical_digest(digest_values), **values
        )
        self.handoff_store.complete(outcome)
        return outcome

    def _preflight(
        self, plan: AgentToolHandoffPlan, *, now: datetime
    ) -> AgentToolHandoffPlan:
        try:
            plan = AgentToolHandoffPlan.model_validate(plan.model_dump(mode="python"))
        except ValidationError as exc:
            raise AgentToolHandoffRejected(
                "Agent tool handoff failed boundary validation"
            ) from exc
        if (
            now < plan.created_at
            or now >= plan.deadline
            or now >= plan.agent_plan.task.deadline
            or (now - plan.created_at).total_seconds() >= plan.limits.timeout_seconds
        ):
            raise AgentToolHandoffTimedOut("Agent tool handoff is outside its wall budget")
        try:
            agent_outcome = self.agent_store.require_completed(plan.agent_plan)
        except AgentRunRecoveryRequired as exc:
            raise AgentToolHandoffRejected(
                "Agent tool handoff requires an authoritative completed Agent run"
            ) from exc
        if (
            canonical_digest(agent_outcome.model_dump(mode="python"))
            != plan.agent_outcome_digest
            or agent_outcome.status is not AgentRunStatus.TOOL_PROPOSED
            or agent_outcome.tool_intent is None
            or not agent_outcome.cleanup.complete
            or not agent_outcome.cleanup.no_tool_executed
            or agent_outcome.tool_intent
            != agent_tool_intent_for_broker_call(plan.broker_call)
        ):
            raise AgentToolHandoffRejected(
                "Agent outcome and typed Broker call commitment do not match"
            )
        try:
            self.broker.validate_call(plan.broker_call)
        except BrokerRejected as exc:
            raise AgentToolHandoffRejected(
                "Agent handoff Broker call failed static preflight"
            ) from exc
        return plan
