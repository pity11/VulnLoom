"""Trusted R11 application service for a sealed, approval-bound Attack Graph."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    Scope,
    ScopeState,
)
from vulnloom.policy import ActionRequest, DecisionEffect, PolicyEngine

from .attack_models import (
    AttackAction,
    AttackActionAuditRecord,
    AttackActionAuthorization,
    AttackActionCommand,
    AttackActionObservation,
    AttackActionOutcome,
    AttackAuditDecision,
    AttackChainCheckpoint,
    AttackChainPlan,
    AttackChainStatus,
    AttackGraph,
    AttackImpact,
    AttackNodeProgress,
)
from .attack_state_machine import (
    record_attack_observation,
    start_attack_chain,
    stop_attack_chain,
)
from .attack_store import AttackChainStore
from .models import ImpactClass, RedTeamFlowPlan, RedTeamFlowStatus
from .store import RedTeamStore


class AttackChainRejected(ValueError):
    pass


class AttackActionAdapterInterrupted(RuntimeError):
    pass


class AttackActionAdapter(Protocol):
    """Payloads, transport, and test identity material stay behind this boundary."""

    def execute(
        self, command: AttackActionCommand, action: AttackAction, *, now: datetime
    ) -> AttackActionObservation: ...


@dataclass(frozen=True, slots=True)
class OfflineAttackScenario:
    outcome: AttackActionOutcome = AttackActionOutcome.SUCCEEDED
    reason_code: str = "offline_action_succeeded"
    cleanup_complete: bool = True
    interrupt: bool = False


class OfflineAttackActionAdapter:
    """No-network adapter for deterministic control-plane tests."""

    def __init__(self, scenario: OfflineAttackScenario | None = None):
        self.scenario = scenario or OfflineAttackScenario()
        self.calls = 0

    def execute(
        self, command: AttackActionCommand, action: AttackAction, *, now: datetime
    ) -> AttackActionObservation:
        self.calls += 1
        if self.scenario.interrupt:
            raise AttackActionAdapterInterrupted("offline Attack Action interrupted")
        succeeded = self.scenario.outcome is AttackActionOutcome.SUCCEEDED
        return AttackActionObservation.create(
            command_id=command.command_id,
            action_id=action.action_id,
            outcome=self.scenario.outcome,
            reason_code=self.scenario.reason_code,
            evidence_refs=(("e" * 64,) if succeeded else ()),
            goal_reached=succeeded and action.kind.value == "verify_objective",
            cleanup_complete=self.scenario.cleanup_complete,
            sensitive_data_redacted=True,
            observed_at=now,
        )


class AttackChainService:
    def __init__(self, *, flow_store: RedTeamStore, chain_store: AttackChainStore) -> None:
        self.flow_store = flow_store
        self.chain_store = chain_store

    def prepare(
        self,
        *,
        flow_plan: RedTeamFlowPlan,
        flow_checkpoint_id: str,
        graph: AttackGraph,
        scope: Scope,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AttackChainPlan:
        checkpoint = self._flow_preflight(flow_plan, flow_checkpoint_id, graph, scope, now)
        if (
            graph.flow_plan_id != flow_plan.plan_id
            or graph.target_id != flow_plan.target.target_id
            or graph.scope_id != scope.scope_id
            or graph.scope_version != scope.version
            or checkpoint.actions_used + len(graph.actions)
            > flow_plan.rules.stop_conditions.max_actions
            or any(
                action.test_class not in flow_plan.rules.allowed_test_classes
                for action in graph.actions
            )
            or deadline > flow_plan.deadline
        ):
            raise AttackChainRejected("Attack Graph exceeds its sealed Flow boundary")
        return AttackChainPlan.create(
            graph=graph,
            expected_flow_checkpoint_id=flow_checkpoint_id,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def create_and_start(
        self, plan: AttackChainPlan, *, scope: Scope, now: datetime
    ) -> AttackChainCheckpoint:
        flow_plan = self.flow_store.plan(plan.graph.flow_plan_id)
        self._flow_preflight(
            flow_plan,
            plan.expected_flow_checkpoint_id,
            plan.graph,
            scope,
            now,
        )
        planned = AttackChainCheckpoint.create(
            chain_plan_id=plan.chain_plan_id,
            revision=0,
            status=AttackChainStatus.PLANNED,
            nodes=tuple(
                AttackNodeProgress(action_id=action.action_id) for action in plan.graph.actions
            ),
            failures=0,
            updated_at=now,
        )
        current = self.chain_store.create(plan, planned)
        if current.status is AttackChainStatus.PLANNED:
            running = start_attack_chain(plan, current, now=now)
            return self.chain_store.advance(current, running)
        return current

    def authorization(
        self,
        *,
        plan: AttackChainPlan,
        action: AttackAction,
        scope: Scope,
        now: datetime,
    ) -> AttackActionAuthorization:
        flow_plan = self.flow_store.plan(plan.graph.flow_plan_id)
        self._flow_preflight(
            flow_plan,
            plan.expected_flow_checkpoint_id,
            plan.graph,
            scope,
            now,
        )
        if action not in plan.graph.actions:
            raise AttackChainRejected("Attack Action is absent from the sealed graph")
        request = self._policy_request(plan, action, scope, now)
        required = set(scope.approval_requirements)
        if action.impact is AttackImpact.STATE_CHANGE:
            required.add(ApprovalAction.MUTATE_TARGET_STATE)
        return AttackActionAuthorization.create(
            chain_plan_id=plan.chain_plan_id,
            action_id=action.action_id,
            execution_approval_digest=action.action_id,
            policy_action_digest=request.digest(),
            required_policy_approvals=tuple(sorted(required, key=str)),
        )

    def command(
        self,
        *,
        plan: AttackChainPlan,
        checkpoint: AttackChainCheckpoint,
        action: AttackAction,
        attempt: int = 1,
    ) -> AttackActionCommand:
        if checkpoint.chain_plan_id != plan.chain_plan_id or action not in plan.graph.actions:
            raise AttackChainRejected("Attack Action command binding is invalid")
        return AttackActionCommand.create(
            chain_plan_id=plan.chain_plan_id,
            expected_checkpoint_id=checkpoint.checkpoint_id,
            action_id=action.action_id,
            attempt=attempt,
        )

    def execute(
        self,
        *,
        command: AttackActionCommand,
        scope: Scope,
        approvals: tuple[ApprovalRequest, ...],
        adapter: AttackActionAdapter,
        now: datetime,
    ) -> tuple[AttackChainCheckpoint, AttackActionObservation]:
        plan = self.chain_store.plan(command.chain_plan_id)
        checkpoint = self.chain_store.latest(plan.chain_plan_id)
        action = next(
            (item for item in plan.graph.actions if item.action_id == command.action_id),
            None,
        )
        if action is None:
            raise AttackChainRejected("Attack Action is absent from the sealed graph")
        replay = self.chain_store.completed(command)
        if replay is not None:
            return checkpoint, replay
        try:
            self._execute_preflight(plan, checkpoint, command, action, scope, now)
            authorization = self.authorization(plan=plan, action=action, scope=scope, now=now)
            execution_approval = next(
                (
                    approval
                    for approval in approvals
                    if approval.engagement_id == scope.engagement_id
                    and approval.target_id == plan.graph.target_id
                    and approval.policy_version == scope.version
                    and approval.is_valid_for(
                        action=ApprovalAction.EXECUTE_RED_TEAM_ACTION,
                        digest=action.action_id,
                        now=now,
                    )
                ),
                None,
            )
            if execution_approval is None:
                raise AttackChainRejected("Attack Action lacks its exact execution Approval")
            policy_request = self._policy_request(plan, action, scope, now)
            if policy_request.digest() != authorization.policy_action_digest:
                raise AttackChainRejected("Attack Action policy digest drifted")
            decision = PolicyEngine(scope).decide(policy_request, approvals)
            if decision.effect is not DecisionEffect.ALLOW:
                raise AttackChainRejected("Attack Action lacks required policy Approval")
        except AttackChainRejected as exc:
            self._audit(
                plan,
                checkpoint,
                action,
                AttackAuditDecision.REJECTED,
                self._reason(exc),
                approvals,
                now,
            )
            raise

        self._audit(
            plan,
            checkpoint,
            action,
            AttackAuditDecision.ALLOWED,
            "approval_and_policy_satisfied",
            approvals,
            now,
        )
        replay = self.chain_store.claim(command)
        if replay is not None:
            return self.chain_store.latest(plan.chain_plan_id), replay
        try:
            observation = adapter.execute(command, action, now=now)
        except AttackActionAdapterInterrupted:
            if command.attempt < 2:
                raise
            observation = AttackActionObservation.create(
                command_id=command.command_id,
                action_id=action.action_id,
                outcome=AttackActionOutcome.FAILED,
                reason_code="adapter_attempts_exhausted",
                cleanup_complete=False,
                sensitive_data_redacted=True,
                observed_at=now,
            )
        if (
            observation.command_id != command.command_id
            or observation.action_id != action.action_id
            or not plan.created_at <= observation.observed_at < plan.deadline
            or observation.goal_reached
            != (
                action == plan.graph.actions[-1]
                and observation.outcome is AttackActionOutcome.SUCCEEDED
            )
        ):
            if command.attempt < 2:
                raise AttackActionAdapterInterrupted(
                    "Attack Action observation provenance is invalid"
                )
            observation = AttackActionObservation.create(
                command_id=command.command_id,
                action_id=action.action_id,
                outcome=AttackActionOutcome.FAILED,
                reason_code="observation_provenance_invalid",
                cleanup_complete=False,
                sensitive_data_redacted=True,
                observed_at=now,
            )
        advanced = record_attack_observation(
            plan, checkpoint, action, observation, now=observation.observed_at
        )
        return (
            self.chain_store.complete(command, checkpoint, advanced, observation),
            observation,
        )

    def _execute_preflight(
        self,
        plan: AttackChainPlan,
        checkpoint: AttackChainCheckpoint,
        command: AttackActionCommand,
        action: AttackAction,
        scope: Scope,
        now: datetime,
    ) -> None:
        flow_plan = self.flow_store.plan(plan.graph.flow_plan_id)
        try:
            self._flow_preflight(
                flow_plan,
                plan.expected_flow_checkpoint_id,
                plan.graph,
                scope,
                now,
            )
        except AttackChainRejected:
            latest = self.flow_store.latest(flow_plan.plan_id)
            if latest.status is RedTeamFlowStatus.KILLED:
                stopped = stop_attack_chain(
                    plan,
                    checkpoint,
                    reason="flow_kill_switch_activated",
                    now=now,
                )
                if stopped != checkpoint:
                    self.chain_store.advance(checkpoint, stopped)
            raise
        if (
            checkpoint.status is not AttackChainStatus.RUNNING
            or command.expected_checkpoint_id != checkpoint.checkpoint_id
            or now >= plan.deadline
        ):
            raise AttackChainRejected("Attack Chain checkpoint is stale or terminal")
        progress = {node.action_id: node for node in checkpoint.nodes}
        if any(
            progress[item].status.value != "succeeded" for item in action.prerequisite_action_ids
        ):
            raise AttackChainRejected("Attack Action prerequisites are incomplete")
        earlier_pending = any(
            item.ordinal < action.ordinal and progress[item.action_id].status.value == "pending"
            for item in plan.graph.actions
        )
        if earlier_pending:
            raise AttackChainRejected("Attack Action sequence cannot be skipped")

    def _flow_preflight(
        self,
        flow_plan: RedTeamFlowPlan,
        flow_checkpoint_id: str,
        graph: AttackGraph,
        scope: Scope,
        now: datetime,
    ):
        checkpoint = self.flow_store.latest(flow_plan.plan_id)
        prohibited = {
            ImpactClass.REAL_CREDENTIAL,
            ImpactClass.EXTERNAL_CALLBACK,
            ImpactClass.LATERAL_MOVEMENT,
            ImpactClass.PERSISTENCE,
        }
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or flow_plan.rules.scope_id != scope.scope_id
            or flow_plan.rules.scope_version != scope.version
            or checkpoint.checkpoint_id != flow_checkpoint_id
            or checkpoint.status is not RedTeamFlowStatus.RUNNING
            or flow_plan.rules.approval_required_impacts != (ImpactClass.STATE_CHANGE,)
            or set(flow_plan.rules.prohibited_impacts) != prohibited
            or graph.flow_plan_id != flow_plan.plan_id
            or graph.target_id != flow_plan.target.target_id
            or graph.scope_id != scope.scope_id
            or graph.scope_version != scope.version
        ):
            raise AttackChainRejected("Attack Chain Flow boundary is invalid or stopped")
        return checkpoint

    def _policy_request(
        self,
        plan: AttackChainPlan,
        action: AttackAction,
        scope: Scope,
        now: datetime,
    ) -> ActionRequest:
        flow_plan = self.flow_store.plan(plan.graph.flow_plan_id)
        base = urlsplit(flow_plan.target.url)
        url = urlunsplit((base.scheme, base.netloc, action.target_path, "", ""))
        return ActionRequest(
            engagement_id=scope.engagement_id,
            target_id=plan.graph.target_id,
            action=f"red_team.attack.{action.kind.value}",
            requested_at=now,
            url=url,
            test_class=action.test_class,
            mutates_state=action.impact is AttackImpact.STATE_CHANGE,
        )

    def _audit(
        self,
        plan: AttackChainPlan,
        checkpoint: AttackChainCheckpoint,
        action: AttackAction,
        decision: AttackAuditDecision,
        reason: str,
        approvals: tuple[ApprovalRequest, ...],
        now: datetime,
    ) -> None:
        record = AttackActionAuditRecord.create(
            chain_plan_id=plan.chain_plan_id,
            action_id=action.action_id,
            checkpoint_id=checkpoint.checkpoint_id,
            decision=decision,
            reason_code=reason,
            approval_ids=tuple(sorted((item.approval_id for item in approvals), key=str)),
            recorded_at=now,
        )
        self.chain_store.append_audit(record)

    @staticmethod
    def _reason(exc: AttackChainRejected) -> str:
        message = str(exc)
        if "execution Approval" in message:
            return "execution_approval_missing"
        if "policy Approval" in message:
            return "policy_approval_missing"
        if "prerequisites" in message or "sequence" in message:
            return "prerequisite_incomplete"
        if "stale or terminal" in message:
            return "checkpoint_invalid"
        return "flow_boundary_rejected"
