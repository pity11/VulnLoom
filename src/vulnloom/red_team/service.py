"""Trusted application service for the offline-first Authorized Red Team slice."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.policy import ActionRequest, DecisionEffect, PolicyEngine
from vulnloom.workflows import (
    AutonomyLevel,
    ExecutionProfile,
    Visibility,
    WorkflowKind,
    WorkflowMode,
)

from .models import (
    AuthorizedWebTarget,
    ImpactClass,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamCheckpoint,
    RedTeamFlowPlan,
    RedTeamFlowStatus,
    RedTeamPhase,
    RedTeamReconAction,
    RedTeamReconCommand,
    RedTeamReconObservation,
    RedTeamStopConditions,
    RulesOfEngagement,
)
from .state_machine import (
    activate_kill_switch,
    cancel_flow,
    expire_flow,
    record_observation,
    start_flow,
)
from .store import RedTeamStore


class RedTeamRejected(ValueError):
    pass


class RedTeamAdapterInterrupted(RuntimeError):
    pass


class RedTeamReconAdapter(Protocol):
    """Network credentials and transports remain behind this trusted boundary."""

    def execute(
        self, action: RedTeamReconAction, *, now: datetime
    ) -> RedTeamReconObservation: ...


@dataclass(frozen=True, slots=True)
class OfflineReconScenario:
    outcome: ReconOutcome = ReconOutcome.SUCCEEDED
    status_code: int | None = 204
    reason_code: str = "offline_recon_succeeded"
    cleanup_complete: bool = True
    interrupt: bool = False


class OfflineRedTeamReconAdapter:
    """Deterministic no-network adapter used by CLI and default tests."""

    def __init__(self, scenario: OfflineReconScenario | None = None):
        self.scenario = scenario or OfflineReconScenario()
        self.calls = 0

    def execute(self, action, *, now):
        self.calls += 1
        if self.scenario.interrupt:
            raise RedTeamAdapterInterrupted("offline Recon adapter interrupted")
        return RedTeamReconObservation.create(
            action_id=action.action_id,
            outcome=self.scenario.outcome,
            status_code=self.scenario.status_code,
            reason_code=self.scenario.reason_code,
            cleanup_complete=self.scenario.cleanup_complete,
            sensitive_data_redacted=True,
            observed_at=now,
        )


class RedTeamService:
    def __init__(self, *, store: RedTeamStore):
        self.store = store

    def prepare(
        self,
        *,
        scope: Scope,
        target_url: str,
        visibility: Visibility,
        allowed_test_classes: tuple[str, ...],
        max_actions: int,
        max_consecutive_failures: int,
        emergency_contact_ref: str,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> RedTeamFlowPlan:
        self._scope(scope, now)
        canonical_target = AuthorizedWebTarget(url=target_url)
        target = canonical_target.model_copy(
            update={
                "target_id": uuid5(
                    NAMESPACE_URL,
                    f"vulnloom:red-team-target:{scope.scope_id}:{canonical_target.url}",
                )
            }
        )
        classes = tuple(sorted(set(allowed_test_classes)))
        if (
            not classes
            or classes != allowed_test_classes
            or not set(classes) <= set(scope.allowed_test_classes)
        ):
            raise RedTeamRejected("Red Team test classes exceed approved Scope")
        policy = PolicyEngine(scope).decide(
            ActionRequest(
                engagement_id=scope.engagement_id,
                target_id=target.target_id,
                action="red_team.flow.prepare",
                requested_at=now,
                url=target.url,
                test_class=classes[0] if classes else None,
            )
        )
        if policy.effect is not DecisionEffect.ALLOW:
            raise RedTeamRejected("Red Team target is outside approved Scope")
        stop_at = min(deadline, scope.valid_until)
        rules = RulesOfEngagement.create(
            scope_id=scope.scope_id,
            scope_version=scope.version,
            target_id=target.target_id,
            phases=(RedTeamPhase.RECON,),
            allowed_test_classes=classes,
            allowed_impacts=(ImpactClass.READ_ONLY,),
            approval_required_impacts=(),
            prohibited_impacts=tuple(
                item for item in ImpactClass if item is not ImpactClass.READ_ONLY
            ),
            stop_conditions=RedTeamStopConditions(
                stop_at=stop_at,
                max_actions=max_actions,
                max_consecutive_failures=max_consecutive_failures,
            ),
            emergency_contact_ref=emergency_contact_ref,
        )
        return RedTeamFlowPlan.create(
            mode=WorkflowMode(
                workflow=WorkflowKind.AUTHORIZED_RED_TEAM,
                visibility=visibility,
                execution_profile=ExecutionProfile.RED_TEAM,
                autonomy=AutonomyLevel.BOUNDED_EXECUTION,
            ),
            target=target,
            rules=rules,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def create_and_start(
        self, plan: RedTeamFlowPlan, *, scope: Scope, now: datetime
    ) -> RedTeamCheckpoint:
        self._preflight_plan(plan, scope, now)
        existing = self.store.plan_by_key(plan.idempotency_key)
        if existing is not None:
            if existing != plan:
                raise RedTeamRejected("Red Team idempotency collision")
            checkpoint = self.store.latest(plan.plan_id)
            if checkpoint.status is RedTeamFlowStatus.PLANNED:
                running = start_flow(plan, checkpoint, now=now)
                return self.store.advance(checkpoint, running)
            return checkpoint
        planned = RedTeamCheckpoint.create(
            plan_id=plan.plan_id,
            revision=0,
            status=RedTeamFlowStatus.PLANNED,
            actions_used=0,
            consecutive_failures=0,
            observation_ids=(),
            updated_at=now,
        )
        self.store.create(plan, planned)
        running = start_flow(plan, planned, now=now)
        return self.store.advance(planned, running)

    def prepare_recon(
        self,
        *,
        plan: RedTeamFlowPlan,
        checkpoint: RedTeamCheckpoint,
        scope: Scope,
        kind: RedTeamActionKind,
        test_class: str,
        now: datetime,
        ttl_seconds: int,
        idempotency_key: str,
        attempt: int = 1,
    ) -> RedTeamReconCommand:
        self._preflight_running(plan, checkpoint, scope, now)
        if test_class not in plan.rules.allowed_test_classes:
            raise RedTeamRejected("Red Team Recon test class is not authorized")
        if not 0 < ttl_seconds <= 300:
            raise RedTeamRejected("Red Team Recon TTL is invalid")
        action = RedTeamReconAction.create(
            plan_id=plan.plan_id,
            expected_checkpoint_id=checkpoint.checkpoint_id,
            kind=kind,
            target_url=plan.target.url,
            test_class=test_class,
            created_at=now,
            deadline=min(now + timedelta(seconds=ttl_seconds), plan.deadline),
            idempotency_key=idempotency_key,
        )
        return RedTeamReconCommand.create(action=action, attempt=attempt)

    def execute_recon(
        self,
        *,
        command: RedTeamReconCommand,
        scope: Scope,
        adapter: RedTeamReconAdapter,
        now: datetime,
    ) -> tuple[RedTeamCheckpoint, RedTeamReconObservation]:
        plan = self.store.plan(command.action.plan_id)
        checkpoint = self.store.latest(plan.plan_id)
        action = command.action
        self._scope_binding(plan, scope)
        if (
            action.target_url != plan.target.url
            or action.test_class not in plan.rules.allowed_test_classes
            or action.deadline > plan.deadline
        ):
            raise RedTeamRejected("Red Team Recon action binding is invalid")
        replay = self.store.completed_action(command)
        if replay is not None:
            return checkpoint, replay
        self._preflight_running(plan, checkpoint, scope, now)
        if action.expected_checkpoint_id != checkpoint.checkpoint_id or now >= action.deadline:
            raise RedTeamRejected("Red Team Recon action binding is invalid")
        decision = PolicyEngine(scope).decide(
            ActionRequest(
                engagement_id=scope.engagement_id,
                target_id=plan.target.target_id,
                action=f"red_team.recon.{action.kind.value}",
                requested_at=now,
                url=action.target_url,
                test_class=action.test_class,
            )
        )
        if decision.effect is not DecisionEffect.ALLOW:
            raise RedTeamRejected("Red Team Recon was denied by Scope policy")
        replay = self.store.claim_action(command)
        if replay is not None:
            return self.store.latest(plan.plan_id), replay
        try:
            observation = adapter.execute(action, now=now)
        except RedTeamAdapterInterrupted:
            if command.attempt < 3:
                raise
            observation = RedTeamReconObservation.create(
                action_id=action.action_id,
                outcome=ReconOutcome.FAILED,
                status_code=None,
                reason_code="adapter_attempts_exhausted",
                cleanup_complete=False,
                sensitive_data_redacted=True,
                observed_at=now,
            )
        if (
            observation.action_id != action.action_id
            or not action.created_at <= observation.observed_at < action.deadline
            or (
                action.kind is RedTeamActionKind.HTTP_HEAD
                and observation.outcome is ReconOutcome.SUCCEEDED
                and (
                    observation.status_code is None
                    or observation.service_identity is not None
                )
            )
            or (
                action.kind is RedTeamActionKind.TLS_INSPECT
                and observation.outcome is ReconOutcome.SUCCEEDED
                and (
                    observation.status_code is not None
                    or observation.service_identity is None
                    or observation.attack_surface is not None
                )
            )
        ):
            raise RedTeamRejected("Red Team Recon observation provenance is invalid")
        advanced = record_observation(
            plan, checkpoint, observation, now=observation.observed_at
        )
        return self.store.complete_action(command, checkpoint, advanced, observation), observation

    def cancel(
        self, plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint, *, scope: Scope, now: datetime
    ) -> RedTeamCheckpoint:
        self._scope_binding(plan, scope)
        return self.store.advance(checkpoint, cancel_flow(plan, checkpoint, now=now))

    def kill(
        self, plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint, *, scope: Scope, now: datetime
    ) -> RedTeamCheckpoint:
        self._scope_binding(plan, scope)
        return self.store.advance(
            checkpoint, activate_kill_switch(plan, checkpoint, now=now)
        )

    def expire(
        self, plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint, *, now: datetime
    ) -> RedTeamCheckpoint:
        expired = expire_flow(plan, checkpoint, now=now)
        return checkpoint if expired == checkpoint else self.store.advance(checkpoint, expired)

    @staticmethod
    def _scope(scope: Scope, now: datetime) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise RedTeamRejected("Red Team requires a currently approved Scope")

    def _scope_binding(self, plan, scope):
        expected_prohibited = {
            item for item in ImpactClass if item is not ImpactClass.READ_ONLY
        }
        if (
            plan.rules.scope_id != scope.scope_id
            or plan.rules.scope_version != scope.version
            or plan.deadline > scope.valid_until
            or plan.rules.stop_conditions.stop_at > scope.valid_until
            or plan.rules.phases != (RedTeamPhase.RECON,)
            or plan.rules.allowed_impacts != (ImpactClass.READ_ONLY,)
            or plan.rules.approval_required_impacts
            or set(plan.rules.prohibited_impacts) != expected_prohibited
            or not set(plan.rules.allowed_test_classes) <= set(
                scope.allowed_test_classes
            )
        ):
            raise RedTeamRejected("Red Team plan no longer matches Scope")

    def _preflight_plan(self, plan, scope, now):
        self._scope(scope, now)
        self._scope_binding(plan, scope)
        if now >= plan.deadline:
            raise RedTeamRejected("Red Team plan no longer matches Scope")
        decision = PolicyEngine(scope).decide(
            ActionRequest(
                engagement_id=scope.engagement_id,
                target_id=plan.target.target_id,
                action="red_team.flow.start",
                requested_at=now,
                url=plan.target.url,
                test_class=plan.rules.allowed_test_classes[0],
            )
        )
        if decision.effect is not DecisionEffect.ALLOW:
            raise RedTeamRejected("Red Team plan target is outside approved Scope")

    def _preflight_running(self, plan, checkpoint, scope, now):
        self._preflight_plan(plan, scope, now)
        authoritative = self.store.latest(plan.plan_id)
        if authoritative != checkpoint or checkpoint.status is not RedTeamFlowStatus.RUNNING:
            raise RedTeamRejected("Red Team checkpoint is stale or not running")
