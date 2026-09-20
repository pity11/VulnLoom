"""Pure R11 Attack Chain transitions."""

from __future__ import annotations

from datetime import datetime

from .attack_models import (
    AttackAction,
    AttackActionObservation,
    AttackActionOutcome,
    AttackChainCheckpoint,
    AttackChainPlan,
    AttackChainStatus,
    AttackNodeProgress,
    AttackNodeStatus,
)


class AttackChainTransitionRejected(ValueError):
    pass


def start_attack_chain(
    plan: AttackChainPlan, checkpoint: AttackChainCheckpoint, *, now: datetime
) -> AttackChainCheckpoint:
    _current(plan, checkpoint)
    if checkpoint.status is not AttackChainStatus.PLANNED:
        raise AttackChainTransitionRejected("Attack Chain is not planned")
    if now >= plan.deadline:
        return _next(
            checkpoint,
            status=AttackChainStatus.TIMED_OUT,
            stop_reason="deadline_reached",
            now=now,
        )
    return _next(checkpoint, status=AttackChainStatus.RUNNING, now=now)


def record_attack_observation(
    plan: AttackChainPlan,
    checkpoint: AttackChainCheckpoint,
    action: AttackAction,
    observation: AttackActionObservation,
    *,
    now: datetime,
) -> AttackChainCheckpoint:
    _running(plan, checkpoint, now)
    progress_by_id = {node.action_id: node for node in checkpoint.nodes}
    progress = progress_by_id.get(action.action_id)
    if progress is None or progress.status is not AttackNodeStatus.PENDING:
        raise AttackChainTransitionRejected("Attack Action is not pending")
    compensating_cleanup = (
        checkpoint.status is AttackChainStatus.CLEANUP_REQUIRED
        and action.kind.value == "cleanup_test_session"
    )
    if not compensating_cleanup and any(
        progress_by_id[item].status is not AttackNodeStatus.SUCCEEDED
        for item in action.prerequisite_action_ids
    ):
        raise AttackChainTransitionRejected("Attack Action prerequisites are incomplete")
    if observation.action_id != action.action_id:
        raise AttackChainTransitionRejected("Attack Action observation is misbound")

    node_status = {
        AttackActionOutcome.SUCCEEDED: AttackNodeStatus.SUCCEEDED,
        AttackActionOutcome.REJECTED: AttackNodeStatus.FAILED,
        AttackActionOutcome.FAILED: AttackNodeStatus.FAILED,
        AttackActionOutcome.TIMED_OUT: AttackNodeStatus.TIMED_OUT,
    }[observation.outcome]
    nodes = tuple(
        AttackNodeProgress(
            action_id=node.action_id,
            status=node_status,
            observation_id=observation.observation_id,
        )
        if node.action_id == action.action_id
        else node
        for node in checkpoint.nodes
    )
    failures = checkpoint.failures + int(observation.outcome is not AttackActionOutcome.SUCCEEDED)
    updates = {"nodes": nodes, "failures": failures}
    is_cleanup_action = action.kind.value == "cleanup_test_session"
    if is_cleanup_action:
        updates["deferred_outcome"] = None
    if observation.outcome is not AttackActionOutcome.SUCCEEDED and not is_cleanup_action:
        return _next(
            checkpoint,
            status=AttackChainStatus.CLEANUP_REQUIRED,
            deferred_outcome=observation.outcome,
            now=now,
            **updates,
        )
    if not observation.cleanup_complete:
        return _next(
            checkpoint,
            status=AttackChainStatus.FAILED,
            stop_reason="cleanup_unproven",
            now=now,
            **updates,
        )
    if observation.outcome is not AttackActionOutcome.SUCCEEDED:
        reason = "failure_limit_reached" if failures >= plan.max_failures else "action_failed"
        return _next(
            checkpoint,
            status=AttackChainStatus.FAILED,
            stop_reason=reason,
            now=now,
            **updates,
        )
    is_goal_action = action.kind.value == "verify_objective"
    if observation.goal_reached != is_goal_action:
        raise AttackChainTransitionRejected("Attack Objective evidence is inconsistent")
    if is_goal_action:
        updates["objective_observation_id"] = observation.observation_id
    if is_cleanup_action:
        if checkpoint.deferred_outcome is not None:
            timed_out = checkpoint.deferred_outcome is AttackActionOutcome.TIMED_OUT
            return _next(
                checkpoint,
                status=(AttackChainStatus.TIMED_OUT if timed_out else AttackChainStatus.FAILED),
                stop_reason=(
                    "action_timed_out_after_cleanup" if timed_out else "action_failed_after_cleanup"
                ),
                now=now,
                **updates,
            )
        if checkpoint.objective_observation_id is None:
            raise AttackChainTransitionRejected("Attack Chain Cleanup lacks objective evidence")
        return _next(
            checkpoint,
            status=AttackChainStatus.GOAL_REACHED,
            stop_reason="objective_evidence_and_cleanup_recorded",
            now=now,
            **updates,
        )
    return _next(checkpoint, status=AttackChainStatus.RUNNING, now=now, **updates)


def stop_attack_chain(
    plan: AttackChainPlan,
    checkpoint: AttackChainCheckpoint,
    *,
    reason: str,
    now: datetime,
) -> AttackChainCheckpoint:
    _current(plan, checkpoint)
    if checkpoint.status not in {
        AttackChainStatus.RUNNING,
        AttackChainStatus.CLEANUP_REQUIRED,
    }:
        return checkpoint
    return _next(
        checkpoint,
        status=AttackChainStatus.KILLED,
        stop_reason=reason,
        deferred_outcome=None,
        now=now,
    )


def _current(plan: AttackChainPlan, checkpoint: AttackChainCheckpoint) -> None:
    if checkpoint.chain_plan_id != plan.chain_plan_id:
        raise AttackChainTransitionRejected("Attack Chain checkpoint is misbound")


def _running(plan: AttackChainPlan, checkpoint: AttackChainCheckpoint, now: datetime) -> None:
    _current(plan, checkpoint)
    if checkpoint.status not in {
        AttackChainStatus.RUNNING,
        AttackChainStatus.CLEANUP_REQUIRED,
    }:
        raise AttackChainTransitionRejected("Attack Chain is not running")
    if now >= plan.deadline:
        raise AttackChainTransitionRejected("Attack Chain deadline elapsed")


def _next(
    checkpoint: AttackChainCheckpoint,
    *,
    status: AttackChainStatus,
    now: datetime,
    stop_reason: str | None = None,
    **updates: object,
) -> AttackChainCheckpoint:
    values: dict[str, object] = {
        "chain_plan_id": checkpoint.chain_plan_id,
        "nodes": checkpoint.nodes,
        "objective_observation_id": checkpoint.objective_observation_id,
        "deferred_outcome": checkpoint.deferred_outcome,
        "failures": checkpoint.failures,
    }
    values.update(updates)
    return AttackChainCheckpoint.create(
        **values,
        revision=checkpoint.revision + 1,
        status=status,
        stop_reason=stop_reason,
        updated_at=now,
    )
