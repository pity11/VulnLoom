"""Pure Red Team Flow transitions; agent prose never changes state."""

from __future__ import annotations

from datetime import datetime

from .models import (
    ReconOutcome,
    RedTeamCheckpoint,
    RedTeamFlowPlan,
    RedTeamFlowStatus,
    RedTeamReconObservation,
)


class RedTeamTransitionRejected(ValueError):
    pass


TERMINAL_STATUSES = frozenset(
    {
        RedTeamFlowStatus.COMPLETED,
        RedTeamFlowStatus.CANCELLED,
        RedTeamFlowStatus.TIMED_OUT,
        RedTeamFlowStatus.FAILED,
        RedTeamFlowStatus.KILLED,
    }
)


def start_flow(
    plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint, *, now: datetime
) -> RedTeamCheckpoint:
    _current(plan, checkpoint)
    if checkpoint.status is not RedTeamFlowStatus.PLANNED:
        raise RedTeamTransitionRejected("Red Team Flow is not planned")
    if now >= plan.deadline:
        return _terminal(checkpoint, RedTeamFlowStatus.TIMED_OUT, "deadline_reached", now)
    return _next(checkpoint, status=RedTeamFlowStatus.RUNNING, now=now)


def record_observation(
    plan: RedTeamFlowPlan,
    checkpoint: RedTeamCheckpoint,
    observation: RedTeamReconObservation,
    *,
    now: datetime,
) -> RedTeamCheckpoint:
    _running(plan, checkpoint, now)
    if observation.observation_id in checkpoint.observation_ids:
        raise RedTeamTransitionRejected("Red Team observation is already recorded")
    used = checkpoint.actions_used + 1
    failures = (
        0
        if observation.outcome is ReconOutcome.SUCCEEDED
        else checkpoint.consecutive_failures + 1
    )
    values = {
        "actions_used": used,
        "consecutive_failures": failures,
        "observation_ids": (*checkpoint.observation_ids, observation.observation_id),
    }
    if not observation.cleanup_complete:
        return _terminal(
            checkpoint,
            RedTeamFlowStatus.FAILED,
            "cleanup_unproven",
            now,
            **values,
        )
    if observation.outcome is ReconOutcome.TIMED_OUT:
        return _terminal(
            checkpoint, RedTeamFlowStatus.TIMED_OUT, "action_timed_out", now, **values
        )
    if failures >= plan.rules.stop_conditions.max_consecutive_failures:
        return _terminal(
            checkpoint,
            RedTeamFlowStatus.FAILED,
            "failure_limit_reached",
            now,
            **values,
        )
    if used >= plan.rules.stop_conditions.max_actions:
        return _terminal(
            checkpoint,
            RedTeamFlowStatus.COMPLETED,
            "action_budget_reached",
            now,
            **values,
        )
    return _next(checkpoint, status=RedTeamFlowStatus.RUNNING, now=now, **values)


def cancel_flow(
    plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint, *, now: datetime
) -> RedTeamCheckpoint:
    _current(plan, checkpoint)
    if checkpoint.status in TERMINAL_STATUSES:
        raise RedTeamTransitionRejected("Red Team Flow is already terminal")
    return _terminal(checkpoint, RedTeamFlowStatus.CANCELLED, "operator_cancelled", now)


def activate_kill_switch(
    plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint, *, now: datetime
) -> RedTeamCheckpoint:
    _current(plan, checkpoint)
    if checkpoint.status in TERMINAL_STATUSES:
        raise RedTeamTransitionRejected("Red Team Flow is already terminal")
    return _terminal(checkpoint, RedTeamFlowStatus.KILLED, "kill_switch_activated", now)


def expire_flow(
    plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint, *, now: datetime
) -> RedTeamCheckpoint:
    _current(plan, checkpoint)
    if checkpoint.status in TERMINAL_STATUSES:
        return checkpoint
    if now < plan.deadline:
        raise RedTeamTransitionRejected("Red Team Flow deadline has not elapsed")
    return _terminal(checkpoint, RedTeamFlowStatus.TIMED_OUT, "deadline_reached", now)


def _running(plan, checkpoint, now):
    _current(plan, checkpoint)
    if checkpoint.status is not RedTeamFlowStatus.RUNNING:
        raise RedTeamTransitionRejected("Red Team Flow is not running")
    if now >= plan.deadline:
        raise RedTeamTransitionRejected("Red Team Flow deadline elapsed")


def _current(plan, checkpoint):
    if checkpoint.plan_id != plan.plan_id:
        raise RedTeamTransitionRejected("Red Team checkpoint does not belong to plan")


def _terminal(checkpoint, status, reason, now, **updates):
    return _next(
        checkpoint, status=status, stop_reason=reason, now=now, **updates
    )


def _next(checkpoint, *, status, now, stop_reason=None, **updates):
    values = {
        "plan_id": checkpoint.plan_id,
        "revision": checkpoint.revision + 1,
        "status": status,
        "actions_used": checkpoint.actions_used,
        "consecutive_failures": checkpoint.consecutive_failures,
        "observation_ids": checkpoint.observation_ids,
        "stop_reason": stop_reason,
        "updated_at": now,
        **updates,
    }
    return RedTeamCheckpoint.create(**values)
