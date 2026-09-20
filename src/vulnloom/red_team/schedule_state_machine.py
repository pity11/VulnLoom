"""Pure lifecycle transitions for recurring Endpoint checks."""

from __future__ import annotations

from datetime import datetime, timedelta

from .schedule_models import (
    EndpointCheckSchedule,
    EndpointScheduleCheckpoint,
    EndpointScheduleRun,
    EndpointScheduleRunState,
    EndpointScheduleState,
)


class EndpointScheduleTransitionRejected(ValueError):
    pass


def start_endpoint_schedule(
    schedule: EndpointCheckSchedule,
) -> EndpointScheduleCheckpoint:
    return EndpointScheduleCheckpoint.create(
        schedule_id=schedule.schedule_id,
        revision=0,
        state=EndpointScheduleState.ACTIVE,
        next_due_at=schedule.active_from,
        updated_at=schedule.created_at,
    )


def claim_endpoint_schedule_run(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    *,
    now: datetime,
) -> tuple[EndpointScheduleCheckpoint, EndpointScheduleRun]:
    _current(schedule, checkpoint, now)
    if checkpoint.state is not EndpointScheduleState.ACTIVE:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule is not active")
    if checkpoint.active_run_id is not None:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule already has an active run")
    if now < checkpoint.next_due_at:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule is not due")
    run = EndpointScheduleRun.create(
        schedule_id=schedule.schedule_id,
        scheduled_for=checkpoint.next_due_at,
        state=EndpointScheduleRunState.STARTED,
        attempt=1,
        started_at=now,
        deadline=min(
            now + timedelta(seconds=schedule.run_ttl_seconds), schedule.active_until
        ),
    )
    return (
        _next(checkpoint, now=now, active_run_id=run.schedule_run_id),
        run,
    )


def recover_endpoint_schedule_run(
    run: EndpointScheduleRun, *, now: datetime
) -> EndpointScheduleRun:
    if run.state is not EndpointScheduleRunState.STARTED:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule Run is not awaiting recovery")
    if now < run.started_at or now >= run.deadline:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule Run recovery window elapsed")
    if run.attempt >= 3:
        raise EndpointScheduleTransitionRejected(
            "Endpoint Schedule Run recovery attempts are exhausted"
        )
    return _replace_run(run, attempt=run.attempt + 1)


def materialize_endpoint_schedule_run(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    run: EndpointScheduleRun,
    *,
    flow_plan_id: str,
    seed_set_id: str,
    endpoint_recon_plan_id: str,
    now: datetime,
) -> tuple[EndpointScheduleCheckpoint, EndpointScheduleRun]:
    _active_run(schedule, checkpoint, run, now)
    completed = _replace_run(
        run,
        state=EndpointScheduleRunState.MATERIALIZED,
        flow_plan_id=flow_plan_id,
        seed_set_id=seed_set_id,
        endpoint_recon_plan_id=endpoint_recon_plan_id,
        cleanup_complete=True,
        terminal_reason="flow_materialized",
        completed_at=now,
    )
    return _finish(schedule, checkpoint, completed, now=now, pause_reason=None)


def timeout_endpoint_schedule_run(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    run: EndpointScheduleRun,
    *,
    cleanup_complete: bool,
    now: datetime,
) -> tuple[EndpointScheduleCheckpoint, EndpointScheduleRun]:
    if now < run.deadline:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule Run deadline has not elapsed")
    _active_run(schedule, checkpoint, run, now, allow_deadline=True)
    timed_out = _replace_run(
        run,
        state=EndpointScheduleRunState.TIMED_OUT,
        cleanup_complete=cleanup_complete,
        terminal_reason="materialization_timed_out",
        completed_at=now,
    )
    return _finish(
        schedule,
        checkpoint,
        timed_out,
        now=now,
        pause_reason=None if cleanup_complete else "cleanup_unproven",
    )


def fail_endpoint_schedule_run(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    run: EndpointScheduleRun,
    *,
    cleanup_complete: bool,
    now: datetime,
) -> tuple[EndpointScheduleCheckpoint, EndpointScheduleRun]:
    _active_run(schedule, checkpoint, run, now, allow_deadline=True)
    failed = _replace_run(
        run,
        state=EndpointScheduleRunState.FAILED,
        cleanup_complete=cleanup_complete,
        terminal_reason="materialization_attempts_exhausted",
        completed_at=now,
    )
    return _finish(
        schedule,
        checkpoint,
        failed,
        now=now,
        pause_reason="materialization_attempts_exhausted",
    )


def pause_endpoint_schedule(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    *,
    now: datetime,
) -> EndpointScheduleCheckpoint:
    _current(schedule, checkpoint, now)
    if checkpoint.state is EndpointScheduleState.PAUSED:
        return checkpoint
    if checkpoint.state is not EndpointScheduleState.ACTIVE or checkpoint.active_run_id:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule cannot be paused")
    return _next(
        checkpoint,
        now=now,
        state=EndpointScheduleState.PAUSED,
        reason_code="operator_paused",
    )


def resume_endpoint_schedule(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    *,
    now: datetime,
) -> EndpointScheduleCheckpoint:
    _current(schedule, checkpoint, now)
    if checkpoint.state is EndpointScheduleState.ACTIVE:
        return checkpoint
    if checkpoint.state is not EndpointScheduleState.PAUSED:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule is not paused")
    return _next(
        checkpoint,
        now=now,
        state=EndpointScheduleState.ACTIVE,
        next_due_at=_next_due(schedule, checkpoint.next_due_at, now),
        reason_code=None,
    )


def cancel_endpoint_schedule(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    *,
    now: datetime,
) -> EndpointScheduleCheckpoint:
    _current(schedule, checkpoint, now, allow_window_end=True)
    if checkpoint.state in {EndpointScheduleState.CANCELLED, EndpointScheduleState.EXPIRED}:
        return checkpoint
    if checkpoint.active_run_id is not None:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule has an active run")
    return _next(
        checkpoint,
        now=now,
        state=EndpointScheduleState.CANCELLED,
        reason_code="operator_cancelled",
    )


def expire_endpoint_schedule(
    schedule: EndpointCheckSchedule,
    checkpoint: EndpointScheduleCheckpoint,
    *,
    now: datetime,
) -> EndpointScheduleCheckpoint:
    if now < checkpoint.updated_at:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule time is invalid")
    if now < schedule.active_until:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule window has not elapsed")
    _identity(schedule, checkpoint)
    if checkpoint.state is EndpointScheduleState.EXPIRED:
        return checkpoint
    if checkpoint.active_run_id is not None:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule has an active run")
    if checkpoint.state is EndpointScheduleState.CANCELLED:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule is cancelled")
    return _next(
        checkpoint,
        now=now,
        state=EndpointScheduleState.EXPIRED,
        reason_code="schedule_window_elapsed",
    )


def _finish(schedule, checkpoint, run, *, now, pause_reason):
    state = (
        EndpointScheduleState.PAUSED
        if pause_reason is not None
        else EndpointScheduleState.ACTIVE
    )
    return (
        _next(
            checkpoint,
            now=now,
            state=state,
            next_due_at=_next_due(schedule, run.scheduled_for, now),
            active_run_id=None,
            last_run_id=run.schedule_run_id,
            reason_code=pause_reason,
        ),
        run,
    )


def _next_due(schedule, previous_due, now):
    elapsed = max(0.0, (now - previous_due).total_seconds())
    steps = int(elapsed // schedule.interval_seconds) + 1
    return previous_due + timedelta(seconds=schedule.interval_seconds * steps)


def _active_run(schedule, checkpoint, run, now, *, allow_deadline=False):
    _current(schedule, checkpoint, now, allow_window_end=allow_deadline)
    if (
        checkpoint.active_run_id != run.schedule_run_id
        or run.schedule_id != schedule.schedule_id
        or run.state is not EndpointScheduleRunState.STARTED
        or (not allow_deadline and now >= run.deadline)
    ):
        raise EndpointScheduleTransitionRejected("Endpoint Schedule active run is inconsistent")


def _current(schedule, checkpoint, now, *, allow_window_end=False):
    _identity(schedule, checkpoint)
    if now < checkpoint.updated_at or now < schedule.active_from:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule time is invalid")
    if not allow_window_end and now >= schedule.active_until:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule window elapsed")


def _identity(schedule, checkpoint):
    if checkpoint.schedule_id != schedule.schedule_id:
        raise EndpointScheduleTransitionRejected("Endpoint Schedule checkpoint is foreign")


def _next(checkpoint, *, now, **changes):
    values = checkpoint.model_dump(mode="python", exclude={"checkpoint_id"})
    values.update(changes)
    values["revision"] = checkpoint.revision + 1
    values["updated_at"] = now
    return EndpointScheduleCheckpoint.create(**values)


def _replace_run(run, **changes):
    values = run.model_dump(mode="python", exclude={"schedule_run_id"})
    values.update(changes)
    return EndpointScheduleRun.create(**values)
