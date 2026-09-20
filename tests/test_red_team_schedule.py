from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.cli import main
from vulnloom.domain.models import ScopeState
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    EndpointReconLimits,
    EndpointReconReservationState,
    EndpointReconService,
    EndpointReconStore,
    RedTeamFlowStatus,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.red_team.schedule_models import (
    EndpointCheckSchedule,
    EndpointScheduleRunState,
    EndpointScheduleState,
)
from vulnloom.red_team.schedule_service import (
    EndpointScheduleMaterializationInterrupted,
    EndpointScheduleRejected,
    EndpointScheduleService,
)
from vulnloom.red_team.schedule_store import EndpointScheduleStore
from vulnloom.workflows import Visibility


def _runtime(tmp_path):
    red_store = RedTeamStore(tmp_path / "red-team.sqlite3")
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    endpoint_service = EndpointReconService(
        red_team_store=red_store,
        recon_store=recon_store,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
    )
    schedule_store = EndpointScheduleStore(tmp_path / "endpoint-schedule.sqlite3")
    service = EndpointScheduleService(
        schedule_store=schedule_store,
        red_team_store=red_store,
        recon_store=recon_store,
        endpoint_service=endpoint_service,
    )
    return service, schedule_store, red_store, recon_store, endpoint_service


def _schedule(tmp_path, approved_scope, now, *, service_type=EndpointScheduleService):
    base, schedule_store, red_store, recon_store, endpoint_service = _runtime(tmp_path)
    service = service_type(
        schedule_store=schedule_store,
        red_team_store=red_store,
        recon_store=recon_store,
        endpoint_service=endpoint_service,
    )
    schedule, checkpoint = service.create(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        test_class="read_only",
        operator_ref="operator:alice",
        emergency_contact_ref="contact:security-owner",
        paths=("/health", "/ready"),
        interval_seconds=60,
        run_ttl_seconds=30,
        max_consecutive_failures=2,
        recon_limits=EndpointReconLimits(
            max_steps=2,
            max_requests=2,
            per_request_seconds=2,
            total_seconds=20,
        ),
        active_from=now,
        active_until=now + timedelta(minutes=5),
        now=now,
        idempotency_key="schedule:exact-endpoints",
    )
    del base
    return (
        service,
        schedule_store,
        red_store,
        recon_store,
        endpoint_service,
        schedule,
        checkpoint,
    )


def _close(schedule_store, red_store, recon_store):
    schedule_store.close()
    red_store.close()
    recon_store.close()


def test_schedule_materializes_exact_flow_without_dispatch_and_replays(
    tmp_path, approved_scope, now
):
    service, schedule_store, red_store, recon_store, _, schedule, checkpoint = _schedule(
        tmp_path, approved_scope, now
    )
    assert checkpoint.state is EndpointScheduleState.ACTIVE
    replayed_schedule, replayed_checkpoint = service.create(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        test_class="read_only",
        operator_ref="operator:alice",
        emergency_contact_ref="contact:security-owner",
        paths=("/health", "/ready"),
        interval_seconds=60,
        run_ttl_seconds=30,
        max_consecutive_failures=2,
        recon_limits=schedule.recon_limits,
        active_from=now + timedelta(seconds=1),
        active_until=now + timedelta(minutes=5, seconds=1),
        now=now + timedelta(seconds=1),
        idempotency_key="schedule:exact-endpoints",
    )
    assert replayed_schedule == schedule
    assert replayed_checkpoint == checkpoint
    claim = service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    assert claim.created
    assert claim.run.state is EndpointScheduleRunState.MATERIALIZED
    assert claim.run.cleanup_complete
    assert claim.checkpoint.active_run_id is None
    assert claim.checkpoint.next_due_at == now + timedelta(seconds=60)

    flow = red_store.plan(claim.run.flow_plan_id)
    endpoint_plan = recon_store.plan(claim.run.endpoint_recon_plan_id)
    seed_set = recon_store.seed_set(claim.run.seed_set_id)
    assert red_store.latest(flow.plan_id).status is RedTeamFlowStatus.RUNNING
    assert red_store.latest(flow.plan_id).actions_used == 0
    assert tuple(seed.path for seed in seed_set.seeds) == ("/health", "/ready")
    assert tuple(step.method for step in endpoint_plan.steps) == ("HEAD", "HEAD")
    assert not any(step.follow_redirects for step in endpoint_plan.steps)

    replay = service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    assert not replay.created
    assert replay.run == claim.run
    assert red_store.latest(flow.plan_id).actions_used == 0
    _close(schedule_store, red_store, recon_store)


def test_schedule_blocks_overlap_until_previous_flow_is_clean(
    tmp_path, approved_scope, now
):
    service, schedule_store, red_store, recon_store, endpoint_service, schedule, _ = _schedule(
        tmp_path, approved_scope, now
    )
    first = service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    with pytest.raises(EndpointScheduleRejected, match="clean terminal"):
        service.trigger(
            schedule.schedule_id,
            scope=approved_scope,
            now=now + timedelta(seconds=60),
        )

    endpoint_service.cancel_reservation(
        first.run.endpoint_recon_plan_id,
        operator_ref="operator:alice",
        now=now + timedelta(seconds=10),
    )
    flow = red_store.plan(first.run.flow_plan_id)
    RedTeamService(store=red_store).cancel(
        flow,
        red_store.latest(flow.plan_id),
        scope=approved_scope,
        now=now + timedelta(seconds=10),
    )
    second = service.trigger(
        schedule.schedule_id,
        scope=approved_scope,
        now=now + timedelta(seconds=60),
    )
    assert second.run.schedule_run_id != first.run.schedule_run_id
    assert second.run.state is EndpointScheduleRunState.MATERIALIZED
    _close(schedule_store, red_store, recon_store)


def test_schedule_pause_resume_scope_drift_and_operator_binding(
    tmp_path, approved_scope, now
):
    service, schedule_store, red_store, recon_store, _, schedule, _ = _schedule(
        tmp_path, approved_scope, now
    )
    with pytest.raises(EndpointScheduleRejected, match="operator binding"):
        service.pause(schedule.schedule_id, operator_ref="operator:bob", now=now)
    paused = service.pause(schedule.schedule_id, operator_ref="operator:alice", now=now)
    assert paused.state is EndpointScheduleState.PAUSED
    assert (
        service.pause(schedule.schedule_id, operator_ref="operator:alice", now=now)
        == paused
    )
    with pytest.raises(EndpointScheduleRejected, match="binding is invalid"):
        service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    drifted = approved_scope.model_copy(update={"version": approved_scope.version + 1})
    with pytest.raises(EndpointScheduleRejected, match="Scope binding"):
        service.resume(
            schedule.schedule_id,
            scope=drifted,
            operator_ref="operator:alice",
            now=now + timedelta(seconds=1),
        )
    resumed = service.resume(
        schedule.schedule_id,
        scope=approved_scope,
        operator_ref="operator:alice",
        now=now + timedelta(seconds=1),
    )
    assert resumed.state is EndpointScheduleState.ACTIVE
    assert resumed.next_due_at == now + timedelta(seconds=60)
    assert (
        service.resume(
            schedule.schedule_id,
            scope=approved_scope,
            operator_ref="operator:alice",
            now=now + timedelta(seconds=1),
        )
        == resumed
    )
    _close(schedule_store, red_store, recon_store)


def test_schedule_rejects_revoked_scope_without_claim(tmp_path, approved_scope, now):
    service, schedule_store, red_store, recon_store, _, schedule, checkpoint = _schedule(
        tmp_path, approved_scope, now
    )
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(EndpointScheduleRejected, match="current approved Scope"):
        service.trigger(schedule.schedule_id, scope=revoked, now=now)
    assert schedule_store.latest(schedule.schedule_id) == checkpoint
    _close(schedule_store, red_store, recon_store)


def test_schedule_interruption_requires_explicit_recovery(tmp_path, approved_scope, now):
    class InterruptOnce(EndpointScheduleService):
        interrupted = False

        def _materialize(self, schedule, run, *, scope):
            if not self.interrupted:
                self.interrupted = True
                raise EndpointScheduleMaterializationInterrupted("synthetic interruption")
            return super()._materialize(schedule, run, scope=scope)

    service, schedule_store, red_store, recon_store, _, schedule, _ = _schedule(
        tmp_path, approved_scope, now, service_type=InterruptOnce
    )
    with pytest.raises(EndpointScheduleMaterializationInterrupted):
        service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    started = schedule_store.latest(schedule.schedule_id)
    assert started.active_run_id is not None
    assert schedule_store.run(started.active_run_id).attempt == 1

    recovered = service.recover(
        schedule.schedule_id,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    assert recovered.run.state is EndpointScheduleRunState.MATERIALIZED
    assert recovered.run.attempt == 2
    _close(schedule_store, red_store, recon_store)


def test_schedule_timeout_cleans_partial_flow_and_reservation(
    tmp_path, approved_scope, now
):
    class InterruptAfterMaterialization(EndpointScheduleService):
        def _materialize(self, schedule, run, *, scope):
            super()._materialize(schedule, run, scope=scope)
            raise EndpointScheduleMaterializationInterrupted("synthetic post-write interruption")

    service, schedule_store, red_store, recon_store, _, schedule, _ = _schedule(
        tmp_path,
        approved_scope,
        now,
        service_type=InterruptAfterMaterialization,
    )
    with pytest.raises(EndpointScheduleMaterializationInterrupted):
        service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    timed_out = service.recover(
        schedule.schedule_id,
        scope=approved_scope,
        now=now + timedelta(seconds=30),
    )
    assert timed_out.run.state is EndpointScheduleRunState.TIMED_OUT
    assert timed_out.run.cleanup_complete
    flow_key, _, endpoint_key = service._keys(timed_out.run)
    flow = red_store.plan_by_key(flow_key)
    endpoint_plan = recon_store.plan_by_key(endpoint_key)
    assert red_store.latest(flow.plan_id).status is RedTeamFlowStatus.CANCELLED
    assert (
        recon_store.reservation(endpoint_plan.endpoint_recon_plan_id).state
        is EndpointReconReservationState.CANCELLED
    )
    _close(schedule_store, red_store, recon_store)


def test_schedule_attempt_exhaustion_pauses_after_cleanup(tmp_path, approved_scope, now):
    class AlwaysInterrupt(EndpointScheduleService):
        def _materialize(self, schedule, run, *, scope):
            raise EndpointScheduleMaterializationInterrupted("synthetic interruption")

    service, schedule_store, red_store, recon_store, _, schedule, _ = _schedule(
        tmp_path, approved_scope, now, service_type=AlwaysInterrupt
    )
    with pytest.raises(EndpointScheduleMaterializationInterrupted):
        service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    with pytest.raises(EndpointScheduleMaterializationInterrupted):
        service.recover(
            schedule.schedule_id,
            scope=approved_scope,
            now=now + timedelta(seconds=1),
        )
    failed = service.recover(
        schedule.schedule_id,
        scope=approved_scope,
        now=now + timedelta(seconds=2),
    )
    assert failed.run.state is EndpointScheduleRunState.FAILED
    assert failed.run.attempt == 3
    assert failed.run.cleanup_complete
    assert failed.checkpoint.state is EndpointScheduleState.PAUSED
    assert failed.checkpoint.reason_code == "materialization_attempts_exhausted"
    _close(schedule_store, red_store, recon_store)


def test_schedule_unproven_cleanup_cannot_resume(tmp_path, approved_scope, now):
    class UncleanInterrupt(EndpointScheduleService):
        def _materialize(self, schedule, run, *, scope):
            raise EndpointScheduleMaterializationInterrupted("synthetic interruption")

        def _cleanup_partial(self, schedule, run, *, scope, now):
            return False

    service, schedule_store, red_store, recon_store, _, schedule, _ = _schedule(
        tmp_path, approved_scope, now, service_type=UncleanInterrupt
    )
    with pytest.raises(EndpointScheduleMaterializationInterrupted):
        service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    with pytest.raises(EndpointScheduleMaterializationInterrupted):
        service.recover(
            schedule.schedule_id,
            scope=approved_scope,
            now=now + timedelta(seconds=1),
        )
    failed = service.recover(
        schedule.schedule_id,
        scope=approved_scope,
        now=now + timedelta(seconds=2),
    )
    assert not failed.run.cleanup_complete
    with pytest.raises(EndpointScheduleRejected, match="cleanup is unproven"):
        service.resume(
            schedule.schedule_id,
            scope=approved_scope,
            operator_ref="operator:alice",
            now=now + timedelta(seconds=3),
        )
    _close(schedule_store, red_store, recon_store)


def test_schedule_contract_rejects_noncanonical_paths(approved_scope, now):
    values = {
        "scope_id": approved_scope.scope_id,
        "scope_version": approved_scope.version,
        "target_url": "https://app.example.test/",
        "visibility": Visibility.BLACK_BOX,
        "test_class": "read_only",
        "operator_ref": "operator:alice",
        "emergency_contact_ref": "contact:security-owner",
        "paths": ("/../admin",),
        "interval_seconds": 60,
        "run_ttl_seconds": 30,
        "max_consecutive_failures": 2,
        "recon_limits": EndpointReconLimits(max_steps=1, max_requests=1),
        "active_from": now,
        "active_until": now + timedelta(minutes=5),
        "created_at": now,
        "idempotency_key": "schedule:invalid",
    }
    with pytest.raises(ValidationError):
        EndpointCheckSchedule.create(**values)
    values["paths"] = ("/health",)
    values["test_class"] = "idor"
    with pytest.raises(ValidationError):
        EndpointCheckSchedule.create(**values)


def test_schedule_service_rejects_path_outside_target_base(tmp_path, approved_scope, now):
    service, schedule_store, red_store, recon_store, _ = _runtime(tmp_path)
    with pytest.raises(EndpointScheduleRejected, match="preflight is invalid"):
        service.create(
            scope=approved_scope,
            target_url="https://app.example.test/app/",
            visibility=Visibility.BLACK_BOX,
            test_class="read_only",
            operator_ref="operator:alice",
            emergency_contact_ref="contact:security-owner",
            paths=("/health",),
            interval_seconds=60,
            run_ttl_seconds=30,
            max_consecutive_failures=2,
            recon_limits=EndpointReconLimits(max_steps=1, max_requests=1),
            active_from=now,
            active_until=now + timedelta(minutes=5),
            now=now,
            idempotency_key="schedule:escaped-path",
        )
    assert schedule_store.schedule_by_key("schedule:escaped-path") is None
    _close(schedule_store, red_store, recon_store)


def test_schedule_cancel_and_expire_are_terminal(tmp_path, approved_scope, now):
    service, schedule_store, red_store, recon_store, _, schedule, _ = _schedule(
        tmp_path / "cancelled", approved_scope, now
    )
    cancelled = service.cancel(
        schedule.schedule_id, operator_ref="operator:alice", now=now
    )
    assert cancelled.state is EndpointScheduleState.CANCELLED
    assert (
        service.cancel(schedule.schedule_id, operator_ref="operator:alice", now=now)
        == cancelled
    )
    with pytest.raises(EndpointScheduleRejected, match="binding is invalid"):
        service.trigger(schedule.schedule_id, scope=approved_scope, now=now)
    _close(schedule_store, red_store, recon_store)

    service, schedule_store, red_store, recon_store, _, schedule, _ = _schedule(
        tmp_path / "expired", approved_scope, now
    )
    with pytest.raises(EndpointScheduleRejected, match="has not elapsed"):
        service.expire(schedule.schedule_id, now=now)
    expired = service.expire(
        schedule.schedule_id, now=now + timedelta(minutes=5)
    )
    assert expired.state is EndpointScheduleState.EXPIRED
    _close(schedule_store, red_store, recon_store)


def test_schedule_cli_materializes_offline_and_redacts_targets(
    tmp_path, approved_scope, now, monkeypatch, capsys
):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(approved_scope.model_dump_json(), encoding="utf-8")
    paths_file = tmp_path / "paths.json"
    paths_file.write_text('["/health"]', encoding="utf-8")
    monkeypatch.setattr("vulnloom.red_team.cli.utc_now", lambda: now)
    common = [
        "--red-team-db",
        str(tmp_path / "red-team.sqlite3"),
        "--endpoint-recon-db",
        str(tmp_path / "endpoint-recon.sqlite3"),
        "--endpoint-schedule-db",
        str(tmp_path / "endpoint-schedule.sqlite3"),
        "--evidence-root",
        str(tmp_path / "evidence"),
    ]
    assert (
        main(
            [
                "red-team",
                "create-endpoint-schedule",
                "--scope-file",
                str(scope_file),
                "--target-url",
                "https://app.example.test/",
                "--paths-file",
                str(paths_file),
                "--operator-ref",
                "operator:alice",
                "--emergency-contact-ref",
                "contact:security-owner",
                "--interval-seconds",
                "60",
                "--schedule-ttl-seconds",
                "300",
                "--run-ttl-seconds",
                "30",
                "--max-steps",
                "1",
                "--max-requests",
                "1",
                "--total-seconds",
                "20",
                "--idempotency-key",
                "cli:endpoint-schedule",
                *common,
            ]
        )
        == 0
    )
    created_text = capsys.readouterr().out
    created = __import__("json").loads(created_text)
    assert "/health" not in created_text
    assert "app.example.test" not in created_text
    assert created["path_count"] == 1

    assert (
        main(
            [
                "red-team",
                "trigger-endpoint-schedule",
                "--schedule-id",
                created["schedule_id"],
                "--scope-file",
                str(scope_file),
                *common,
            ]
        )
        == 0
    )
    triggered_text = capsys.readouterr().out
    triggered = __import__("json").loads(triggered_text)
    assert "/health" not in triggered_text
    assert "app.example.test" not in triggered_text
    assert triggered["run"]["state"] == "materialized"

    assert (
        main(
            [
                "red-team",
                "endpoint-schedule-status",
                "--schedule-id",
                created["schedule_id"],
                "--endpoint-schedule-db",
                str(tmp_path / "endpoint-schedule.sqlite3"),
            ]
        )
        == 0
    )
    status_text = capsys.readouterr().out
    assert "/health" not in status_text
    assert "app.example.test" not in status_text
