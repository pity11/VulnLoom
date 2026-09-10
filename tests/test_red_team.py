from __future__ import annotations

from datetime import timedelta

import pytest

from vulnloom.cli import main
from vulnloom.domain.models import ScopeState
from vulnloom.red_team import (
    ImpactClass,
    OfflineReconScenario,
    OfflineRedTeamReconAdapter,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamAdapterInterrupted,
    RedTeamCheckpoint,
    RedTeamFlowStatus,
    RedTeamReconAction,
    RedTeamReconObservation,
    RedTeamRecoveryRequired,
    RedTeamRejected,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.workflows import Visibility


def _running(tmp_path, approved_scope, now, *, max_actions=3, max_failures=2):
    store = RedTeamStore(tmp_path / "red-team.sqlite3")
    service = RedTeamService(store=store)
    plan = service.prepare(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=max_actions,
        max_consecutive_failures=max_failures,
        emergency_contact_ref="contact:security-owner",
        now=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="red-team:test:flow",
    )
    checkpoint = service.create_and_start(plan, scope=approved_scope, now=now)
    return service, store, plan, checkpoint


def _command(service, plan, checkpoint, scope, now, *, key="red-team:test:action", attempt=1):
    return service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key=key,
        attempt=attempt,
    )


def test_authorized_red_team_flow_is_typed_idempotent_and_read_only(
    tmp_path, approved_scope, now
):
    service, store, plan, checkpoint = _running(tmp_path, approved_scope, now)
    assert checkpoint.status is RedTeamFlowStatus.RUNNING
    assert plan.mode.visibility is Visibility.BLACK_BOX
    assert tuple(item.value for item in plan.rules.allowed_impacts) == ("read_only",)
    assert {item.value for item in plan.rules.prohibited_impacts} == {
        "state_change",
        "real_credential",
        "external_callback",
        "lateral_movement",
        "persistence",
    }
    assert service.create_and_start(plan, scope=approved_scope, now=now) == checkpoint
    assert (
        service.prepare(
            scope=approved_scope,
            target_url="https://app.example.test/",
            visibility=Visibility.BLACK_BOX,
            allowed_test_classes=("read_only",),
            max_actions=3,
            max_consecutive_failures=2,
            emergency_contact_ref="contact:security-owner",
            now=now,
            deadline=now + timedelta(minutes=10),
            idempotency_key="red-team:test:flow",
        )
        == plan
    )

    command = _command(service, plan, checkpoint, approved_scope, now)
    adapter = OfflineRedTeamReconAdapter()
    advanced, observation = service.execute_recon(
        command=command, scope=approved_scope, adapter=adapter, now=now
    )
    assert advanced.status is RedTeamFlowStatus.RUNNING
    assert advanced.actions_used == 1
    assert observation.status_code == 204
    assert observation.sensitive_data_redacted
    replay_checkpoint, replay = service.execute_recon(
        command=command,
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(
            OfflineReconScenario(outcome=ReconOutcome.FAILED)
        ),
        now=now,
    )
    assert replay_checkpoint == advanced
    assert replay == observation
    assert adapter.calls == 1

    second = _command(
        service,
        plan,
        advanced,
        approved_scope,
        now + timedelta(seconds=1),
        key="red-team:test:action",
    )
    with pytest.raises(ValueError, match="identity conflict"):
        service.execute_recon(
            command=second,
            scope=approved_scope,
            adapter=OfflineRedTeamReconAdapter(),
            now=now + timedelta(seconds=1),
        )
    store.close()


def test_red_team_recovers_plan_created_before_start(
    tmp_path, approved_scope, now
):
    with RedTeamStore(tmp_path / "recovery.sqlite3") as store:
        service = RedTeamService(store=store)
        plan = service.prepare(
            scope=approved_scope,
            target_url="https://app.example.test/",
            visibility=Visibility.GREY_BOX,
            allowed_test_classes=("read_only",),
            max_actions=2,
            max_consecutive_failures=2,
            emergency_contact_ref="contact:security-owner",
            now=now,
            deadline=now + timedelta(minutes=5),
            idempotency_key="red-team:test:created-only",
        )
        planned = RedTeamCheckpoint.create(
            plan_id=plan.plan_id,
            revision=0,
            status=RedTeamFlowStatus.PLANNED,
            actions_used=0,
            consecutive_failures=0,
            observation_ids=(),
            updated_at=now,
        )
        store.create(plan, planned)
        recovered = service.create_and_start(plan, scope=approved_scope, now=now)
        assert recovered.status is RedTeamFlowStatus.RUNNING
        assert recovered.revision == 1


def test_red_team_rejects_out_of_scope_noncanonical_and_scope_drift(
    tmp_path, approved_scope, now
):
    with RedTeamStore(tmp_path / "red-team.sqlite3") as store:
        service = RedTeamService(store=store)
        kwargs = {
            "scope": approved_scope,
            "visibility": Visibility.BLACK_BOX,
            "allowed_test_classes": ("read_only",),
            "max_actions": 3,
            "max_consecutive_failures": 2,
            "emergency_contact_ref": "contact:security-owner",
            "now": now,
            "deadline": now + timedelta(minutes=5),
            "idempotency_key": "red-team:test:rejected",
        }
        with pytest.raises(RedTeamRejected, match="outside approved Scope"):
            service.prepare(target_url="https://outside.example/", **kwargs)
        with pytest.raises(ValueError, match="canonical"):
            service.prepare(target_url="HTTPS://APP.EXAMPLE.TEST", **kwargs)
        with pytest.raises(ValueError, match="uncredentialed"):
            service.prepare(
                target_url="https://user:password@app.example.test/", **kwargs
            )
        with pytest.raises(ValueError, match="black/grey-box"):
            service.prepare(
                target_url="https://app.example.test/",
                **(kwargs | {"visibility": Visibility.WHITE_BOX}),
            )

    service, store, plan, checkpoint = _running(tmp_path / "drift", approved_scope, now)
    command = _command(service, plan, checkpoint, approved_scope, now)
    drifted = approved_scope.model_copy(update={"version": approved_scope.version + 1})
    with pytest.raises(RedTeamRejected, match="Scope"):
        service.execute_recon(
            command=command,
            scope=drifted,
            adapter=OfflineRedTeamReconAdapter(),
            now=now,
        )
    assert store.latest(plan.plan_id) == checkpoint
    store.close()


def test_red_team_contract_rejects_dangerous_action_and_raw_response_fields(
    tmp_path, approved_scope, now
):
    service, store, plan, checkpoint = _running(tmp_path, approved_scope, now)
    command = _command(service, plan, checkpoint, approved_scope, now)
    action_values = command.action.model_dump(mode="python", exclude={"action_id"})
    with pytest.raises(ValueError, match="read-only"):
        RedTeamReconAction.create(
            **(action_values | {"impact": ImpactClass.STATE_CHANGE})
        )
    observation = OfflineRedTeamReconAdapter().execute(command.action, now=now)
    with pytest.raises(ValueError, match="Extra inputs"):
        RedTeamReconObservation.model_validate(
            observation.model_dump(mode="python")
            | {"response_body": "Authorization: Bearer synthetic-secret"}
        )
    store.close()


def test_red_team_interruption_requires_bounded_recovery_attempt(
    tmp_path, approved_scope, now
):
    service, store, plan, checkpoint = _running(tmp_path, approved_scope, now)
    command = _command(service, plan, checkpoint, approved_scope, now)
    with pytest.raises(RedTeamAdapterInterrupted):
        service.execute_recon(
            command=command,
            scope=approved_scope,
            adapter=OfflineRedTeamReconAdapter(
                OfflineReconScenario(interrupt=True)
            ),
            now=now,
        )
    assert store.latest(plan.plan_id) == checkpoint
    concurrent = _command(
        service,
        plan,
        checkpoint,
        approved_scope,
        now,
        key="red-team:test:concurrent-action",
    )
    with pytest.raises(ValueError, match="action claim rejected"):
        service.execute_recon(
            command=concurrent,
            scope=approved_scope,
            adapter=OfflineRedTeamReconAdapter(),
            now=now,
        )
    with pytest.raises(RedTeamRecoveryRequired, match="next bounded attempt"):
        service.execute_recon(
            command=command,
            scope=approved_scope,
            adapter=OfflineRedTeamReconAdapter(),
            now=now,
        )
    retry = command.model_copy(update={"attempt": 2})
    retry = retry.__class__.create(action=retry.action, attempt=retry.attempt)
    advanced, _ = service.execute_recon(
        command=retry,
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(),
        now=now + timedelta(seconds=1),
    )
    assert advanced.actions_used == 1
    store.close()


@pytest.mark.parametrize(
    ("scenario", "expected", "reason"),
    [
        (
            OfflineReconScenario(
                outcome=ReconOutcome.TIMED_OUT,
                status_code=None,
                reason_code="offline_timeout",
            ),
            RedTeamFlowStatus.TIMED_OUT,
            "action_timed_out",
        ),
        (
            OfflineReconScenario(
                outcome=ReconOutcome.FAILED,
                status_code=None,
                reason_code="cleanup_failed",
                cleanup_complete=False,
            ),
            RedTeamFlowStatus.FAILED,
            "cleanup_unproven",
        ),
    ],
)
def test_red_team_timeout_and_cleanup_failure_stop_flow(
    tmp_path, approved_scope, now, scenario, expected, reason
):
    service, store, plan, checkpoint = _running(tmp_path, approved_scope, now)
    command = _command(service, plan, checkpoint, approved_scope, now)
    terminal, _ = service.execute_recon(
        command=command,
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(scenario),
        now=now,
    )
    assert terminal.status is expected
    assert terminal.stop_reason == reason
    store.close()


def test_red_team_action_budget_completes_and_failure_budget_stops(
    tmp_path, approved_scope, now
):
    service, store, plan, checkpoint = _running(
        tmp_path / "complete", approved_scope, now, max_actions=2
    )
    for ordinal in (1, 2):
        command = _command(
            service,
            plan,
            checkpoint,
            approved_scope,
            now + timedelta(seconds=ordinal - 1),
            key=f"red-team:test:success:{ordinal}",
        )
        checkpoint, _ = service.execute_recon(
            command=command,
            scope=approved_scope,
            adapter=OfflineRedTeamReconAdapter(),
            now=now + timedelta(seconds=ordinal - 1),
        )
    assert checkpoint.status is RedTeamFlowStatus.COMPLETED
    assert checkpoint.stop_reason == "action_budget_reached"
    store.close()

    service, store, plan, checkpoint = _running(
        tmp_path / "failures", approved_scope, now, max_failures=2
    )
    failed = OfflineRedTeamReconAdapter(
        OfflineReconScenario(
            outcome=ReconOutcome.FAILED,
            status_code=None,
            reason_code="offline_failed",
        )
    )
    for ordinal in (1, 2):
        command = _command(
            service,
            plan,
            checkpoint,
            approved_scope,
            now + timedelta(seconds=ordinal - 1),
            key=f"red-team:test:failure:{ordinal}",
        )
        checkpoint, _ = service.execute_recon(
            command=command,
            scope=approved_scope,
            adapter=failed,
            now=now + timedelta(seconds=ordinal - 1),
        )
    assert checkpoint.status is RedTeamFlowStatus.FAILED
    assert checkpoint.stop_reason == "failure_limit_reached"
    store.close()


def test_red_team_kill_switch_and_expiry_are_fail_closed(
    tmp_path, approved_scope, now
):
    service, store, plan, checkpoint = _running(tmp_path, approved_scope, now)
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    killed = service.kill(plan, checkpoint, scope=revoked, now=now)
    assert killed.status is RedTeamFlowStatus.KILLED
    assert killed.stop_reason == "kill_switch_activated"
    assert store.latest(plan.plan_id) == killed
    store.close()

    service, store, plan, checkpoint = _running(
        tmp_path / "cancelled", approved_scope, now
    )
    cancelled = service.cancel(plan, checkpoint, scope=approved_scope, now=now)
    assert cancelled.status is RedTeamFlowStatus.CANCELLED
    assert cancelled.stop_reason == "operator_cancelled"
    store.close()

    service, store, plan, checkpoint = _running(
        tmp_path / "expired", approved_scope, now
    )
    expired = service.expire(plan, checkpoint, now=plan.deadline)
    assert expired.status is RedTeamFlowStatus.TIMED_OUT
    with pytest.raises(RedTeamRejected):
        service.prepare_recon(
            plan=plan,
            checkpoint=expired,
            scope=approved_scope,
            kind=RedTeamActionKind.HTTP_HEAD,
            test_class="read_only",
            now=plan.deadline,
            ttl_seconds=30,
            idempotency_key="red-team:test:after-expiry",
        )
    store.close()


def test_red_team_third_interruption_closes_flow_with_unproven_cleanup(
    tmp_path, approved_scope, now
):
    service, store, plan, checkpoint = _running(tmp_path, approved_scope, now)
    first = _command(service, plan, checkpoint, approved_scope, now)
    for attempt in (1, 2):
        command = first.__class__.create(action=first.action, attempt=attempt)
        with pytest.raises(RedTeamAdapterInterrupted):
            service.execute_recon(
                command=command,
                scope=approved_scope,
                adapter=OfflineRedTeamReconAdapter(
                    OfflineReconScenario(interrupt=True)
                ),
                now=now + timedelta(seconds=attempt - 1),
            )
    third = first.__class__.create(action=first.action, attempt=3)
    terminal, observation = service.execute_recon(
        command=third,
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(OfflineReconScenario(interrupt=True)),
        now=now + timedelta(seconds=2),
    )
    assert terminal.status is RedTeamFlowStatus.FAILED
    assert terminal.stop_reason == "cleanup_unproven"
    assert observation.reason_code == "adapter_attempts_exhausted"
    assert not observation.cleanup_complete
    store.close()


def test_red_team_cli_reuses_application_service_without_network(
    tmp_path, approved_scope, now, capsys, monkeypatch
):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(approved_scope.model_dump_json(), encoding="utf-8")
    database = tmp_path / "red-team.sqlite3"
    monkeypatch.setattr("vulnloom.red_team.cli.utc_now", lambda: now)
    assert main(
        [
            "red-team",
            "start",
            "--scope-file",
            str(scope_file),
            "--target-url",
            "https://app.example.test/",
            "--test-class",
            "read_only",
            "--max-actions",
            "2",
            "--emergency-contact-ref",
            "contact:security-owner",
            "--idempotency-key",
            "red-team:cli:flow",
            "--red-team-db",
            str(database),
        ]
    ) == 0
    started = __import__("json").loads(capsys.readouterr().out)
    plan_id = started["plan"]["plan_id"]
    assert started["checkpoint"]["status"] == "running"

    assert main(
        [
            "red-team",
            "prepare-recon",
            "--plan-id",
            plan_id,
            "--scope-file",
            str(scope_file),
            "--kind",
            "http_head",
            "--test-class",
            "read_only",
            "--idempotency-key",
            "red-team:cli:action:1",
            "--red-team-db",
            str(database),
        ]
    ) == 0
    prepared = __import__("json").loads(capsys.readouterr().out)
    command_file = tmp_path / "recon-command.json"
    command_file.write_text(
        __import__("json").dumps(prepared["command"]), encoding="utf-8"
    )
    assert main(
        [
            "red-team",
            "run-recon-offline",
            "--command-file",
            str(command_file),
            "--scope-file",
            str(scope_file),
            "--outcome",
            "succeeded",
            "--status-code",
            "204",
            "--red-team-db",
            str(database),
        ]
    ) == 0
    executed = __import__("json").loads(capsys.readouterr().out)
    assert executed["checkpoint"]["actions_used"] == 1
    assert executed["observation"]["sensitive_data_redacted"] is True

    assert main(
        [
            "red-team",
            "status",
            "--plan-id",
            plan_id,
            "--red-team-db",
            str(database),
        ]
    ) == 0
    status = __import__("json").loads(capsys.readouterr().out)
    assert status["status"] == "running"
    persisted = database.read_bytes()
    for forbidden in (b"Authorization", b"Cookie", b"Bearer", b"api_key"):
        assert forbidden not in persisted
