from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.cli import main
from vulnloom.domain.models import ScopeState
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    EndpointReconAdapterInterrupted,
    EndpointReconLimits,
    EndpointReconOutcomeKind,
    EndpointReconRecoveryRequired,
    EndpointReconRejected,
    EndpointReconService,
    EndpointReconStepResult,
    EndpointReconStore,
    EndpointSeed,
    OfflineEndpointReconAdapter,
    OfflineEndpointReconScenario,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.workflows import Visibility


def _runtime(tmp_path, approved_scope, now, *, target="https://app.example.test/", max_actions=4):
    red_store = RedTeamStore(tmp_path / "red-team.sqlite3")
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    flow_service = RedTeamService(store=red_store)
    flow = flow_service.prepare(
        scope=approved_scope,
        target_url=target,
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=max_actions,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:security-owner",
        now=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="endpoint-seeds:flow",
    )
    checkpoint = flow_service.create_and_start(flow, scope=approved_scope, now=now)
    service = EndpointReconService(
        red_team_store=red_store,
        recon_store=recon_store,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
    )
    return service, red_store, recon_store, flow, checkpoint


def _seed_and_plan(tmp_path, approved_scope, now, *, paths=("/health", "/robots.txt")):
    service, red_store, recon_store, flow, checkpoint = _runtime(tmp_path, approved_scope, now)
    seed_set = service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=approved_scope,
        operator_ref="operator:alice",
        paths=paths,
        now=now,
        expires_at=now + timedelta(minutes=5),
        idempotency_key="endpoint-seeds:set",
    )
    plan = service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=approved_scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=4, max_requests=4),
        now=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="endpoint-seeds:recon",
    )
    return service, red_store, recon_store, seed_set, plan


def test_operator_seals_exact_paths_and_plan_is_one_head_per_seed(tmp_path, approved_scope, now):
    service, red_store, recon_store, seed_set, plan = _seed_and_plan(tmp_path, approved_scope, now)
    assert tuple(seed.path for seed in seed_set.seeds) == ("/health", "/robots.txt")
    assert tuple(step.method for step in plan.steps) == ("HEAD", "HEAD")
    assert not any(step.follow_redirects for step in plan.steps)
    assert tuple(step.seed_id for step in plan.steps) == tuple(
        seed.seed_id for seed in seed_set.seeds
    )
    assert {step.target_url for step in plan.steps} == {
        "https://app.example.test/health",
        "https://app.example.test/robots.txt",
    }
    assert service.recon_store.seed_set(seed_set.seed_set_id) == seed_set
    red_store.close()
    recon_store.close()


def test_endpoint_seed_cli_is_offline_and_redacts_paths(
    tmp_path, approved_scope, now, capsys, monkeypatch
):
    _, red_store, recon_store, flow, _ = _runtime(tmp_path, approved_scope, now, max_actions=2)
    red_store.close()
    recon_store.close()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(approved_scope.model_dump_json(), encoding="utf-8")
    paths_file = tmp_path / "paths.json"
    paths_file.write_text('["/health", "/robots.txt"]', encoding="utf-8")
    monkeypatch.setattr("vulnloom.red_team.cli.utc_now", lambda: now)
    common = [
        "--scope-file",
        str(scope_file),
        "--red-team-db",
        str(tmp_path / "red-team.sqlite3"),
        "--endpoint-recon-db",
        str(tmp_path / "endpoint-recon.sqlite3"),
        "--evidence-root",
        str(tmp_path / "evidence"),
    ]
    assert (
        main(
            [
                "red-team",
                "seal-endpoint-seeds",
                "--plan-id",
                flow.plan_id,
                "--paths-file",
                str(paths_file),
                "--operator-ref",
                "operator:alice",
                "--idempotency-key",
                "cli:seeds",
                *common,
            ]
        )
        == 0
    )
    sealed_text = capsys.readouterr().out
    sealed = __import__("json").loads(sealed_text)
    assert "/health" not in sealed_text
    assert "app.example.test" not in sealed_text
    assert sealed["seed_count"] == 2
    assert (
        main(
            [
                "red-team",
                "prepare-endpoint-recon",
                "--seed-set-id",
                sealed["seed_set_id"],
                "--test-class",
                "read_only",
                "--max-steps",
                "2",
                "--max-requests",
                "2",
                "--idempotency-key",
                "cli:plan",
                *common,
            ]
        )
        == 0
    )
    prepared_text = capsys.readouterr().out
    prepared = __import__("json").loads(prepared_text)
    assert "/health" not in prepared_text
    assert "app.example.test" not in prepared_text
    assert (
        main(
            [
                "red-team",
                "run-endpoint-recon-offline",
                "--endpoint-recon-plan-id",
                prepared["endpoint_recon_plan_id"],
                *common,
            ]
        )
        == 0
    )
    outcome_text = capsys.readouterr().out
    assert "/health" not in outcome_text
    assert "app.example.test" not in outcome_text


def test_endpoint_seed_cli_rejects_symlink_input(tmp_path, approved_scope, now, monkeypatch):
    _, red_store, recon_store, flow, _ = _runtime(tmp_path, approved_scope, now)
    red_store.close()
    recon_store.close()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(approved_scope.model_dump_json(), encoding="utf-8")
    source = tmp_path / "source.json"
    source.write_text('["/health"]', encoding="utf-8")
    link = tmp_path / "paths.json"
    link.symlink_to(source)
    monkeypatch.setattr("vulnloom.red_team.cli.utc_now", lambda: now)
    with pytest.raises(OSError):
        main(
            [
                "red-team",
                "seal-endpoint-seeds",
                "--plan-id",
                flow.plan_id,
                "--scope-file",
                str(scope_file),
                "--paths-file",
                str(link),
                "--operator-ref",
                "operator:alice",
                "--idempotency-key",
                "cli:symlink",
                "--red-team-db",
                str(tmp_path / "red-team.sqlite3"),
                "--endpoint-recon-db",
                str(tmp_path / "endpoint-recon.sqlite3"),
                "--evidence-root",
                str(tmp_path / "evidence"),
            ]
        )


@pytest.mark.parametrize(
    "path",
    (
        "https://evil.example/path",
        "relative",
        "/a?query=1",
        "/a#fragment",
        "/a//b",
        "/a/../b",
        "/a%2fb",
        "/a\\b",
    ),
)
def test_endpoint_seed_rejects_noncanonical_or_discovery_shaped_input(path):
    with pytest.raises(ValidationError, match="canonical query-free absolute path"):
        EndpointSeed.create(path=path)


def test_seed_set_rejects_duplicates_base_path_escape_and_budget(tmp_path, approved_scope, now):
    service, red_store, recon_store, flow, checkpoint = _runtime(
        tmp_path,
        approved_scope,
        now,
        target="https://app.example.test/api",
        max_actions=1,
    )
    common = dict(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=approved_scope,
        operator_ref="operator:alice",
        now=now,
        expires_at=now + timedelta(minutes=5),
    )
    with pytest.raises(EndpointReconRejected, match="duplicate"):
        service.seal_seed_set(paths=("/api/a", "/api/a"), idempotency_key="dupe", **common)
    with pytest.raises(EndpointReconRejected, match="base path"):
        service.seal_seed_set(paths=("/admin",), idempotency_key="escape", **common)
    seed_set = service.seal_seed_set(paths=("/api/a", "/api/b"), idempotency_key="budget", **common)
    with pytest.raises(EndpointReconRejected, match="remaining action budget"):
        service.prepare(
            seed_set_id=seed_set.seed_set_id,
            scope=approved_scope,
            test_class="read_only",
            limits=EndpointReconLimits(max_steps=2, max_requests=2),
            now=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="budget-plan",
        )
    red_store.close()
    recon_store.close()


def test_offline_execution_is_idempotent_and_result_has_no_url_or_new_paths(
    tmp_path, approved_scope, now
):
    service, red_store, recon_store, _, plan = _seed_and_plan(tmp_path, approved_scope, now)
    adapter = OfflineEndpointReconAdapter()
    outcome = service.execute(plan, scope=approved_scope, adapter=adapter, now=now)
    assert outcome.outcome is EndpointReconOutcomeKind.SUCCEEDED
    assert outcome.requests_used == 2
    assert adapter.calls == 2
    serialized = outcome.model_dump_json()
    assert "app.example.test" not in serialized
    assert "/health" not in serialized
    replay_adapter = OfflineEndpointReconAdapter(
        OfflineEndpointReconScenario(outcome=EndpointReconOutcomeKind.FAILED)
    )
    assert service.execute(plan, scope=approved_scope, adapter=replay_adapter, now=now) == outcome
    assert replay_adapter.calls == 0
    red_store.close()
    recon_store.close()


def test_timeout_cleanup_and_interrupt_recovery_are_explicit(tmp_path, approved_scope, now):
    service, red_store, recon_store, _, plan = _seed_and_plan(tmp_path, approved_scope, now)
    interrupted = OfflineEndpointReconAdapter(OfflineEndpointReconScenario(interrupt=True))
    with pytest.raises(EndpointReconAdapterInterrupted):
        service.execute(plan, scope=approved_scope, adapter=interrupted, now=now)
    assert recon_store.state(plan.endpoint_recon_plan_id)[0].value == "started"
    timed_out = OfflineEndpointReconAdapter(
        OfflineEndpointReconScenario(
            outcome=EndpointReconOutcomeKind.TIMED_OUT,
            status_code=None,
            reason_code="offline_timeout",
            cleanup_complete=False,
        )
    )
    outcome = service.recover(plan, scope=approved_scope, adapter=timed_out, now=now)
    assert outcome.outcome is EndpointReconOutcomeKind.TIMED_OUT
    assert not outcome.cleanup_complete
    assert outcome.attempt == 2
    with pytest.raises(EndpointReconRecoveryRequired, match="not awaiting recovery"):
        service.recover(plan, scope=approved_scope, adapter=timed_out, now=now)
    red_store.close()
    recon_store.close()


def test_forged_result_digest_and_missing_evidence_fail_closed(tmp_path, approved_scope, now):
    service, red_store, recon_store, _, plan = _seed_and_plan(
        tmp_path, approved_scope, now, paths=("/health",)
    )

    class ForgedAdapter:
        def execute(self, step, *, now, deadline):
            del deadline
            return EndpointReconStepResult(
                step_id=step.step_id,
                target_url_digest="f" * 64,
                outcome=EndpointReconOutcomeKind.SUCCEEDED,
                status_code=200,
                reason_code="forged",
                evidence_refs=("e" * 64,),
                cleanup_complete=True,
                completed_at=now,
            )

    with pytest.raises(EndpointReconRejected, match="provenance"):
        service.execute(plan, scope=approved_scope, adapter=ForgedAdapter(), now=now)
    assert recon_store.state(plan.endpoint_recon_plan_id)[0].value == "started"
    red_store.close()
    recon_store.close()


def test_measured_per_request_timeout_is_fail_closed(tmp_path, approved_scope, now):
    service, red_store, recon_store, _, plan = _seed_and_plan(
        tmp_path, approved_scope, now, paths=("/health",)
    )
    ticks = iter((0.0, 0.0, 0.0, 6.0))
    measured = EndpointReconService(
        red_team_store=red_store,
        recon_store=recon_store,
        evidence_store=service.evidence_store,
        monotonic=lambda: next(ticks),
    )
    outcome = measured.execute(
        plan,
        scope=approved_scope,
        adapter=OfflineEndpointReconAdapter(),
        now=now,
    )
    assert outcome.outcome is EndpointReconOutcomeKind.TIMED_OUT
    assert outcome.results[0].status_code is None
    assert outcome.results[0].reason_code == "per_request_deadline_exceeded"
    red_store.close()
    recon_store.close()


def test_transactional_reservation_and_revoked_scope_fail_closed(tmp_path, approved_scope, now):
    service, red_store, recon_store, flow, checkpoint = _runtime(
        tmp_path, approved_scope, now, max_actions=2
    )
    first = service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=approved_scope,
        operator_ref="operator:alice",
        paths=("/one",),
        now=now,
        expires_at=now + timedelta(minutes=5),
        idempotency_key="reserve:first:set",
    )
    plan = service.prepare(
        seed_set_id=first.seed_set_id,
        scope=approved_scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="reserve:first:plan",
    )
    second = service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=approved_scope,
        operator_ref="operator:alice",
        paths=("/two", "/three"),
        now=now,
        expires_at=now + timedelta(minutes=5),
        idempotency_key="reserve:second:set",
    )
    with pytest.raises(EndpointReconRejected, match="reservations"):
        service.prepare(
            seed_set_id=second.seed_set_id,
            scope=approved_scope,
            test_class="read_only",
            limits=EndpointReconLimits(max_steps=2, max_requests=2),
            now=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="reserve:second:plan",
        )
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    adapter = OfflineEndpointReconAdapter()
    with pytest.raises(EndpointReconRejected, match="approved Scope"):
        service.execute(plan, scope=revoked, adapter=adapter, now=now)
    assert adapter.calls == 0
    red_store.close()
    recon_store.close()


def test_final_interruption_records_failed_cleanup(tmp_path, approved_scope, now):
    service, red_store, recon_store, _, plan = _seed_and_plan(
        tmp_path, approved_scope, now, paths=("/health",)
    )
    adapter = OfflineEndpointReconAdapter(OfflineEndpointReconScenario(interrupt=True))
    with pytest.raises(EndpointReconAdapterInterrupted):
        service.execute(plan, scope=approved_scope, adapter=adapter, now=now)
    with pytest.raises(EndpointReconAdapterInterrupted):
        service.recover(plan, scope=approved_scope, adapter=adapter, now=now)
    outcome = service.recover(plan, scope=approved_scope, adapter=adapter, now=now)
    assert outcome.outcome is EndpointReconOutcomeKind.FAILED
    assert outcome.results[0].reason_code == "adapter_attempts_exhausted"
    assert not outcome.cleanup_complete
    assert outcome.attempt == 3
    red_store.close()
    recon_store.close()
