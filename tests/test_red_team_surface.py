from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.cli import main
from vulnloom.domain.models import EvidenceKind, ScopeState
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    AttackSurfaceEndpoint,
    AttackSurfaceInventory,
    AttackSurfaceReductionIdempotencyConflict,
    AttackSurfaceReductionLimits,
    AttackSurfaceReductionOutcome,
    AttackSurfaceReductionPlan,
    AttackSurfaceReductionRecoveryRequired,
    AttackSurfaceReductionRejected,
    AttackSurfaceReductionService,
    AttackSurfaceReductionState,
    AttackSurfaceReductionStore,
    AttackSurfaceReductionTimedOut,
    AttackSurfaceSnapshot,
    OfflineRedTeamReconAdapter,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamReconObservation,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.workflows import Visibility

PEER = "10.20.30.40"
POLICY = "7" * 64


class _SurfaceAdapter:
    def __init__(self, *, plan, scope, status_code, evidence_ref, target_id=None):
        self.plan = plan
        self.scope = scope
        self.status_code = status_code
        self.evidence_ref = evidence_ref
        self.target_id = target_id or plan.target.target_id

    def execute(self, action, *, now):
        requested = hashlib.sha256(action.target_url.encode()).hexdigest()
        surface = AttackSurfaceSnapshot.create(
            plan_id=self.plan.plan_id,
            action_id=action.action_id,
            target_id=self.target_id,
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            requested_url_digest=requested,
            final_url_digest=requested,
            status_code=self.status_code,
            peer_ip=PEER,
            redirect_count=0,
            evidence_refs=(self.evidence_ref,),
            policy_record_digests=(POLICY,),
            captured_at=now,
        )
        return RedTeamReconObservation.create(
            action_id=action.action_id,
            outcome=ReconOutcome.SUCCEEDED,
            status_code=self.status_code,
            reason_code="fixture_surface_observed",
            cleanup_complete=True,
            sensitive_data_redacted=True,
            attack_surface=surface,
            observed_at=now,
        )


class _FailOnceReductionStore(AttackSurfaceReductionStore):
    def __init__(self, path, *, failures=1):
        super().__init__(path)
        self.failures = failures

    def complete(self, outcome, *, completed_at):
        if self.failures:
            self.failures -= 1
            raise RuntimeError("synthetic interruption before completion")
        return super().complete(outcome, completed_at=completed_at)


def _flow(tmp_path, approved_scope, now, *, surfaces=2):
    red_store = RedTeamStore(tmp_path / "red-team.sqlite3")
    service = RedTeamService(store=red_store)
    plan = service.prepare(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=4,
        max_consecutive_failures=3,
        emergency_contact_ref="contact:surface-owner",
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="red-team:surface-flow",
    )
    checkpoint = service.create_and_start(plan, scope=approved_scope, now=now)
    evidence_store = EvidenceStore(tmp_path / "evidence")
    for ordinal in range(surfaces):
        observed_at = now + timedelta(seconds=ordinal)
        evidence = evidence_store.capture_text(
            f"redacted surface evidence {ordinal}",
            kind=EvidenceKind.HTTP,
            source_ref="url-sha256:" + hashlib.sha256(str(ordinal).encode()).hexdigest(),
            producer="test.red-team.surface",
            target_version=plan.plan_id,
            summary=f"surface status {200 + ordinal * 4}",
        )
        command = service.prepare_recon(
            plan=plan,
            checkpoint=checkpoint,
            scope=approved_scope,
            kind=RedTeamActionKind.HTTP_HEAD,
            test_class="read_only",
            now=observed_at,
            ttl_seconds=30,
            idempotency_key=f"red-team:surface-action:{ordinal}",
        )
        checkpoint, _ = service.execute_recon(
            command=command,
            scope=approved_scope,
            adapter=_SurfaceAdapter(
                plan=plan,
                scope=approved_scope,
                status_code=200 + ordinal * 4,
                evidence_ref=evidence.evidence_id,
            ),
            now=observed_at,
        )
    return red_store, service, plan, checkpoint, evidence_store


def _reducer(tmp_path, red_store, evidence_store, *, store=None, monotonic=None):
    reduction_store = store or AttackSurfaceReductionStore(tmp_path / "surface.sqlite3")
    kwargs = {
        "red_team_store": red_store,
        "reduction_store": reduction_store,
        "evidence_store": evidence_store,
    }
    if monotonic is not None:
        kwargs["monotonic"] = monotonic
    return AttackSurfaceReductionService(**kwargs), reduction_store


def _prepare(reducer, plan, checkpoint, scope, now, *, key="surface:reduce:1", limits=None):
    return reducer.prepare(
        flow_plan=plan,
        checkpoint=checkpoint,
        scope=scope,
        limits=limits or AttackSurfaceReductionLimits(),
        now=now + timedelta(seconds=3),
        deadline=now + timedelta(minutes=2),
        idempotency_key=key,
    )


def test_surface_reducer_deduplicates_facts_and_replays_transactionally(
    tmp_path, approved_scope, now
):
    red_store, _, plan, checkpoint, evidence_store = _flow(
        tmp_path, approved_scope, now
    )
    reducer, reduction_store = _reducer(tmp_path, red_store, evidence_store)
    reduction = _prepare(reducer, plan, checkpoint, approved_scope, now)

    outcome = reducer.execute(
        reduction, scope=approved_scope, now=now + timedelta(seconds=3)
    )
    endpoint = outcome.inventory.endpoints[0]
    assert endpoint.status_codes == (200, 204)
    assert endpoint.redirect_counts == (0,)
    assert len(endpoint.observation_ids) == 2
    assert len(endpoint.evidence_refs) == 2
    assert outcome.inventory.reduced_at == reduction.created_at
    assert outcome.cleanup_complete
    assert reduction_store.state(reduction.reduction_id) == (
        AttackSurfaceReductionState.COMPLETED,
        1,
    )
    assert (
        reducer.execute(
            reduction, scope=approved_scope, now=now + timedelta(seconds=4)
        )
        == outcome
    )
    red_store.close()
    reduction_store.close()


def test_surface_reducer_rejects_evidence_loss_and_stale_checkpoint_before_claim(
    tmp_path, approved_scope, now
):
    red_store, service, plan, checkpoint, evidence_store = _flow(
        tmp_path, approved_scope, now, surfaces=1
    )
    reducer, reduction_store = _reducer(tmp_path, red_store, evidence_store)
    reduction = _prepare(reducer, plan, checkpoint, approved_scope, now)
    observation = red_store.observation(checkpoint.observation_ids[0])
    assert observation.attack_surface is not None
    (evidence_store.objects / observation.attack_surface.evidence_refs[0]).unlink()
    with pytest.raises(AttackSurfaceReductionRejected, match="Evidence integrity"):
        reducer.execute(reduction, scope=approved_scope, now=now + timedelta(seconds=3))
    assert reduction_store.state(reduction.reduction_id) is None

    evidence_store.capture_text(
        "redacted surface evidence 0",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + hashlib.sha256(b"0").hexdigest(),
        producer="test.red-team.surface",
        target_version=plan.plan_id,
        summary="surface status 200",
    )
    next_command = service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=approved_scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now + timedelta(seconds=4),
        ttl_seconds=30,
        idempotency_key="red-team:surface-stale",
    )
    service.execute_recon(
        command=next_command,
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(),
        now=now + timedelta(seconds=4),
    )
    with pytest.raises(AttackSurfaceReductionRejected, match="binding drifted"):
        reducer.execute(reduction, scope=approved_scope, now=now + timedelta(seconds=5))
    assert reduction_store.state(reduction.reduction_id) is None
    red_store.close()
    reduction_store.close()


def test_surface_reducer_rejects_forged_provenance_and_revoked_scope_before_claim(
    tmp_path, approved_scope, now
):
    red_store, service, plan, checkpoint, evidence_store = _flow(
        tmp_path, approved_scope, now, surfaces=0
    )
    evidence = evidence_store.capture_text(
        "redacted forged-binding fixture",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "9" * 64,
        producer="test.red-team.surface",
        target_version=plan.plan_id,
        summary="forged binding fixture",
    )
    command = service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=approved_scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key="red-team:forged-surface",
    )
    checkpoint, _ = service.execute_recon(
        command=command,
        scope=approved_scope,
        adapter=_SurfaceAdapter(
            plan=plan,
            scope=approved_scope,
            status_code=200,
            evidence_ref=evidence.evidence_id,
            target_id=uuid4(),
        ),
        now=now,
    )
    reducer, reduction_store = _reducer(tmp_path, red_store, evidence_store)
    reduction = _prepare(reducer, plan, checkpoint, approved_scope, now)
    with pytest.raises(AttackSurfaceReductionRejected, match="provenance"):
        reducer.execute(reduction, scope=approved_scope, now=now + timedelta(seconds=3))
    assert reduction_store.state(reduction.reduction_id) is None

    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(AttackSurfaceReductionRejected, match="approved Scope"):
        reducer.execute(reduction, scope=revoked, now=now + timedelta(seconds=3))
    assert reduction_store.state(reduction.reduction_id) is None
    red_store.close()
    reduction_store.close()


def test_surface_reducer_timeout_leaves_no_started_checkpoint(tmp_path, approved_scope, now):
    red_store, _, plan, checkpoint, evidence_store = _flow(
        tmp_path, approved_scope, now, surfaces=1
    )
    ticks = iter((0.0, 1.0))
    reducer, reduction_store = _reducer(
        tmp_path, red_store, evidence_store, monotonic=lambda: next(ticks)
    )
    reduction = _prepare(
        reducer,
        plan,
        checkpoint,
        approved_scope,
        now,
        limits=AttackSurfaceReductionLimits(timeout_seconds=0.5),
    )
    with pytest.raises(AttackSurfaceReductionTimedOut):
        reducer.execute(reduction, scope=approved_scope, now=now + timedelta(seconds=3))
    assert reduction_store.state(reduction.reduction_id) is None
    red_store.close()
    reduction_store.close()


def test_surface_reducer_requires_explicit_bounded_recovery(tmp_path, approved_scope, now):
    red_store, _, plan, checkpoint, evidence_store = _flow(
        tmp_path, approved_scope, now, surfaces=1
    )
    reduction_store = _FailOnceReductionStore(tmp_path / "surface.sqlite3")
    reducer, _ = _reducer(
        tmp_path, red_store, evidence_store, store=reduction_store
    )
    reduction = _prepare(reducer, plan, checkpoint, approved_scope, now)
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        reducer.execute(reduction, scope=approved_scope, now=now + timedelta(seconds=3))
    assert reduction_store.state(reduction.reduction_id) == (
        AttackSurfaceReductionState.STARTED,
        1,
    )
    with pytest.raises(AttackSurfaceReductionRecoveryRequired):
        reducer.execute(reduction, scope=approved_scope, now=now + timedelta(seconds=4))
    recovered = reducer.recover(
        reduction, scope=approved_scope, now=now + timedelta(seconds=5)
    )
    assert recovered.attempt == 2
    assert recovered.cleanup_complete
    assert reduction_store.state(reduction.reduction_id) == (
        AttackSurfaceReductionState.COMPLETED,
        2,
    )
    red_store.close()
    reduction_store.close()


def test_surface_reducer_exhausts_bounded_recovery_attempts(
    tmp_path, approved_scope, now
):
    red_store, _, plan, checkpoint, evidence_store = _flow(
        tmp_path, approved_scope, now, surfaces=1
    )
    reduction_store = _FailOnceReductionStore(
        tmp_path / "surface.sqlite3", failures=2
    )
    reducer, _ = _reducer(
        tmp_path, red_store, evidence_store, store=reduction_store
    )
    reduction = _prepare(
        reducer,
        plan,
        checkpoint,
        approved_scope,
        now,
        limits=AttackSurfaceReductionLimits(max_attempts=2),
    )
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        reducer.execute(reduction, scope=approved_scope, now=now + timedelta(seconds=3))
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        reducer.recover(reduction, scope=approved_scope, now=now + timedelta(seconds=4))
    with pytest.raises(AttackSurfaceReductionRecoveryRequired, match="exhausted"):
        reducer.recover(reduction, scope=approved_scope, now=now + timedelta(seconds=5))
    assert reduction_store.state(reduction.reduction_id) == (
        AttackSurfaceReductionState.STARTED,
        2,
    )
    red_store.close()
    reduction_store.close()


def test_surface_reducer_rejects_empty_input_idempotency_collision_and_raw_fields(
    tmp_path, approved_scope, now
):
    red_store, _, plan, checkpoint, evidence_store = _flow(
        tmp_path, approved_scope, now, surfaces=0
    )
    service = RedTeamService(store=red_store)
    command = service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=approved_scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key="red-team:offline-only",
    )
    checkpoint, _ = service.execute_recon(
        command=command,
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(),
        now=now,
    )
    reducer, reduction_store = _reducer(tmp_path, red_store, evidence_store)
    with pytest.raises(AttackSurfaceReductionRejected, match="trusted live"):
        _prepare(reducer, plan, checkpoint, approved_scope, now)
    red_store.close()
    reduction_store.close()


def test_surface_reduction_cli_uses_same_offline_service_contract(
    tmp_path, approved_scope, now, capsys, monkeypatch
):
    red_store, _, plan, _, _ = _flow(tmp_path, approved_scope, now, surfaces=1)
    red_store.close()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(approved_scope.model_dump_json(), encoding="utf-8")
    reduction_file = tmp_path / "reduction.json"
    surface_db = tmp_path / "surface.sqlite3"
    monkeypatch.setattr(
        "vulnloom.red_team.cli.utc_now", lambda: now + timedelta(seconds=3)
    )

    assert main(
        [
            "red-team",
            "prepare-surface-reduction",
            "--plan-id",
            plan.plan_id,
            "--scope-file",
            str(scope_file),
            "--idempotency-key",
            "surface:cli:1",
            "--red-team-db",
            str(tmp_path / "red-team.sqlite3"),
            "--surface-db",
            str(surface_db),
            "--evidence-root",
            str(tmp_path / "evidence"),
        ]
    ) == 0
    prepared = json.loads(capsys.readouterr().out)["reduction"]
    reduction_file.write_text(json.dumps(prepared), encoding="utf-8")

    assert main(
        [
            "red-team",
            "run-surface-reduction-offline",
            "--reduction-file",
            str(reduction_file),
            "--scope-file",
            str(scope_file),
            "--red-team-db",
            str(tmp_path / "red-team.sqlite3"),
            "--surface-db",
            str(surface_db),
            "--evidence-root",
            str(tmp_path / "evidence"),
        ]
    ) == 0
    outcome = json.loads(capsys.readouterr().out)["outcome"]
    assert outcome["cleanup_complete"] is True
    assert len(outcome["inventory"]["endpoints"]) == 1
    reduction_id = prepared["reduction_id"]

    assert main(
        [
            "red-team",
            "surface-status",
            "--reduction-id",
            reduction_id,
            "--surface-db",
            str(surface_db),
        ]
    ) == 0
    status = json.loads(capsys.readouterr().out)
    assert status == {
        "reduction_id": reduction_id,
        "state": "completed",
        "attempt": 1,
        "inventory_id": outcome["inventory"]["inventory_id"],
        "endpoint_count": 1,
        "observation_count": 1,
        "evidence_count": 1,
        "cleanup_complete": True,
    }


def test_surface_reducer_rejects_idempotency_collision_and_raw_contract_fields(
    tmp_path, approved_scope, now
):
    red_store, _, plan, checkpoint, evidence_store = _flow(
        tmp_path / "collision", approved_scope, now, surfaces=1
    )
    reducer, reduction_store = _reducer(
        tmp_path / "collision", red_store, evidence_store
    )
    first = _prepare(reducer, plan, checkpoint, approved_scope, now, key="same-key")
    reducer.execute(first, scope=approved_scope, now=now + timedelta(seconds=3))
    second = reducer.prepare(
        flow_plan=plan,
        checkpoint=checkpoint,
        scope=approved_scope,
        limits=AttackSurfaceReductionLimits(max_endpoints=2),
        now=now + timedelta(seconds=4),
        deadline=now + timedelta(minutes=2),
        idempotency_key="same-key",
    )
    with pytest.raises(AttackSurfaceReductionIdempotencyConflict):
        reducer.execute(second, scope=approved_scope, now=now + timedelta(seconds=4))

    schema = json.dumps(
        [
            model.model_json_schema()
            for model in (
                AttackSurfaceEndpoint,
                AttackSurfaceInventory,
                AttackSurfaceReductionLimits,
                AttackSurfaceReductionOutcome,
                AttackSurfaceReductionPlan,
            )
        ]
    ).lower()
    for forbidden in (
        "authorization",
        "cookie",
        "api_key",
        "response_body",
        "response_headers",
        "target_url",
    ):
        assert forbidden not in schema
    database = (tmp_path / "collision" / "surface.sqlite3").read_text(errors="ignore")
    assert plan.target.url not in database
    assert "synthetic-secret" not in database
    red_store.close()
    reduction_store.close()
