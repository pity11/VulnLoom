from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.cli import main
from vulnloom.domain.models import EvidenceKind, ScopeState
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    AttackSurfaceChangeKind,
    AttackSurfaceDriftIdempotencyConflict,
    AttackSurfaceDriftLimits,
    AttackSurfaceDriftRecoveryRequired,
    AttackSurfaceDriftRejected,
    AttackSurfaceDriftService,
    AttackSurfaceDriftState,
    AttackSurfaceDriftStore,
    AttackSurfaceDriftTimedOut,
    AttackSurfaceEndpoint,
    AttackSurfaceInventory,
    AttackSurfaceReductionLimits,
    AttackSurfaceReductionOutcome,
    AttackSurfaceReductionPlan,
    AttackSurfaceReductionStore,
    AttackSurfaceServiceIdentity,
    ServiceIdentitySnapshot,
    ServiceTlsVersion,
)

REQUESTED = "1" * 64
FINAL_A = "2" * 64
FINAL_B = "3" * 64
POLICY = "4" * 64


class _InventorySource:
    def __init__(self, outcomes):
        self.outcomes = dict(outcomes)

    def outcome(self, reduction_id):
        return self.outcomes[reduction_id]


class _FailOnceStore(AttackSurfaceDriftStore):
    def __init__(self, path, *, failures=1):
        super().__init__(path)
        self.failures = failures

    def complete(self, outcome, *, completed_at):
        if self.failures:
            self.failures -= 1
            raise RuntimeError("synthetic completion interruption")
        return super().complete(outcome, completed_at=completed_at)


def _inventory(
    *,
    reduction_id,
    scope,
    target_id,
    reduced_at,
    evidence_ref,
    final=FINAL_A,
    peer="192.0.2.10",
    status=200,
    redirect=0,
    certificate="5" * 64,
    tls_version=ServiceTlsVersion.TLS_1_2,
    cipher="ECDHE_RSA_AES256_GCM_SHA384",
    endpoint=True,
    identity=True,
):
    observation_ids = []
    snapshot_ids = []
    endpoints = []
    identities = []
    if endpoint:
        observation_id = reduction_id[0] * 64
        snapshot_id = reduction_id[1] * 64
        observation_ids.append(observation_id)
        snapshot_ids.append(snapshot_id)
        endpoints.append(
            AttackSurfaceEndpoint.create(
                requested_url_digest=REQUESTED,
                final_url_digest=final,
                peer_ip=peer,
                status_codes=(status,),
                redirect_counts=(redirect,),
                observation_ids=(observation_id,),
                snapshot_ids=(snapshot_id,),
                evidence_refs=(evidence_ref,),
                first_observed_at=reduced_at - timedelta(seconds=1),
                last_observed_at=reduced_at - timedelta(seconds=1),
            )
        )
    if identity:
        observation_id = reduction_id[2] * 64
        identity_snapshot = ServiceIdentitySnapshot.create(
            plan_id=reduction_id[3] * 64,
            action_id=reduction_id[4] * 64,
            target_id=target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            endpoint_url_digest=REQUESTED,
            peer_ip=peer,
            tls_version=tls_version,
            cipher_suite=cipher,
            cipher_bits=256,
            leaf_certificate_sha256=certificate,
            evidence_refs=(evidence_ref,),
            policy_record_digests=(POLICY,),
            captured_at=reduced_at - timedelta(seconds=1),
        )
        observation_ids.append(observation_id)
        snapshot_ids.append(identity_snapshot.snapshot_id)
        identities.append(
            AttackSurfaceServiceIdentity(
                observation_id=observation_id,
                identity=identity_snapshot,
            )
        )
        if endpoints:
            endpoints[0] = endpoints[0].model_copy(
                update={"service_identity_ids": (identity_snapshot.snapshot_id,)}
            )
    inventory = AttackSurfaceInventory.create(
        reduction_id=reduction_id,
        flow_plan_id=reduction_id[5] * 64,
        source_checkpoint_id=reduction_id[6] * 64,
        target_id=target_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        observation_ids=tuple(sorted(observation_ids)),
        snapshot_ids=tuple(sorted(snapshot_ids)),
        evidence_refs=(evidence_ref,),
        endpoints=tuple(endpoints),
        service_identities=tuple(identities),
        reduced_at=reduced_at,
    )
    return AttackSurfaceReductionOutcome(
        reduction_id=reduction_id,
        inventory=inventory,
        attempt=1,
        cleanup_complete=True,
    )


def _runtime(tmp_path, approved_scope, now, *, drift_store=None, monotonic=None):
    evidence_store = EvidenceStore(tmp_path / "evidence")
    old_evidence = evidence_store.capture_text(
        "redacted baseline facts",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "a" * 64,
        producer="test.drift",
        target_version="baseline",
        summary="baseline",
    )
    new_evidence = evidence_store.capture_text(
        "redacted current facts",
        kind=EvidenceKind.TLS,
        source_ref="url-sha256:" + "b" * 64,
        producer="test.drift",
        target_version="current",
        summary="current",
    )
    target_id = uuid4()
    baseline_id = "abcdef0" * 9 + "a"
    current_id = "bcdef01" * 9 + "b"
    baseline = _inventory(
        reduction_id=baseline_id,
        scope=approved_scope,
        target_id=target_id,
        reduced_at=now - timedelta(minutes=2),
        evidence_ref=old_evidence.evidence_id,
    )
    current = _inventory(
        reduction_id=current_id,
        scope=approved_scope,
        target_id=target_id,
        reduced_at=now - timedelta(minutes=1),
        evidence_ref=new_evidence.evidence_id,
        final=FINAL_B,
        peer="192.0.2.11",
        status=204,
        redirect=1,
        certificate="6" * 64,
        tls_version=ServiceTlsVersion.TLS_1_3,
        cipher="TLS_AES_256_GCM_SHA384",
    )
    store = drift_store or AttackSurfaceDriftStore(tmp_path / "drift.sqlite3")
    kwargs = {
        "inventory_source": _InventorySource(
            {baseline_id: baseline, current_id: current}
        ),
        "drift_store": store,
        "evidence_store": evidence_store,
    }
    if monotonic is not None:
        kwargs["monotonic"] = monotonic
    service = AttackSurfaceDriftService(**kwargs)
    return service, store, evidence_store, baseline, current


def _plan(service, baseline, current, scope, now, *, limits=None, key="drift:1"):
    return service.prepare(
        baseline_reduction_id=baseline.reduction_id,
        current_reduction_id=current.reduction_id,
        scope=scope,
        limits=limits or AttackSurfaceDriftLimits(),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )


def test_drift_reports_http_tls_and_peer_changes_and_replays(tmp_path, approved_scope, now):
    service, store, _, baseline, current = _runtime(tmp_path, approved_scope, now)
    plan = _plan(service, baseline, current, approved_scope, now)
    first = service.execute(plan, scope=approved_scope, now=now)
    replay = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    )

    assert replay == first
    assert first.attempt == 1
    assert first.cleanup_complete
    assert first.report.compared_surface_count == 1
    assert first.report.unchanged_surface_count == 0
    assert set(first.report.changes[0].change_kinds) == {
        AttackSurfaceChangeKind.PEER_SET_CHANGED,
        AttackSurfaceChangeKind.FINAL_DESTINATION_CHANGED,
        AttackSurfaceChangeKind.HTTP_STATUS_CHANGED,
        AttackSurfaceChangeKind.REDIRECT_BEHAVIOR_CHANGED,
        AttackSurfaceChangeKind.TLS_VERSION_CHANGED,
        AttackSurfaceChangeKind.CIPHER_CHANGED,
        AttackSurfaceChangeKind.CERTIFICATE_CHANGED,
    }
    assert "https://" not in first.model_dump_json()
    assert store.state(plan.comparison_id) == (AttackSurfaceDriftState.COMPLETED, 1)
    store.close()


def test_drift_detects_endpoint_removal_and_tls_addition(tmp_path, approved_scope, now):
    service, store, _, baseline, current = _runtime(tmp_path, approved_scope, now)
    current_inventory = _inventory(
        reduction_id=current.reduction_id,
        scope=approved_scope,
        target_id=baseline.inventory.target_id,
        reduced_at=current.inventory.reduced_at,
        evidence_ref=current.inventory.evidence_refs[0],
        endpoint=False,
        identity=True,
    )
    baseline_inventory = _inventory(
        reduction_id=baseline.reduction_id,
        scope=approved_scope,
        target_id=baseline.inventory.target_id,
        reduced_at=baseline.inventory.reduced_at,
        evidence_ref=baseline.inventory.evidence_refs[0],
        endpoint=True,
        identity=False,
    )
    service.inventory_source = _InventorySource(
        {
            baseline.reduction_id: baseline_inventory,
            current.reduction_id: current_inventory,
        }
    )
    plan = _plan(
        service, baseline_inventory, current_inventory, approved_scope, now
    )
    outcome = service.execute(plan, scope=approved_scope, now=now)
    assert set(outcome.report.changes[0].change_kinds) == {
        AttackSurfaceChangeKind.ENDPOINT_REMOVED,
        AttackSurfaceChangeKind.TLS_IDENTITY_ADDED,
    }
    store.close()


def test_drift_separates_unchanged_facts_from_new_evidence(
    tmp_path, approved_scope, now
):
    service, store, _, baseline, current = _runtime(tmp_path, approved_scope, now)
    unchanged = _inventory(
        reduction_id=current.reduction_id,
        scope=approved_scope,
        target_id=baseline.inventory.target_id,
        reduced_at=current.inventory.reduced_at,
        evidence_ref=current.inventory.evidence_refs[0],
    )
    service.inventory_source = _InventorySource(
        {baseline.reduction_id: baseline, current.reduction_id: unchanged}
    )
    plan = _plan(service, baseline, unchanged, approved_scope, now)
    outcome = service.execute(plan, scope=approved_scope, now=now)
    assert outcome.report.compared_surface_count == 1
    assert outcome.report.unchanged_surface_count == 1
    assert outcome.report.changes == ()
    assert outcome.report.evidence_refs == ()
    store.close()


def test_drift_rejects_missing_evidence_reversed_time_and_revoked_scope(
    tmp_path, approved_scope, now
):
    service, store, evidence_store, baseline, current = _runtime(
        tmp_path, approved_scope, now
    )
    missing = current.inventory.evidence_refs[0]
    (evidence_store.objects / missing).unlink()
    with pytest.raises(AttackSurfaceDriftRejected, match="Evidence integrity"):
        _plan(service, baseline, current, approved_scope, now)
    assert store.state("0" * 64) is None

    service, store2, _, baseline, current = _runtime(
        tmp_path / "reversed", approved_scope, now
    )
    with pytest.raises(AttackSurfaceDriftRejected, match="ordered inventories"):
        service.prepare(
            baseline_reduction_id=current.reduction_id,
            current_reduction_id=baseline.reduction_id,
            scope=approved_scope,
            limits=AttackSurfaceDriftLimits(),
            now=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="drift:reversed",
        )
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(AttackSurfaceDriftRejected, match="current Scope"):
        _plan(service, baseline, current, revoked, now)
    store.close()
    store2.close()


def test_drift_timeout_happens_before_checkpoint(tmp_path, approved_scope, now):
    values = iter((0.0, 1.0))
    service, store, _, baseline, current = _runtime(
        tmp_path, approved_scope, now, monotonic=lambda: next(values)
    )
    plan = _plan(
        service,
        baseline,
        current,
        approved_scope,
        now,
        limits=AttackSurfaceDriftLimits(timeout_seconds=0.5),
    )
    with pytest.raises(AttackSurfaceDriftTimedOut):
        service.execute(plan, scope=approved_scope, now=now)
    assert store.state(plan.comparison_id) is None
    store.close()


def test_drift_reloads_sources_and_rejects_binding_change_before_claim(
    tmp_path, approved_scope, now
):
    service, store, _, baseline, current = _runtime(tmp_path, approved_scope, now)
    plan = _plan(service, baseline, current, approved_scope, now)
    changed = _inventory(
        reduction_id=current.reduction_id,
        scope=approved_scope,
        target_id=current.inventory.target_id,
        reduced_at=current.inventory.reduced_at,
        evidence_ref=current.inventory.evidence_refs[0],
        status=500,
    )
    service.inventory_source = _InventorySource(
        {baseline.reduction_id: baseline, current.reduction_id: changed}
    )
    with pytest.raises(AttackSurfaceDriftRejected, match="source binding changed"):
        service.execute(plan, scope=approved_scope, now=now)
    assert store.state(plan.comparison_id) is None
    store.close()


def test_drift_interruption_requires_explicit_bounded_recovery(
    tmp_path, approved_scope, now
):
    store = _FailOnceStore(tmp_path / "drift.sqlite3")
    service, _, _, baseline, current = _runtime(
        tmp_path, approved_scope, now, drift_store=store
    )
    plan = _plan(service, baseline, current, approved_scope, now)
    with pytest.raises(RuntimeError, match="interruption"):
        service.execute(plan, scope=approved_scope, now=now)
    assert store.state(plan.comparison_id) == (AttackSurfaceDriftState.STARTED, 1)
    with pytest.raises(AttackSurfaceDriftRecoveryRequired):
        service.execute(plan, scope=approved_scope, now=now)
    recovered = service.recover(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    )
    assert recovered.attempt == 2
    assert recovered.cleanup_complete
    store.close()


def test_drift_idempotency_conflict_fails_closed(tmp_path, approved_scope, now):
    service, store, _, baseline, current = _runtime(tmp_path, approved_scope, now)
    plan = _plan(service, baseline, current, approved_scope, now)
    service.execute(plan, scope=approved_scope, now=now)
    collision = _plan(
        service,
        baseline,
        current,
        approved_scope,
        now + timedelta(seconds=1),
        key=plan.idempotency_key,
    )
    with pytest.raises(AttackSurfaceDriftIdempotencyConflict):
        service.execute(
            collision, scope=approved_scope, now=now + timedelta(seconds=1)
        )
    store.close()


def test_drift_recovery_attempts_are_bounded(tmp_path, approved_scope, now):
    store = _FailOnceStore(tmp_path / "drift.sqlite3", failures=2)
    service, _, _, baseline, current = _runtime(
        tmp_path, approved_scope, now, drift_store=store
    )
    plan = _plan(
        service,
        baseline,
        current,
        approved_scope,
        now,
        limits=AttackSurfaceDriftLimits(max_attempts=2),
    )
    with pytest.raises(RuntimeError):
        service.execute(plan, scope=approved_scope, now=now)
    with pytest.raises(RuntimeError):
        service.recover(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    with pytest.raises(AttackSurfaceDriftRecoveryRequired, match="exhausted"):
        service.recover(plan, scope=approved_scope, now=now + timedelta(seconds=2))
    assert store.state(plan.comparison_id) == (AttackSurfaceDriftState.STARTED, 2)
    store.close()


def _persist_source(store, outcome, scope, now, key):
    inventory = outcome.inventory
    plan = AttackSurfaceReductionPlan.create(
        flow_plan_id=inventory.flow_plan_id,
        source_checkpoint_id=inventory.source_checkpoint_id,
        target_id=inventory.target_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        observation_ids=inventory.observation_ids,
        snapshot_ids=inventory.snapshot_ids,
        limits=AttackSurfaceReductionLimits(),
        created_at=inventory.reduced_at - timedelta(seconds=1),
        deadline=now + timedelta(minutes=5),
        idempotency_key=key,
    )
    rebound_inventory = AttackSurfaceInventory.create(
        reduction_id=plan.reduction_id,
        flow_plan_id=inventory.flow_plan_id,
        source_checkpoint_id=inventory.source_checkpoint_id,
        target_id=inventory.target_id,
        scope_id=inventory.scope_id,
        scope_version=inventory.scope_version,
        observation_ids=inventory.observation_ids,
        snapshot_ids=inventory.snapshot_ids,
        evidence_refs=inventory.evidence_refs,
        endpoints=inventory.endpoints,
        service_identities=inventory.service_identities,
        reduced_at=inventory.reduced_at,
    )
    rebound = AttackSurfaceReductionOutcome(
        reduction_id=plan.reduction_id,
        inventory=rebound_inventory,
        attempt=1,
        cleanup_complete=True,
    )
    store.claim(plan, now=now)
    store.complete(rebound, completed_at=now)
    return rebound


def test_drift_cli_prepares_runs_and_reports_redacted_status(
    tmp_path, approved_scope, now, capsys
):
    _, drift_store, evidence_store, baseline, current = _runtime(
        tmp_path / "fixtures", approved_scope, now
    )
    drift_store.close()
    surface_db = tmp_path / "surface.sqlite3"
    with AttackSurfaceReductionStore(surface_db) as source_store:
        baseline = _persist_source(
            source_store, baseline, approved_scope, now, "source:baseline"
        )
        current = _persist_source(
            source_store, current, approved_scope, now, "source:current"
        )
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(approved_scope.model_dump_json(), encoding="utf-8")
    drift_db = tmp_path / "drift.sqlite3"
    arguments = [
        "red-team",
        "prepare-surface-drift",
        "--baseline-reduction-id",
        baseline.reduction_id,
        "--current-reduction-id",
        current.reduction_id,
        "--scope-file",
        str(scope_file),
        "--surface-db",
        str(surface_db),
        "--drift-db",
        str(drift_db),
        "--evidence-root",
        str(evidence_store.root),
        "--idempotency-key",
        "cli:drift",
    ]
    assert main(arguments) == 0
    comparison = json.loads(capsys.readouterr().out)["comparison"]
    comparison_file = tmp_path / "comparison.json"
    comparison_file.write_text(json.dumps(comparison), encoding="utf-8")
    assert main(
        [
            "red-team",
            "run-surface-drift-offline",
            "--comparison-file",
            str(comparison_file),
            "--scope-file",
            str(scope_file),
            "--surface-db",
            str(surface_db),
            "--drift-db",
            str(drift_db),
            "--evidence-root",
            str(evidence_store.root),
        ]
    ) == 0
    outcome_text = capsys.readouterr().out
    outcome = json.loads(outcome_text)["outcome"]
    assert "https://" not in outcome_text
    assert main(
        [
            "red-team",
            "surface-drift-status",
            "--comparison-id",
            comparison["comparison_id"],
            "--drift-db",
            str(drift_db),
        ]
    ) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["state"] == "completed"
    assert status["report_id"] == outcome["report"]["report_id"]
