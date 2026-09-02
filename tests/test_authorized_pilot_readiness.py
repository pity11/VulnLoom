from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    REQUIRED_PILOT_FORBIDDEN_CAPABILITIES,
    REQUIRED_PILOT_HUMAN_GATES,
    AuthorizedPilotReadinessArtifactStore,
    AuthorizedPilotReadinessConflict,
    AuthorizedPilotReadinessPlan,
    AuthorizedPilotReadinessPolicy,
    AuthorizedPilotReadinessRecoveryRequired,
    AuthorizedPilotReadinessRejected,
    AuthorizedPilotReadinessService,
    AuthorizedPilotReadinessStore,
    AuthorizedPilotReadinessTimedOut,
    BenchmarkGateStatus,
    LocalSourceEffectCounters,
    LocalSourceRobustnessResult,
)
from vulnloom.benchmark.pilot_readiness_fixture import PILOT_NOW, build_pilot_fixture
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ScopeState


def _service(tmp_path: Path, *, max_artifact_bytes: int = 1024 * 1024):
    store = AuthorizedPilotReadinessStore(tmp_path / "readiness.sqlite3")
    artifacts = AuthorizedPilotReadinessArtifactStore(
        tmp_path / "readiness-artifacts", max_artifact_bytes=max_artifact_bytes
    )
    return store, artifacts, AuthorizedPilotReadinessService(store=store, artifact_store=artifacts)


def _evaluate(service, fixture, *, plan=None, scope=None, now=PILOT_NOW):
    return service.evaluate(
        scope=scope or fixture.scope,
        snapshot=fixture.snapshot,
        target_store_root=fixture.target_store_root,
        graph=fixture.graph,
        candidate_set=fixture.candidate_set,
        quality_profile=fixture.quality_profile,
        quality_result=fixture.quality_result,
        manifest=fixture.manifest,
        plan=plan or fixture.plan,
        now=now,
    )


def test_authorized_local_pilot_passes_and_replays_without_operational_effects(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    store, artifacts, service = _service(tmp_path)
    try:
        first = _evaluate(service, fixture)
        second = _evaluate(service, fixture)
        loaded = artifacts.read_result(first.artifact)
    finally:
        store.close()

    assert first == second
    assert loaded == first.result
    assert first.result.gate_status is BenchmarkGateStatus.PASSED
    assert first.result.violations == ()
    assert first.result.metrics.source_file_count == 18
    assert first.result.metrics.candidate_count == 5
    assert first.result.metrics.proposed_candidate_count == 5
    assert first.result.metrics.human_gate_count == len(REQUIRED_PILOT_HUMAN_GATES) == 10
    assert len(REQUIRED_PILOT_FORBIDDEN_CAPABILITIES) == 8
    assert first.result.metrics.forbidden_effect_count == 0
    assert fixture.manifest.selected_candidate_ids == ()

    persisted = (tmp_path / "readiness.sqlite3").read_bytes() + b"".join(
        path.read_bytes()
        for path in (tmp_path / "readiness-artifacts").rglob("*")
        if path.is_file()
    )
    assert b"Invoice.query" not in persisted
    assert b"signed-authorization" not in persisted


def test_nonzero_forbidden_effect_fails_closed(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    plan = AuthorizedPilotReadinessPlan.create(
        manifest=fixture.manifest,
        quality_profile=fixture.quality_profile,
        quality_result=fixture.quality_result,
        policy=AuthorizedPilotReadinessPolicy(),
        effects=LocalSourceEffectCounters(runner_calls=1, submissions=1),
        created_at=PILOT_NOW,
        deadline=PILOT_NOW + timedelta(minutes=5),
        idempotency_key="m9.5-effects-rejected",
    )
    store, _, service = _service(tmp_path)
    try:
        outcome = _evaluate(service, fixture, plan=plan)
    finally:
        store.close()
    assert outcome.result.gate_status is BenchmarkGateStatus.FAILED
    assert tuple(item.code for item in outcome.result.violations) == ("forbidden_effect_observed",)
    assert outcome.result.metrics.forbidden_effect_count == 2


def test_failed_bound_quality_result_fails_readiness(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    values = fixture.quality_result.model_dump(mode="python", exclude={"result_id"}) | {
        "violations": ("negative_candidate_observed",),
        "gate_status": BenchmarkGateStatus.FAILED,
    }
    values["metrics"] = fixture.quality_result.metrics
    digest_values = values | {"metrics": fixture.quality_result.metrics.model_dump(mode="python")}
    failed_quality = LocalSourceRobustnessResult(
        result_id=canonical_digest(digest_values), **values
    )
    plan = AuthorizedPilotReadinessPlan.create(
        manifest=fixture.manifest,
        quality_profile=fixture.quality_profile,
        quality_result=failed_quality,
        policy=AuthorizedPilotReadinessPolicy(),
        effects=LocalSourceEffectCounters(),
        created_at=PILOT_NOW,
        deadline=PILOT_NOW + timedelta(minutes=5),
        idempotency_key="m9.5-quality-rejected",
    )
    store, _, service = _service(tmp_path)
    try:
        outcome = service.evaluate(
            scope=fixture.scope,
            snapshot=fixture.snapshot,
            target_store_root=fixture.target_store_root,
            graph=fixture.graph,
            candidate_set=fixture.candidate_set,
            quality_profile=fixture.quality_profile,
            quality_result=failed_quality,
            manifest=fixture.manifest,
            plan=plan,
            now=PILOT_NOW,
        )
    finally:
        store.close()
    assert outcome.result.gate_status is BenchmarkGateStatus.FAILED
    assert tuple(item.code for item in outcome.result.violations) == ("quality_gate_failed",)


def test_scope_snapshot_and_analysis_drift_are_rejected_before_checkpoint(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    store, _, service = _service(tmp_path)
    try:
        with pytest.raises(AuthorizedPilotReadinessRejected, match="authorization"):
            _evaluate(
                service,
                fixture,
                scope=fixture.scope.model_copy(update={"state": ScopeState.REVOKED}),
            )
        changed = fixture.candidate_set.model_copy(update={"generator_version": "untrusted-change"})
        with pytest.raises(AuthorizedPilotReadinessRejected, match="analysis content drifted"):
            service.evaluate(
                scope=fixture.scope,
                snapshot=fixture.snapshot,
                target_store_root=fixture.target_store_root,
                graph=fixture.graph,
                candidate_set=changed,
                quality_profile=fixture.quality_profile,
                quality_result=fixture.quality_result,
                manifest=fixture.manifest,
                plan=fixture.plan,
                now=PILOT_NOW,
            )
        count = store.connection.execute(
            "SELECT COUNT(*) FROM authorized_pilot_readiness"
        ).fetchone()[0]
    finally:
        store.close()
    assert count == 0


def test_timeout_is_rejected_before_checkpoint(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    store, _, service = _service(tmp_path)
    try:
        with pytest.raises(AuthorizedPilotReadinessTimedOut):
            _evaluate(service, fixture, now=fixture.plan.deadline)
        count = store.connection.execute(
            "SELECT COUNT(*) FROM authorized_pilot_readiness"
        ).fetchone()[0]
    finally:
        store.close()
    assert count == 0


def test_artifact_failure_cleans_temporary_data_and_requires_recovery(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    store, artifacts, service = _service(tmp_path, max_artifact_bytes=1)
    try:
        with pytest.raises(ValueError, match="size limit"):
            _evaluate(service, fixture)
        assert tuple(artifacts.objects.iterdir()) == ()
        state = store.connection.execute("SELECT state FROM authorized_pilot_readiness").fetchone()[
            0
        ]
        with pytest.raises(AuthorizedPilotReadinessRecoveryRequired):
            _evaluate(service, fixture)
    finally:
        store.close()
    assert state == "started"


def test_idempotency_and_manifest_reuse_conflict(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    store, _, service = _service(tmp_path)
    try:
        _evaluate(service, fixture)
        conflicting = AuthorizedPilotReadinessPlan.create(
            manifest=fixture.manifest,
            quality_profile=fixture.quality_profile,
            quality_result=fixture.quality_result,
            policy=AuthorizedPilotReadinessPolicy(),
            effects=LocalSourceEffectCounters(),
            created_at=PILOT_NOW,
            deadline=PILOT_NOW + timedelta(minutes=10),
            idempotency_key="m9.5-conflicting-plan",
        )
        with pytest.raises(AuthorizedPilotReadinessConflict):
            _evaluate(service, fixture, plan=conflicting)
    finally:
        store.close()


def test_artifact_symlink_is_rejected(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    store, artifacts, service = _service(tmp_path)
    try:
        outcome = _evaluate(service, fixture)
        result_path = artifacts.root / outcome.artifact.json_ref
        directory = result_path.parent
        os.chmod(directory, 0o700)
        result_path.unlink()
        result_path.symlink_to(directory / "result.md")
        with pytest.raises(ValueError, match="unsafe"):
            artifacts.read_result(outcome.artifact)
    finally:
        store.close()


def test_policy_and_manifest_cannot_remove_human_gates_or_enable_actions(tmp_path):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    with pytest.raises(ValidationError, match="less than or equal to 0"):
        AuthorizedPilotReadinessPolicy(max_forbidden_effects=1)
    changed = fixture.manifest.model_dump(mode="python") | {
        "required_human_gates": REQUIRED_PILOT_HUMAN_GATES[:-1]
    }
    changed["pilot_manifest_id"] = canonical_digest(
        {key: value for key, value in changed.items() if key != "pilot_manifest_id"}
    )
    with pytest.raises(ValidationError, match="cannot be changed"):
        fixture.manifest.__class__.model_validate(changed)
    changed = fixture.manifest.model_dump(mode="python") | {
        "forbidden_capabilities": REQUIRED_PILOT_FORBIDDEN_CAPABILITIES[:-1]
    }
    changed["pilot_manifest_id"] = canonical_digest(
        {key: value for key, value in changed.items() if key != "pilot_manifest_id"}
    )
    with pytest.raises(ValidationError, match="cannot be changed"):
        fixture.manifest.__class__.model_validate(changed)
