from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    AUTOPENBENCH_ADAPTER_DIGEST,
    AUTOPENBENCH_ADAPTER_ID,
    AutoPenBenchSnapshotAdapter,
    BenchmarkObservation,
    BenchmarkObservationSet,
    BenchmarkSource,
    BountyBenchSnapshotAdapter,
    ExternalBenchmarkArtifactStore,
    ExternalBenchmarkImportPlan,
    ExternalBenchmarkImportService,
    ExternalBenchmarkImportStore,
    ExternalBenchmarkKind,
    ExternalBenchmarkRejected,
    ExternalImportIdempotencyConflict,
    ExternalImportLimits,
    ExternalImportRecoveryRequired,
    create_external_snapshot,
    evaluate_metrics,
)
from vulnloom.benchmark.external_io import ImportDeadline, inspect_snapshot_directory
from vulnloom.cli import main
from vulnloom.domain.models import CandidateState, CriticVerdict, ValidationResult


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _bounty_root(tmp_path):
    root = tmp_path / "bountytasks"
    root.mkdir(parents=True)
    (root / "LICENSE").write_text("Apache License 2.0", encoding="utf-8")
    _write_json(
        root / "lunary/bounties/bounty_0/bounty_metadata.json",
        {
            "bounty_link": "https://example.invalid/private-report",
            "CWE": "cwe-639",
            "CVE": "",
            "vulnerable_commit": "abc123-release",
            "detect_prompt_some_info": "secret prompt must not be normalized",
        },
    )
    _write_json(
        root / "lunary/bounties/bounty_1/bounty_metadata.json",
        {
            "CWE": "",
            "CVE": "CVE-2025-12345",
            "vulnerable_commit": "def456-release",
        },
    )
    exploit = root / "lunary/bounties/bounty_0/exploit_files/exploit.sh"
    exploit.parent.mkdir(parents=True)
    exploit.write_text("#!/bin/sh\necho should-never-be-read\n", encoding="utf-8")
    return root


def _auto_root(tmp_path):
    root = tmp_path / "autopenbench"
    (root / "data").mkdir(parents=True)
    (root / "LICENSE").write_text("MIT License", encoding="utf-8")
    _write_json(
        root / "data/games.json",
        {
            "in-vitro": {
                "web_security": [
                    {
                        "task": "private task text admin@example.test",
                        "flag": "SUPER-SECRET-FLAG",
                        "target": "in-vitro_web_security_vm0",
                        "vulnerability": "path traversal without replacement",
                    },
                    {
                        "task": "another private task",
                        "flag": "ANOTHER-SECRET-FLAG",
                        "target": "in-vitro_web_security_vm1",
                        "vulnerability": "sql injection",
                    },
                ]
            }
        },
    )
    _write_json(
        root / "vulnloom-autopenbench-cwe.json",
        {"in-vitro_web_security_vm0": "CWE-22"},
    )
    return root


def _snapshot(root, kind):
    return create_external_snapshot(
        root,
        kind=kind,
        upstream_revision="a" * 40,
        license_spdx=(
            "Apache-2.0" if kind is ExternalBenchmarkKind.BOUNTYBENCH else "MIT"
        ),
    )


def _plan(snapshot, adapter, now, *, key="external:1", limits=None):
    return ExternalBenchmarkImportPlan.create(
        snapshot=snapshot,
        adapter_id=adapter.adapter_id,
        adapter_digest=adapter.adapter_digest,
        limits=limits or ExternalImportLimits(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )


def _service(tmp_path, adapter):
    store = ExternalBenchmarkImportStore(tmp_path / "external.db")
    artifacts = ExternalBenchmarkArtifactStore(tmp_path / "external-artifacts")
    service = ExternalBenchmarkImportService(
        adapter=adapter,
        store=store,
        artifact_store=artifacts,
    )
    return service, store, artifacts


def test_bountybench_snapshot_normalizes_metadata_and_replays(tmp_path, now):
    root = _bounty_root(tmp_path)
    snapshot = _snapshot(root, ExternalBenchmarkKind.BOUNTYBENCH)
    adapter = BountyBenchSnapshotAdapter()
    plan = _plan(snapshot, adapter, now)
    service, store, artifacts = _service(tmp_path, adapter)

    first = service.import_snapshot(root, snapshot, plan, now=now)
    second = service.import_snapshot(root, snapshot, plan, now=now)

    assert first == second
    assert first.suite.source is BenchmarkSource.BOUNTYBENCH_SNAPSHOT
    assert first.suite.version == "a" * 40
    assert len(first.suite.cases) == 1
    assert first.suite.cases[0].target_version == "abc123-release"
    assert first.suite.cases[0].ground_truth[0].cwe == "CWE-639"
    assert first.exclusions[0].reason_code == "unsupported_or_missing_cwe"
    serialized = first.suite.model_dump_json()
    assert "secret prompt" not in serialized
    assert "private-report" not in serialized
    assert "exploit" not in serialized
    assert artifacts.read_suite(first.artifact) == first.suite
    case = first.suite.cases[0]
    observations = BenchmarkObservationSet.create(
        suite_id=first.suite.suite_id,
        observations=(
            BenchmarkObservation(
                case_id=case.case_id,
                target_version=case.target_version,
                candidate_id=uuid4(),
                candidate_state=CandidateState.PROMOTED,
                duplicate_fingerprint="9" * 64,
                matched_truth_id=case.ground_truth[0].truth_id,
                validation_result=ValidationResult.REPRODUCED,
                critic_verdict=CriticVerdict.ACCEPTED,
                finding_id=uuid4(),
                evidence_required=1,
                evidence_present=1,
                elapsed_ms=1,
                cost_microunits=0,
            ),
        ),
    )
    assert evaluate_metrics(first.suite, observations).candidate_recall == 1.0
    store.close()


def test_autopenbench_discards_flags_and_requires_explicit_cwe_mapping(tmp_path, now):
    root = _auto_root(tmp_path)
    snapshot = _snapshot(root, ExternalBenchmarkKind.AUTOPENBENCH)
    adapter = AutoPenBenchSnapshotAdapter()
    service, store, _ = _service(tmp_path, adapter)

    outcome = service.import_snapshot(root, snapshot, _plan(snapshot, adapter, now), now=now)

    assert outcome.suite.source is BenchmarkSource.AUTOPENBENCH_SNAPSHOT
    assert len(outcome.suite.cases) == 1
    assert outcome.suite.cases[0].ground_truth[0].cwe == "CWE-22"
    assert outcome.exclusions[0].reason_code == "missing_cwe_mapping"
    serialized = outcome.model_dump_json()
    assert "SUPER-SECRET-FLAG" not in serialized
    assert "ANOTHER-SECRET-FLAG" not in serialized
    assert "admin@example.test" not in serialized
    assert "private task" not in serialized
    store.close()


def test_snapshot_content_drift_is_rejected_before_checkpoint(tmp_path, now):
    root = _bounty_root(tmp_path)
    snapshot = _snapshot(root, ExternalBenchmarkKind.BOUNTYBENCH)
    metadata = root / "lunary/bounties/bounty_0/bounty_metadata.json"
    metadata.write_text("{}", encoding="utf-8")
    adapter = BountyBenchSnapshotAdapter()
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(ExternalBenchmarkRejected, match="sealed manifest"):
        service.import_snapshot(root, snapshot, _plan(snapshot, adapter, now), now=now)
    assert store.connection.execute(
        "SELECT COUNT(*) FROM external_benchmark_imports"
    ).fetchone()[0] == 0
    store.close()


def test_snapshot_mutation_during_normalization_is_rejected(tmp_path, now):
    root = _bounty_root(tmp_path)
    snapshot = _snapshot(root, ExternalBenchmarkKind.BOUNTYBENCH)

    class MutatingAdapter(BountyBenchSnapshotAdapter):
        def normalize(self, source, sealed, *, limits, deadline):
            result = super().normalize(source, sealed, limits=limits, deadline=deadline)
            (source / "LICENSE").write_text("changed", encoding="utf-8")
            return result

    adapter = MutatingAdapter()
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(ExternalBenchmarkRejected, match="sealed manifest"):
        service.import_snapshot(root, snapshot, _plan(snapshot, adapter, now), now=now)
    assert store.connection.execute(
        "SELECT COUNT(*) FROM external_benchmark_imports"
    ).fetchone()[0] == 0
    store.close()


def test_symlink_and_special_file_snapshots_are_rejected(tmp_path):
    root = tmp_path / "unsafe"
    root.mkdir()
    (root / "LICENSE").write_text("MIT", encoding="utf-8")
    target = tmp_path / "outside"
    target.write_text("outside", encoding="utf-8")
    (root / "link").symlink_to(target)
    with pytest.raises(ExternalBenchmarkRejected, match="symbolic links"):
        inspect_snapshot_directory(
            root,
            limits=ExternalImportLimits(),
            deadline=ImportDeadline(1),
        )
    (root / "link").unlink()
    fifo = root / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ExternalBenchmarkRejected, match="special files"):
        inspect_snapshot_directory(
            root,
            limits=ExternalImportLimits(),
            deadline=ImportDeadline(1),
        )


def test_snapshot_limits_and_timeout_fail_closed(tmp_path, monkeypatch):
    root = tmp_path / "limited"
    root.mkdir()
    (root / "LICENSE").write_text("too-large", encoding="utf-8")
    with pytest.raises(ExternalBenchmarkRejected, match="maximum size"):
        inspect_snapshot_directory(
            root,
            limits=ExternalImportLimits(max_single_file_bytes=1),
            deadline=ImportDeadline(1),
        )

    ticks = iter((0.0, 2.0))
    monkeypatch.setattr("vulnloom.benchmark.external_io.time.monotonic", lambda: next(ticks))
    deadline = ImportDeadline(1)
    with pytest.raises(ExternalBenchmarkRejected, match="timed out"):
        inspect_snapshot_directory(root, limits=ExternalImportLimits(), deadline=deadline)


def test_duplicate_json_keys_and_stale_autopen_mapping_are_rejected(tmp_path, now):
    root = _auto_root(tmp_path)
    mapping = root / "vulnloom-autopenbench-cwe.json"
    mapping.write_text('{"stale_target":"CWE-79"}', encoding="utf-8")
    snapshot = _snapshot(root, ExternalBenchmarkKind.AUTOPENBENCH)
    adapter = AutoPenBenchSnapshotAdapter()
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(ExternalBenchmarkRejected, match="stale targets"):
        service.import_snapshot(root, snapshot, _plan(snapshot, adapter, now), now=now)
    store.close()

    root = _bounty_root(tmp_path / "duplicate")
    metadata = root / "lunary/bounties/bounty_0/bounty_metadata.json"
    metadata.write_text(
        '{"CWE":"CWE-22","CWE":"CWE-79","vulnerable_commit":"v1"}',
        encoding="utf-8",
    )
    snapshot = _snapshot(root, ExternalBenchmarkKind.BOUNTYBENCH)
    adapter = BountyBenchSnapshotAdapter()
    service, store, _ = _service(tmp_path / "duplicate", adapter)
    with pytest.raises(ExternalBenchmarkRejected, match="malformed or ambiguous"):
        service.import_snapshot(root, snapshot, _plan(snapshot, adapter, now), now=now)
    store.close()


def test_adapter_and_deadline_bindings_are_fail_closed(tmp_path, now):
    root = _bounty_root(tmp_path)
    snapshot = _snapshot(root, ExternalBenchmarkKind.BOUNTYBENCH)
    adapter = BountyBenchSnapshotAdapter()
    plan = ExternalBenchmarkImportPlan.create(
        snapshot=snapshot,
        adapter_id=AUTOPENBENCH_ADAPTER_ID,
        adapter_digest=AUTOPENBENCH_ADAPTER_DIGEST,
        limits=ExternalImportLimits(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="wrong-adapter",
    )
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(ExternalBenchmarkRejected, match="binding mismatch"):
        service.import_snapshot(root, snapshot, plan, now=now)

    expired = _plan(snapshot, adapter, now, key="expired")
    with pytest.raises(ExternalBenchmarkRejected, match="not active"):
        service.import_snapshot(root, snapshot, expired, now=expired.deadline)
    assert store.connection.execute(
        "SELECT COUNT(*) FROM external_benchmark_imports"
    ).fetchone()[0] == 0
    store.close()


def test_import_checkpoint_conflict_recovery_and_artifact_cleanup(tmp_path, now, monkeypatch):
    root = _bounty_root(tmp_path)
    snapshot = _snapshot(root, ExternalBenchmarkKind.BOUNTYBENCH)
    adapter = BountyBenchSnapshotAdapter()
    plan = _plan(snapshot, adapter, now)
    service, store, artifacts = _service(tmp_path, adapter)
    monkeypatch.setattr(artifacts, "_write", lambda *_: (_ for _ in ()).throw(OSError("write")))
    with pytest.raises(OSError, match="write"):
        service.import_snapshot(root, snapshot, plan, now=now)
    assert not tuple(artifacts.objects.glob("external-benchmark-*"))
    with pytest.raises(ExternalImportRecoveryRequired, match="unfinished STARTED"):
        service.import_snapshot(root, snapshot, plan, now=now)

    changed = _plan(snapshot, adapter, now, key=plan.idempotency_key)
    changed = changed.model_copy(
        update={
            "plan_id": "f" * 64,
            "adapter_digest": "e" * 64,
        }
    )
    with pytest.raises(ExternalImportIdempotencyConflict):
        store.claim(changed, now=now)
    store.close()


def test_snapshot_license_and_manifest_digest_are_validated(tmp_path):
    root = _auto_root(tmp_path)
    snapshot = _snapshot(root, ExternalBenchmarkKind.AUTOPENBENCH)
    with pytest.raises(ValidationError, match="license"):
        type(snapshot).create(
            kind=snapshot.kind,
            upstream_revision=snapshot.upstream_revision,
            license_spdx="Apache-2.0",
            files=snapshot.files,
        )

    raw = snapshot.model_dump(mode="python")
    raw["upstream_revision"] = "b" * 40
    with pytest.raises(ValidationError, match="content digest mismatch"):
        type(snapshot).model_validate(raw)


def test_external_import_store_context_manager_closes_connection(tmp_path):
    with ExternalBenchmarkImportStore(tmp_path / "closed.db") as store:
        connection = store.connection
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_external_import_protocol_has_no_network_credential_or_submission_fields():
    schema = json.dumps(ExternalBenchmarkImportPlan.model_json_schema()).lower()
    assert "url" not in schema
    assert "credential" not in schema
    assert "token" not in schema
    assert "submission" not in schema
    assert "command" not in schema


def test_external_benchmark_cli_is_offline_and_emits_safe_summary(
    tmp_path, now, capsys
):
    root = _auto_root(tmp_path)
    assert (
        main(
            [
                "benchmark-snapshot-manifest-local",
                "--source",
                str(root),
                "--kind",
                "autopenbench",
                "--upstream-revision",
                "a" * 40,
                "--license-spdx",
                "MIT",
            ]
        )
        == 0
    )
    snapshot_json = capsys.readouterr().out
    snapshot_file = tmp_path / "snapshot.json"
    snapshot_file.write_text(snapshot_json, encoding="utf-8")
    snapshot = _snapshot(root, ExternalBenchmarkKind.AUTOPENBENCH)
    assert json.loads(snapshot_json) == json.loads(snapshot.model_dump_json())
    adapter = AutoPenBenchSnapshotAdapter()
    plan = _plan(snapshot, adapter, now)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(plan.model_dump_json(), encoding="utf-8")

    assert (
        main(
            [
                "benchmark-import-offline",
                "--source",
                str(root),
                "--snapshot-file",
                str(snapshot_file),
                "--plan-file",
                str(plan_file),
                "--import-db",
                str(tmp_path / "cli.db"),
                "--suite-store",
                str(tmp_path / "cli-suites"),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    summary = json.loads(output)
    assert summary["suite_source"] == "autopenbench_snapshot"
    assert summary["cases"] == 1
    assert "SUPER-SECRET-FLAG" not in output
    assert "admin@example.test" not in output
