from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    AnalyzerImportIdempotencyConflict,
    AnalyzerImportLimits,
    AnalyzerImportPlan,
    AnalyzerImportRecoveryRequired,
    AnalyzerImportRejected,
    AnalyzerImportService,
    AnalyzerImportStore,
    AnalyzerKind,
    AnalyzerObservationArtifactStore,
    AnalyzerResultSnapshot,
    CheckovJsonAdapter,
    CodeQLSarifAdapter,
    KubesecJsonAdapter,
    TrivyJsonAdapter,
    create_analyzer_snapshot,
)
from vulnloom.benchmark.analyzer_io import AnalyzerDeadline
from vulnloom.cli import main


def _write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _inputs(tmp_path, kind):
    output = tmp_path / f"{kind.value}.json"
    cwe_map = tmp_path / f"{kind.value}-cwe.json"
    if kind is AnalyzerKind.CODEQL:
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "py/sql-injection",
                                    "properties": {"tags": ["security", "external/cwe/cwe-89"]},
                                },
                                {"id": "py/unmapped"},
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/sql-injection",
                            "level": "error",
                            "message": {"text": "private source excerpt admin@example.test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 9, "endLine": 10},
                                    }
                                }
                            ],
                        },
                        {"ruleId": "py/unmapped", "message": {"text": "not persisted"}},
                    ],
                }
            ],
        }
        mapping = None
    elif kind is AnalyzerKind.TRIVY:
        document = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "deploy/app.yaml",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "CweIDs": ["CWE-78"],
                            "Severity": "HIGH",
                            "Title": "private package detail",
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "AVD-KSV-0001",
                            "Severity": "MEDIUM",
                            "Message": "private manifest content",
                            "CauseMetadata": {"StartLine": 3, "EndLine": 4},
                        }
                    ],
                    "Secrets": [{"RuleID": "secret-key", "Match": "DO-NOT-PERSIST"}],
                }
            ],
        }
        mapping = {"AVD-KSV-0001": "CWE-250"}
    elif kind is AnalyzerKind.CHECKOV:
        document = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_20",
                        "check_name": "private check prose",
                        "file_path": "k8s/deploy.yaml",
                        "file_line_range": [4, 8],
                    }
                ]
            }
        }
        mapping = {"CKV_K8S_20": ["CWE-250"]}
    else:
        document = [
            {
                "object": "Deployment/private-object-name",
                "valid": True,
                "score": -1,
                "scoring": {
                    "critical": [
                        {
                            "id": "Privileged",
                            "selector": "containers[] .securityContext .privileged == true",
                            "reason": "private pod detail",
                            "points": -30,
                        }
                    ],
                    "advise": [],
                },
            }
        ]
        mapping = {"Privileged": "CWE-250"}
    _write_json(output, document)
    if mapping is not None:
        _write_json(cwe_map, mapping)
        return output, cwe_map
    return output, None


def _adapter(kind):
    return {
        AnalyzerKind.CODEQL: CodeQLSarifAdapter(),
        AnalyzerKind.TRIVY: TrivyJsonAdapter(),
        AnalyzerKind.CHECKOV: CheckovJsonAdapter(),
        AnalyzerKind.KUBESEC: KubesecJsonAdapter(),
    }[kind]


def _snapshot(output, cwe_map, kind, *, limits=None):
    return create_analyzer_snapshot(
        output,
        analyzer=kind,
        target_id=uuid4(),
        target_version="sha256:" + "a" * 64,
        tool_version="1.2.3",
        rules_digest="b" * 64,
        cwe_map_path=cwe_map,
        limits=limits,
    )


def _plan(snapshot, adapter, now, *, key="analyzer:1", limits=None):
    return AnalyzerImportPlan.create(
        snapshot=snapshot,
        adapter_id=adapter.adapter_id,
        adapter_digest=adapter.adapter_digest,
        limits=limits or AnalyzerImportLimits(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )


def _service(tmp_path, adapter):
    store = AnalyzerImportStore(tmp_path / "analyzer.db")
    artifacts = AnalyzerObservationArtifactStore(tmp_path / "analyzer-artifacts")
    return (
        AnalyzerImportService(adapter=adapter, store=store, artifact_store=artifacts),
        store,
        artifacts,
    )


@pytest.mark.parametrize("kind", list(AnalyzerKind))
def test_precomputed_adapters_normalize_without_workflow_promotion(tmp_path, now, kind):
    output, cwe_map = _inputs(tmp_path, kind)
    adapter = _adapter(kind)
    snapshot = _snapshot(output, cwe_map, kind)
    service, store, artifacts = _service(tmp_path, adapter)

    first = service.import_result(
        output,
        snapshot,
        _plan(snapshot, adapter, now),
        now=now,
        cwe_map_path=cwe_map,
    )
    second = service.import_result(
        output,
        snapshot,
        _plan(snapshot, adapter, now),
        now=now,
        cwe_map_path=cwe_map,
    )

    assert first == second
    assert first.observation_set.analyzer is kind
    assert first.observation_set.observations
    if kind is AnalyzerKind.TRIVY:
        assert any(
            item.reason_code == "unsupported_secret_result"
            for item in first.observation_set.exclusions
        )
    serialized = first.model_dump_json()
    for forbidden in (
        "private source excerpt",
        "admin@example.test",
        "private package detail",
        "private manifest content",
        "DO-NOT-PERSIST",
        "private check prose",
        "private-object-name",
        "private pod detail",
        "candidate_id",
        "finding_id",
        "validation_result",
        "critic_verdict",
    ):
        assert forbidden not in serialized
    assert artifacts.read(first.artifact) == first.observation_set
    store.close()


def test_codeql_unsafe_location_is_discarded_but_not_security_decision(tmp_path, now):
    output, _ = _inputs(tmp_path, AnalyzerKind.CODEQL)
    document = json.loads(output.read_text())
    document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "https://example.invalid/secret.py"
    _write_json(output, document)
    adapter = CodeQLSarifAdapter()
    snapshot = _snapshot(output, None, AnalyzerKind.CODEQL)
    service, store, _ = _service(tmp_path, adapter)
    outcome = service.import_result(output, snapshot, _plan(snapshot, adapter, now), now=now)
    assert outcome.observation_set.observations[0].locations == ()
    store.close()


def test_missing_cwe_becomes_typed_exclusion(tmp_path, now):
    output = tmp_path / "checkov.json"
    _write_json(
        output,
        {"results": {"failed_checks": [{"check_id": "CKV_AWS_1"}]}},
    )
    adapter = CheckovJsonAdapter()
    snapshot = _snapshot(output, None, AnalyzerKind.CHECKOV)
    service, store, _ = _service(tmp_path, adapter)
    outcome = service.import_result(output, snapshot, _plan(snapshot, adapter, now), now=now)
    assert not outcome.observation_set.observations
    assert outcome.observation_set.exclusions[0].reason_code == "missing_cwe_mapping"
    store.close()


def test_content_drift_and_symlink_are_rejected_before_checkpoint(tmp_path, now):
    output, mapping = _inputs(tmp_path, AnalyzerKind.CHECKOV)
    adapter = CheckovJsonAdapter()
    snapshot = _snapshot(output, mapping, AnalyzerKind.CHECKOV)
    output.write_text("{}", encoding="utf-8")
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(AnalyzerImportRejected, match="sealed manifest"):
        service.import_result(
            output,
            snapshot,
            _plan(snapshot, adapter, now),
            now=now,
            cwe_map_path=mapping,
        )
    assert store.connection.execute("SELECT COUNT(*) FROM analyzer_imports").fetchone()[0] == 0
    store.close()

    target = tmp_path / "regular.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(AnalyzerImportRejected, match="symbolic links"):
        create_analyzer_snapshot(
            link,
            analyzer=AnalyzerKind.CHECKOV,
            target_id=uuid4(),
            target_version="v1",
            tool_version="1.0",
            rules_digest="a" * 64,
        )


def test_mutation_during_normalization_is_rejected_before_checkpoint(tmp_path, now):
    output, mapping = _inputs(tmp_path, AnalyzerKind.CHECKOV)

    class MutatingAdapter(CheckovJsonAdapter):
        def normalize(self, snapshot, document, cwe_map, *, limits, deadline):
            result = super().normalize(
                snapshot, document, cwe_map, limits=limits, deadline=deadline
            )
            output.write_text("{}", encoding="utf-8")
            return result

    adapter = MutatingAdapter()
    snapshot = _snapshot(output, mapping, AnalyzerKind.CHECKOV)
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(AnalyzerImportRejected, match="sealed manifest"):
        service.import_result(
            output,
            snapshot,
            _plan(snapshot, adapter, now),
            now=now,
            cwe_map_path=mapping,
        )
    assert store.connection.execute("SELECT COUNT(*) FROM analyzer_imports").fetchone()[0] == 0
    store.close()


def test_duplicate_json_mapping_and_size_limit_fail_closed(tmp_path, now):
    output, mapping = _inputs(tmp_path, AnalyzerKind.CHECKOV)
    mapping.write_text('{"CKV_K8S_20":"CWE-250","CKV_K8S_20":"CWE-79"}', encoding="utf-8")
    adapter = CheckovJsonAdapter()
    snapshot = _snapshot(output, mapping, AnalyzerKind.CHECKOV)
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(AnalyzerImportRejected, match="duplicate"):
        service.import_result(
            output,
            snapshot,
            _plan(snapshot, adapter, now),
            now=now,
            cwe_map_path=mapping,
        )
    store.close()


def test_stale_mapping_and_observation_limit_are_rejected(tmp_path, now):
    output, mapping = _inputs(tmp_path, AnalyzerKind.CHECKOV)
    _write_json(mapping, {"CKV_K8S_20": "CWE-250", "CKV_STALE": "CWE-79"})
    adapter = CheckovJsonAdapter()
    snapshot = _snapshot(output, mapping, AnalyzerKind.CHECKOV)
    service, store, _ = _service(tmp_path, adapter)
    with pytest.raises(AnalyzerImportRejected, match="stale"):
        service.import_result(
            output,
            snapshot,
            _plan(snapshot, adapter, now),
            now=now,
            cwe_map_path=mapping,
        )
    store.close()

    output, mapping = _inputs(tmp_path, AnalyzerKind.TRIVY)
    snapshot = _snapshot(output, mapping, AnalyzerKind.TRIVY)
    service, store, _ = _service(tmp_path / "limited", TrivyJsonAdapter())
    limits = AnalyzerImportLimits(max_observations=1)
    with pytest.raises(AnalyzerImportRejected, match="observation limit"):
        service.import_result(
            output,
            snapshot,
            _plan(snapshot, TrivyJsonAdapter(), now, limits=limits),
            now=now,
            cwe_map_path=mapping,
        )
    store.close()

    with pytest.raises(AnalyzerImportRejected, match="size limit"):
        _snapshot(
            output,
            None,
            AnalyzerKind.CHECKOV,
            limits=AnalyzerImportLimits(max_output_bytes=1),
        )


def test_timeout_wrong_adapter_and_inactive_plan_are_rejected(tmp_path, now, monkeypatch):
    output, mapping = _inputs(tmp_path, AnalyzerKind.CHECKOV)
    adapter = CheckovJsonAdapter()
    snapshot = _snapshot(output, mapping, AnalyzerKind.CHECKOV)
    service, store, _ = _service(tmp_path, TrivyJsonAdapter())
    with pytest.raises(AnalyzerImportRejected, match="binding"):
        service.import_result(
            output,
            snapshot,
            _plan(snapshot, adapter, now),
            now=now,
            cwe_map_path=mapping,
        )
    store.close()

    service, store, _ = _service(tmp_path / "inactive", adapter)
    plan = _plan(snapshot, adapter, now)
    with pytest.raises(AnalyzerImportRejected, match="not active"):
        service.import_result(
            output,
            snapshot,
            plan,
            now=plan.deadline,
            cwe_map_path=mapping,
        )
    store.close()

    ticks = iter((0.0, 2.0))
    monkeypatch.setattr("vulnloom.benchmark.analyzer_io.time.monotonic", lambda: next(ticks))
    deadline = AnalyzerDeadline(1)
    with pytest.raises(AnalyzerImportRejected, match="timed out"):
        deadline.check()


def test_artifact_failure_cleanup_recovery_and_idempotency_conflict(tmp_path, now, monkeypatch):
    output, mapping = _inputs(tmp_path, AnalyzerKind.CHECKOV)
    adapter = CheckovJsonAdapter()
    snapshot = _snapshot(output, mapping, AnalyzerKind.CHECKOV)
    plan = _plan(snapshot, adapter, now)
    service, store, artifacts = _service(tmp_path, adapter)
    monkeypatch.setattr(artifacts, "_write", lambda *_: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError, match="disk"):
        service.import_result(output, snapshot, plan, now=now, cwe_map_path=mapping)
    assert not list(artifacts.objects.iterdir())
    with pytest.raises(AnalyzerImportRecoveryRequired, match="unfinished"):
        service.import_result(output, snapshot, plan, now=now, cwe_map_path=mapping)
    store.close()

    conflict_store = AnalyzerImportStore(tmp_path / "conflict.db")
    conflict_store.claim(plan, now=now)
    different = AnalyzerImportPlan.create(
        snapshot=snapshot,
        adapter_id=adapter.adapter_id,
        adapter_digest=adapter.adapter_digest,
        limits=AnalyzerImportLimits(max_observations=2),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=plan.idempotency_key,
    )
    with pytest.raises(AnalyzerImportIdempotencyConflict):
        conflict_store.claim(different, now=now)
    conflict_store.close()


def test_snapshot_schema_and_protocol_have_no_workflow_or_execution_fields(tmp_path):
    output, mapping = _inputs(tmp_path, AnalyzerKind.KUBESEC)
    snapshot = _snapshot(output, mapping, AnalyzerKind.KUBESEC)
    with pytest.raises(ValidationError, match="Extra inputs"):
        AnalyzerResultSnapshot.model_validate(
            {**snapshot.model_dump(mode="python"), "url": "https://example.invalid"}
        )
    schema = json.dumps(AnalyzerImportPlan.model_json_schema()).lower()
    for forbidden in (
        "credential",
        "token",
        "submission",
        "command",
        "docker",
        "candidate",
        "finding",
        "approval",
    ):
        assert forbidden not in schema


def test_cli_manifest_and_import_emit_only_safe_summary(tmp_path, now, capsys):
    output, mapping = _inputs(tmp_path, AnalyzerKind.KUBESEC)
    target_id = uuid4()
    snapshot_path = tmp_path / "snapshot.json"
    plan_path = tmp_path / "plan.json"
    assert (
        main(
            [
                "analyzer-result-manifest-local",
                "--output",
                str(output),
                "--cwe-map",
                str(mapping),
                "--analyzer",
                "kubesec",
                "--target-id",
                str(target_id),
                "--target-version",
                "v1",
                "--tool-version",
                "1.0.0",
                "--rules-digest",
                "a" * 64,
            ]
        )
        == 0
    )
    manifest_output = capsys.readouterr().out
    snapshot_path.write_text(manifest_output, encoding="utf-8")
    snapshot = AnalyzerResultSnapshot.model_validate_json(manifest_output)
    adapter = KubesecJsonAdapter()
    plan_path.write_text(_plan(snapshot, adapter, now).model_dump_json(), encoding="utf-8")
    assert (
        main(
            [
                "analyzer-observations-import-offline",
                "--output",
                str(output),
                "--cwe-map",
                str(mapping),
                "--snapshot-file",
                str(snapshot_path),
                "--plan-file",
                str(plan_path),
                "--import-db",
                str(tmp_path / "cli.db"),
                "--observation-store",
                str(tmp_path / "cli-artifacts"),
            ]
        )
        == 0
    )
    summary = capsys.readouterr().out
    assert "offline_precomputed_analyzer_import" in summary
    assert "private-object-name" not in summary
    assert "private pod detail" not in summary


def test_store_context_manager_closes_connection(tmp_path):
    with AnalyzerImportStore(tmp_path / "closed.db") as store:
        connection = store.connection
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_special_file_is_rejected(tmp_path):
    fifo = tmp_path / "result.pipe"
    os.mkfifo(fifo)
    with pytest.raises(AnalyzerImportRejected, match="regular file"):
        create_analyzer_snapshot(
            fifo,
            analyzer=AnalyzerKind.TRIVY,
            target_id=uuid4(),
            target_version="v1",
            tool_version="1.0",
            rules_digest="a" * 64,
        )
