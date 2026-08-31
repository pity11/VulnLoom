from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    CODEQL_TOOL_VERSION,
    AnalyzerExecutionMode,
    AnalyzerExecutionPlan,
    AnalyzerExecutionRejected,
    AnalyzerExecutionStore,
    AnalyzerKind,
    AnalyzerToolRegistry,
    CodeQLSnapshotLimits,
    CodeQLSnapshotRejected,
    OfflineAnalyzerExecutionService,
    OfflineAnalyzerExecutionStatus,
    codeql_registration,
    inspect_codeql_snapshot,
    validate_admitted_registration,
    verify_codeql_snapshot,
)
from vulnloom.domain.models import (
    Artifact,
    ArtifactKind,
    StaticFileCategory,
    Target,
    TargetKind,
    TargetManifest,
    TargetSnapshot,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    MountKind,
    OfflineSandboxRunner,
    SandboxLimits,
    SandboxRunRequest,
    ToolInvocation,
    analyzer_profile,
    sandbox_profile_digest,
)

IMAGE = "sha256:" + "1" * 64


def _write_snapshot(root: Path) -> None:
    (root / "database").mkdir(parents=True)
    (root / "queries").mkdir()
    (root / "database" / "codeql-database.yml").write_text("primaryLanguage: python\n")
    (root / "database" / "db-python").write_bytes(b"sealed database")
    (root / "queries" / "qlpack.yml").write_text("name: vulnloom/python-queries\n")
    (root / "queries" / "security.qls").write_text("- queries: .\n")
    (root / "queries" / "example.qlx").write_bytes(b"precompiled query")
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _inspect(root: Path, *, limits: CodeQLSnapshotLimits | None = None):
    return inspect_codeql_snapshot(
        root,
        database_language="python",
        query_pack_name="vulnloom/python-queries",
        query_suite_path="queries/security.qls",
        limits=limits,
    )


def _target(scope, now) -> TargetSnapshot:
    target = Target(
        engagement_id=scope.engagement_id,
        kind=TargetKind.REPOSITORY,
        source_ref="https://example.test/app.git",
        version="a" * 40,
        ingested_at=now,
    )
    artifact = Artifact(
        artifact_id="2" * 64,
        engagement_id=scope.engagement_id,
        kind=ArtifactKind.GIT_REPOSITORY,
        source_name="fixture.git",
        source_ref="https://example.test/app.git",
        original_size=1,
        detected_format="git",
        captured_at=now,
    )
    manifest = TargetManifest(
        manifest_id="3" * 64,
        artifact_id=artifact.artifact_id,
        target_id=target.target_id,
        target_version=target.version,
        files=(
            {
                "path": "app.py",
                "size": 1,
                "sha256": "4" * 64,
                "category": StaticFileCategory.SOURCE,
            },
        ),
        total_size=1,
        created_at=now,
    )
    return TargetSnapshot(target=target, artifact=artifact, manifest=manifest)


def test_codeql_snapshot_is_read_only_content_addressed_and_reverified(tmp_path):
    root = tmp_path / "sealed"
    root.mkdir()
    _write_snapshot(root)

    snapshot = _inspect(root)

    assert snapshot.tool_version == CODEQL_TOOL_VERSION
    assert snapshot.total_size == sum(item.size for item in snapshot.files)
    assert {item.path for item in snapshot.files} >= {
        "database/codeql-database.yml",
        "queries/qlpack.yml",
        "queries/security.qls",
    }
    verify_codeql_snapshot(root, snapshot)

    (root / "database" / "db-python").chmod(0o644)
    (root / "database" / "db-python").write_bytes(b"changed")
    (root / "database" / "db-python").chmod(0o444)
    with pytest.raises(CodeQLSnapshotRejected, match="no longer matches"):
        verify_codeql_snapshot(root, snapshot)


@pytest.mark.parametrize(
    "mutation", ("writable", "symlink", "results", "missing-suite", "metadata-mismatch")
)
def test_codeql_snapshot_rejects_unsafe_or_incomplete_trees(tmp_path, mutation):
    root = tmp_path / mutation
    root.mkdir()
    _write_snapshot(root)
    if mutation == "writable":
        (root / "database" / "db-python").chmod(0o644)
    elif mutation == "symlink":
        (root / "database").chmod(0o755)
        os.symlink("db-python", root / "database" / "linked")
        (root / "database").chmod(0o555)
    elif mutation == "results":
        root.chmod(0o755)
        (root / "database").chmod(0o755)
        (root / "database" / "results").mkdir()
        (root / "database" / "results" / "old.bqrs").write_bytes(b"old")
        (root / "database" / "results" / "old.bqrs").chmod(0o444)
        (root / "database" / "results").chmod(0o555)
        (root / "database").chmod(0o555)
        root.chmod(0o555)
    elif mutation == "missing-suite":
        (root / "queries").chmod(0o755)
        (root / "queries" / "security.qls").unlink()
        (root / "queries").chmod(0o555)
    else:
        marker = root / "queries" / "qlpack.yml"
        marker.chmod(0o644)
        marker.write_text("name: different/query-pack\n")
        marker.chmod(0o444)

    with pytest.raises((CodeQLSnapshotRejected, ValidationError)):
        _inspect(root)


def test_codeql_snapshot_enforces_file_total_and_timeout_limits(tmp_path, monkeypatch):
    root = tmp_path / "limits"
    root.mkdir()
    _write_snapshot(root)
    with pytest.raises(CodeQLSnapshotRejected, match="file limit"):
        _inspect(
            root,
            limits=CodeQLSnapshotLimits(
                max_files=3,
                max_single_file_bytes=1024,
                max_total_bytes=4096,
            ),
        )

    import vulnloom.benchmark.codeql_snapshot as module

    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks, 2.0))
    with pytest.raises(CodeQLSnapshotRejected, match="timed out"):
        _inspect(root, limits=CodeQLSnapshotLimits(timeout_seconds=1))


def test_codeql_registration_is_protocol_only_and_cannot_materialize_docker_tool(
    tmp_path, approved_scope, now
):
    root = tmp_path / "protocol"
    root.mkdir()
    _write_snapshot(root)
    snapshot = _inspect(root)
    registration = codeql_registration(
        tool_version=CODEQL_TOOL_VERSION,
        image_digest=IMAGE,
        snapshot=snapshot,
    )

    assert registration.analyzer is AnalyzerKind.CODEQL
    assert registration.mode is AnalyzerExecutionMode.PREBUILT_DATABASE_QUERY_ONLY
    assert registration.rules_digest == snapshot.snapshot_id
    assert registration.argv[:3] == ("/opt/codeql/codeql", "database", "analyze")
    assert "create" not in registration.argv
    assert "--download" not in registration.argv
    assert registration.environment == {"HOME": "/tmp", "TMPDIR": "/tmp"}

    registry = AnalyzerToolRegistry((registration,))
    with pytest.raises(ValueError, match="mutable-copy admission"):
        _ = registry.docker_tools
    with pytest.raises(ValueError, match="bounded stdout"):
        validate_admitted_registration(_target(approved_scope, now), registration)

    raw = registration.model_dump(mode="python")
    raw["rules_digest"] = "9" * 64
    with pytest.raises(ValidationError, match="CodeQL registration"):
        type(registration).model_validate(raw)


def test_codeql_protocol_binds_snapshot_input_and_read_only_mount(tmp_path, approved_scope, now):
    root = tmp_path / "bound"
    root.mkdir()
    _write_snapshot(root)
    snapshot = _inspect(root)
    registration = codeql_registration(
        tool_version=CODEQL_TOOL_VERSION,
        image_digest=IMAGE,
        snapshot=snapshot,
    )
    target = _target(approved_scope, now)
    registry = AnalyzerToolRegistry((registration,))
    limits = SandboxLimits(
        wall_seconds=60,
        cpu_millis=60_000,
        memory_bytes=256 * 1024 * 1024,
        pids=64,
        open_files=512,
        file_bytes=32 * 1024 * 1024,
        tmp_bytes=64 * 1024 * 1024,
    )
    profile = analyzer_profile(
        image_digest=IMAGE,
        snapshot_id=target.manifest.manifest_id,
        tool_id=registration.tool_id,
        limits=limits,
        analyzer_data_id=snapshot.snapshot_id,
    )
    task = TaskEnvelope(
        engagement_id=approved_scope.engagement_id,
        target_id=target.target.target_id,
        target_version=target.target.version,
        scope_id=approved_scope.scope_id,
        worker_role=WorkerRole.ANALYZER,
        scope_version=approved_scope.version,
        policy_digest=PolicyEngine(approved_scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=registry.digest,
        input_refs=(
            f"snapshot:{target.manifest.manifest_id}",
            f"analyzer-data:{snapshot.snapshot_id}",
        ),
        allowed_tools=frozenset({registration.tool_id}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(seconds=45),
        idempotency_key="task:codeql-protocol:1",
    )
    request = SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(tool_id=registration.tool_id, working_directory="source"),
        environment=registration.environment,
        idempotency_key="runner:codeql-protocol:1",
    )
    plan = AnalyzerExecutionPlan.create(
        target=target,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        registration=registration,
        registry_digest=registry.digest,
        runner_request=request,
        created_at=now - timedelta(seconds=1),
        deadline=now + timedelta(minutes=1),
        idempotency_key="codeql-protocol:1",
    )
    store = AnalyzerExecutionStore(tmp_path / "execution.db")
    service = OfflineAnalyzerExecutionService(
        scope=approved_scope,
        registry=registry,
        runner=OfflineSandboxRunner(registry.tool_ids),
        store=store,
    )

    unbound_task = task.model_copy(
        update={"input_refs": (f"snapshot:{target.manifest.manifest_id}",)}
    )
    unbound_request = request.model_copy(update={"task": unbound_task})
    unbound_plan = AnalyzerExecutionPlan.create(
        target=target,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        registration=registration,
        registry_digest=registry.digest,
        runner_request=unbound_request,
        created_at=now - timedelta(seconds=1),
        deadline=now + timedelta(minutes=1),
        idempotency_key="codeql-protocol:unbound",
    )
    with pytest.raises(AnalyzerExecutionRejected, match="data provenance"):
        service.execute(target, unbound_plan, now=now)
    assert store.connection.execute("SELECT COUNT(*) FROM analyzer_executions").fetchone()[0] == 0

    outcome = service.execute(target, plan, now=now)

    data_mount = next(mount for mount in profile.mounts if mount.kind is MountKind.ANALYZER_DATA)
    assert data_mount.object_id == snapshot.snapshot_id
    assert data_mount.read_only
    assert outcome.status is OfflineAnalyzerExecutionStatus.PROTOCOL_COMPLETED
    assert outcome.analyzer_result_snapshot is None
    store.close()
