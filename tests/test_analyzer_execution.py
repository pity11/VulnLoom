from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    AnalyzerExecutionIdempotencyConflict,
    AnalyzerExecutionPlan,
    AnalyzerExecutionRecoveryRequired,
    AnalyzerExecutionRejected,
    AnalyzerExecutionStore,
    AnalyzerKind,
    AnalyzerToolRegistration,
    AnalyzerToolRegistry,
    OfflineAnalyzerExecutionService,
    OfflineAnalyzerExecutionStatus,
)
from vulnloom.domain.digests import canonical_digest
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
    NetworkMode,
    OfflineOutcome,
    OfflineSandboxRunner,
    OfflineScenario,
    SandboxLimits,
    SandboxRunRequest,
    ToolInvocation,
    analyzer_profile,
    sandbox_profile_digest,
)

IMAGE = "sha256:" + "1" * 64
RULES = "2" * 64
ADAPTER = "3" * 64
MANIFEST = "4" * 64


def _target(scope, now):
    target = Target(
        engagement_id=scope.engagement_id,
        kind=TargetKind.REPOSITORY,
        source_ref="https://example.test/app.git",
        version="a" * 40,
        ingested_at=now,
    )
    artifact = Artifact(
        artifact_id="5" * 64,
        engagement_id=scope.engagement_id,
        kind=ArtifactKind.GIT_REPOSITORY,
        source_name="fixture.git",
        source_ref="https://example.test/app.git",
        original_size=10,
        detected_format="git",
        captured_at=now,
    )
    manifest = TargetManifest(
        manifest_id=MANIFEST,
        artifact_id=artifact.artifact_id,
        target_id=target.target_id,
        target_version=target.version,
        files=(
            {
                "path": "app.py",
                "size": 10,
                "sha256": "6" * 64,
                "category": StaticFileCategory.SOURCE,
            },
        ),
        total_size=10,
        created_at=now,
    )
    return TargetSnapshot(target=target, artifact=artifact, manifest=manifest)


def _registration():
    return AnalyzerToolRegistration.create(
        tool_id="analyzer.checkov",
        analyzer=AnalyzerKind.CHECKOV,
        tool_version="3.2.1",
        image_digest=IMAGE,
        rules_digest=RULES,
        adapter_id="checkov-json-v1",
        adapter_digest=ADAPTER,
        argv=(
            "/opt/checkov/bin/checkov",
            "--directory",
            "/workspace/source",
            "--output-file-path",
            "/workspace/output/output.json",
        ),
    )


def _setup(scope, now, *, key="analyzer-execution:1", task_deadline=None):
    target = _target(scope, now)
    registration = _registration()
    registry = AnalyzerToolRegistry((registration,))
    limits = SandboxLimits(
        wall_seconds=60,
        cpu_millis=60_000,
        memory_bytes=256 * 1024 * 1024,
        pids=64,
        open_files=512,
        file_bytes=16 * 1024 * 1024,
        tmp_bytes=64 * 1024 * 1024,
    )
    profile = analyzer_profile(
        image_digest=registration.image_digest,
        snapshot_id=target.manifest.manifest_id,
        tool_id=registration.tool_id,
        limits=limits,
    )
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=target.target.target_id,
        target_version=target.target.version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.ANALYZER,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=registry.digest,
        input_refs=(f"snapshot:{target.manifest.manifest_id}",),
        allowed_tools=frozenset({registration.tool_id}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=1),
        deadline=task_deadline or now + timedelta(seconds=45),
        idempotency_key="task:" + key,
    )
    request = SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(tool_id=registration.tool_id, working_directory="source"),
        environment={},
        idempotency_key="runner:" + key,
    )
    plan = AnalyzerExecutionPlan.create(
        target=target,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        registration=registration,
        registry_digest=registry.digest,
        runner_request=request,
        created_at=now - timedelta(seconds=1),
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )
    return target, registration, registry, plan


def _service(tmp_path, scope, registry, runner=None):
    store = AnalyzerExecutionStore(tmp_path / "execution.db")
    service = OfflineAnalyzerExecutionService(
        scope=scope,
        registry=registry,
        runner=runner or OfflineSandboxRunner(registry.tool_ids),
        store=store,
    )
    return service, store


def test_offline_protocol_success_is_idempotent_and_never_claims_output(
    tmp_path, approved_scope, now
):
    target, registration, registry, plan = _setup(approved_scope, now)
    service, store = _service(tmp_path, approved_scope, registry)
    first = service.execute(target, plan, now=now)
    second = service.execute(target, plan, now=now + timedelta(seconds=1))

    assert first == second
    assert first.status is OfflineAnalyzerExecutionStatus.PROTOCOL_COMPLETED
    assert first.registration_id == registration.registration_id
    assert first.analyzer_result_snapshot is None
    assert first.runner_result.cleanup.complete
    serialized = first.model_dump_json()
    for forbidden in ("candidate_id", "finding_id", "critic_verdict", "submission"):
        assert forbidden not in serialized
    store.close()


def test_registration_rejects_shell_placeholders_network_and_unsafe_environment():
    base = _registration().model_dump(mode="python")
    for argv in (
        ("/bin/sh", "-c", "/workspace/output/output.json"),
        ("/bin/tool", "{target}", "/workspace/output/output.json"),
        ("/bin/tool", "--db=https://rules.invalid", "/workspace/output/output.json"),
    ):
        raw = {**base, "argv": argv}
        raw["registration_id"] = canonical_digest(
            {key: value for key, value in raw.items() if key != "registration_id"}
        )
        with pytest.raises(ValidationError):
            AnalyzerToolRegistration.model_validate(raw)

    with pytest.raises(ValidationError, match="credential-like"):
        AnalyzerToolRegistration.create(
            tool_id="analyzer.checkov",
            analyzer=AnalyzerKind.CHECKOV,
            tool_version="1.0",
            image_digest=IMAGE,
            rules_digest=RULES,
            adapter_id="checkov-json-v1",
            adapter_digest=ADAPTER,
            argv=("/bin/tool", "/workspace/output/output.json"),
            environment={"GITHUB_TOKEN": "secret"},
        )


def test_registry_materializes_only_the_sealed_docker_argv():
    registration = _registration()
    registry = AnalyzerToolRegistry((registration,))
    assert registry.docker_tools[0].tool_id == registration.tool_id
    assert registry.docker_tools[0].argv_prefix == registration.argv


@pytest.mark.parametrize(
    "mutation",
    ("network", "target_code", "image", "arguments", "environment", "role", "registry"),
)
def test_preflight_refuses_weakened_or_unbound_requests_before_checkpoint(
    tmp_path, approved_scope, now, mutation
):
    target, _, registry, plan = _setup(approved_scope, now)
    request = plan.runner_request
    if mutation == "network":
        profile = request.profile.model_copy(update={"network_mode": NetworkMode.TARGET_ONLY})
        request = request.model_copy(update={"profile": profile})
    elif mutation == "target_code":
        profile = request.profile.model_copy(update={"execute_target_code": True})
        request = request.model_copy(update={"profile": profile})
    elif mutation == "image":
        profile = request.profile.model_copy(update={"image_digest": "sha256:" + "9" * 64})
        request = request.model_copy(update={"profile": profile})
    elif mutation == "arguments":
        invocation = request.invocation.model_copy(update={"arguments": ("--download",)})
        request = request.model_copy(update={"invocation": invocation})
    elif mutation == "environment":
        request = request.model_copy(update={"environment": {"EXTRA": "value"}})
    elif mutation == "role":
        request = request.model_copy(
            update={"task": request.task.model_copy(update={"worker_role": WorkerRole.HYPOTHESIS})}
        )
    else:
        request = request.model_copy(
            update={"task": request.task.model_copy(update={"tool_registry_digest": "9" * 64})}
        )
    bypassed = plan.model_copy(update={"runner_request": request})
    service, store = _service(tmp_path, approved_scope, registry)
    with pytest.raises(AnalyzerExecutionRejected):
        service.execute(target, bypassed, now=now)
    assert store.connection.execute("SELECT COUNT(*) FROM analyzer_executions").fetchone()[0] == 0
    store.close()


def test_expired_task_maps_to_timeout_with_complete_cleanup(tmp_path, approved_scope, now):
    target, _, registry, plan = _setup(approved_scope, now, task_deadline=now)
    service, store = _service(tmp_path, approved_scope, registry)
    outcome = service.execute(target, plan, now=now)
    assert outcome.status is OfflineAnalyzerExecutionStatus.TIMED_OUT
    assert outcome.runner_result.cleanup.complete
    assert outcome.runner_result.budget_used.tool_calls == 0
    store.close()


def test_cancelled_and_failed_paths_preserve_cleanup(tmp_path, approved_scope, now):
    for index, (scenario, status) in enumerate(
        (
            (OfflineScenario(outcome=OfflineOutcome.CANCELLED), "cancelled"),
            (OfflineScenario(outcome=OfflineOutcome.FAILED), "failed"),
        )
    ):
        target, _, registry, plan = _setup(
            approved_scope, now, key=f"analyzer-execution:{index + 10}"
        )
        runner = OfflineSandboxRunner(registry.tool_ids)
        original = runner.execute
        runner.execute = lambda request, original=original, *, now, selected=scenario: original(
            request, now=now, scenario=selected
        )
        service, store = _service(tmp_path / str(index), approved_scope, registry, runner)
        outcome = service.execute(target, plan, now=now)
        assert outcome.status.value == status
        assert outcome.runner_result.cleanup.complete
        store.close()


def test_offline_service_rejects_runner_substitution(tmp_path, approved_scope, now):
    class LookalikeRunner(OfflineSandboxRunner):
        pass

    _, _, registry, _ = _setup(approved_scope, now)
    store = AnalyzerExecutionStore(tmp_path / "execution.db")
    with pytest.raises(TypeError, match="exact OfflineSandboxRunner"):
        OfflineAnalyzerExecutionService(
            scope=approved_scope,
            registry=registry,
            runner=LookalikeRunner(registry.tool_ids),
            store=store,
        )
    store.close()


def test_checkpoint_conflict_and_unfinished_recovery(tmp_path, approved_scope, now):
    target, _, registry, plan = _setup(approved_scope, now)
    service, store = _service(tmp_path, approved_scope, registry)
    store.claim(plan, now=now)
    with pytest.raises(AnalyzerExecutionRecoveryRequired):
        service.execute(target, plan, now=now)

    _, _, _, conflicting = _setup(approved_scope, now, key=plan.idempotency_key)
    with pytest.raises(AnalyzerExecutionIdempotencyConflict):
        store.claim(conflicting, now=now)
    store.close()
