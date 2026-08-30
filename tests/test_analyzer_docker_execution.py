from __future__ import annotations

import json
import os
import shutil
from datetime import timedelta
from pathlib import Path

import pytest

from vulnloom.benchmark import (
    AnalyzerDockerExecutionRecoveryRequired,
    AnalyzerDockerExecutionStore,
    AnalyzerExecutionPlan,
    AnalyzerExecutionRejected,
    AnalyzerImportService,
    AnalyzerImportStore,
    AnalyzerKind,
    AnalyzerObservationArtifactStore,
    AnalyzerToolRegistration,
    AnalyzerToolRegistry,
    CheckovJsonAdapter,
    DockerAnalyzerExecutionService,
    DockerAnalyzerExecutionStatus,
    KubesecJsonAdapter,
    TrivyJsonAdapter,
    checkov_registration,
    inspect_trivy_database,
    kubesec_registration,
    trivy_registration,
    validate_admitted_registration,
)
from vulnloom.benchmark.analyzer_io import AnalyzerDeadline, inspect_result_file
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
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    RegisteredObjectStore,
    RunnerOutputStore,
    SandboxLimits,
    SandboxRunRequest,
    ToolInvocation,
    analyzer_profile,
    sandbox_profile_digest,
)

IMAGE = "sha256:" + "1" * 64
MANIFEST = "2" * 64
RULES = "3" * 64


class FakeAnalyzerDockerBackend:
    def __init__(self, inspection, output):
        self.inspection = inspection
        self.output = output
        self.created_arguments = None
        self.container_exists = False
        self.killed = False
        self.removed = False
        self.start_error = None
        self.on_start = None
        self.starts = 0

    def engine_info(self):
        return {
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless"],
            "CgroupVersion": "2",
            "MemoryLimit": True,
            "CpuCfsQuota": True,
            "PidsLimit": True,
        }

    def inspect_image(self, image):
        return {"Id": image}

    def create(self, arguments):
        self.created_arguments = tuple(arguments)
        self.container_exists = True
        return "analyzer-container"

    def inspect_container(self, container):
        return self.inspection

    def start(self, container, timeout):
        raise AssertionError("analyzer execution must use bounded attached output")

    def start_capture(self, container, timeout, destination, max_bytes):
        self.starts += 1
        if self.on_start is not None:
            self.on_start()
        if self.start_error:
            raise self.start_error
        if len(self.output) > max_bytes:
            raise ValueError("oversized")
        destination.write_bytes(self.output)
        return 0

    def kill(self, container):
        self.killed = True

    def remove(self, container):
        self.removed = True
        self.container_exists = False

    def exists(self, container):
        return self.container_exists


def _target(scope, now):
    target = Target(
        engagement_id=scope.engagement_id,
        kind=TargetKind.REPOSITORY,
        source_ref="https://example.test/app.git",
        version="a" * 40,
        ingested_at=now,
    )
    artifact = Artifact(
        artifact_id="4" * 64,
        engagement_id=scope.engagement_id,
        kind=ArtifactKind.GIT_REPOSITORY,
        source_name="fixture.git",
        source_ref=target.source_ref,
        original_size=256,
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
                "path": "deploy.yaml",
                "size": 256,
                "sha256": "5" * 64,
                "category": StaticFileCategory.KUBERNETES,
            },
        ),
        total_size=256,
        created_at=now,
    )
    return TargetSnapshot(target=target, artifact=artifact, manifest=manifest)


def _inspection(profile, source, registration, analyzer_data=None):
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        **registration.environment,
    }
    return {
        "Config": {
            "User": f"{profile.run_as_uid}:{profile.run_as_gid}",
            "Env": [f"{key}={value}" for key, value in environment.items()],
            "Entrypoint": [registration.argv[0]],
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "NetworkMode": "none",
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "PidsLimit": profile.limits.pids,
            "Memory": profile.limits.memory_bytes,
            "MemorySwap": profile.limits.memory_bytes,
            "NanoCpus": 1_000_000_000,
            "Tmpfs": {
                "/tmp": ("rw,noexec,nosuid,nodev,size=67108864,uid=65532,gid=65532,mode=0700"),
                "/workspace/output": (
                    "rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700"
                ),
            },
            "Ulimits": [{"Name": "nofile", "Soft": 512, "Hard": 512}],
            "Init": True,
            "LogConfig": {"Type": "none"},
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": [
            {"Source": str(source), "Destination": "/workspace/source", "RW": False},
            *(
                [
                    {
                        "Source": str(analyzer_data),
                        "Destination": "/workspace/analyzer-data",
                        "RW": False,
                    }
                ]
                if analyzer_data is not None
                else []
            ),
        ],
        "State": {"ExitCode": 0, "OOMKilled": False},
    }


def _trivy_database(objects, source=None):
    staging = objects / "trivy-database-staging"
    if source is None:
        database = staging / "db"
        database.mkdir(parents=True)
        (database / "metadata.json").write_text('{"Version":2,"UpdatedAt":"sealed"}')
        (database / "trivy.db").write_bytes(b"sealed-trivy-database")
    else:
        shutil.copytree(source, staging)
        database = staging / "db"
    for path in sorted(staging.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    staging.chmod(0o555)
    snapshot = inspect_trivy_database(staging, tool_version="0.73.0")
    destination = objects / snapshot.snapshot_id
    staging.rename(destination)
    return destination, snapshot


def _setup(
    tmp_path,
    scope,
    now,
    *,
    analyzer=AnalyzerKind.CHECKOV,
    image=IMAGE,
    real_backend=None,
):
    objects = tmp_path / "targets"
    source = objects / MANIFEST
    source.mkdir(parents=True)
    (source / "deploy.yaml").write_text("apiVersion: v1\nkind: Pod\n")
    cwe_path = None
    cwe = None
    analyzer_data_path = None
    database = None
    if analyzer is not AnalyzerKind.TRIVY:
        cwe_path = tmp_path / f"{analyzer.value}-cwe.json"
        cwe_path.write_text(
            json.dumps(
                {"CKV_K8S_20": "CWE-250"}
                if analyzer is AnalyzerKind.CHECKOV
                else {"Privileged": "CWE-250"}
            )
        )
        cwe = inspect_result_file(
            cwe_path,
            logical_name="cwe-map.json",
            max_bytes=1024 * 1024,
            deadline=AnalyzerDeadline(5),
        )
    else:
        provisioned = (
            os.environ.get("VULNLOOM_TRIVY_DATABASE") if real_backend is not None else None
        )
        analyzer_data_path, database = _trivy_database(
            objects,
            Path(provisioned) if provisioned is not None else None,
        )
    target = _target(scope, now)
    if analyzer is AnalyzerKind.CHECKOV:
        assert cwe is not None
        registration = checkov_registration(
            tool_version="3.3.15",
            image_digest=image,
            rules_digest=RULES,
            cwe_map=cwe,
        )
        adapter = CheckovJsonAdapter()
    elif analyzer is AnalyzerKind.KUBESEC:
        assert cwe is not None
        registration = kubesec_registration(
            target=target,
            input_paths=("deploy.yaml",),
            tool_version="2.14.2",
            image_digest=image,
            rules_digest=RULES,
            cwe_map=cwe,
        )
        adapter = KubesecJsonAdapter()
    else:
        assert database is not None
        registration = trivy_registration(
            tool_version="0.73.0",
            image_digest=image,
            database=database,
        )
        adapter = TrivyJsonAdapter()
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
        image_digest=image,
        snapshot_id=MANIFEST,
        tool_id=registration.tool_id,
        limits=limits,
        analyzer_data_id=(database.snapshot_id if database is not None else None),
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
        input_refs=(
            f"snapshot:{MANIFEST}",
            *((f"analyzer-data:{database.snapshot_id}",) if database is not None else ()),
        ),
        allowed_tools=frozenset({registration.tool_id}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(seconds=45),
        idempotency_key="task:docker-analyzer:1",
    )
    request = SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(tool_id=registration.tool_id, working_directory="source"),
        environment=registration.environment,
        idempotency_key="runner:docker-analyzer:1",
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
        idempotency_key="docker-analyzer:1",
    )
    if analyzer is AnalyzerKind.CHECKOV:
        document = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_20",
                        "check_name": "private raw message",
                        "file_path": "/deploy.yaml",
                        "file_line_range": [1, 2],
                    }
                ]
            }
        }
    elif analyzer is AnalyzerKind.KUBESEC:
        document = [
            {
                "fileName": "/workspace/source/deploy.yaml",
                "scoring": {
                    "critical": [
                        {"id": "Privileged", "reason": "private raw message", "points": -30}
                    ],
                    "advise": [],
                },
            }
        ]
    else:
        document = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "CweIDs": ["CWE-79"],
                            "Severity": "HIGH",
                            "Title": "private raw message",
                        }
                    ],
                }
            ]
        }
    output = json.dumps(document).encode()
    backend = real_backend or FakeAnalyzerDockerBackend(
        _inspection(profile, source, registration, analyzer_data_path), output
    )
    output_store = RunnerOutputStore(tmp_path / "outputs", max_output_bytes=16 * 1024 * 1024)
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(
            objects,
            {
                MANIFEST: source,
                **(
                    {database.snapshot_id: analyzer_data_path}
                    if database is not None and analyzer_data_path is not None
                    else {}
                ),
            },
        ),
        registry.docker_tools,
        engine_policy=(
            DockerEnginePolicy(
                require_rootless=os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
            )
            if real_backend is not None
            else None
        ),
        output_store=output_store,
        captured_output_tools=registry.tool_ids,
    )
    execution_store = AnalyzerDockerExecutionStore(tmp_path / "docker-execution.db")
    import_store = AnalyzerImportStore(tmp_path / "imports.db")
    import_service = AnalyzerImportService(
        adapter=adapter,
        store=import_store,
        artifact_store=AnalyzerObservationArtifactStore(tmp_path / "observations"),
    )
    service = DockerAnalyzerExecutionService(
        scope=scope,
        registry=registry,
        runner=runner,
        output_store=output_store,
        execution_store=execution_store,
        import_service=import_service,
    )
    return (
        target,
        registration,
        plan,
        cwe_path,
        backend,
        output_store,
        execution_store,
        import_store,
        service,
        analyzer_data_path,
    )


def test_docker_execution_seals_output_and_only_publishes_observations(
    tmp_path, approved_scope, now
):
    target, registration, plan, cwe_path, backend, outputs, store, imports, service, _ = _setup(
        tmp_path, approved_scope, now
    )
    first = service.execute(target, plan, cwe_map_path=cwe_path, now=now)
    second = service.execute(target, plan, cwe_map_path=cwe_path, now=now)

    assert first == second
    assert first.status is DockerAnalyzerExecutionStatus.COMPLETED
    assert first.analyzer_result_snapshot is not None
    assert first.import_outcome is not None
    assert first.import_outcome.observation_set.observations
    assert first.import_outcome.observation_set.analyzer is AnalyzerKind.CHECKOV
    assert outputs.read(first.runner_result.outputs[0]) == backend.output
    assert first.runner_result.cleanup.complete
    assert backend.starts == 1 and backend.removed
    serialized = first.model_dump_json()
    assert "private raw message" not in serialized
    for forbidden in ("candidate_id", "finding_id", "critic_verdict", "submission"):
        assert forbidden not in serialized
    with pytest.raises(ValueError, match="status does not match"):
        type(first).model_validate(
            {**first.model_dump(mode="python"), "status": DockerAnalyzerExecutionStatus.FAILED}
        )
    assert first.registration_id == registration.registration_id
    store.close()
    imports.close()


def test_cwe_drift_and_unadmitted_argv_fail_before_runner_checkpoint(tmp_path, approved_scope, now):
    target, _, plan, cwe_path, backend, _, store, imports, service, _ = _setup(
        tmp_path, approved_scope, now
    )
    cwe_path.write_text(json.dumps({"CKV_K8S_20": "CWE-79"}))
    with pytest.raises(AnalyzerExecutionRejected, match="CWE map"):
        service.execute(target, plan, cwe_map_path=cwe_path, now=now)
    assert backend.created_arguments is None
    assert (
        store.connection.execute("SELECT COUNT(*) FROM analyzer_docker_executions").fetchone()[0]
        == 0
    )
    store.close()
    imports.close()


def test_timeout_is_typed_and_container_is_cleaned(tmp_path, approved_scope, now):
    target, _, plan, cwe_path, backend, _, store, imports, service, _ = _setup(
        tmp_path, approved_scope, now
    )
    backend.start_error = TimeoutError("fixture timeout")
    outcome = service.execute(target, plan, cwe_map_path=cwe_path, now=now)
    assert outcome.status is DockerAnalyzerExecutionStatus.TIMED_OUT
    assert outcome.analyzer_result_snapshot is None
    assert outcome.import_outcome is None
    assert outcome.runner_result.cleanup.complete
    assert backend.killed and backend.removed and not backend.container_exists
    store.close()
    imports.close()


def test_unfinished_docker_checkpoint_refuses_replay(tmp_path, approved_scope, now):
    target, _, plan, cwe_path, backend, _, store, imports, service, _ = _setup(
        tmp_path, approved_scope, now
    )
    store.claim(plan, now=now)
    with pytest.raises(AnalyzerDockerExecutionRecoveryRequired):
        service.execute(target, plan, cwe_map_path=cwe_path, now=now)
    assert backend.created_arguments is None
    store.close()
    imports.close()


def test_kubesec_registration_only_accepts_manifest_kubernetes_paths(tmp_path, approved_scope, now):
    target = _target(approved_scope, now)
    cwe_path = tmp_path / "kubesec-cwe.json"
    cwe_path.write_text(json.dumps({"Privileged": "CWE-250"}))
    cwe = inspect_result_file(
        cwe_path,
        logical_name="cwe-map.json",
        max_bytes=1024,
        deadline=AnalyzerDeadline(5),
    )
    registration = kubesec_registration(
        target=target,
        input_paths=("deploy.yaml",),
        tool_version="2.14.2",
        image_digest=IMAGE,
        rules_digest=RULES,
        cwe_map=cwe,
    )
    assert registration.argv[2] == "/workspace/source/deploy.yaml"
    with pytest.raises(ValueError, match="Kubernetes files"):
        kubesec_registration(
            target=target,
            input_paths=("missing.yaml",),
            tool_version="2.14.2",
            image_digest=IMAGE,
            rules_digest=RULES,
            cwe_map=cwe,
        )


def test_trivy_uses_exact_offline_database_and_mandatory_observation_import(
    tmp_path, approved_scope, now
):
    (
        target,
        registration,
        plan,
        cwe_path,
        backend,
        _,
        store,
        imports,
        service,
        data_path,
    ) = _setup(tmp_path, approved_scope, now, analyzer=AnalyzerKind.TRIVY)

    outcome = service.execute(
        target,
        plan,
        cwe_map_path=cwe_path,
        analyzer_data_path=data_path,
        now=now,
    )

    assert outcome.status is DockerAnalyzerExecutionStatus.COMPLETED
    assert outcome.import_outcome is not None
    assert outcome.import_outcome.observation_set.analyzer is AnalyzerKind.TRIVY
    assert registration.trivy_database is not None
    assert registration.rules_digest == registration.trivy_database.snapshot_id
    assert registration.argv[registration.argv.index("--scanners") + 1] == "vuln"
    assert "secret" not in registration.argv
    tampered_argv = tuple(
        "vuln,secret" if item == "vuln" else item for item in registration.argv
    )
    tampered = AnalyzerToolRegistration.create(
        tool_id=registration.tool_id,
        analyzer=registration.analyzer,
        tool_version=registration.tool_version,
        image_digest=registration.image_digest,
        rules_digest=registration.rules_digest,
        adapter_id=registration.adapter_id,
        adapter_digest=registration.adapter_digest,
        argv=tampered_argv,
        environment=registration.environment,
        output_mode=registration.output_mode,
        trivy_database=registration.trivy_database,
    )
    with pytest.raises(ValueError, match="exact argv"):
        validate_admitted_registration(target, tampered)
    with pytest.raises(ValueError, match="only Trivy 0.73.0"):
        trivy_registration(
            tool_version="0.74.0",
            image_digest=registration.image_digest,
            database=registration.trivy_database,
        )
    assert backend.created_arguments is not None
    assert tuple(
        backend.created_arguments[
            backend.created_arguments.index("--pull") : backend.created_arguments.index("--pull")
            + 2
        ]
    ) == ("--pull", "never")
    assert "network=none" not in backend.created_arguments
    assert backend.created_arguments[backend.created_arguments.index("--network") + 1] == "none"
    assert any(
        "dst=/workspace/analyzer-data,readonly" in item for item in backend.created_arguments
    )
    assert outcome.runner_result.cleanup.complete and backend.removed
    store.close()
    imports.close()


def test_trivy_database_drift_fails_before_checkpoint_and_during_execution(
    tmp_path, approved_scope, now
):
    target, _, plan, _, backend, _, store, imports, service, data_path = _setup(
        tmp_path, approved_scope, now, analyzer=AnalyzerKind.TRIVY
    )
    assert data_path is not None
    payload = data_path / "db" / "trivy.db"
    database_dir = payload.parent
    database_dir.chmod(0o755)
    payload.chmod(0o644)
    payload.write_bytes(b"preflight drift")
    payload.chmod(0o444)
    database_dir.chmod(0o555)
    with pytest.raises(AnalyzerExecutionRejected, match="verification failed"):
        service.execute(target, plan, analyzer_data_path=data_path, now=now)
    assert backend.created_arguments is None
    assert (
        store.connection.execute("SELECT COUNT(*) FROM analyzer_docker_executions").fetchone()[0]
        == 0
    )
    store.close()
    imports.close()

    target, _, plan, _, backend, _, store, imports, service, data_path = _setup(
        tmp_path / "during", approved_scope, now, analyzer=AnalyzerKind.TRIVY
    )
    assert data_path is not None
    payload = data_path / "db" / "trivy.db"

    def mutate_database():
        payload.parent.chmod(0o755)
        payload.chmod(0o644)
        payload.write_bytes(b"runtime drift")
        payload.chmod(0o444)
        payload.parent.chmod(0o555)

    backend.on_start = mutate_database
    with pytest.raises(AnalyzerExecutionRejected, match="changed during execution"):
        service.execute(target, plan, analyzer_data_path=data_path, now=now)
    assert backend.removed and not backend.container_exists
    assert (
        store.connection.execute("SELECT state FROM analyzer_docker_executions").fetchone()[0]
        == "started"
    )
    store.close()
    imports.close()


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_ANALYZER_INTEGRATION") != "1",
    reason="set VULNLOOM_ANALYZER_INTEGRATION=1 after provisioning exact analyzer images",
)
@pytest.mark.parametrize(
    ("analyzer", "image_ref", "expected_rule"),
    (
        (
            AnalyzerKind.CHECKOV,
            os.environ.get("VULNLOOM_CHECKOV_IMAGE", "bridgecrew/checkov:3.3.15"),
            "CKV_K8S_20",
        ),
        (
            AnalyzerKind.KUBESEC,
            os.environ.get("VULNLOOM_KUBESEC_IMAGE", "kubesec/kubesec:v2.14.2"),
            "Privileged",
        ),
        (
            AnalyzerKind.TRIVY,
            os.environ.get("VULNLOOM_TRIVY_IMAGE", "aquasec/trivy:0.73.0"),
            "CVE-2019-19844",
        ),
    ),
)
def test_real_analyzer_executes_offline_and_imports_only_observations(
    tmp_path, approved_scope, now, analyzer, image_ref, expected_rule
):
    backend = DockerCliBackend()
    image = backend.inspect_image(image_ref)["Id"]
    target, _, plan, cwe_path, _, outputs, store, imports, service, data_path = _setup(
        tmp_path,
        approved_scope,
        now,
        analyzer=analyzer,
        image=image,
        real_backend=backend,
    )
    source = tmp_path / "targets" / MANIFEST
    (source / "deploy.yaml").write_text(
        """apiVersion: v1
kind: Pod
metadata:
  name: unsafe-fixture
spec:
  containers:
    - name: fixture
      image: alpine:3.22
      securityContext:
        allowPrivilegeEscalation: true
        privileged: true
"""
    )
    source.chmod(0o755)
    (source / "deploy.yaml").chmod(0o644)
    if analyzer is AnalyzerKind.TRIVY:
        (source / "requirements.txt").write_text("django==2.0.0\n")
        (source / "requirements.txt").chmod(0o644)

    outcome = service.execute(
        target,
        plan,
        cwe_map_path=cwe_path,
        analyzer_data_path=data_path,
        now=now,
    )

    assert outcome.status is DockerAnalyzerExecutionStatus.COMPLETED, (
        outcome.runner_result.error_codes,
        (service.runner.last_terminal_inspection or {}).get("State"),
    )
    assert outcome.import_outcome is not None
    assert canonical_digest(expected_rule) in {
        item.rule_id_digest for item in outcome.import_outcome.observation_set.observations
    }
    assert outcome.runner_result.cleanup.complete
    assert len(outcome.runner_result.outputs) == 1
    assert outputs.read(outcome.runner_result.outputs[0])
    assert service.runner.last_inspection is not None
    assert service.runner.last_inspection["HostConfig"]["NetworkMode"] == "none"
    assert not backend.exists(service.runner.last_inspection["Id"])
    store.close()
    imports.close()
