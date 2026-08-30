from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.runners import (
    DockerSandboxRunner,
    DockerTool,
    NetworkGrant,
    RegisteredObjectStore,
    RunnerCleanupFailed,
    RunnerOutputStore,
    RunnerRejected,
    SandboxRunRequest,
    SandboxRunStatus,
    ToolInvocation,
    sandbox_profile_digest,
    static_profile,
    validation_profile,
)
from vulnloom.runners.docker import DockerBackendError, _network_gateway_ips

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64


class FakeDockerBackend:
    def __init__(self, inspection):
        self.inspection = inspection
        self.security_options = ["name=seccomp,profile=builtin", "name=rootless"]
        self.created_arguments = None
        self.container_exists = False
        self.start_error = None
        self.exit_code = 0
        self.killed = False
        self.removed = False
        self.cleanup_leaks = False
        self.output_bytes = b'{"results": []}'
        self.copy_error = None
        self.output_symlink = None

    def engine_info(self):
        return {
            "SecurityOptions": self.security_options,
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
        return "container-id"

    def inspect_container(self, container):
        return self.inspection

    def start(self, container, timeout):
        if self.start_error:
            raise self.start_error
        return self.exit_code

    def kill(self, container):
        self.killed = True

    def start_capture(self, container, timeout, destination, max_bytes):
        if self.start_error:
            raise self.start_error
        if self.copy_error:
            raise self.copy_error
        if self.output_symlink is not None:
            destination.symlink_to(self.output_symlink)
        elif len(self.output_bytes) > max_bytes:
            raise ValueError("oversized")
        else:
            destination.write_bytes(self.output_bytes)
        return self.exit_code

    def remove(self, container):
        self.removed = True
        if not self.cleanup_leaks:
            self.container_exists = False

    def exists(self, container):
        return self.container_exists


def _request(now, profile):
    task = TaskEnvelope(
        engagement_id=uuid4(),
        target_id=uuid4(),
        target_version="4" * 40,
        scope_id=uuid4(),
        worker_role=WorkerRole.SOURCE_MAPPER,
        scope_version=1,
        policy_digest="5" * 64,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest="6" * 64,
        input_refs=("snapshot:" + SNAPSHOT,),
        allowed_tools=frozenset({"source.read"}),
        budget=TaskBudget(wall_seconds=30, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(seconds=30),
        idempotency_key="task:docker:1",
    )
    return SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(
            tool_id="source.read", arguments=("safe.txt",), working_directory="source"
        ),
        environment={"VULNLOOM_TASK_ID": str(task.task_id)},
        idempotency_key="run:docker:1",
    )


def _inspection(profile, source: Path):
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    }
    return {
        "Config": {
            "User": f"{profile.run_as_uid}:{profile.run_as_gid}",
            "Env": [f"{key}={value}" for key, value in environment.items()],
            "Entrypoint": ["/usr/bin/tool"],
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
                "/tmp": (
                    "rw,noexec,nosuid,nodev,size=268435456,uid=65532,gid=65532,mode=0700"
                ),
                "/workspace/output": (
                    "rw,noexec,nosuid,nodev,size=67108864,uid=65532,gid=65532,mode=0700"
                ),
            },
            "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
            "Init": True,
            "LogConfig": {"Type": "none"},
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": [{"Source": str(source), "Destination": "/workspace/source", "RW": False}],
        "State": {"ExitCode": 0, "OOMKilled": False},
    }


def _runner(tmp_path, now, *, rootless=True):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={_request(now, profile).task.task_id}")
    backend = FakeDockerBackend(inspection)
    if not rootless:
        backend.security_options = ["name=seccomp,profile=builtin"]
    store = RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source})
    runner = DockerSandboxRunner(
        backend,
        store,
        (DockerTool(tool_id="source.read", argv_prefix=("/usr/bin/tool",)),),
    )
    return runner, backend, profile


def test_docker_runner_rejects_non_rootless_engine_before_create(tmp_path, now):
    runner, backend, profile = _runner(tmp_path, now, rootless=False)
    with pytest.raises(RunnerRejected, match="rootless"):
        runner.execute(_request(now, profile), now=now)
    assert backend.created_arguments is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("CgroupVersion", "1", "cgroup v2"),
        ("MemoryLimit", False, "resource controls"),
        ("CpuCfsQuota", False, "resource controls"),
        ("PidsLimit", False, "resource controls"),
    ],
)
def test_docker_runner_rejects_engines_without_enforced_resource_controls(
    tmp_path, now, field, value, message
):
    runner, backend, profile = _runner(tmp_path, now)
    original = backend.engine_info
    backend.engine_info = lambda: {**original(), field: value}

    with pytest.raises(RunnerRejected, match=message):
        runner.execute(_request(now, profile), now=now)

    assert backend.created_arguments is None


def test_docker_runner_builds_hardened_argv_and_cleans_container(tmp_path, now):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    request = _request(now, profile)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={request.task.task_id}")
    backend = FakeDockerBackend(inspection)
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="source.read", argv_prefix=("/usr/bin/tool", "--fixed")),),
    )

    result = runner.execute(request, now=now)

    assert result.status is SandboxRunStatus.COMPLETED
    assert result.cleanup.complete
    assert backend.removed and not backend.container_exists
    arguments = backend.created_arguments
    assert arguments is not None
    for flag in (
        "--read-only",
        "--cap-drop",
        "--security-opt",
        "--network",
        "--pids-limit",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--ulimit",
        "--tmpfs",
        "--mount",
        "--init",
        "--log-driver",
        "--restart",
    ):
        assert flag in arguments
    assert arguments[-2:] == ("--fixed", "safe.txt")
    entrypoint = arguments.index("--entrypoint")
    assert arguments[entrypoint + 1] == "/usr/bin/tool"
    assert all("AWS_" not in item and "TOKEN" not in item for item in arguments)


def test_docker_runner_timeout_kills_and_removes_container(tmp_path, now):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    request = _request(now, profile)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={request.task.task_id}")
    backend = FakeDockerBackend(inspection)
    backend.start_error = TimeoutError()
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="source.read", argv_prefix=("/usr/bin/tool",)),),
    )

    result = runner.execute(request, now=now)
    assert result.status is SandboxRunStatus.TIMED_OUT
    assert backend.killed and backend.removed


def test_docker_runner_captures_one_immutable_output_before_cleanup(tmp_path, now):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    request = _request(now, profile)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={request.task.task_id}")
    backend = FakeDockerBackend(inspection)
    outputs = RunnerOutputStore(tmp_path / "runner-outputs")
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="source.read", argv_prefix=("/usr/bin/tool",)),),
        output_store=outputs,
        captured_output_tools=frozenset({"source.read"}),
    )

    result = runner.execute(request, now=now)

    assert result.status is SandboxRunStatus.COMPLETED
    assert result.cleanup.complete
    assert len(result.outputs) == 1
    assert outputs.read(result.outputs[0]) == backend.output_bytes
    assert result.usage.output_bytes == len(backend.output_bytes)
    assert backend.removed and not backend.container_exists


@pytest.mark.parametrize(
    ("success_codes", "expected_status", "expected_outputs"),
    (
        (frozenset({0, 2}), SandboxRunStatus.COMPLETED, 1),
        (frozenset({0}), SandboxRunStatus.FAILED, 0),
    ),
)
def test_tool_specific_exit_codes_do_not_publish_failed_output(
    tmp_path, now, success_codes, expected_status, expected_outputs
):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    request = _request(now, profile)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={request.task.task_id}")
    inspection["State"]["ExitCode"] = 2
    backend = FakeDockerBackend(inspection)
    backend.exit_code = 2
    outputs = RunnerOutputStore(tmp_path / "runner-outputs")
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (
            DockerTool(
                tool_id="source.read",
                argv_prefix=("/usr/bin/tool",),
                successful_exit_codes=success_codes,
            ),
        ),
        output_store=outputs,
        captured_output_tools=frozenset({"source.read"}),
    )

    result = runner.execute(request, now=now)

    assert result.status is expected_status
    assert len(result.outputs) == expected_outputs
    assert result.cleanup.complete


def test_docker_tool_rejects_unbounded_success_exit_codes():
    with pytest.raises(ValueError, match="exit codes"):
        DockerTool(
            tool_id="source.read",
            argv_prefix=("/usr/bin/tool",),
            successful_exit_codes=frozenset({256}),
        )


@pytest.mark.parametrize("failure", ("missing", "oversized", "symlink"))
def test_output_capture_failure_is_typed_and_still_cleans_container(
    tmp_path, now, failure
):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    request = _request(now, profile)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={request.task.task_id}")
    backend = FakeDockerBackend(inspection)
    if failure == "missing":
        backend.copy_error = FileNotFoundError("missing")
    elif failure == "oversized":
        backend.output_bytes = b"x" * 17
    else:
        outside = tmp_path / "outside.json"
        outside.write_text("{}")
        backend.output_symlink = outside
    outputs = RunnerOutputStore(tmp_path / "runner-outputs", max_output_bytes=16)
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="source.read", argv_prefix=("/usr/bin/tool",)),),
        output_store=outputs,
        captured_output_tools=frozenset({"source.read"}),
    )

    result = runner.execute(request, now=now)

    assert result.status is SandboxRunStatus.FAILED
    assert result.error_codes == ("output_capture_failed",)
    assert result.outputs == ()
    assert result.cleanup.complete
    assert backend.removed and not backend.container_exists
    assert tuple(outputs.temporary.iterdir()) == ()


def test_post_create_hardening_refusal_still_removes_container(tmp_path, now):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    request = _request(now, profile)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={request.task.task_id}")
    inspection["HostConfig"]["ReadonlyRootfs"] = False
    backend = FakeDockerBackend(inspection)
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="source.read", argv_prefix=("/usr/bin/tool",)),),
    )

    with pytest.raises(RunnerRejected, match="hardening"):
        runner.execute(request, now=now)
    assert backend.removed and not backend.container_exists


def test_docker_runner_refuses_target_only_network_before_create(tmp_path, now):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id=SNAPSHOT,
        network_grants=(
            NetworkGrant(
                host="target.example.test",
                ports=frozenset({443}),
                schemes=frozenset({"https"}),
            ),
        ),
    )
    task_request = _request(now, static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT))
    task = task_request.task.model_copy(
        update={
            "worker_role": WorkerRole.VALIDATOR,
            "sandbox_profile_digest": sandbox_profile_digest(profile),
            "allowed_tools": frozenset({"sandbox.test"}),
        }
    )
    request = task_request.model_copy(
        update={
            "task": task,
            "profile": profile,
            "invocation": ToolInvocation(tool_id="sandbox.test", working_directory="source"),
        }
    )
    backend = FakeDockerBackend(_inspection(profile, source))
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="sandbox.test", argv_prefix=("/usr/bin/test-tool",)),),
    )
    with pytest.raises(RunnerRejected, match="target-only"):
        runner.execute(request, now=now)
    assert backend.created_arguments is None


def test_cleanup_leak_is_never_reported_as_clean(tmp_path, now):
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    request = _request(now, profile)
    inspection = _inspection(profile, source)
    inspection["Config"]["Env"].append(f"VULNLOOM_TASK_ID={request.task.task_id}")
    backend = FakeDockerBackend(inspection)
    backend.cleanup_leaks = True
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="source.read", argv_prefix=("/usr/bin/tool",)),),
    )
    with pytest.raises(RunnerCleanupFailed):
        runner.execute(request, now=now)


def test_registered_object_store_rejects_post_registration_symlink_swap(tmp_path):
    root = tmp_path / "objects"
    source = root / SNAPSHOT
    source.mkdir(parents=True)
    store = RegisteredObjectStore(root, {SNAPSHOT: source})
    moved = root / "moved"
    source.rename(moved)
    outside = tmp_path / "outside"
    outside.mkdir()
    source.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RunnerRejected, match="no longer safe"):
        store.resolve(SNAPSHOT)


def test_docker_network_gateway_parser_normalizes_and_fails_closed():
    inspections = (
        {"IPAM": {"Config": [{"Gateway": "172.17.0.1"}, {"Gateway": "2001:db8::1"}]}},
        {"IPAM": {"Config": None}},
    )
    assert _network_gateway_ips(inspections) == frozenset({"172.17.0.1", "2001:db8::1"})

    with pytest.raises(DockerBackendError, match="malformed"):
        _network_gateway_ips(({"IPAM": {"Config": [{"Gateway": "not-an-ip"}]}},))
