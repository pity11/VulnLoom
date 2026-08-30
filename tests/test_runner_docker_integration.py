from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    RegisteredObjectStore,
    SandboxRunRequest,
    SandboxRunStatus,
    ToolInvocation,
    sandbox_profile_digest,
    static_profile,
)

SNAPSHOT = "a" * 64


def _request(profile, now, *, wall_seconds=20, arguments=()):
    task = TaskEnvelope(
        engagement_id=uuid4(),
        target_id=uuid4(),
        target_version="b" * 40,
        scope_id=uuid4(),
        worker_role=WorkerRole.SOURCE_MAPPER,
        scope_version=1,
        policy_digest="c" * 64,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest="d" * 64,
        input_refs=("snapshot:" + SNAPSHOT,),
        allowed_tools=frozenset({"source.read"}),
        budget=TaskBudget(wall_seconds=wall_seconds, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(seconds=wall_seconds + 5),
        idempotency_key=f"task:docker-integration:{uuid4()}",
    )
    return SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(
            tool_id="source.read", arguments=arguments, working_directory="source"
        ),
        environment={"VULNLOOM_TASK_ID": str(task.task_id)},
        idempotency_key=f"run:docker-integration:{uuid4()}",
    )


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 to run real Docker isolation probes",
)
def test_real_container_hardening_and_cleanup(tmp_path: Path):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    source.chmod(0o755)
    (source / "safe.txt").write_text("authorized fixture\n")
    (source / "safe.txt").chmod(0o644)

    profile = static_profile(image_digest=image, snapshot_id=SNAPSHOT)
    now = datetime.now(UTC)
    request = _request(profile, now)
    probe = """
set -eu
[ "$(id -u)" = "65532" ]
grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
! touch /root-filesystem-must-be-read-only
! touch /workspace/source/source-must-be-read-only
touch /workspace/output/output-is-writable
touch /tmp/temp-is-writable
[ "$(wc -l < /proc/net/route)" = "1" ]
[ ! -S /var/run/docker.sock ]
[ ! -e /run/host-services/docker.proxy.sock ]
[ -z "${AWS_SECRET_ACCESS_KEY+x}" ]
[ -n "${VULNLOOM_TASK_ID}" ]
""".strip()
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (
            DockerTool(
                tool_id="source.read",
                argv_prefix=("/bin/sh", "-c", probe, "vulnloom-isolation-probe"),
            ),
        ),
        # Docker Desktop is rootful. This exception exists only in the integration test;
        # the production default remains fail-closed and requires a rootless daemon.
        engine_policy=DockerEnginePolicy(require_rootless=False),
    )

    result = runner.execute(request, now=now)

    assert result.status is SandboxRunStatus.COMPLETED
    assert result.cleanup.complete
    assert runner.last_inspection is not None
    container_id = runner.last_inspection["Id"]
    assert not backend.exists(container_id)


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 to run real Docker isolation probes",
)
def test_real_timeout_kills_and_removes_container(tmp_path: Path):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    source.chmod(0o755)
    profile = static_profile(image_digest=image, snapshot_id=SNAPSHOT)
    limits = profile.limits.model_copy(update={"wall_seconds": 1, "cpu_millis": 1_000})
    profile = profile.model_copy(update={"limits": limits})
    now = datetime.now(UTC)
    request = _request(profile, now, wall_seconds=1, arguments=("10",))
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="source.read", argv_prefix=("/bin/sleep",)),),
        engine_policy=DockerEnginePolicy(require_rootless=False),
    )

    result = runner.execute(request, now=now)

    assert result.status is SandboxRunStatus.TIMED_OUT
    assert result.cleanup.complete
    assert runner.last_inspection is not None
    assert not backend.exists(runner.last_inspection["Id"])
