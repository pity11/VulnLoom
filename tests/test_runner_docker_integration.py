from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.broker import (
    BrokerCall,
    BrokerStatus,
    HttpRequestPlan,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.domain.models import NetworkTargetScope, Scope, ScopeState
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    HostileWorkerProbeExpectation,
    HostileWorkerProbeKind,
    HostileWorkerProbeObservation,
    HostileWorkerQualificationPlan,
    HostileWorkerQualificationStatus,
    NetworkGrant,
    RegisteredObjectStore,
    ResourcePressureProbeExpectation,
    ResourcePressureProbeKind,
    ResourcePressureProbeObservation,
    ResourcePressureQualificationPlan,
    ResourcePressureQualificationStatus,
    RunnerOutputStore,
    SandboxRunRequest,
    SandboxRunStatus,
    ToolInvocation,
    qualify_hostile_worker,
    qualify_resource_pressure,
    sandbox_profile_digest,
    static_profile,
    validation_profile,
)

SNAPSHOT = "a" * 64


def _engine_policy() -> DockerEnginePolicy:
    if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1":
        return DockerEnginePolicy()
    # Local Docker Desktop can exercise the container boundary, but cannot qualify production.
    return DockerEnginePolicy(require_rootless=False, require_versioned_seccomp=False)


def _docker(backend: DockerCliBackend, *arguments: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        (backend.executable, *arguments),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env=backend.environment,
    )
    if result.returncode != 0:
        raise AssertionError(f"Docker fixture command failed: {result.stderr.strip()[:500]}")
    return result


class _PinnedGatewayResolver:
    implementation_digest = PinnedHttpTransport.implementation_digest

    def __init__(self, gateway: str):
        self.gateway = gateway

    def resolve(self, host: str) -> tuple[str, ...]:
        return (self.gateway,)


class _NoSocketTransport:
    implementation_digest = PinnedHttpTransport.implementation_digest

    def __init__(self):
        self.calls = []

    def send(self, request):
        self.calls.append(request)
        raise AssertionError("host gateway denial must happen before opening a socket")


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
grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status
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
        engine_policy=_engine_policy(),
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
        engine_policy=_engine_policy(),
    )

    result = runner.execute(request, now=now)

    assert result.status is SandboxRunStatus.TIMED_OUT
    assert result.cleanup.complete
    assert runner.last_inspection is not None
    assert not backend.exists(runner.last_inspection["Id"])


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 to run real Docker isolation probes",
)
def test_real_output_is_captured_before_container_cleanup(tmp_path: Path):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    source.chmod(0o755)
    profile = static_profile(image_digest=image, snapshot_id=SNAPSHOT)
    now = datetime.now(UTC)
    request = _request(profile, now)
    outputs = RunnerOutputStore(tmp_path / "outputs")
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (
            DockerTool(
                tool_id="source.read",
                argv_prefix=(
                    "/bin/sh",
                    "-c",
                    "printf '%s' '{\"results\":[]}'",
                ),
            ),
        ),
        engine_policy=_engine_policy(),
        output_store=outputs,
        captured_output_tools=frozenset({"source.read"}),
    )

    result = runner.execute(request, now=now)

    assert result.status is SandboxRunStatus.COMPLETED
    assert outputs.read(result.outputs[0]) == b'{"results":[]}'
    assert result.cleanup.complete
    assert runner.last_inspection is not None
    assert not backend.exists(runner.last_inspection["Id"])


@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_ROOTLESS_QUALIFICATION=1 on a rootless Linux daemon",
)
def test_rootless_worker_cannot_reach_bridge_gateway_or_sibling_container(tmp_path: Path):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    peer_name = f"vulnloom-isolation-peer-{uuid4().hex}"
    peer_id = _docker(
        backend,
        "run",
        "--detach",
        "--name",
        peer_name,
        "--network",
        "bridge",
        "--pull",
        "never",
        "alpine:3.22",
        "/bin/busybox",
        "nc",
        "-lk",
        "-p",
        "8080",
        "-e",
        "/bin/echo",
    ).stdout.strip()
    try:
        _docker(
            backend,
            "exec",
            peer_id,
            "/bin/busybox",
            "nc",
            "-z",
            "-w",
            "1",
            "127.0.0.1",
            "8080",
        )
        peer = json.loads(_docker(backend, "inspect", peer_id).stdout)[0]
        bridge = peer["NetworkSettings"]["Networks"]["bridge"]
        gateways = backend.network_gateway_ips()
        gateway_ip = next((value for value in sorted(gateways) if ":" not in value), None)
        peer_ip = bridge["IPAddress"] or _docker(
            backend, "exec", peer_id, "/bin/hostname", "-i"
        ).stdout.split()[0]
        assert gateway_ip and peer_ip
        assert gateway_ip in gateways

        source = tmp_path / "objects" / SNAPSHOT
        source.mkdir(parents=True)
        source.chmod(0o755)
        profile = static_profile(image_digest=image, snapshot_id=SNAPSHOT)
        now = datetime.now(UTC)
        probe = """
set -eu
[ "$(wc -l < /proc/net/route)" = "1" ]
for address in "$@"; do
  ! nc -z -w 1 "$address" 8080
done
""".strip()
        request = _request(profile, now, arguments=(gateway_ip, peer_ip))
        runner = DockerSandboxRunner(
            backend,
            RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
            (
                DockerTool(
                    tool_id="source.read",
                    argv_prefix=("/bin/sh", "-c", probe, "vulnloom-egress-probe"),
                ),
            ),
        )

        result = runner.execute(request, now=now)

        assert result.status is SandboxRunStatus.COMPLETED
        assert result.cleanup.complete
        assert runner.last_inspection is not None
        assert not backend.exists(runner.last_inspection["Id"])
    finally:
        backend.remove(peer_id)
        assert not backend.exists(peer_id)


@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_ROOTLESS_QUALIFICATION=1 on a rootless Linux daemon",
)
def test_rootless_hostile_worker_canary_qualification(tmp_path: Path, monkeypatch):
    """S1.1 admission uses only local fake secrets and non-exploitative canaries."""

    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    (source / "immutable.txt").write_text("sealed\n")
    source.chmod(0o755)
    (source / "immutable.txt").chmod(0o644)
    authority_canary = tmp_path / "control-plane-authority-canary"
    authority_canary.write_text("FAKE_CONTROL_PLANE_SECRET\n")
    monkeypatch.setenv("VULNLOOM_FAKE_PROVIDER_TOKEN", "FAKE_PROVIDER_TOKEN")
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "fake-ssh-agent.sock"))
    now = datetime.now(UTC)
    profile = static_profile(image_digest=image, snapshot_id=SNAPSHOT)
    store = RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source})

    observations_by_kind = {}
    expectations_by_kind = {}

    def execute(
        script: str,
        *,
        kinds,
        expected_status: SandboxRunStatus = SandboxRunStatus.COMPLETED,
        wall_seconds: int = 20,
    ):
        current_profile = profile
        if wall_seconds != profile.limits.wall_seconds:
            limits = profile.limits.model_copy(
                update={"wall_seconds": wall_seconds, "cpu_millis": wall_seconds * 1_000}
            )
            current_profile = profile.model_copy(update={"limits": limits})
        request = _request(current_profile, now, wall_seconds=wall_seconds)
        for kind in kinds:
            expectations_by_kind[kind] = HostileWorkerProbeExpectation.from_request(
                kind=kind,
                request=request,
                expected_status=expected_status,
            )
        runner = DockerSandboxRunner(
            backend,
            store,
            (
                DockerTool(
                    tool_id="source.read",
                    argv_prefix=("/bin/sh", "-c", script, "vulnloom-s1.1-canary"),
                ),
            ),
        )
        result = runner.execute(request, now=now)
        assert runner.last_inspection is not None
        return result, not backend.exists(runner.last_inspection["Id"])

    boundary_script = f"""
set -eu
[ -z "${{VULNLOOM_FAKE_PROVIDER_TOKEN+x}}" ]
[ -z "${{SSH_AUTH_SOCK+x}}" ]
[ ! -e /var/run/docker.sock ]
[ ! -e /run/host-services/docker.proxy.sock ]
[ ! -e /root/.ssh ]
[ ! -e /control-plane-authority-canary ]
[ ! -e {authority_canary} ]
! touch /s1-root-must-stay-read-only
! printf tampered > /workspace/source/immutable.txt
! touch /workspace/source/injected
[ "$(wc -l < /proc/net/route)" = "1" ]
touch /tmp/s1-persistence-canary
touch /workspace/output/s1-persistence-canary
sleep 300 &
""".strip()
    boundary_kinds = (
        HostileWorkerProbeKind.SECRET_BOUNDARY,
        HostileWorkerProbeKind.NETWORK_BOUNDARY,
        HostileWorkerProbeKind.HOST_RESOURCE_BOUNDARY,
        HostileWorkerProbeKind.AUTHORITY_READ_ONLY,
    )
    boundary, boundary_absent = execute(boundary_script, kinds=boundary_kinds)
    assert boundary.status is SandboxRunStatus.COMPLETED
    for kind in boundary_kinds:
        observations_by_kind[kind] = HostileWorkerProbeObservation.from_result(
            kind=kind, result=boundary, container_absent=boundary_absent
        )

    ephemeral, ephemeral_absent = execute(
        "set -eu; [ ! -e /tmp/s1-persistence-canary ]; "
        "[ ! -e /workspace/output/s1-persistence-canary ]",
        kinds=(HostileWorkerProbeKind.EPHEMERAL_WRITABLE_LAYER,),
    )
    observations_by_kind[HostileWorkerProbeKind.EPHEMERAL_WRITABLE_LAYER] = (
        HostileWorkerProbeObservation.from_result(
            kind=HostileWorkerProbeKind.EPHEMERAL_WRITABLE_LAYER,
            result=ephemeral,
            container_absent=ephemeral_absent,
        )
    )

    crashed, crash_absent = execute(
        "kill -SEGV $$",
        kinds=(HostileWorkerProbeKind.CRASH_CLEANUP,),
        expected_status=SandboxRunStatus.FAILED,
    )
    assert crashed.status is SandboxRunStatus.FAILED
    observations_by_kind[HostileWorkerProbeKind.CRASH_CLEANUP] = (
        HostileWorkerProbeObservation.from_result(
            kind=HostileWorkerProbeKind.CRASH_CLEANUP,
            result=crashed,
            container_absent=crash_absent,
        )
    )

    timed_out, timeout_absent = execute(
        "sleep 10",
        kinds=(HostileWorkerProbeKind.TIMEOUT_CLEANUP,),
        expected_status=SandboxRunStatus.TIMED_OUT,
        wall_seconds=1,
    )
    assert timed_out.status is SandboxRunStatus.TIMED_OUT
    observations_by_kind[HostileWorkerProbeKind.TIMEOUT_CLEANUP] = (
        HostileWorkerProbeObservation.from_result(
            kind=HostileWorkerProbeKind.TIMEOUT_CLEANUP,
            result=timed_out,
            container_absent=timeout_absent,
        )
    )

    observations = tuple(observations_by_kind[kind] for kind in HostileWorkerProbeKind)
    expectations = tuple(expectations_by_kind[kind] for kind in HostileWorkerProbeKind)
    plan = HostileWorkerQualificationPlan.create(
        image_digest=image,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        probes=expectations,
    )

    outcome = qualify_hostile_worker(plan, observations, now=now)

    assert outcome.status is HostileWorkerQualificationStatus.ADMITTED
    assert authority_canary.read_text() == "FAKE_CONTROL_PLANE_SECRET\n"
    assert (source / "immutable.txt").read_text() == "sealed\n"
    assert not (source / "injected").exists()


@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_ROOTLESS_QUALIFICATION=1 on a rootless Linux daemon",
)
def test_rootless_resource_pressure_canary_qualification(tmp_path: Path):
    """S1.2 uses bounded local saturation canaries, never an unbounded fork bomb."""

    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    now = datetime.now(UTC)
    base_profile = static_profile(image_digest=image, snapshot_id=SNAPSHOT)
    store = RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source})
    observations = []
    expectations = []

    def execute(
        kind: ResourcePressureProbeKind,
        argv_prefix: tuple[str, ...],
        *,
        limits: dict[str, int],
        captured_output: bool = False,
        wall_seconds: int = 20,
    ):
        profile_limits = base_profile.limits.model_copy(update=limits)
        profile = base_profile.model_copy(update={"limits": profile_limits})
        request = _request(profile, now, wall_seconds=wall_seconds)
        expectation = ResourcePressureProbeExpectation.from_request(
            kind=kind, request=request
        )
        output_store = (
            RunnerOutputStore(tmp_path / f"capture-{kind.value}", max_output_bytes=4096)
            if captured_output
            else None
        )
        runner = DockerSandboxRunner(
            backend,
            store,
            (DockerTool(tool_id="source.read", argv_prefix=argv_prefix),),
            output_store=output_store,
            captured_output_tools=(
                frozenset({"source.read"}) if captured_output else frozenset()
            ),
        )
        result = runner.execute(request, now=now)
        assert runner.last_inspection is not None
        observation = ResourcePressureProbeObservation.from_result(
            kind=kind,
            result=result,
            boundary_observed=(
                result.status is expectation.expected_status
                and result.error_codes == expectation.expected_error_codes
            ),
            container_absent=not backend.exists(runner.last_inspection["Id"]),
        )
        expectations.append(expectation)
        observations.append(observation)

    execute(
        ResourcePressureProbeKind.PID_LIMIT,
        (
            "/bin/sh",
            "-c",
            "set -eu; [ \"$(cat /sys/fs/cgroup/pids.max)\" = 16 ]; "
            "! seq 1 64 | xargs -P 64 -n 1 sh -c 'sleep 2'; "
            "awk '$1 == \"max\" && $2 > 0 { seen=1 } END { exit !seen }' "
            "/sys/fs/cgroup/pids.events",
            "vulnloom-s1.2-pid-canary",
        ),
        limits={"pids": 16},
    )
    execute(
        ResourcePressureProbeKind.OPEN_FILES_LIMIT,
        (
            "/bin/sh",
            "-c",
            "set -eu; [ \"$(ulimit -n)\" = 32 ]; "
            "! (n=10; while [ $n -lt 128 ]; do "
            "eval \"exec $n</dev/null\" 2>/dev/null; n=$((n+1)); done)",
            "vulnloom-s1.2-fd-canary",
        ),
        limits={"open_files": 32},
    )
    execute(
        ResourcePressureProbeKind.OUTPUT_LIMIT,
        ("/bin/sh", "-c", "yes x | head -c 65536", "vulnloom-s1.2-output-canary"),
        limits={},
        captured_output=True,
    )
    execute(
        ResourcePressureProbeKind.TEMP_STORAGE_LIMIT,
        (
            "/bin/sh",
            "-c",
            "set -eu; ! dd if=/dev/zero of=/tmp/fill bs=1048576 count=2 2>/dev/null; "
            "[ \"$(wc -c < /tmp/fill)\" -le 1048576 ]",
            "vulnloom-s1.2-temp-canary",
        ),
        limits={"tmp_bytes": 1024 * 1024},
    )
    execute(
        ResourcePressureProbeKind.MEMORY_LIMIT,
        (
            "/usr/bin/awk",
            "BEGIN { for (i=0; i<64; i++) a[i]=sprintf(\"%1048576s\", \"x\") }",
        ),
        limits={"memory_bytes": 16 * 1024 * 1024},
    )
    execute(
        ResourcePressureProbeKind.TIMEOUT_PROCESS_GROUP,
        (
            "/bin/sh",
            "-c",
            "sleep 300 & wait",
            "vulnloom-s1.2-timeout-canary",
        ),
        limits={"wall_seconds": 1, "cpu_millis": 1000},
        wall_seconds=1,
    )

    plan = ResourcePressureQualificationPlan.create(
        image_digest=image,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        probes=tuple(expectations),
    )
    outcome = qualify_resource_pressure(plan, tuple(observations), now=now)

    assert outcome.status is ResourcePressureQualificationStatus.ADMITTED
    assert outcome.denial_codes == ()


@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_ROOTLESS_QUALIFICATION=1 on a rootless Linux daemon",
)
def test_live_broker_denies_actual_daemon_gateway_before_transport():
    backend = DockerCliBackend()
    gateways = backend.network_gateway_ips()
    gateway = next((value for value in sorted(gateways) if ":" not in value), None)
    if gateway is None:
        pytest.skip("rootless daemon exposes no IPv4 network gateway")
    now = datetime.now(UTC)
    host = "docker-gateway.example.test"
    scope = Scope(
        engagement_id=uuid4(),
        authority_reference="rootless-gateway-denial",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=2),
        network_targets=(
            NetworkTargetScope(
                host=host,
                ports=frozenset({80}),
                schemes=frozenset({"http"}),
            ),
        ),
        allowed_test_classes=frozenset({"read_only"}),
        state=ScopeState.APPROVED,
        approved_by="rootless-integration",
        approved_at=now,
    )
    image = backend.inspect_image("alpine:3.22")["Id"]
    profile = validation_profile(
        image_digest=image,
        snapshot_id=SNAPSHOT,
        network_grants=(
            NetworkGrant(
                host=host,
                ports=frozenset({80}),
                schemes=frozenset({"http"}),
            ),
        ),
    )
    registry = pinned_http_tool_registry()
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=uuid4(),
        target_version="b" * 40,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=registry.digest,
        input_refs=("candidate:" + "c" * 64,),
        allowed_tools=frozenset({"http.request"}),
        budget=TaskBudget(wall_seconds=10, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(seconds=20),
        idempotency_key="rootless:gateway-task",
    )
    call = BrokerCall(
        task=task,
        profile=profile,
        tool_id="http.request",
        http=HttpRequestPlan(
            method="GET",
            url=f"http://{host}/",
            test_class="read_only",
        ),
        idempotency_key="rootless:gateway-call",
    )
    transport = _NoSocketTransport()
    broker = ToolBroker(
        scope=scope,
        registry=registry,
        resolver=_PinnedGatewayResolver(gateway),
        http_transport=transport,
        blocked_ips=gateways,
    )

    result = broker.execute(call, now=now)

    assert result.status is BrokerStatus.DENIED
    assert result.error_codes == ("resolved_address_forbidden",)
    assert transport.calls == []
