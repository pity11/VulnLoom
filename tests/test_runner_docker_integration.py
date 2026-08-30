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
    NetworkGrant,
    RegisteredObjectStore,
    SandboxRunRequest,
    SandboxRunStatus,
    ToolInvocation,
    sandbox_profile_digest,
    static_profile,
    validation_profile,
)

SNAPSHOT = "a" * 64


def _engine_policy() -> DockerEnginePolicy:
    if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1":
        return DockerEnginePolicy()
    # Local Docker Desktop can exercise the container boundary, but cannot qualify production.
    return DockerEnginePolicy(require_rootless=False)


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
        "/bin/sh",
        "-c",
        (
            "mkdir -p /tmp/vulnloom-fixture && "
            "printf authorized > /tmp/vulnloom-fixture/index.html && "
            "exec /bin/busybox httpd -f -p 8080 -h /tmp/vulnloom-fixture"
        ),
    ).stdout.strip()
    try:
        assert _docker(
            backend,
            "exec",
            peer_id,
            "/bin/busybox",
            "wget",
            "-q",
            "-O",
            "-",
            "http://127.0.0.1:8080/",
        ).stdout == "authorized"
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
  ! wget -T 1 -q -O /dev/null "http://$address:8080/"
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
