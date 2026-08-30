from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.broker import (
    BrokerCall,
    EvidenceStoreHttpSink,
    HttpRequestPlan,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.domain.models import (
    Candidate,
    CandidateState,
    NetworkTargetScope,
    Scope,
    ScopeState,
    SourceLocation,
    ValidationResult,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    NetworkGrant,
    RegisteredObjectStore,
    SandboxRunRequest,
    ToolInvocation,
    sandbox_profile_digest,
    validation_profile,
)
from vulnloom.validation import (
    DeterministicHttpJudge,
    HttpResponseAssertion,
    ValidationPlan,
    ValidationService,
    ValidationStore,
    candidate_content_digest,
)

SNAPSHOT = "a" * 64
BODY = b'{"fixture":"authorized","object_id":7}'
HOST = "authorized.example.test"


class _Handler(BaseHTTPRequestHandler):
    observed_host = None

    def do_GET(self):
        type(self).observed_host = self.headers.get("Host")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, format, *args):
        return


class _PinnedFixtureResolver:
    implementation_digest = PinnedHttpTransport.implementation_digest

    def __init__(self, address: str):
        self.address = address

    def resolve(self, host: str) -> tuple[str, ...]:
        return (self.address,) if host == HOST else ()


def _safe_local_ipv4() -> str | None:
    try:
        records = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET)
    except OSError:
        return None
    for record in records:
        value = record[4][0]
        address = ipaddress.ip_address(value)
        if not (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            return str(address)
    return None


def _candidate(scope: Scope) -> Candidate:
    entry = SourceLocation(path="fixture/app.py", line=10, symbol="get_object")
    sink = SourceLocation(path="fixture/store.py", line=20, symbol="load_object")
    return Candidate(
        target_id=uuid4(),
        target_version="b" * 40,
        source_graph_id="c" * 64,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        title="Authorized fixture returns the selected object",
        cwe="CWE-639",
        entry_point=entry,
        sink=sink,
        code_path=(entry, sink),
        security_invariant="The fixture response must match the precommitted object",
        hypothesis="The authorized fixture exposes object 7 for the test identity",
        signal_ids=("d" * 64,),
        cheapest_disproof="Compare the exact fixture response status and body digest",
        duplicate_fingerprint="e" * 64,
        confidence=0.8,
    )


def _task(now, scope, candidate, profile, registry_digest, *, key, allowed_tools):
    return TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=registry_digest,
        input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
        allowed_tools=allowed_tools,
        budget=TaskBudget(wall_seconds=30, model_tokens=0, tool_calls=2),
        deadline=now + timedelta(seconds=45),
        idempotency_key=key,
    )


@pytest.mark.composition_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_COMPOSITION_INTEGRATION") != "1",
    reason="set VULNLOOM_COMPOSITION_INTEGRATION=1 to run the full local composition probe",
)
def test_docker_runner_live_broker_and_deterministic_judge_compose(
    tmp_path: Path, request: pytest.FixtureRequest
):
    address = _safe_local_ipv4()
    if address is None:
        pytest.skip("no non-loopback local IPv4 address is available for the Broker policy probe")
    server = ThreadingHTTPServer((address, 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def stop_server() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    request.addfinalizer(stop_server)
    port = server.server_address[1]
    now = datetime.now(UTC)
    scope = Scope(
        engagement_id=uuid4(),
        authority_reference="local-composition-fixture",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=2),
        network_targets=(
            NetworkTargetScope(
                host=HOST,
                ports=frozenset({port}),
                schemes=frozenset({"http"}),
            ),
        ),
        allowed_test_classes=frozenset({"read_only"}),
        state=ScopeState.APPROVED,
        approved_by="integration-test",
        approved_at=now,
    )
    candidate = _candidate(scope)
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    source = tmp_path / "objects" / SNAPSHOT
    source.mkdir(parents=True)
    source.chmod(0o755)

    runner_profile = validation_profile(image_digest=image, snapshot_id=SNAPSHOT)
    registry = pinned_http_tool_registry()
    runner_task = _task(
        now,
        scope,
        candidate,
        runner_profile,
        registry.digest,
        key="composition:runner-task",
        allowed_tools=frozenset({"sandbox.test"}),
    )
    runner_request = SandboxRunRequest(
        task=runner_task,
        profile=runner_profile,
        invocation=ToolInvocation(tool_id="sandbox.test", working_directory="source"),
        environment={"VULNLOOM_TASK_ID": str(runner_task.task_id)},
        idempotency_key="composition:runner",
    )
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {SNAPSHOT: source}),
        (DockerTool(tool_id="sandbox.test", argv_prefix=("/bin/true",)),),
        # Docker Desktop is rootful. Production continues to require rootless.
        engine_policy=DockerEnginePolicy(require_rootless=False),
    )

    broker_profile = validation_profile(
        image_digest=image,
        snapshot_id=SNAPSHOT,
        network_grants=(
            NetworkGrant(
                host=HOST,
                ports=frozenset({port}),
                schemes=frozenset({"http"}),
            ),
        ),
    )
    broker_task = _task(
        now,
        scope,
        candidate,
        broker_profile,
        registry.digest,
        key="composition:broker-task",
        allowed_tools=frozenset({"http.request"}),
    )
    url = f"http://{HOST}:{port}/objects/7"
    call = BrokerCall(
        task=broker_task,
        profile=broker_profile,
        tool_id="http.request",
        http=HttpRequestPlan(method="GET", url=url, test_class="read_only"),
        idempotency_key="composition:broker",
    )
    assertion = HttpResponseAssertion.create(
        call_id=call.call_id,
        expected_status_code=200,
        expected_body_sha256=hashlib.sha256(BODY).hexdigest(),
        match_result=ValidationResult.REPRODUCED,
    )
    plan = ValidationPlan.create(
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate_content_digest(candidate),
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        selected_by="integration-test",
        selected_at=now,
        selection_reason="Exercise the authorized local composition with an exact assertion",
        runner_request=runner_request,
        broker_calls=(call,),
        http_assertion=assertion,
        idempotency_key="composition:validation",
    )
    evidence_store = EvidenceStore(tmp_path / "evidence")
    sink = EvidenceStoreHttpSink(evidence_store, target_version=candidate.target_version)
    broker = ToolBroker(
        scope=scope,
        registry=registry,
        resolver=_PinnedFixtureResolver(address),
        http_transport=PinnedHttpTransport(sink),
    )

    with ValidationStore(tmp_path / "validation.db") as validation_store:
        outcome = ValidationService(
            scope=scope,
            runner=runner,
            broker=broker,
            store=validation_store,
            evidence_store=evidence_store,
            judge=DeterministicHttpJudge(),
        ).execute(candidate, plan, now=now)

    assert outcome.validation_run.result is ValidationResult.REPRODUCED
    assert outcome.candidate.state is CandidateState.VALIDATED
    assert outcome.runner_result.cleanup.complete
    assert outcome.evidence_bundle is not None
    assert all(evidence_store.contains(item) for item in outcome.evidence_bundle.evidence_refs)
    assert _Handler.observed_host == f"{HOST}:{port}"
    assert runner.last_inspection is not None
    assert not backend.exists(runner.last_inspection["Id"])
