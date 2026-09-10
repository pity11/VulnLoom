from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.broker import (
    EvidenceStoreHttpSink,
    OfflineHttpHop,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.broker.implementation import PINNED_HTTP_IMPLEMENTATION_DIGEST
from vulnloom.domain.models import EvidenceKind, NetworkTargetScope, Scope, ScopeState
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    IsolatedLocalHttpReconAdapter,
    IsolatedLocalReconAdmission,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamFlowStatus,
    RedTeamRejected,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.runners import NetworkGrant, validation_profile
from vulnloom.workflows import Visibility

HOST = "fixture.internal.test"
IP = "10.23.45.67"
IMAGE = "sha256:" + "1" * 64
EVIDENCE_TEXT = "redacted local fixture evidence"
EVIDENCE = hashlib.sha256(EVIDENCE_TEXT.encode()).hexdigest()
BODY = "3" * 64


class _PinnedResolver:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def resolve(self, host):
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer if host == HOST else ()


class _PinnedTransport:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def __init__(self, hops):
        self.hops = list(hops)
        self.calls = []

    def send(self, request):
        self.calls.append(request)
        hop = self.hops[len(self.calls) - 1]
        if isinstance(hop, BaseException):
            raise hop
        return hop


def _scope(now, port=8080):
    return Scope(
        engagement_id=uuid4(),
        authority_reference="isolated-local-red-team-fixture",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=10),
        network_targets=(
            NetworkTargetScope(
                host=HOST,
                ports=frozenset({port}),
                schemes=frozenset({"http"}),
            ),
        ),
        allowed_test_classes=frozenset({"read_only"}),
        state=ScopeState.APPROVED,
        approved_by="integration-owner",
        approved_at=now,
    )


def _runtime(tmp_path, now, *, port=8080, resolver=None, transport=None):
    scope = _scope(now, port)
    store = RedTeamStore(tmp_path / "red-team.sqlite3")
    service = RedTeamService(store=store)
    plan = service.prepare(
        scope=scope,
        target_url=f"http://{HOST}:{port}/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=2,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:fixture-owner",
        now=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key=f"red-team:local:{port}",
    )
    checkpoint = service.create_and_start(plan, scope=scope, now=now)
    command = service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key=f"red-team:local-head:{port}",
    )
    profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id=plan.plan_id,
        network_grants=(
            NetworkGrant(
                host=HOST,
                ports=frozenset({port}),
                schemes=frozenset({"http"}),
            ),
        ),
    )
    admission = IsolatedLocalReconAdmission.create(
        fixture_ref="fixture:red-team-head-v1",
        host=HOST,
        port=port,
        scheme="http",
        allowed_peer_ips=(IP,),
        expires_at=now + timedelta(minutes=2),
    )
    broker = ToolBroker(
        scope=scope,
        registry=pinned_http_tool_registry(),
        resolver=resolver or _PinnedResolver(((IP,),)),
        http_transport=transport
        or _PinnedTransport(
            (
                OfflineHttpHop(
                    status_code=204,
                    peer_ip=IP,
                    response_bytes=0,
                    response_body_sha256=BODY,
                    evidence_ref=EVIDENCE,
                ),
            )
        ),
        allowed_resolved_ips=frozenset({IP}),
    )
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        EVIDENCE_TEXT,
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "4" * 64,
        producer="test.red-team.pinned",
        target_version=plan.plan_id,
        summary="redacted fixture response",
    )
    assert evidence.evidence_id == EVIDENCE
    adapter = IsolatedLocalHttpReconAdapter(
        plan=plan,
        broker=broker,
        profile=profile,
        admission=admission,
        evidence_store=evidence_store,
    )
    return scope, store, service, plan, checkpoint, command, adapter


def test_live_recon_adapter_routes_head_and_persists_redacted_attack_surface(tmp_path, now):
    scope, store, service, plan, checkpoint, command, adapter = _runtime(tmp_path, now)
    advanced, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )

    assert advanced.status is RedTeamFlowStatus.RUNNING
    assert observation.outcome is ReconOutcome.SUCCEEDED
    assert observation.attack_surface is not None
    assert observation.attack_surface.evidence_refs == (EVIDENCE,)
    assert observation.attack_surface.requested_url_digest not in plan.target.url
    assert store.observation(observation.observation_id) == observation
    persisted = (tmp_path / "red-team.sqlite3").read_text(errors="ignore")
    assert plan.target.url not in observation.model_dump_json()
    assert "authorization" not in persisted.lower()
    assert adapter.calls == 1

    replayed, replay = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now + timedelta(seconds=1)
    )
    assert replayed == advanced
    assert replay == observation
    assert adapter.calls == 1
    store.close()


def test_live_recon_refuses_snapshot_when_evidence_object_is_missing(tmp_path, now):
    scope, store, service, _, _, command, adapter = _runtime(tmp_path, now)
    (adapter.evidence_store.objects / EVIDENCE).unlink()
    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )
    assert observation.outcome is ReconOutcome.FAILED
    assert observation.reason_code == "evidence_integrity_failed"
    assert observation.attack_surface is None
    assert checkpoint.actions_used == 1
    store.close()


def test_live_recon_rechecks_redirect_and_rejects_private_dns_drift(tmp_path, now):
    redirect = OfflineHttpHop(
        status_code=302,
        peer_ip=IP,
        response_bytes=0,
        response_body_sha256=BODY,
        evidence_ref=EVIDENCE,
        location="/next",
    )
    transport = _PinnedTransport((redirect,))
    resolver = _PinnedResolver(((IP,), ("10.23.45.68",)))
    scope, store, service, _, _, command, adapter = _runtime(
        tmp_path, now, resolver=resolver, transport=transport
    )

    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )

    assert observation.outcome is ReconOutcome.REJECTED
    assert observation.reason_code == "broker.resolved_address_forbidden"
    assert observation.attack_surface is None
    assert len(transport.calls) == 1
    assert checkpoint.status is RedTeamFlowStatus.RUNNING
    store.close()


def test_live_recon_timeout_is_typed_and_connection_cleanup_is_reported(tmp_path, now):
    scope, store, service, _, _, command, adapter = _runtime(
        tmp_path, now, transport=_PinnedTransport((TimeoutError("synthetic timeout"),))
    )
    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )
    assert observation.outcome is ReconOutcome.TIMED_OUT
    assert observation.reason_code == "broker.http_transport_timeout"
    assert observation.cleanup_complete
    assert checkpoint.status is RedTeamFlowStatus.TIMED_OUT
    store.close()


def test_cancelled_flow_never_reaches_live_recon_adapter(tmp_path, now):
    scope, store, service, plan, checkpoint, command, adapter = _runtime(tmp_path, now)
    cancelled = service.cancel(plan, checkpoint, scope=scope, now=now)
    assert cancelled.status is RedTeamFlowStatus.CANCELLED
    with pytest.raises(RedTeamRejected, match="stale or not running"):
        service.execute_recon(command=command, scope=scope, adapter=adapter, now=now)
    assert adapter.calls == 0
    store.close()


def test_expired_local_admission_is_a_completed_fail_closed_observation(tmp_path, now):
    scope, store, service, _, _, command, adapter = _runtime(tmp_path, now)
    expired = IsolatedLocalReconAdmission.create(
        fixture_ref=adapter.admission.fixture_ref,
        host=adapter.admission.host,
        port=adapter.admission.port,
        scheme=adapter.admission.scheme,
        allowed_peer_ips=adapter.admission.allowed_peer_ips,
        expires_at=now - timedelta(seconds=1),
    )
    expired_adapter = IsolatedLocalHttpReconAdapter(
        plan=adapter.plan,
        broker=adapter.broker,
        profile=adapter.profile,
        admission=expired,
        evidence_store=adapter.evidence_store,
    )
    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=expired_adapter, now=now
    )
    assert observation.outcome is ReconOutcome.REJECTED
    assert observation.reason_code == "local_admission_expired"
    assert checkpoint.actions_used == 1
    assert store.completed_action(command) == observation
    store.close()


def test_local_admission_and_adapter_fail_closed_on_unsafe_or_broader_binding(tmp_path, now):
    for address in ("127.0.0.1", "8.8.8.8", "169.254.169.254"):
        with pytest.raises(ValueError, match="private non-loopback"):
            IsolatedLocalReconAdmission.create(
                fixture_ref="fixture:unsafe",
                host=HOST,
                port=8080,
                scheme="http",
                allowed_peer_ips=(address,),
                expires_at=now + timedelta(minutes=1),
            )

    scope, store, _, plan, _, _, _ = _runtime(tmp_path, now)
    broad = validation_profile(
        image_digest=IMAGE,
        snapshot_id=plan.plan_id,
        network_grants=(
            NetworkGrant(host=HOST, ports=frozenset({8080}), schemes=frozenset({"http"})),
            NetworkGrant(
                host="other.internal.test",
                ports=frozenset({8080}),
                schemes=frozenset({"http"}),
            ),
        ),
    )
    admission = IsolatedLocalReconAdmission.create(
        fixture_ref="fixture:strict",
        host=HOST,
        port=8080,
        scheme="http",
        allowed_peer_ips=(IP,),
        expires_at=now + timedelta(minutes=1),
    )
    broker = ToolBroker(
        scope=scope,
        registry=pinned_http_tool_registry(),
        resolver=_PinnedResolver(((IP,),)),
        http_transport=_PinnedTransport(()),
        allowed_resolved_ips=frozenset({IP}),
    )
    with pytest.raises(RedTeamRejected, match="binding is invalid"):
        IsolatedLocalHttpReconAdapter(
            plan=plan,
            broker=broker,
            profile=broad,
            admission=admission,
            evidence_store=EvidenceStore(tmp_path / "broad-evidence"),
        )
    store.close()


def _safe_local_ipv4() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect selects a local route without sending a packet.
        probe.connect(("192.0.2.1", 9))
        candidates = (probe.getsockname()[0],)
    except OSError:
        try:
            records = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET)
        except OSError:
            return None
        candidates = tuple(record[4][0] for record in records)
    finally:
        probe.close()
    for value in candidates:
        address = ipaddress.ip_address(value)
        if address.is_private and not address.is_loopback and not address.is_link_local:
            return str(address)
    return None


@pytest.mark.red_team_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_RED_TEAM_INTEGRATION") != "1",
    reason="set VULNLOOM_RED_TEAM_INTEGRATION=1 for isolated local HTTP Recon",
)
def test_real_local_fixture_process_is_pinned_redacted_and_cleaned(tmp_path: Path):
    address = _safe_local_ipv4()
    if address is None:
        pytest.skip("no private non-loopback IPv4 is available")
    program = """
import http.server
import sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Set-Cookie', 'session=must-not-persist')
        self.send_header('X-Authorization', 'Bearer must-not-persist')
        self.end_headers()
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer((sys.argv[1], 0), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", program, address],
        env={"PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        port = int(process.stdout.readline().strip())
        now = datetime.now(UTC)
        scope, store, service, plan, _, command, _ = _runtime(tmp_path, now, port=port)
        evidence_store = EvidenceStore(tmp_path / "evidence")
        sink = EvidenceStoreHttpSink(evidence_store, target_version=plan.plan_id)
        broker = ToolBroker(
            scope=scope,
            registry=pinned_http_tool_registry(),
            resolver=_PinnedResolver(((address,),)),
            http_transport=PinnedHttpTransport(sink),
            allowed_resolved_ips=frozenset({address}),
        )
        profile = validation_profile(
            image_digest=IMAGE,
            snapshot_id=plan.plan_id,
            network_grants=(
                NetworkGrant(
                    host=HOST,
                    ports=frozenset({port}),
                    schemes=frozenset({"http"}),
                ),
            ),
        )
        admission = IsolatedLocalReconAdmission.create(
            fixture_ref="fixture:real-process-v1",
            host=HOST,
            port=port,
            scheme="http",
            allowed_peer_ips=(address,),
            expires_at=now + timedelta(minutes=1),
        )
        adapter = IsolatedLocalHttpReconAdapter(
            plan=plan,
            broker=broker,
            profile=profile,
            admission=admission,
            evidence_store=evidence_store,
        )
        _, observation = service.execute_recon(
            command=command, scope=scope, adapter=adapter, now=now
        )
        assert observation.attack_surface is not None
        evidence = sink.records[observation.attack_surface.evidence_refs[0]]
        content = evidence_store.read_text(evidence).lower()
        assert "must-not-persist" not in content
        assert plan.target.url not in content
        store.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    assert process.poll() is not None
