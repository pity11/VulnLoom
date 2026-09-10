from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnloom.broker import (
    EvidenceStoreTlsSink,
    OfflineTlsHandshake,
    PinnedTlsTransport,
    ToolBroker,
    pinned_tls_tool_registry,
)
from vulnloom.broker.implementation import PINNED_TLS_IMPLEMENTATION_DIGEST
from vulnloom.domain.models import EvidenceKind, NetworkTargetScope
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    IsolatedLocalReconAdmission,
    IsolatedLocalTlsReconAdapter,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.runners import NetworkGrant, validation_profile
from vulnloom.workflows import Visibility

HOST = "app.example.test"
IP = "192.0.2.10"
IMAGE = "sha256:" + "1" * 64
CERTIFICATE = "4" * 64


class _Resolver:
    implementation_digest = PINNED_TLS_IMPLEMENTATION_DIGEST

    def resolve(self, host):
        return (IP,) if host == HOST else ()


class _Transport:
    implementation_digest = PINNED_TLS_IMPLEMENTATION_DIGEST

    def __init__(self, result):
        self.result = result
        self.calls = []

    def inspect(self, request):
        self.calls.append(request)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _runtime(tmp_path, approved_scope, now, *, transport_result=None):
    store = RedTeamStore(tmp_path / "red-team.sqlite3")
    service = RedTeamService(store=store)
    plan = service.prepare(
        scope=approved_scope,
        target_url=f"https://{HOST}/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=2,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:tls-owner",
        now=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="red-team:tls",
    )
    checkpoint = service.create_and_start(plan, scope=approved_scope, now=now)
    command = service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=approved_scope,
        kind=RedTeamActionKind.TLS_INSPECT,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key="red-team:tls:inspect",
    )
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        "redacted TLS identity evidence",
        kind=EvidenceKind.TLS,
        source_ref="url-sha256:" + "7" * 64,
        producer="test.tls",
        target_version=plan.plan_id,
        summary="verified TLS identity",
    )
    handshake = transport_result or OfflineTlsHandshake(
        peer_ip=IP,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        leaf_certificate_sha256=CERTIFICATE,
        evidence_ref=evidence.evidence_id,
    )
    transport = _Transport(handshake)
    registry = pinned_tls_tool_registry()
    broker = ToolBroker(
        scope=approved_scope,
        registry=registry,
        resolver=_Resolver(),
        tls_transport=transport,
        allowed_resolved_ips=frozenset({IP}),
    )
    profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id=plan.plan_id,
        network_grants=(
            NetworkGrant(
                host=HOST,
                ports=frozenset({443}),
                schemes=frozenset({"https"}),
            ),
        ),
    ).model_copy(update={"allowed_tools": frozenset({"tls.inspect"})})
    admission = IsolatedLocalReconAdmission.create(
        fixture_ref="fixture:red-team-tls-v1",
        host=HOST,
        port=443,
        scheme="https",
        allowed_peer_ips=(IP,),
        expires_at=now + timedelta(minutes=1),
    )
    adapter = IsolatedLocalTlsReconAdapter(
        plan=plan,
        broker=broker,
        profile=profile,
        admission=admission,
        evidence_store=evidence_store,
    )
    return store, service, plan, command, adapter, evidence_store


def test_tls_recon_creates_only_verified_digest_identity(tmp_path, approved_scope, now):
    store, service, plan, command, adapter, _ = _runtime(
        tmp_path, approved_scope, now
    )
    _, observation = service.execute_recon(
        command=command, scope=approved_scope, adapter=adapter, now=now
    )
    assert observation.outcome is ReconOutcome.SUCCEEDED
    assert observation.status_code is None
    assert observation.attack_surface is None
    assert observation.service_identity is not None
    assert observation.service_identity.leaf_certificate_sha256 == CERTIFICATE
    assert observation.service_identity.endpoint_url_digest == hashlib.sha256(
        plan.target.url.encode()
    ).hexdigest()
    serialized = observation.model_dump_json()
    assert plan.target.url not in serialized
    assert "BEGIN CERTIFICATE" not in serialized
    store.close()


def test_tls_recon_timeout_is_typed_and_cleanup_complete(tmp_path, approved_scope, now):
    store, service, _, command, adapter, _ = _runtime(
        tmp_path, approved_scope, now, transport_result=TimeoutError("synthetic")
    )
    _, observation = service.execute_recon(
        command=command, scope=approved_scope, adapter=adapter, now=now
    )
    assert observation.outcome is ReconOutcome.TIMED_OUT
    assert observation.reason_code == "broker.tls_transport_timeout"
    assert observation.cleanup_complete
    assert observation.service_identity is None
    store.close()


def test_tls_recon_refuses_missing_evidence(tmp_path, approved_scope, now):
    store, service, _, command, adapter, evidence_store = _runtime(
        tmp_path, approved_scope, now
    )
    for path in evidence_store.objects.iterdir():
        path.unlink()
    _, observation = service.execute_recon(
        command=command, scope=approved_scope, adapter=adapter, now=now
    )
    assert observation.outcome is ReconOutcome.FAILED
    assert observation.reason_code == "evidence_integrity_failed"
    assert observation.service_identity is None
    store.close()


def test_live_tls_transport_rejects_context_without_peer_verification(tmp_path):
    context = ssl._create_unverified_context()  # noqa: SLF001 - explicit unsafe fixture
    with pytest.raises(ValueError, match="verify hostnames and peers"):
        PinnedTlsTransport(object(), context=context)


def _safe_local_ipv4() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
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


@pytest.mark.red_team_tls_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_RED_TEAM_TLS_INTEGRATION") != "1",
    reason="set VULNLOOM_RED_TEAM_TLS_INTEGRATION=1 for isolated local TLS Recon",
)
def test_real_local_tls_fixture_is_verified_redacted_and_cleaned(
    tmp_path: Path, approved_scope
):
    address = _safe_local_ipv4()
    openssl = shutil.which("openssl")
    if address is None or openssl is None:
        pytest.skip("private non-loopback IPv4 or openssl is unavailable")
    certificate_path = tmp_path / "fixture-cert.pem"
    key_path = tmp_path / "fixture-key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            f"/CN={HOST}",
            "-addext",
            f"subjectAltName=DNS:{HOST}",
            "-keyout",
            str(key_path),
            "-out",
            str(certificate_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=10,
    )
    program = """
import socket
import ssl
import sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(sys.argv[2], sys.argv[3])
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((sys.argv[1], 0))
listener.listen(4)
print(listener.getsockname()[1], flush=True)
while True:
    raw, _ = listener.accept()
    try:
        with context.wrap_socket(raw, server_side=True):
            pass
    except Exception:
        raw.close()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", program, address, str(certificate_path), str(key_path)],
        env={"PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    store = None
    try:
        assert process.stdout is not None
        port = int(process.stdout.readline().strip())
        now = datetime.now(UTC)
        scope = approved_scope.model_copy(
            update={
                "network_targets": (
                    NetworkTargetScope(
                        host=HOST,
                        ports=frozenset({port}),
                        schemes=frozenset({"https"}),
                    ),
                ),
                "valid_from": now - timedelta(minutes=1),
                "valid_until": now + timedelta(minutes=5),
            }
        )
        store = RedTeamStore(tmp_path / "real-red-team.sqlite3")
        service = RedTeamService(store=store)
        plan = service.prepare(
            scope=scope,
            target_url=f"https://{HOST}:{port}/",
            visibility=Visibility.BLACK_BOX,
            allowed_test_classes=("read_only",),
            max_actions=1,
            max_consecutive_failures=1,
            emergency_contact_ref="contact:tls-fixture-owner",
            now=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="red-team:real-tls",
        )
        checkpoint = service.create_and_start(plan, scope=scope, now=now)
        command = service.prepare_recon(
            plan=plan,
            checkpoint=checkpoint,
            scope=scope,
            kind=RedTeamActionKind.TLS_INSPECT,
            test_class="read_only",
            now=now,
            ttl_seconds=20,
            idempotency_key="red-team:real-tls:inspect",
        )
        evidence_store = EvidenceStore(tmp_path / "real-evidence")
        sink = EvidenceStoreTlsSink(evidence_store, target_version=plan.plan_id)
        context = ssl.create_default_context(cafile=str(certificate_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        class Resolver:
            implementation_digest = PINNED_TLS_IMPLEMENTATION_DIGEST

            def resolve(self, host):
                return (address,) if host == HOST else ()

        broker = ToolBroker(
            scope=scope,
            registry=pinned_tls_tool_registry(),
            resolver=Resolver(),
            tls_transport=PinnedTlsTransport(sink, context=context),
            allowed_resolved_ips=frozenset({address}),
        )
        profile = validation_profile(
            image_digest=IMAGE,
            snapshot_id=plan.plan_id,
            network_grants=(
                NetworkGrant(
                    host=HOST,
                    ports=frozenset({port}),
                    schemes=frozenset({"https"}),
                ),
            ),
        ).model_copy(update={"allowed_tools": frozenset({"tls.inspect"})})
        admission = IsolatedLocalReconAdmission.create(
            fixture_ref="fixture:real-tls-process-v1",
            host=HOST,
            port=port,
            scheme="https",
            allowed_peer_ips=(address,),
            expires_at=now + timedelta(minutes=1),
        )
        adapter = IsolatedLocalTlsReconAdapter(
            plan=plan,
            broker=broker,
            profile=profile,
            admission=admission,
            evidence_store=evidence_store,
        )
        _, observation = service.execute_recon(
            command=command, scope=scope, adapter=adapter, now=now
        )
        assert observation.service_identity is not None
        assert observation.service_identity.tls_version.value in {"TLSv1.2", "TLSv1.3"}
        pem = certificate_path.read_text()
        expected_cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        assert observation.service_identity.leaf_certificate_sha256 == expected_cert
        evidence = sink.records[observation.service_identity.evidence_refs[0]]
        content = evidence_store.read_text(evidence)
        assert plan.target.url not in content
        assert "BEGIN CERTIFICATE" not in content
        assert HOST not in content
    finally:
        if store is not None:
            store.close()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    assert process.poll() is not None
