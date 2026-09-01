from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.adapters import EnvironmentModelCredentialProvider, ModelCredentialReference
from vulnloom.agent_runtime import (
    SUBPROCESS_HTTPS_ADAPTER_DIGEST,
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextSource,
    AgentContextSourceKind,
    AgentContextStore,
    AgentContinuationService,
    AgentContinuationStore,
    AgentMessageRenderer,
    AgentModelRegistration,
    AgentProviderCodecRegistration,
    AgentProviderEgressAuthority,
    AgentProviderEgressIssuerPolicy,
    AgentProviderEgressPurpose,
    AgentProviderEgressStore,
    AgentProviderTransportAdmission,
    AgentProviderTransportLimits,
    AgentProviderTransportMode,
    AgentRunLimits,
    AgentRunPlan,
    AgentRunStatus,
    AgentRunStore,
    AgentSessionAuditArtifactStore,
    AgentSessionAuditRejected,
    AgentSessionAuditService,
    AgentSessionAuditStore,
    AgentSessionCallTemplate,
    AgentSessionService,
    AgentSessionStatus,
    AgentSessionStore,
    AgentToolHandoffLimits,
    AgentToolHandoffPlan,
    AgentToolHandoffService,
    AgentToolHandoffStatus,
    AgentToolHandoffStore,
    OfflineAgentRuntime,
    OpenAIResponsesV1Codec,
    ProviderProcessExecutionError,
    SubprocessHttpsProviderAdapter,
    SubprocessProviderTransportRunner,
    agent_broker_call_commitment,
)
from vulnloom.broker import (
    BrokerCall,
    EvidenceStoreHttpSink,
    HttpRequestPlan,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.domain.models import NetworkTargetScope, Scope, ScopeState
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    NetworkGrant,
    sandbox_profile_digest,
    validation_profile,
)


class _ProviderHandler(BaseHTTPRequestHandler):
    observed_authorization = None
    observed_body = None
    delay_seconds = 0.0
    decision_payloads = []

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        type(self).observed_authorization = self.headers.get("Authorization")
        type(self).observed_body = self.rfile.read(length)
        if type(self).delay_seconds:
            time.sleep(type(self).delay_seconds)
        decision = (
            type(self).decision_payloads.pop(0)
            if type(self).decision_payloads
            else {
                "kind": "complete",
                "summary_digest": "f" * 64,
                "supporting_ref_digests": [],
                "tool_call": None,
            }
        )
        response = json.dumps(
            {
                "id": "resp_loopback",
                "model": "loopback-model-v1",
                "object": "response",
                "output": [{
                    "content": [{
                        "annotations": [],
                        "text": json.dumps(
                            decision, separators=(",", ":"), sort_keys=True
                        ),
                        "type": "output_text",
                    }],
                    "id": "msg_loopback",
                    "role": "assistant",
                    "status": "completed",
                    "type": "message",
                }],
                "status": "completed",
                "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        return


def _certificate(tmp_path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is required for the provider TLS Admission probe")
    certificate = tmp_path / "provider-cert.pem"
    private_key = tmp_path / "provider-key.pem"
    subprocess.run(
        (
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=provider.test",
            "-addext",
            "subjectAltName=DNS:provider.test",
        ),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.path.dirname(openssl)},
    )
    return certificate, private_key


def _server(tmp_path):
    _ProviderHandler.decision_payloads = []
    certificate, private_key = _certificate(tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, certificate.read_bytes()


class _LoopbackResolver:
    def resolve(self, hostname):
        assert hostname == "provider.test"
        return ("127.0.0.1",)


_TARGET_HOST = "authorized.example.test"
_TARGET_BODY = b'{"fixture":"continuation","object_id":7}'


class _TargetHandler(BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self):
        type(self).requests += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_TARGET_BODY)))
        self.end_headers()
        self.wfile.write(_TARGET_BODY)

    def log_message(self, format, *args):
        return


class _PinnedTargetResolver:
    implementation_digest = PinnedHttpTransport.implementation_digest

    def __init__(self, address: str):
        self.address = address

    def resolve(self, hostname: str) -> tuple[str, ...]:
        return (self.address,) if hostname == _TARGET_HOST else ()


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


@pytest.mark.provider_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROVIDER_INTEGRATION") != "1",
    reason="set VULNLOOM_PROVIDER_INTEGRATION=1 for the loopback TLS process probe",
)
def test_real_subprocess_uses_pinned_loopback_tls_and_empty_environment(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PARENT_PROVIDER_SECRET", "must-not-enter-provider-process")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    _ProviderHandler.delay_seconds = 0
    server, thread, ca_bundle = _server(tmp_path)
    secret = bytearray(b"loopback-provider-secret")
    request = bytearray(b'{"sealed":"request"}')
    runner = SubprocessProviderTransportRunner()
    try:
        result = runner.exchange(
            hostname="provider.test",
            port=server.server_address[1],
            request_path="/v1/responses",
            pinned_ip="127.0.0.1",
            request_body=request,
            credential=memoryview(secret).toreadonly(),
            ca_bundle=ca_bundle,
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result.peer_ip == "127.0.0.1"
    assert result.tls_version in {"TLSv1.2", "TLSv1.3"}
    assert result.process_started and result.process_terminated
    assert result.stderr_discarded and result.network_opened
    assert _ProviderHandler.observed_authorization == "Bearer loopback-provider-secret"
    assert _ProviderHandler.observed_body == request
    payload = json.loads(result.response_body)
    assert payload["object"] == "response"
    assert b"loopback-provider-secret" not in result.response_body


@pytest.mark.provider_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROVIDER_INTEGRATION") != "1",
    reason="set VULNLOOM_PROVIDER_INTEGRATION=1 for the loopback TLS process probe",
)
def test_real_subprocess_timeout_forces_process_cleanup(tmp_path):
    _ProviderHandler.delay_seconds = 1
    server, thread, ca_bundle = _server(tmp_path)
    runner = SubprocessProviderTransportRunner()
    try:
        with pytest.raises(ProviderProcessExecutionError) as failure:
            runner.exchange(
                hostname="provider.test",
                port=server.server_address[1],
                request_path="/v1/responses",
                pinned_ip="127.0.0.1",
                request_body=bytearray(b"{}"),
                credential=memoryview(bytearray(b"timeout-secret")).toreadonly(),
                ca_bundle=ca_bundle,
                timeout_seconds=0.1,
                max_response_bytes=4096,
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        _ProviderHandler.delay_seconds = 0

    assert failure.value.timed_out
    assert failure.value.process_started
    assert failure.value.process_terminated
    assert failure.value.stderr_discarded


@pytest.mark.provider_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROVIDER_INTEGRATION") != "1",
    reason="set VULNLOOM_PROVIDER_INTEGRATION=1 for the loopback TLS process probe",
)
def test_full_loopback_admission_runtime_uses_real_tls_subprocess(tmp_path):
    _ProviderHandler.delay_seconds = 0
    server, thread, ca_bundle = _server(tmp_path)
    now = datetime.now(UTC)
    source_ref = "observation:" + "d" * 64
    task = TaskEnvelope(
        engagement_id=uuid4(),
        target_id=uuid4(),
        target_version="a" * 40,
        scope_id=uuid4(),
        worker_role=WorkerRole.HYPOTHESIS,
        scope_version=1,
        policy_digest="a" * 64,
        sandbox_profile_digest="b" * 64,
        tool_registry_digest="c" * 64,
        input_refs=(source_ref,),
        allowed_tools=frozenset({"source.search"}),
        budget=TaskBudget(wall_seconds=20, model_tokens=100, tool_calls=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="worker:loopback-provider:1",
    )
    snapshot = AgentContextAssembler().assemble(
        task=task,
        sources=(
            AgentContextSource(
                source_ref=source_ref,
                kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                text="api_key=raw-loopback-context-secret",
            ),
        ),
        limits=AgentContextLimits(),
        now=now,
        deadline=now + timedelta(minutes=1),
    )
    reference = ModelCredentialReference.create(
        environment_variable="VULNLOOM_LOOPBACK_PROVIDER_KEY"
    )
    admission = AgentProviderTransportAdmission.create_loopback_probe(
        provider_id="loopback",
        hostname="provider.test",
        port=server.server_address[1],
        request_path="/v1/responses",
        credential_reference_id=reference.reference_id,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        ca_bundle_digest=hashlib.sha256(ca_bundle).hexdigest(),
        limits=AgentProviderTransportLimits(timeout_seconds=5),
    )
    issuer_policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="phase3-security-operator",
        allowed_provider_ids=(admission.provider_id,),
        allowed_modes=(AgentProviderTransportMode.LOOPBACK_HTTPS_PROBE,),
        max_lifetime_seconds=3600,
    )
    egress_store = AgentProviderEgressStore(tmp_path / "provider-egress")
    egress_grant = AgentProviderEgressAuthority(
        store=egress_store, issuer_policies=(issuer_policy,)
    ).issue(
        admission=admission,
        issuer_policy_id=issuer_policy.policy_id,
        purpose=AgentProviderEgressPurpose.LOOPBACK_ADMISSION_PROBE,
        now=now,
        expires_at=now + timedelta(minutes=30),
        deadline=now + timedelta(seconds=10),
        idempotency_key="provider-egress:phase3-loopback:1",
    )
    codec_registration = AgentProviderCodecRegistration.create(provider_id="loopback")
    registration = AgentModelRegistration.create_subprocess_https(
        provider_id="loopback",
        model="loopback-model-v1",
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        credential_reference_id=reference.reference_id,
        transport_admission_id=admission.admission_id,
        egress_grant_id=egress_grant.grant_id,
        provider_codec_id=codec_registration.codec_id,
        supported_roles=(WorkerRole.HYPOTHESIS,),
        max_output_tokens=64,
    )
    plan = AgentRunPlan.create(
        task=task,
        registration=registration,
        limits=AgentRunLimits(
            max_steps=1, max_output_tokens_per_step=64, timeout_seconds=10
        ),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="agent:loopback-provider:1",
        context_snapshot=snapshot,
    )
    context_store = AgentContextStore(tmp_path / "contexts")
    context_store.publish(snapshot)
    adapter = SubprocessHttpsProviderAdapter(
        registration=registration,
        admission=admission,
        credential_reference=reference,
        credential_provider=EnvironmentModelCredentialProvider(
            {
                reference.environment_variable: "loopback-provider-secret",
                "UNRELATED_PROVIDER_SECRET": "must-not-enter-child",
            },
            allowed_references=(reference,),
        ),
        egress_store=egress_store,
        provider_codec=OpenAIResponsesV1Codec(codec_registration),
        ca_bundle=ca_bundle,
        resolver=_LoopbackResolver(),
    )
    store = AgentRunStore(tmp_path / "loopback-runs.sqlite3")
    runtime = OfflineAgentRuntime(
        store=store,
        registration=registration,
        adapter=adapter,
        context_store=context_store,
        message_renderer=AgentMessageRenderer(),
    )
    try:
        outcome = runtime.execute(plan, now=now + timedelta(seconds=1))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert outcome.status is AgentRunStatus.COMPLETED
    assert adapter.attempts[0].network_opened
    assert adapter.attempts[0].process_terminated
    assert adapter.attempts[0].tls_version in {"TLSv1.2", "TLSv1.3"}
    assert adapter.released_leases[0].zeroed
    assert b"raw-loopback-context-secret" not in (tmp_path / "loopback-runs.sqlite3").read_bytes()
    assert b"loopback-provider-secret" not in (tmp_path / "loopback-runs.sqlite3").read_bytes()
    store.close()
    egress_store.close()


@pytest.mark.provider_integration
@pytest.mark.composition_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROVIDER_INTEGRATION") != "1"
    or os.environ.get("VULNLOOM_COMPOSITION_INTEGRATION") != "1",
    reason="set both provider and composition integration flags for the M7.10 probe",
)
def test_live_provider_fixed_two_tool_session_chain(
    tmp_path: Path, monkeypatch
):
    address = _safe_local_ipv4()
    if address is None:
        pytest.skip("no non-loopback local IPv4 address is available for the Broker probe")
    monkeypatch.setenv("PARENT_PROVIDER_SECRET", "must-not-enter-provider-process")
    _TargetHandler.requests = 0
    target_server = ThreadingHTTPServer((address, 0), _TargetHandler)
    target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
    target_thread.start()
    provider_server, provider_thread, ca_bundle = _server(tmp_path)
    now = datetime.now(UTC)
    target_port = target_server.server_address[1]
    scope = Scope(
        engagement_id=uuid4(),
        authority_reference="m7.10-full-chain-fixture",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=2),
        network_targets=(
            NetworkTargetScope(
                host=_TARGET_HOST,
                ports=frozenset({target_port}),
                schemes=frozenset({"http"}),
            ),
        ),
        allowed_test_classes=frozenset({"read_only"}),
        state=ScopeState.APPROVED,
        approved_by="integration-test",
        approved_at=now,
    )
    registry = pinned_http_tool_registry()
    profile = validation_profile(
        image_digest="sha256:" + "f" * 64,
        snapshot_id="a" * 64,
        network_grants=(
            NetworkGrant(
                host=_TARGET_HOST,
                ports=frozenset({target_port}),
                schemes=frozenset({"http"}),
            ),
        ),
    )
    source_ref = "candidate:" + "c" * 64
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
        input_refs=(source_ref,),
        allowed_tools=frozenset({"http.request"}),
        budget=TaskBudget(wall_seconds=30, model_tokens=100, tool_calls=2),
        deadline=now + timedelta(minutes=1),
        idempotency_key="m7.10:root-task",
    )
    root_snapshot = AgentContextAssembler().assemble(
        task=task,
        sources=(
            AgentContextSource(
                source_ref=source_ref,
                kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                text="Authorized fixture object 7 requires one read-only validation.",
            ),
        ),
        limits=AgentContextLimits(),
        now=now,
        deadline=now + timedelta(seconds=20),
    )
    call = BrokerCall(
        task=task,
        profile=profile,
        tool_id="http.request",
        http=HttpRequestPlan(
            method="GET",
            url=f"http://{_TARGET_HOST}:{target_port}/objects/7",
            test_class="read_only",
        ),
        idempotency_key="m7.10:broker-call-1",
    )
    reference = ModelCredentialReference.create(
        environment_variable="VULNLOOM_M710_PROVIDER_KEY"
    )
    admission = AgentProviderTransportAdmission.create_loopback_probe(
        provider_id="loopback",
        hostname="provider.test",
        port=provider_server.server_address[1],
        request_path="/v1/responses",
        credential_reference_id=reference.reference_id,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        ca_bundle_digest=hashlib.sha256(ca_bundle).hexdigest(),
        limits=AgentProviderTransportLimits(timeout_seconds=5),
    )
    issuer_policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="phase3-security-operator",
        allowed_provider_ids=(admission.provider_id,),
        allowed_modes=(AgentProviderTransportMode.LOOPBACK_HTTPS_PROBE,),
        max_lifetime_seconds=3600,
    )
    egress_store = AgentProviderEgressStore(tmp_path / "provider-egress-m710")
    grant = AgentProviderEgressAuthority(
        store=egress_store, issuer_policies=(issuer_policy,)
    ).issue(
        admission=admission,
        issuer_policy_id=issuer_policy.policy_id,
        purpose=AgentProviderEgressPurpose.LOOPBACK_ADMISSION_PROBE,
        now=now,
        expires_at=now + timedelta(minutes=30),
        deadline=now + timedelta(seconds=10),
        idempotency_key="m7.10:egress",
    )
    codec_registration = AgentProviderCodecRegistration.create(provider_id="loopback")
    registration = AgentModelRegistration.create_subprocess_https(
        provider_id="loopback",
        model="loopback-model-v1",
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        credential_reference_id=reference.reference_id,
        transport_admission_id=admission.admission_id,
        egress_grant_id=grant.grant_id,
        provider_codec_id=codec_registration.codec_id,
        supported_roles=(WorkerRole.VALIDATOR,),
        max_output_tokens=64,
    )
    root_plan = AgentRunPlan.create(
        task=task,
        registration=registration,
        limits=AgentRunLimits(
            max_steps=1, max_output_tokens_per_step=64, timeout_seconds=20
        ),
        created_at=now,
        deadline=now + timedelta(seconds=40),
        idempotency_key="m7.10:root-run",
        context_snapshot=root_snapshot,
    )
    _ProviderHandler.decision_payloads = [
        {
            "kind": "propose_tool",
            "summary_digest": None,
            "supporting_ref_digests": [],
            "tool_call": {
                "arguments": [agent_broker_call_commitment(call)],
                "tool_id": "http.request",
                "working_directory": "source",
            },
        },
    ]
    context_store = AgentContextStore(tmp_path / "m710-context")
    context_store.publish(root_snapshot)
    adapter = SubprocessHttpsProviderAdapter(
        registration=registration,
        admission=admission,
        credential_reference=reference,
        credential_provider=EnvironmentModelCredentialProvider(
            {reference.environment_variable: "m710-loopback-provider-secret"},
            allowed_references=(reference,),
        ),
        egress_store=egress_store,
        provider_codec=OpenAIResponsesV1Codec(codec_registration),
        ca_bundle=ca_bundle,
        resolver=_LoopbackResolver(),
    )
    evidence_store = EvidenceStore(tmp_path / "m710-evidence")
    broker = ToolBroker(
        scope=scope,
        registry=registry,
        resolver=_PinnedTargetResolver(address),
        http_transport=PinnedHttpTransport(
            EvidenceStoreHttpSink(evidence_store, target_version=task.target_version)
        ),
    )
    try:
        with (
            AgentRunStore(tmp_path / "m710-root-runs.sqlite3") as root_store,
            AgentToolHandoffStore(tmp_path / "m710-handoffs.sqlite3") as handoff_store,
            AgentRunStore(tmp_path / "m710-session-runs.sqlite3") as next_store,
            AgentContinuationStore(
                tmp_path / "m710-continuations.sqlite3"
            ) as continuation_store,
            AgentSessionStore(tmp_path / "m710-sessions.sqlite3") as session_store,
            AgentSessionAuditStore(
                tmp_path / "m711-audits.sqlite3"
            ) as audit_store,
        ):
            root_outcome = OfflineAgentRuntime(
                store=root_store,
                registration=registration,
                adapter=adapter,
                context_store=context_store,
                message_renderer=AgentMessageRenderer(),
            ).execute(root_plan, now=now + timedelta(seconds=1))
            handoff_plan = AgentToolHandoffPlan.create(
                agent_plan=root_plan,
                agent_outcome=root_outcome,
                broker_call=call,
                limits=AgentToolHandoffLimits(),
                created_at=now + timedelta(seconds=1),
                deadline=now + timedelta(seconds=35),
                idempotency_key="m7.10:handoff-1",
            )
            handoff_outcome = AgentToolHandoffService(
                agent_store=root_store,
                handoff_store=handoff_store,
                broker=broker,
            ).execute(handoff_plan, now=now + timedelta(seconds=2))
            next_runtime = OfflineAgentRuntime(
                store=next_store,
                registration=registration,
                adapter=adapter,
                context_store=context_store,
                message_renderer=AgentMessageRenderer(),
            )
            next_handoff_service = AgentToolHandoffService(
                agent_store=next_store,
                handoff_store=handoff_store,
                broker=broker,
            )
            continuation_service = AgentContinuationService(
                root_agent_store=next_store,
                handoff_store=handoff_store,
                continuation_store=continuation_store,
                continuation_runtime=next_runtime,
                evidence_store=evidence_store,
                context_store=context_store,
            )
            session_service = AgentSessionService(
                root_agent_store=root_store,
                handoff_store=handoff_store,
                session_store=session_store,
                round_runtime=next_runtime,
                round_handoff_service=next_handoff_service,
                terminal_continuation_service=continuation_service,
                evidence_store=evidence_store,
                context_store=context_store,
            )
            session_plan = session_service.prepare(
                root_plan=root_plan,
                first_handoff_id=handoff_plan.handoff_id,
                call_templates=(
                    AgentSessionCallTemplate.create(
                        profile=profile,
                        tool_id="http.request",
                        http=HttpRequestPlan(
                            method="GET",
                            url=(
                                f"http://{_TARGET_HOST}:{target_port}/objects/8"
                            ),
                            test_class="read_only",
                        ),
                        idempotency_key="m7.10:broker-call-2",
                    ),
                ),
                now=now + timedelta(seconds=3),
                idempotency_key="m7.10:session",
                round_run_key="m7.10:round-2-run",
            )
            second_commitment = (
                session_plan.authorized_calls.options[0].call_commitment
            )
            _ProviderHandler.decision_payloads.extend(
                [
                    {
                        "kind": "propose_tool",
                        "summary_digest": None,
                        "supporting_ref_digests": [],
                        "tool_call": {
                            "arguments": [second_commitment],
                            "tool_id": "http.request",
                            "working_directory": "source",
                        },
                    },
                    {
                        "kind": "complete",
                        "summary_digest": "e" * 64,
                        "supporting_ref_digests": [],
                        "tool_call": None,
                    },
                ]
            )
            session_outcome = session_service.execute(
                session_plan,
                now=now + timedelta(seconds=4),
                terminal_continuation_key="m7.10:terminal-continuation",
                terminal_run_key="m7.10:terminal-run",
            )
            audit_service = AgentSessionAuditService(
                session_store=session_store,
                root_agent_store=root_store,
                round_agent_store=next_store,
                handoff_store=handoff_store,
                continuation_store=continuation_store,
                evidence_store=evidence_store,
                audit_store=audit_store,
                artifact_store=AgentSessionAuditArtifactStore(
                    tmp_path / "m711-audit-artifacts"
                ),
            )
            audit_plan = audit_service.prepare(
                session_plan=session_plan,
                now=now + timedelta(seconds=5),
                idempotency_key="m7.11:audit",
            )
            audit_outcome = audit_service.execute(
                audit_plan,
                session_plan=session_plan,
                now=now + timedelta(seconds=6),
            )
            tampered_session_plan = session_plan.model_copy(
                update={"root_outcome_digest": "0" * 64}
            )
            with pytest.raises(AgentSessionAuditRejected):
                audit_service.execute(
                    audit_plan,
                    session_plan=tampered_session_plan,
                    now=now + timedelta(seconds=7),
                )
    finally:
        target_server.shutdown()
        target_server.server_close()
        target_thread.join(timeout=2)
        provider_server.shutdown()
        provider_server.server_close()
        provider_thread.join(timeout=2)
        egress_store.close()

    assert root_outcome.status is AgentRunStatus.TOOL_PROPOSED
    assert handoff_outcome.status is AgentToolHandoffStatus.COMPLETED
    assert session_outcome.status is AgentSessionStatus.COMPLETED
    assert session_outcome.budget.consumed_tool_calls == 2
    assert session_outcome.budget.provider_attempts == 3
    assert _TargetHandler.requests == 2
    assert len(adapter.attempts) == 3
    assert all(item.process_terminated for item in adapter.attempts)
    assert all(item.network_opened for item in adapter.attempts)
    assert session_outcome.terminal_continuation is not None
    assert session_outcome.terminal_continuation.agent_outcome.tool_intent is None
    assert audit_outcome.bundle.recommendation.disposition.value == "completed"
    assert len(audit_outcome.bundle.observation_ids) == 2
    assert len(audit_outcome.bundle.evidence_refs) == 2
    assert audit_outcome.bundle.budget == session_outcome.budget
    assert _TARGET_BODY not in (tmp_path / "m711-audits.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m710-sessions.sqlite3").read_bytes()
    assert b"m710-loopback-provider-secret" not in (
        tmp_path / "m710-sessions.sqlite3"
    ).read_bytes()
