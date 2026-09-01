from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    OfflineAgentRuntime,
    OpenAIResponsesV1Codec,
    ProviderProcessExecutionError,
    SubprocessHttpsProviderAdapter,
    SubprocessProviderTransportRunner,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole


class _ProviderHandler(BaseHTTPRequestHandler):
    observed_authorization = None
    observed_body = None
    delay_seconds = 0.0

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        type(self).observed_authorization = self.headers.get("Authorization")
        type(self).observed_body = self.rfile.read(length)
        if type(self).delay_seconds:
            time.sleep(type(self).delay_seconds)
        response = json.dumps(
            {
                "id": "resp_loopback",
                "model": "loopback-model-v1",
                "object": "response",
                "output": [{
                    "content": [{
                        "annotations": [],
                        "text": json.dumps({
                            "kind": "complete",
                            "summary_digest": "f" * 64,
                            "supporting_ref_digests": [],
                            "tool_call": None,
                        }, separators=(",", ":"), sort_keys=True),
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
