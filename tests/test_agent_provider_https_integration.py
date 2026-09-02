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
from vulnloom.benchmark import (
    REQUIRED_AGENT_WORKFLOW_STAGES,
    AgentWorkflowCheckpoint,
    AgentWorkflowEffectCounters,
    AgentWorkflowRegressionArtifactStore,
    AgentWorkflowRegressionObservation,
    AgentWorkflowRegressionPlan,
    AgentWorkflowRegressionPolicy,
    AgentWorkflowRegressionService,
    AgentWorkflowRegressionStore,
)
from vulnloom.broker import (
    BrokerCall,
    EvidenceStoreHttpSink,
    HttpRequestPlan,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.critic import (
    REQUIRED_ANGLES,
    AgentCriticIntakeCommand,
    AgentCriticIntakeDecision,
    AgentCriticIntakeReason,
    AgentCriticIntakeService,
    AgentCriticIntakeStore,
    AgentCriticOutcomeBindingRejected,
    AgentCriticOutcomeBindingService,
    AgentCriticOutcomeBindingStore,
    CounterevidenceAssessment,
    CounterevidenceDisposition,
    CriticPlan,
    CriticStore,
    DeterministicCritic,
    agent_critic_intake_plan_digest,
    agent_critic_outcome_binding_digest,
    domain_object_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    Candidate,
    EvidenceKind,
    NetworkTargetScope,
    ReportChannel,
    ReportSection,
    ReportSectionKind,
    Scope,
    ScopeState,
    SourceLocation,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.findings import (
    AgentFindingIntakeCommand,
    AgentFindingIntakeDecision,
    AgentFindingIntakeReason,
    AgentFindingIntakeRejected,
    AgentFindingIntakeService,
    AgentFindingIntakeStore,
    DuplicateCheckResult,
    FindingDuplicateCheck,
    FindingDuplicateCheckStore,
    FindingPromotionPlan,
    FindingPromotionRejected,
    FindingPromotionService,
    FindingPromotionStore,
    agent_finding_intake_plan_digest,
)
from vulnloom.hypotheses import CandidateSet, CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.policy import PolicyEngine
from vulnloom.reporting import (
    REPORT_EXPORT_EFFECTS,
    REPORT_REVIEW_EFFECTS,
    AgentReportDraftExecutionRejected,
    AgentReportDraftExecutionService,
    AgentReportDraftExecutionStore,
    AgentReportExportExecutionRejected,
    AgentReportExportExecutionService,
    AgentReportExportExecutionStore,
    AgentReportExportIntakeCommand,
    AgentReportExportIntakeDecision,
    AgentReportExportIntakeReason,
    AgentReportExportIntakeRejected,
    AgentReportExportIntakeService,
    AgentReportExportIntakeStore,
    AgentReportIntakeCommand,
    AgentReportIntakeDecision,
    AgentReportIntakeReason,
    AgentReportIntakeRejected,
    AgentReportIntakeService,
    AgentReportIntakeStore,
    AgentReportReviewExecutionRejected,
    AgentReportReviewExecutionService,
    AgentReportReviewExecutionStore,
    AgentReportReviewIntakeCommand,
    AgentReportReviewIntakeDecision,
    AgentReportReviewIntakeReason,
    AgentReportReviewIntakeRejected,
    AgentReportReviewIntakeService,
    AgentReportReviewIntakeStore,
    DeterministicReportService,
    HumanReportReviewService,
    LocalReportExportService,
    ReportArtifactStore,
    ReportDraftPlan,
    ReportDraftStore,
    ReportExportPlan,
    ReportExportStore,
    ReportReviewCommand,
    ReportReviewPlan,
    ReportReviewStore,
    ReviewDecisionKind,
    agent_report_export_intake_plan_digest,
    agent_report_intake_plan_digest,
    agent_report_review_intake_plan_digest,
)
from vulnloom.runners import (
    NetworkGrant,
    OfflineSandboxRunner,
    OfflineScenario,
    ToolInvocation,
    sandbox_profile_digest,
    validation_profile,
)
from vulnloom.runners.models import SandboxRunRequest
from vulnloom.validation import (
    AgentValidationIntakeCommand,
    AgentValidationIntakeDecision,
    AgentValidationIntakeReason,
    AgentValidationIntakeRejected,
    AgentValidationIntakeService,
    AgentValidationIntakeStore,
    AgentValidationOutcomeBindingRejected,
    AgentValidationOutcomeBindingService,
    AgentValidationOutcomeBindingStore,
    ValidationPlan,
    ValidationService,
    ValidationStore,
    ValidationVerdict,
    agent_validation_intake_plan_digest,
    candidate_content_digest,
)


class _CountingOfflineSandboxRunner:
    def __init__(self):
        self.delegate = OfflineSandboxRunner(frozenset({"sandbox.test"}))
        self.calls = 0
        self.evidence_refs = ()

    def execute(self, request, *, now):
        self.calls += 1
        return self.delegate.execute(
            request, now=now, scenario=OfflineScenario(evidence_refs=self.evidence_refs)
        )


class _ReproducedJudge:
    def evaluate(self, *, evidence_refs, **_):
        return ValidationVerdict(
            result="reproduced",
            rationale_code="m8_3_admission_reproduced",
            evidence_refs=evidence_refs,
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
                "output": [
                    {
                        "content": [
                            {
                                "annotations": [],
                                "text": json.dumps(decision, separators=(",", ":"), sort_keys=True),
                                "type": "output_text",
                            }
                        ],
                        "id": "msg_loopback",
                        "role": "assistant",
                        "status": "completed",
                        "type": "message",
                    }
                ],
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
def test_real_subprocess_uses_pinned_loopback_tls_and_empty_environment(tmp_path, monkeypatch):
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
        limits=AgentRunLimits(max_steps=1, max_output_tokens_per_step=64, timeout_seconds=10),
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
    reason="set both provider and composition integration flags for the M7.10-M8.5 probe",
)
def test_live_provider_session_audit_validation_intake_and_outcome_binding_chain(
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
    reference = ModelCredentialReference.create(environment_variable="VULNLOOM_M710_PROVIDER_KEY")
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
        limits=AgentRunLimits(max_steps=1, max_output_tokens_per_step=64, timeout_seconds=20),
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
    validation_runner = _CountingOfflineSandboxRunner()
    report_review_store = ReportReviewStore(tmp_path / "m810-report-reviews.sqlite3")
    report_review_execution_store = AgentReportReviewExecutionStore(
        tmp_path / "m810-report-review-bindings.sqlite3"
    )
    report_export_intake_store = AgentReportExportIntakeStore(
        tmp_path / "m811-report-export-intakes.sqlite3"
    )
    report_export_store = ReportExportStore(tmp_path / "m812-report-exports.sqlite3")
    report_export_execution_store = AgentReportExportExecutionStore(
        tmp_path / "m812-report-export-bindings.sqlite3"
    )
    workflow_regression_store = AgentWorkflowRegressionStore(
        tmp_path / "m91-agent-workflow-regressions.sqlite3"
    )
    try:
        with (
            AgentRunStore(tmp_path / "m710-root-runs.sqlite3") as root_store,
            AgentToolHandoffStore(tmp_path / "m710-handoffs.sqlite3") as handoff_store,
            AgentRunStore(tmp_path / "m710-session-runs.sqlite3") as next_store,
            AgentContinuationStore(tmp_path / "m710-continuations.sqlite3") as continuation_store,
            AgentSessionStore(tmp_path / "m710-sessions.sqlite3") as session_store,
            AgentSessionAuditStore(tmp_path / "m711-audits.sqlite3") as audit_store,
            AgentValidationIntakeStore(tmp_path / "m81-intakes.sqlite3") as intake_store,
            ValidationStore(tmp_path / "m82-validations.sqlite3") as validation_store,
            AgentValidationOutcomeBindingStore(tmp_path / "m82-bindings.sqlite3") as binding_store,
            AgentCriticIntakeStore(tmp_path / "m83-critic-intakes.sqlite3") as critic_intake_store,
            CriticStore(tmp_path / "m84-critic-executions.sqlite3") as critic_store,
            AgentCriticOutcomeBindingStore(
                tmp_path / "m84-critic-outcome-bindings.sqlite3"
            ) as critic_binding_store,
            AgentFindingIntakeStore(
                tmp_path / "m85-finding-intakes.sqlite3"
            ) as finding_intake_store,
            FindingDuplicateCheckStore(
                tmp_path / "m85-duplicate-checks.sqlite3"
            ) as duplicate_check_store,
            FindingPromotionStore(
                tmp_path / "m86-finding-promotions.sqlite3"
            ) as finding_promotion_store,
            AgentReportIntakeStore(tmp_path / "m87-report-intakes.sqlite3") as report_intake_store,
            ReportDraftStore(tmp_path / "m88-report-drafts.sqlite3") as report_draft_store,
            AgentReportDraftExecutionStore(
                tmp_path / "m88-report-draft-bindings.sqlite3"
            ) as report_draft_execution_store,
            AgentReportReviewIntakeStore(
                tmp_path / "m89-report-review-intakes.sqlite3"
            ) as report_review_intake_store,
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
                            url=(f"http://{_TARGET_HOST}:{target_port}/objects/8"),
                            test_class="read_only",
                        ),
                        idempotency_key="m7.10:broker-call-2",
                    ),
                ),
                now=now + timedelta(seconds=3),
                idempotency_key="m7.10:session",
                round_run_key="m7.10:round-2-run",
            )
            second_commitment = session_plan.authorized_calls.options[0].call_commitment
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
            audit_artifact_store = AgentSessionAuditArtifactStore(tmp_path / "m711-audit-artifacts")
            audit_service = AgentSessionAuditService(
                session_store=session_store,
                root_agent_store=root_store,
                round_agent_store=next_store,
                handoff_store=handoff_store,
                continuation_store=continuation_store,
                evidence_store=evidence_store,
                audit_store=audit_store,
                artifact_store=audit_artifact_store,
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

            candidate = Candidate(
                target_id=task.target_id,
                target_version=task.target_version,
                source_graph_id="8" * 64,
                scope_id=scope.scope_id,
                scope_version=scope.version,
                title="Human-selected local Validation fixture",
                cwe="CWE-639",
                entry_point=SourceLocation(path="app.py", line=1, symbol="read"),
                sink=SourceLocation(path="store.py", line=2, symbol="get"),
                code_path=(
                    SourceLocation(path="app.py", line=1, symbol="read"),
                    SourceLocation(path="store.py", line=2, symbol="get"),
                ),
                security_invariant="Only authorized fixture objects are readable",
                hypothesis="The local fixture may omit an ownership check",
                signal_ids=("9" * 64,),
                cheapest_disproof="Run the separately sealed local Validation plan",
                duplicate_fingerprint="a" * 64,
                confidence=0.5,
            )
            candidate_set_partial = CandidateSet(
                candidate_set_id="0" * 64,
                source_graph_id=candidate.source_graph_id,
                target_id=candidate.target_id,
                target_version=candidate.target_version,
                scope_id=candidate.scope_id,
                scope_version=candidate.scope_version,
                generator_version="m8.1-admission",
                candidates=(candidate,),
            )
            candidate_set = candidate_set_partial.model_copy(
                update={"candidate_set_id": candidate_set_digest(candidate_set_partial)}
            )
            candidate_store = CandidateSetStore(tmp_path / "m81-candidates")
            candidate_store.put(candidate_set)
            intake_profile = validation_profile(
                image_digest="sha256:" + "f" * 64,
                snapshot_id="a" * 64,
            )
            intake_task = TaskEnvelope(
                engagement_id=scope.engagement_id,
                target_id=candidate.target_id,
                target_version=candidate.target_version,
                scope_id=scope.scope_id,
                worker_role=WorkerRole.VALIDATOR,
                scope_version=scope.version,
                policy_digest=PolicyEngine(scope).policy_digest,
                sandbox_profile_digest=sandbox_profile_digest(intake_profile),
                tool_registry_digest=registry.digest,
                input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
                allowed_tools=intake_profile.allowed_tools,
                budget=TaskBudget(wall_seconds=20, model_tokens=0, tool_calls=1),
                deadline=now + timedelta(seconds=50),
                idempotency_key="m8.1:validation-task",
            )
            runner_request = SandboxRunRequest(
                task=intake_task,
                profile=intake_profile,
                invocation=ToolInvocation(tool_id="sandbox.test", working_directory="source"),
                environment={},
                idempotency_key="m8.1:runner-request",
            )
            validation_plan = ValidationPlan.create(
                candidate_id=candidate.candidate_id,
                candidate_digest=candidate_content_digest(candidate),
                target_id=candidate.target_id,
                target_version=candidate.target_version,
                scope_id=scope.scope_id,
                scope_version=scope.version,
                selected_by="phase3-human-reviewer",
                selected_at=now + timedelta(seconds=7),
                selection_reason="Bind only; do not execute the local fixture",
                runner_request=runner_request,
                idempotency_key="m8.1:validation-plan",
            )
            intake_service = AgentValidationIntakeService(
                scope=scope,
                audit_artifact_store=audit_artifact_store,
                candidate_set_store=candidate_store,
                store=intake_store,
            )
            intake_plan = intake_service.prepare(
                audit_artifact=audit_outcome.artifact,
                candidate_set_id=candidate_set.candidate_set_id,
                candidate_id=candidate.candidate_id,
                validation_plan=validation_plan,
                now=now + timedelta(seconds=7),
                decision_deadline=now + timedelta(seconds=45),
                idempotency_key="m8.1:intake",
            )
            command = AgentValidationIntakeCommand.create(
                intake_plan_id=intake_plan.intake_plan_id,
                intake_plan_digest=agent_validation_intake_plan_digest(intake_plan),
                audit_bundle_id=intake_plan.audit_bundle_id,
                candidate_id=candidate.candidate_id,
                candidate_digest=candidate_content_digest(candidate),
                validation_plan_id=validation_plan.plan_id,
                validation_plan_digest=intake_plan.validation_plan_digest,
                decision=AgentValidationIntakeDecision.ACCEPT,
                reason_code=AgentValidationIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
                reviewer="phase3-human-reviewer",
                decided_at=now + timedelta(seconds=8),
            )
            tampered_validation_plan = validation_plan.model_copy(
                update={"candidate_digest": "0" * 64}
            )
            with pytest.raises(AgentValidationIntakeRejected):
                intake_service.decide(
                    intake_plan,
                    command,
                    audit_artifact=audit_outcome.artifact,
                    validation_plan=tampered_validation_plan,
                    now=now + timedelta(seconds=8),
                )
            intake_record = intake_service.decide(
                intake_plan,
                command,
                audit_artifact=audit_outcome.artifact,
                validation_plan=validation_plan,
                now=now + timedelta(seconds=8),
            )
            validation_runner.evidence_refs = (audit_outcome.bundle.evidence_refs[0],)
            validation_outcome = ValidationService(
                scope=scope,
                runner=validation_runner,
                broker=broker,
                store=validation_store,
                evidence_store=evidence_store,
                judge=_ReproducedJudge(),
            ).execute(
                candidate,
                validation_plan,
                now=now + timedelta(seconds=9),
            )
            binding_service = AgentValidationOutcomeBindingService(
                scope=scope,
                audit_store=audit_artifact_store,
                candidate_store=candidate_store,
                intake_store=intake_store,
                validation_store=validation_store,
                evidence_store=evidence_store,
                binding_store=binding_store,
            )
            binding_plan = binding_service.prepare(
                intake_plan_id=intake_plan.intake_plan_id,
                audit_artifact=audit_outcome.artifact,
                candidate_set_id=candidate_set.candidate_set_id,
                candidate_id=candidate.candidate_id,
                validation_plan=validation_plan,
                now=now + timedelta(seconds=10),
                idempotency_key="m8.2:binding",
            )
            tampered_outcome = validation_outcome.model_copy(
                update={
                    "runner_result": validation_outcome.runner_result.model_copy(
                        update={"run_id": uuid4()}
                    )
                }
            )
            with validation_store.connection:
                validation_store.connection.execute(
                    "UPDATE validation_executions SET outcome_json=? WHERE plan_id=?",
                    (tampered_outcome.model_dump_json(), validation_plan.plan_id),
                )
            with pytest.raises(AgentValidationOutcomeBindingRejected):
                binding_service.execute(
                    binding_plan,
                    audit_artifact=audit_outcome.artifact,
                    validation_plan=validation_plan,
                    now=now + timedelta(seconds=11),
                )
            assert (
                binding_store.connection.execute(
                    "SELECT count(*) FROM agent_validation_outcome_bindings"
                ).fetchone()[0]
                == 0
            )
            with validation_store.connection:
                validation_store.connection.execute(
                    "UPDATE validation_executions SET outcome_json=? WHERE plan_id=?",
                    (validation_outcome.model_dump_json(), validation_plan.plan_id),
                )
            calls_before_binding = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            outcome_binding = binding_service.execute(
                binding_plan,
                audit_artifact=audit_outcome.artifact,
                validation_plan=validation_plan,
                now=now + timedelta(seconds=11),
            )
            calls_after_binding = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            evidence_bundle = validation_outcome.evidence_bundle
            assert evidence_bundle is not None
            critic_assessments = tuple(
                CounterevidenceAssessment(
                    angle=angle,
                    disposition=CounterevidenceDisposition.RULED_OUT,
                    evidence_refs=(evidence_bundle.evidence_refs[0],),
                    rationale_code=f"{angle.value}_ruled_out",
                )
                for angle in sorted(REQUIRED_ANGLES, key=lambda item: item.value)
            )
            critic_plan = CriticPlan.create(
                candidate_id=validation_outcome.candidate.candidate_id,
                candidate_digest=domain_object_digest(validation_outcome.candidate),
                validation_run_id=validation_outcome.validation_run.run_id,
                validation_run_digest=domain_object_digest(validation_outcome.validation_run),
                evidence_bundle_id=evidence_bundle.bundle_id,
                evidence_bundle_digest=domain_object_digest(evidence_bundle),
                scope_id=scope.scope_id,
                scope_version=scope.version,
                validation_context_id="4" * 64,
                review_context_id="5" * 64,
                validation_producer="deterministic-validator/v1",
                review_producer="deterministic-critic/v1",
                assessments=critic_assessments,
                created_at=now + timedelta(seconds=12),
                deadline=now + timedelta(seconds=40),
                idempotency_key="m8.3:critic-plan",
            )
            critic_intake_service = AgentCriticIntakeService(
                scope=scope,
                audit_store=audit_artifact_store,
                candidate_store=candidate_store,
                outcome_binding_store=binding_store,
                validation_store=validation_store,
                evidence_store=evidence_store,
                store=critic_intake_store,
            )
            critic_intake_plan = critic_intake_service.prepare(
                outcome_binding_plan=binding_plan,
                audit_artifact=audit_outcome.artifact,
                critic_plan=critic_plan,
                now=now + timedelta(seconds=12),
                decision_deadline=now + timedelta(seconds=30),
                idempotency_key="m8.3:critic-intake",
            )
            critic_command = AgentCriticIntakeCommand.create(
                intake_plan_id=critic_intake_plan.intake_plan_id,
                intake_plan_digest=agent_critic_intake_plan_digest(critic_intake_plan),
                outcome_binding_id=critic_intake_plan.outcome_binding_id,
                candidate_id=candidate.candidate_id,
                critic_plan_id=critic_plan.plan_id,
                critic_plan_digest=critic_intake_plan.critic_plan_digest,
                decision=AgentCriticIntakeDecision.ACCEPT,
                reason_code=AgentCriticIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
                reviewer="phase3-human-critic-reviewer",
                decided_at=now + timedelta(seconds=13),
            )
            calls_before_critic_intake = calls_after_binding
            critic_intake_record = critic_intake_service.decide(
                critic_intake_plan,
                critic_command,
                outcome_binding_plan=binding_plan,
                audit_artifact=audit_outcome.artifact,
                critic_plan=critic_plan,
                now=critic_command.decided_at,
            )
            calls_after_critic_intake = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            critic_evidence_ref = evidence_bundle.evidence_refs[0]
            critic_evidence = evidence_store.capture_text(
                evidence_store.read_text_ref(critic_evidence_ref),
                kind=EvidenceKind.TEST,
                source_ref="m8.4-phase3-local-evidence",
                producer="phase3.m8.4",
                target_version=candidate.target_version,
                summary="M8.4 admission Evidence metadata",
            )
            assert critic_evidence.evidence_id == critic_evidence_ref
            critic_outcome = DeterministicCritic(
                scope=scope, evidence_store=evidence_store, store=critic_store
            ).review(
                validation_outcome.candidate,
                validation_outcome.validation_run,
                evidence_bundle,
                (critic_evidence,),
                critic_plan,
                now=now + timedelta(seconds=14),
            )
            critic_binding_service = AgentCriticOutcomeBindingService(
                scope=scope,
                critic_intake_store=critic_intake_store,
                outcome_binding_store=binding_store,
                validation_store=validation_store,
                critic_store=critic_store,
                evidence_store=evidence_store,
                binding_store=critic_binding_store,
            )
            critic_binding_plan = critic_binding_service.prepare(
                critic_intake_plan=critic_intake_plan,
                now=now + timedelta(seconds=15),
                idempotency_key="m8.4:critic-outcome-binding",
            )
            tampered_critic_outcome = critic_outcome.model_copy(
                update={
                    "review": critic_outcome.review.model_copy(
                        update={"rationale_code": "tampered_phase3_rationale"}
                    )
                }
            )
            with critic_store.connection:
                critic_store.connection.execute(
                    "UPDATE critic_executions SET outcome_json=? WHERE plan_id=?",
                    (tampered_critic_outcome.model_dump_json(), critic_plan.plan_id),
                )
            with pytest.raises(AgentCriticOutcomeBindingRejected):
                critic_binding_service.execute(
                    critic_binding_plan,
                    critic_intake_plan=critic_intake_plan,
                    now=now + timedelta(seconds=16),
                )
            assert (
                critic_binding_store.connection.execute(
                    "SELECT count(*) FROM agent_critic_outcome_bindings"
                ).fetchone()[0]
                == 0
            )
            with critic_store.connection:
                critic_store.connection.execute(
                    "UPDATE critic_executions SET outcome_json=? WHERE plan_id=?",
                    (critic_outcome.model_dump_json(), critic_plan.plan_id),
                )
            calls_before_critic_binding = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            critic_outcome_binding = critic_binding_service.execute(
                critic_binding_plan,
                critic_intake_plan=critic_intake_plan,
                now=now + timedelta(seconds=16),
            )
            calls_after_critic_binding = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            reviewed_candidate = critic_outcome.candidate
            duplicate_check = FindingDuplicateCheck.create(
                candidate_id=reviewed_candidate.candidate_id,
                candidate_digest=domain_object_digest(reviewed_candidate),
                target_version_digest=canonical_digest(reviewed_candidate.target_version),
                scope_id=scope.scope_id,
                scope_version=scope.version,
                result=DuplicateCheckResult.CLEAR,
                duplicate_family_id=None,
                checked_by="phase3-human-duplicate-reviewer",
                checked_at=now + timedelta(seconds=17),
                expires_at=now + timedelta(seconds=35),
            )
            duplicate_check_store.publish(duplicate_check)
            promotion_plan = FindingPromotionPlan.create(
                critic_outcome_binding_plan_id=critic_binding_plan.binding_plan_id,
                critic_outcome_binding_id=critic_outcome_binding.binding_id,
                critic_outcome_binding_digest=agent_critic_outcome_binding_digest(
                    critic_outcome_binding
                ),
                candidate_id=reviewed_candidate.candidate_id,
                candidate_digest=domain_object_digest(reviewed_candidate),
                validation_run_ids=(validation_outcome.validation_run.run_id,),
                validation_run_digests=(domain_object_digest(validation_outcome.validation_run),),
                evidence_bundle_id=evidence_bundle.bundle_id,
                evidence_bundle_digest=domain_object_digest(evidence_bundle),
                critic_review_id=critic_outcome.review.review_id,
                critic_review_digest=domain_object_digest(critic_outcome.review),
                duplicate_check_id=duplicate_check.check_id,
                duplicate_check_digest=canonical_digest(
                    duplicate_check.model_dump(mode="python", exclude={"check_id"})
                ),
                finding_id=uuid4(),
                root_cause="trusted Phase 3 control-plane root cause",
                affected_versions=(reviewed_candidate.target_version,),
                impact="trusted Phase 3 control-plane impact",
                severity_assessment={"rating": "high", "score": 8.1},
                scope_id=scope.scope_id,
                scope_version=scope.version,
                created_at=now + timedelta(seconds=17),
                deadline=now + timedelta(seconds=34),
                idempotency_key="m8.5:finding-promotion",
            )
            finding_intake_service = AgentFindingIntakeService(
                scope=scope,
                critic_binding_store=critic_binding_store,
                validation_binding_store=binding_store,
                validation_store=validation_store,
                critic_store=critic_store,
                evidence_store=evidence_store,
                duplicate_check_store=duplicate_check_store,
                store=finding_intake_store,
            )
            finding_intake_plan = finding_intake_service.prepare(
                critic_binding_plan=critic_binding_plan,
                promotion_plan=promotion_plan,
                duplicate_check=duplicate_check,
                now=now + timedelta(seconds=18),
                decision_deadline=now + timedelta(seconds=30),
                idempotency_key="m8.5:finding-intake",
            )
            finding_command = AgentFindingIntakeCommand.create(
                intake_plan_id=finding_intake_plan.intake_plan_id,
                intake_plan_digest=agent_finding_intake_plan_digest(finding_intake_plan),
                critic_outcome_binding_id=finding_intake_plan.critic_outcome_binding_id,
                promotion_plan_id=finding_intake_plan.promotion_plan_id,
                promotion_plan_digest=finding_intake_plan.promotion_plan_digest,
                candidate_id=finding_intake_plan.candidate_id,
                finding_id=finding_intake_plan.finding_id,
                decision=AgentFindingIntakeDecision.ACCEPT,
                reason_code=AgentFindingIntakeReason.HUMAN_ACCEPTED_EXACT_PROMOTION,
                reviewer="phase3-human-finding-reviewer",
                decided_at=now + timedelta(seconds=19),
            )
            with pytest.raises(AgentFindingIntakeRejected):
                finding_intake_service.decide(
                    finding_intake_plan,
                    finding_command,
                    critic_binding_plan=critic_binding_plan,
                    promotion_plan=promotion_plan.model_copy(
                        update={"impact": "tampered after sealing"}
                    ),
                    duplicate_check=duplicate_check,
                    now=finding_command.decided_at,
                )
            assert (
                finding_intake_store.connection.execute(
                    "SELECT count(*) FROM agent_finding_intakes"
                ).fetchone()[0]
                == 0
            )
            calls_before_finding_intake = calls_after_critic_binding
            finding_intake_record = finding_intake_service.decide(
                finding_intake_plan,
                finding_command,
                critic_binding_plan=critic_binding_plan,
                promotion_plan=promotion_plan,
                duplicate_check=duplicate_check,
                now=finding_command.decided_at,
            )
            calls_after_finding_intake = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            finding_promotion_service = FindingPromotionService(
                intake_service=finding_intake_service,
                store=finding_promotion_store,
            )
            promotion_action = finding_promotion_service.approval_action(
                record=finding_intake_record,
                promotion_plan=promotion_plan,
            )
            promotion_approval = ApprovalRequest(
                engagement_id=scope.engagement_id,
                target_id=reviewed_candidate.target_id,
                action=ApprovalAction.MUTATE_TARGET_STATE,
                action_digest=promotion_action.action_id,
                expected_side_effects=("candidate:promoted", "finding:created"),
                evidence_summary="Phase 3 human approved the exact sealed promotion",
                policy_version=scope.version,
                expires_at=now + timedelta(seconds=29),
                status=ApprovalStatus.GRANTED,
                decided_by="phase3-human-approval-reviewer",
                decided_at=now + timedelta(seconds=20),
            )
            finding_execution_plan = finding_promotion_service.prepare(
                intake_plan=finding_intake_plan,
                critic_binding_plan=critic_binding_plan,
                promotion_plan=promotion_plan,
                duplicate_check=duplicate_check,
                approval=promotion_approval,
                now=now + timedelta(seconds=21),
                deadline=now + timedelta(seconds=28),
                idempotency_key="m8.6:finding-promotion",
            )
            with pytest.raises(FindingPromotionRejected):
                finding_promotion_service.execute(
                    finding_execution_plan,
                    intake_plan=finding_intake_plan,
                    critic_binding_plan=critic_binding_plan,
                    promotion_plan=promotion_plan,
                    duplicate_check=duplicate_check,
                    approval=promotion_approval.model_copy(update={"action_digest": "0" * 64}),
                    now=now + timedelta(seconds=22),
                )
            assert (
                finding_promotion_store.connection.execute(
                    "SELECT count(*) FROM finding_promotions"
                ).fetchone()[0]
                == 0
            )
            calls_before_finding_promotion = calls_after_finding_intake
            finding_promotion_outcome = finding_promotion_service.execute(
                finding_execution_plan,
                intake_plan=finding_intake_plan,
                critic_binding_plan=critic_binding_plan,
                promotion_plan=promotion_plan,
                duplicate_check=duplicate_check,
                approval=promotion_approval,
                now=now + timedelta(seconds=22),
            )
            calls_after_finding_promotion = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            evidence_ref = evidence_bundle.evidence_refs[0]
            report_sections = (
                ReportSection(
                    kind=ReportSectionKind.SUMMARY,
                    text="trusted Phase 3 report summary",
                ),
                ReportSection(
                    kind=ReportSectionKind.CODE_LOCATION,
                    text="trusted Phase 3 code location",
                    evidence_refs=(evidence_ref,),
                ),
                ReportSection(
                    kind=ReportSectionKind.REQUEST_RESPONSE,
                    text="trusted Phase 3 request response",
                    evidence_refs=(evidence_ref,),
                ),
                ReportSection(
                    kind=ReportSectionKind.REPRODUCTION,
                    text="trusted Phase 3 reproduction",
                    evidence_refs=(evidence_ref,),
                ),
                ReportSection(
                    kind=ReportSectionKind.IMPACT,
                    text="trusted Phase 3 report impact",
                    evidence_refs=(evidence_ref,),
                ),
                ReportSection(
                    kind=ReportSectionKind.REMEDIATION,
                    text="trusted Phase 3 remediation",
                ),
            )
            report_draft_plan = ReportDraftPlan.create(
                finding_id=finding_promotion_outcome.finding.finding_id,
                finding_digest=domain_object_digest(finding_promotion_outcome.finding),
                candidate_id=finding_promotion_outcome.promoted_candidate.candidate_id,
                candidate_digest=domain_object_digest(finding_promotion_outcome.promoted_candidate),
                evidence_bundle_id=evidence_bundle.bundle_id,
                evidence_bundle_digest=domain_object_digest(evidence_bundle),
                scope_id=scope.scope_id,
                scope_version=scope.version,
                channel=ReportChannel.GENERIC,
                title="trusted Phase 3 exact report title",
                sections=report_sections,
                prepared_by="trusted-control-plane",
                created_at=now + timedelta(seconds=23),
                deadline=now + timedelta(seconds=34),
                idempotency_key="m8.7:report-draft",
            )
            report_intake_service = AgentReportIntakeService(
                scope=scope,
                finding_promotion_store=finding_promotion_store,
                critic_binding_store=critic_binding_store,
                validation_binding_store=binding_store,
                validation_store=validation_store,
                evidence_store=evidence_store,
                store=report_intake_store,
            )
            with pytest.raises(AgentReportIntakeRejected):
                report_intake_service.prepare(
                    finding_execution_plan=finding_execution_plan,
                    critic_binding_plan=critic_binding_plan,
                    report_draft_plan=report_draft_plan.model_copy(
                        update={"title": "tampered after sealing"}
                    ),
                    now=now + timedelta(seconds=24),
                    decision_deadline=now + timedelta(seconds=30),
                    idempotency_key="m8.7:report-intake:tampered",
                )
            assert (
                report_intake_store.connection.execute(
                    "SELECT count(*) FROM agent_report_intakes"
                ).fetchone()[0]
                == 0
            )
            report_intake_plan = report_intake_service.prepare(
                finding_execution_plan=finding_execution_plan,
                critic_binding_plan=critic_binding_plan,
                report_draft_plan=report_draft_plan,
                now=now + timedelta(seconds=24),
                decision_deadline=now + timedelta(seconds=30),
                idempotency_key="m8.7:report-intake",
            )
            report_intake_command = AgentReportIntakeCommand.create(
                intake_plan_id=report_intake_plan.intake_plan_id,
                intake_plan_digest=agent_report_intake_plan_digest(report_intake_plan),
                finding_promotion_outcome_id=finding_promotion_outcome.outcome_id,
                report_draft_plan_id=report_draft_plan.plan_id,
                report_draft_plan_digest=report_intake_plan.report_draft_plan_digest,
                report_family_id=report_draft_plan.report_family_id,
                report_version=report_draft_plan.version,
                finding_id=finding_promotion_outcome.finding.finding_id,
                decision=AgentReportIntakeDecision.ACCEPT,
                reason_code=AgentReportIntakeReason.HUMAN_ACCEPTED_EXACT_DRAFT,
                reviewer="phase3-human-report-reviewer",
                decided_at=now + timedelta(seconds=25),
            )
            calls_before_report_intake = calls_after_finding_promotion
            report_intake_record = report_intake_service.decide(
                report_intake_plan,
                report_intake_command,
                finding_execution_plan=finding_execution_plan,
                critic_binding_plan=critic_binding_plan,
                report_draft_plan=report_draft_plan,
                now=report_intake_command.decided_at,
            )
            calls_after_report_intake = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            report_service = DeterministicReportService(
                scope=scope,
                evidence_store=evidence_store,
                store=report_draft_store,
                artifact_store=ReportArtifactStore(tmp_path / "m88-report-artifacts"),
            )
            report_execution_service = AgentReportDraftExecutionService(
                intake_service=report_intake_service,
                report_service=report_service,
                store=report_draft_execution_store,
            )
            drifted_evidence = critic_evidence.model_copy(
                update={"summary": "tampered Evidence metadata"}
            )
            report_execution_plan = report_execution_service.prepare(
                report_intake_plan=report_intake_plan,
                finding_execution_plan=finding_execution_plan,
                critic_binding_plan=critic_binding_plan,
                report_draft_plan=report_draft_plan,
                evidence=(critic_evidence,),
                now=now + timedelta(seconds=26),
                deadline=now + timedelta(seconds=29),
                idempotency_key="m8.8:report-draft-execution",
            )
            with pytest.raises(AgentReportDraftExecutionRejected):
                report_execution_service.execute(
                    report_execution_plan,
                    report_intake_plan=report_intake_plan,
                    finding_execution_plan=finding_execution_plan,
                    critic_binding_plan=critic_binding_plan,
                    report_draft_plan=report_draft_plan,
                    evidence=(drifted_evidence,),
                    now=now + timedelta(seconds=27),
                )
            assert not report_draft_store.has_checkpoint(report_draft_plan.plan_id)
            calls_before_report_execution = calls_after_report_intake
            report_draft_binding = report_execution_service.execute(
                report_execution_plan,
                report_intake_plan=report_intake_plan,
                finding_execution_plan=finding_execution_plan,
                critic_binding_plan=critic_binding_plan,
                report_draft_plan=report_draft_plan,
                evidence=(critic_evidence,),
                now=now + timedelta(seconds=27),
            )
            report_outcome = report_draft_store.load_completed(report_draft_plan.plan_id)
            calls_after_report_execution = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            report_review_plan = ReportReviewPlan.create(
                report=report_outcome.report,
                artifact=report_outcome.artifact,
                evidence_bundle_digest=domain_object_digest(evidence_bundle),
                reviewer="future-phase3-human-report-reviewer",
                diff_id=None,
                created_at=now + timedelta(seconds=28),
                deadline=now + timedelta(seconds=33),
                approval_expires_at=now + timedelta(seconds=34),
                idempotency_key="m8.9:report-review",
            )
            report_review_intake_service = AgentReportReviewIntakeService(
                scope=scope,
                draft_execution_store=report_draft_execution_store,
                report_store=report_draft_store,
                artifact_store=report_service.artifact_store,
                evidence_store=evidence_store,
                store=report_review_intake_store,
            )
            with pytest.raises(AgentReportReviewIntakeRejected):
                report_review_intake_service.prepare(
                    draft_execution_plan=report_execution_plan,
                    report_review_plan=report_review_plan.model_copy(
                        update={"reviewer": "tampered reviewer"}
                    ),
                    evidence_bundle=evidence_bundle,
                    evidence=(critic_evidence,),
                    now=now + timedelta(seconds=29),
                    decision_deadline=now + timedelta(seconds=32),
                    idempotency_key="m8.9:report-review-intake:tampered",
                )
            assert (
                report_review_intake_store.connection.execute(
                    "SELECT count(*) FROM agent_report_review_intakes"
                ).fetchone()[0]
                == 0
            )
            report_review_intake_plan = report_review_intake_service.prepare(
                draft_execution_plan=report_execution_plan,
                report_review_plan=report_review_plan,
                evidence_bundle=evidence_bundle,
                evidence=(critic_evidence,),
                now=now + timedelta(seconds=29),
                decision_deadline=now + timedelta(seconds=32),
                idempotency_key="m8.9:report-review-intake",
            )
            report_review_intake_command = AgentReportReviewIntakeCommand.create(
                intake_plan_id=report_review_intake_plan.intake_plan_id,
                intake_plan_digest=agent_report_review_intake_plan_digest(
                    report_review_intake_plan
                ),
                draft_outcome_binding_id=report_draft_binding.binding_id,
                report_review_plan_id=report_review_plan.plan_id,
                report_review_plan_digest=(report_review_intake_plan.report_review_plan_digest),
                report_id=report_outcome.report.report_id,
                report_digest=report_review_intake_plan.report_digest,
                decision=AgentReportReviewIntakeDecision.ACCEPT,
                reason_code=(AgentReportReviewIntakeReason.HUMAN_ACCEPTED_EXACT_REVIEW),
                reviewer="phase3-human-report-review-intake-reviewer",
                decided_at=now + timedelta(seconds=30),
            )
            calls_before_report_review_intake = calls_after_report_execution
            report_review_intake_record = report_review_intake_service.decide(
                report_review_intake_plan,
                report_review_intake_command,
                draft_execution_plan=report_execution_plan,
                report_review_plan=report_review_plan,
                evidence_bundle=evidence_bundle,
                evidence=(critic_evidence,),
                now=report_review_intake_command.decided_at,
            )
            calls_after_report_review_intake = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            report_review_command = ReportReviewCommand.create(
                plan_id=report_review_plan.plan_id,
                report_id=report_outcome.report.report_id,
                report_digest=domain_object_digest(report_outcome.report),
                reviewer=report_review_plan.reviewer,
                decision=ReviewDecisionKind.APPROVE,
                rationale_code="phase3_human_approved",
                decided_at=now + timedelta(seconds=30),
            )
            report_review_execution_service = AgentReportReviewExecutionService(
                intake_service=report_review_intake_service,
                review_service=HumanReportReviewService(
                    scope=scope,
                    evidence_store=evidence_store,
                    artifact_store=report_service.artifact_store,
                    store=report_review_store,
                ),
                store=report_review_execution_store,
            )
            report_review_action = report_review_execution_service.approval_action(
                record=report_review_intake_record,
                report_review_plan=report_review_plan,
                report_review_command=report_review_command,
            )
            report_review_approval = ApprovalRequest(
                engagement_id=scope.engagement_id,
                action=ApprovalAction.REVIEW_REPORT,
                action_digest=report_review_action.action_id,
                expected_side_effects=REPORT_REVIEW_EFFECTS[report_review_command.decision],
                evidence_summary=(
                    "Phase 3 human authorized the exact sealed Report review decision"
                ),
                policy_version=scope.version,
                expires_at=now + timedelta(seconds=32),
                status=ApprovalStatus.GRANTED,
                decided_by="phase3-human-report-approval-reviewer",
                decided_at=now + timedelta(seconds=30),
            )
            with pytest.raises(AgentReportReviewExecutionRejected):
                report_review_execution_service.prepare(
                    review_intake_plan=report_review_intake_plan,
                    draft_execution_plan=report_execution_plan,
                    report_review_plan=report_review_plan,
                    report_review_command=report_review_command,
                    evidence_bundle=evidence_bundle,
                    evidence=(critic_evidence,),
                    approval=report_review_approval.model_copy(update={"action_digest": "0" * 64}),
                    now=now + timedelta(seconds=30, milliseconds=250),
                    deadline=now + timedelta(seconds=31, milliseconds=500),
                    idempotency_key="m8.10:report-review-execution:tampered",
                )
            assert (
                report_review_execution_store.connection.execute(
                    "SELECT count(*) FROM agent_report_review_executions"
                ).fetchone()[0]
                == 0
            )
            report_review_execution_plan = report_review_execution_service.prepare(
                review_intake_plan=report_review_intake_plan,
                draft_execution_plan=report_execution_plan,
                report_review_plan=report_review_plan,
                report_review_command=report_review_command,
                evidence_bundle=evidence_bundle,
                evidence=(critic_evidence,),
                approval=report_review_approval,
                now=now + timedelta(seconds=30, milliseconds=250),
                deadline=now + timedelta(seconds=31, milliseconds=500),
                idempotency_key="m8.10:report-review-execution",
            )
            calls_before_report_review_execution = calls_after_report_review_intake
            report_review_binding = report_review_execution_service.execute(
                report_review_execution_plan,
                review_intake_plan=report_review_intake_plan,
                draft_execution_plan=report_execution_plan,
                report_review_plan=report_review_plan,
                report_review_command=report_review_command,
                evidence_bundle=evidence_bundle,
                evidence=(critic_evidence,),
                approval=report_review_approval,
                now=now + timedelta(seconds=31),
            )
            report_review_outcome = report_review_store.load_completed(report_review_plan.plan_id)
            calls_after_report_review_execution = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            report_export_plan = ReportExportPlan.create(
                report=report_review_outcome.report,
                artifact=report_review_outcome.artifact,
                review=report_review_outcome.review,
                created_at=now + timedelta(seconds=31, milliseconds=250),
                deadline=now + timedelta(seconds=33, milliseconds=500),
                idempotency_key="m8.11:report-export",
            )
            report_export_intake_service = AgentReportExportIntakeService(
                scope=scope,
                review_execution_store=report_review_execution_store,
                review_store=report_review_store,
                artifact_store=report_service.artifact_store,
                store=report_export_intake_store,
            )
            with pytest.raises(AgentReportExportIntakeRejected):
                report_export_intake_service.prepare(
                    review_execution_plan=report_review_execution_plan,
                    report_export_plan=report_export_plan.model_copy(
                        update={"report_digest": "0" * 64}
                    ),
                    now=now + timedelta(seconds=31, milliseconds=500),
                    decision_deadline=now + timedelta(seconds=33),
                    idempotency_key="m8.11:report-export-intake:tampered",
                )
            assert (
                report_export_intake_store.connection.execute(
                    "SELECT count(*) FROM agent_report_export_intakes"
                ).fetchone()[0]
                == 0
            )
            report_export_intake_plan = report_export_intake_service.prepare(
                review_execution_plan=report_review_execution_plan,
                report_export_plan=report_export_plan,
                now=now + timedelta(seconds=31, milliseconds=500),
                decision_deadline=now + timedelta(seconds=33),
                idempotency_key="m8.11:report-export-intake",
            )
            report_export_intake_command = AgentReportExportIntakeCommand.create(
                intake_plan_id=report_export_intake_plan.intake_plan_id,
                intake_plan_digest=agent_report_export_intake_plan_digest(
                    report_export_intake_plan
                ),
                review_outcome_binding_id=report_review_binding.binding_id,
                report_export_plan_id=report_export_plan.plan_id,
                report_export_plan_digest=(
                    report_export_intake_plan.report_export_plan_digest
                ),
                report_id=report_review_outcome.report.report_id,
                report_digest=report_export_intake_plan.report_digest,
                decision=AgentReportExportIntakeDecision.ACCEPT,
                reason_code=(
                    AgentReportExportIntakeReason.HUMAN_ACCEPTED_EXACT_EXPORT
                ),
                reviewer="phase3-human-report-export-intake-reviewer",
                decided_at=now + timedelta(seconds=32),
            )
            calls_before_report_export_intake = calls_after_report_review_execution
            report_artifacts_before_export_intake = tuple(
                sorted(report_service.artifact_store.objects.iterdir())
            )
            report_export_intake_record = report_export_intake_service.decide(
                report_export_intake_plan,
                report_export_intake_command,
                review_execution_plan=report_review_execution_plan,
                report_export_plan=report_export_plan,
                now=report_export_intake_command.decided_at,
            )
            calls_after_report_export_intake = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            report_artifacts_after_export_intake = tuple(
                sorted(report_service.artifact_store.objects.iterdir())
            )
            report_export_execution_service = AgentReportExportExecutionService(
                intake_service=report_export_intake_service,
                export_service=LocalReportExportService(
                    scope=scope,
                    artifact_store=report_service.artifact_store,
                    store=report_export_store,
                ),
                store=report_export_execution_store,
            )
            report_export_action = report_export_execution_service.approval_action(
                record=report_export_intake_record,
                report_export_plan=report_export_plan,
            )
            report_export_approval = ApprovalRequest(
                engagement_id=scope.engagement_id,
                action=ApprovalAction.EXPORT_REPORT,
                action_digest=report_export_action.action_id,
                expected_side_effects=REPORT_EXPORT_EFFECTS,
                evidence_summary=(
                    "Phase 3 human authorized the exact sealed local Report export"
                ),
                policy_version=scope.version,
                expires_at=now + timedelta(seconds=33),
                status=ApprovalStatus.GRANTED,
                decided_by="phase3-human-report-export-approval-reviewer",
                decided_at=now + timedelta(seconds=32),
            )
            with pytest.raises(AgentReportExportExecutionRejected):
                report_export_execution_service.prepare(
                    export_intake_plan=report_export_intake_plan,
                    review_execution_plan=report_review_execution_plan,
                    report_export_plan=report_export_plan,
                    approval=report_export_approval.model_copy(
                        update={"action_digest": "0" * 64}
                    ),
                    now=now + timedelta(seconds=32, milliseconds=250),
                    deadline=now + timedelta(seconds=32, milliseconds=750),
                    idempotency_key="m8.12:report-export-execution:tampered",
                )
            assert (
                report_export_execution_store.connection.execute(
                    "SELECT count(*) FROM agent_report_export_executions"
                ).fetchone()[0]
                == 0
            )
            report_export_execution_plan = report_export_execution_service.prepare(
                export_intake_plan=report_export_intake_plan,
                review_execution_plan=report_review_execution_plan,
                report_export_plan=report_export_plan,
                approval=report_export_approval,
                now=now + timedelta(seconds=32, milliseconds=250),
                deadline=now + timedelta(seconds=32, milliseconds=750),
                idempotency_key="m8.12:report-export-execution",
            )
            calls_before_report_export_execution = calls_after_report_export_intake
            report_export_binding = report_export_execution_service.execute(
                report_export_execution_plan,
                export_intake_plan=report_export_intake_plan,
                review_execution_plan=report_review_execution_plan,
                report_export_plan=report_export_plan,
                approval=report_export_approval,
                now=now + timedelta(seconds=32, milliseconds=500),
            )
            report_export_outcome = report_export_store.load_completed(
                report_export_plan.plan_id
            )
            calls_after_report_export_execution = (
                _TargetHandler.requests,
                len(adapter.attempts),
                validation_runner.calls,
            )
            workflow_objects = (
                audit_outcome.bundle,
                intake_record,
                outcome_binding,
                critic_intake_record,
                critic_outcome_binding,
                finding_intake_record,
                finding_promotion_outcome,
                report_intake_record,
                report_draft_binding,
                report_review_intake_record,
                report_review_binding,
                report_export_intake_record,
                report_export_binding,
            )
            workflow_checkpoints = tuple(
                AgentWorkflowCheckpoint(
                    stage=stage,
                    object_id=canonical_digest(
                        {
                            "stage": stage.value,
                            "object_digest": domain_object_digest(item),
                        }
                    ),
                    object_digest=domain_object_digest(item),
                )
                for stage, item in zip(
                    REQUIRED_AGENT_WORKFLOW_STAGES, workflow_objects, strict=True
                )
            )
            validation_effects = AgentWorkflowEffectCounters(
                target_requests=calls_after_binding[0],
                broker_calls=calls_after_binding[0],
                provider_attempts=calls_after_binding[1],
                runner_calls=calls_after_binding[2],
            )
            export_effects = AgentWorkflowEffectCounters(
                target_requests=calls_after_report_export_execution[0],
                broker_calls=calls_after_report_export_execution[0],
                provider_attempts=calls_after_report_export_execution[1],
                runner_calls=calls_after_report_export_execution[2],
            )
            workflow_observation = AgentWorkflowRegressionObservation.create(
                checkpoints=workflow_checkpoints,
                proposed_candidate_state=candidate.state,
                critic_candidate_state=critic_outcome.candidate.state,
                promoted_candidate_state=finding_promotion_outcome.promoted_candidate.state,
                validation_result=validation_outcome.verdict.result,
                critic_verdict=critic_outcome.review.verdict,
                draft_report_status=report_outcome.report.review_status,
                reviewed_report_status=report_review_outcome.report.review_status,
                exported_report_status=report_export_outcome.report.review_status,
                evidence_refs=tuple(
                    sorted(
                        set(audit_outcome.bundle.evidence_refs)
                        | set(evidence_bundle.evidence_refs)
                    )
                ),
                human_decision_digests=tuple(
                    sorted(
                        domain_object_digest(item)
                        for item in (
                            intake_record,
                            critic_intake_record,
                            finding_intake_record,
                            report_intake_record,
                            report_review_intake_record,
                            report_export_intake_record,
                        )
                    )
                ),
                approval_digests=tuple(
                    sorted(
                        domain_object_digest(item)
                        for item in (
                            promotion_approval,
                            report_review_approval,
                            report_export_approval,
                        )
                    )
                ),
                validation_effects=validation_effects,
                export_effects=export_effects,
                public_network_calls=0,
                target_builds=0,
                automatic_approvals=0,
                submission_calls=0,
                exported_artifact_digest=domain_object_digest(report_export_outcome.artifact),
            )
            workflow_plan = AgentWorkflowRegressionPlan.create(
                observation=workflow_observation,
                policy=AgentWorkflowRegressionPolicy(),
                created_at=now + timedelta(seconds=32, milliseconds=500),
                deadline=now + timedelta(seconds=40),
                idempotency_key="m9.1:agent-workflow-regression",
            )
            workflow_regression_outcome = AgentWorkflowRegressionService(
                store=workflow_regression_store,
                artifact_store=AgentWorkflowRegressionArtifactStore(
                    tmp_path / "m91-agent-workflow-artifacts"
                ),
            ).evaluate(
                workflow_plan,
                workflow_observation,
                now=now + timedelta(seconds=33),
            )
    finally:
        workflow_regression_store.close()
        report_export_execution_store.close()
        report_export_store.close()
        report_export_intake_store.close()
        report_review_execution_store.close()
        report_review_store.close()
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
    assert intake_record.decision is AgentValidationIntakeDecision.ACCEPT
    assert validation_runner.calls == 1
    assert validation_outcome.verdict.result.value == "reproduced"
    assert outcome_binding.validation_run_id == validation_outcome.validation_run.run_id
    assert calls_after_binding == calls_before_binding
    assert critic_intake_record.decision is AgentCriticIntakeDecision.ACCEPT
    assert calls_after_critic_intake == calls_before_critic_intake
    assert critic_outcome.review.verdict.value == "accepted"
    assert critic_outcome_binding.critic_review_id == critic_outcome.review.review_id
    assert critic_outcome_binding.final_candidate_state.value == "critic_reviewed"
    assert calls_after_critic_binding == calls_before_critic_binding
    assert finding_intake_record.decision is AgentFindingIntakeDecision.ACCEPT
    assert calls_after_finding_intake == calls_before_finding_intake
    assert finding_promotion_outcome.promoted_candidate.state.value == "promoted"
    assert finding_promotion_outcome.finding.finding_id == promotion_plan.finding_id
    assert calls_after_finding_promotion == calls_before_finding_promotion
    assert report_intake_record.decision is AgentReportIntakeDecision.ACCEPT
    assert calls_after_report_intake == calls_before_report_intake
    assert report_draft_binding.review_status.value == "draft"
    assert report_draft_binding.report_id == report_outcome.report.report_id
    assert calls_after_report_execution == calls_before_report_execution
    assert report_review_intake_record.decision is AgentReportReviewIntakeDecision.ACCEPT
    assert report_outcome.report.review_status.value == "draft"
    assert calls_after_report_review_intake == calls_before_report_review_intake
    assert report_review_binding.resulting_status.value == "human_approved"
    assert report_review_outcome.report.review_status.value == "human_approved"
    assert report_outcome.report.review_status.value == "draft"
    assert calls_after_report_review_execution == calls_before_report_review_execution
    assert report_export_intake_record.decision is AgentReportExportIntakeDecision.ACCEPT
    assert report_review_outcome.report.review_status.value == "human_approved"
    assert calls_after_report_export_intake == calls_before_report_export_intake
    assert report_artifacts_after_export_intake == report_artifacts_before_export_intake
    assert report_export_binding.resulting_status.value == "exported"
    assert report_export_outcome.report.review_status.value == "exported"
    assert report_review_outcome.report.review_status.value == "human_approved"
    assert calls_after_report_export_execution == calls_before_report_export_execution
    assert workflow_regression_outcome.result.gate_status.value == "passed"
    assert workflow_regression_outcome.result.metrics.stage_completeness == 1.0
    assert not workflow_regression_outcome.result.violations
    assert critic_outcome.candidate.state.value == "critic_reviewed"
    assert candidate.state.value == "proposed"
    assert _TargetHandler.requests == 2
    assert len(adapter.attempts) == 3
    assert _TARGET_BODY not in (tmp_path / "m711-audits.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m81-intakes.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m82-bindings.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m83-critic-intakes.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m84-critic-outcome-bindings.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m85-finding-intakes.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m86-finding-promotions.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m87-report-intakes.sqlite3").read_bytes()
    assert _TARGET_BODY not in (tmp_path / "m88-report-draft-bindings.sqlite3").read_bytes()
    assert (
        b"trusted Phase 3 exact report title"
        not in (tmp_path / "m88-report-draft-bindings.sqlite3").read_bytes()
    )
    assert _TARGET_BODY not in (tmp_path / "m89-report-review-intakes.sqlite3").read_bytes()
    assert (
        b"trusted Phase 3 exact report title"
        not in (tmp_path / "m89-report-review-intakes.sqlite3").read_bytes()
    )
    assert _TARGET_BODY not in (tmp_path / "m810-report-review-bindings.sqlite3").read_bytes()
    assert (
        b"trusted Phase 3 exact report title"
        not in (tmp_path / "m810-report-review-bindings.sqlite3").read_bytes()
    )
    assert (
        b"Phase 3 human authorized the exact sealed"
        not in (tmp_path / "m810-report-review-bindings.sqlite3").read_bytes()
    )
    assert _TARGET_BODY not in (tmp_path / "m811-report-export-intakes.sqlite3").read_bytes()
    assert (
        b"trusted Phase 3 exact report title"
        not in (tmp_path / "m811-report-export-intakes.sqlite3").read_bytes()
    )
    assert _TARGET_BODY not in (tmp_path / "m812-report-export-bindings.sqlite3").read_bytes()
    assert (
        b"trusted Phase 3 exact report title"
        not in (tmp_path / "m812-report-export-bindings.sqlite3").read_bytes()
    )
    assert _TARGET_BODY not in (
        tmp_path / "m91-agent-workflow-regressions.sqlite3"
    ).read_bytes()
    assert (
        b"Phase 3 human authorized the exact sealed local"
        not in (tmp_path / "m812-report-export-bindings.sqlite3").read_bytes()
    )
    assert (
        b"trusted Phase 3 exact report title"
        not in (tmp_path / "m87-report-intakes.sqlite3").read_bytes()
    )
    assert (
        b"Phase 3 human approved the exact sealed promotion"
        not in (tmp_path / "m86-finding-promotions.sqlite3").read_bytes()
    )
    assert (
        b"trusted Phase 3 control-plane root cause"
        not in (tmp_path / "m85-finding-intakes.sqlite3").read_bytes()
    )
    assert _TARGET_BODY not in (tmp_path / "m710-sessions.sqlite3").read_bytes()
    assert b"m710-loopback-provider-secret" not in (tmp_path / "m710-sessions.sqlite3").read_bytes()
