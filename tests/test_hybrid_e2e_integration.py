from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import threading
import zipfile
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

from vulnloom.analyzers import PythonWebSourceMapper
from vulnloom.broker import (
    BrokerCall,
    EvidenceStoreHttpSink,
    HttpRequestPlan,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.broker.models import url_digest
from vulnloom.critic import (
    CounterevidenceAngle,
    CounterevidenceAssessment,
    CounterevidenceDisposition,
    CriticPlan,
    CriticStore,
    DeterministicCritic,
    domain_object_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    ArtifactKind,
    ArtifactScope,
    Evidence,
    EvidenceKind,
    NetworkTargetScope,
    ReportChannel,
    ReportSection,
    ReportSectionKind,
    Target,
    TargetManifest,
    TargetSnapshot,
    ValidationResult,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.findings import DuplicateCheckResult, FindingDuplicateCheck
from vulnloom.hybrid import (
    HYBRID_FINDING_SIDE_EFFECTS,
    DeploymentProof,
    HybridCheckKind,
    HybridCiGateAdapter,
    HybridCiGateStatus,
    HybridFindingPromotionPlan,
    HybridFindingPromotionService,
    HybridFindingPromotionStore,
    HybridReleaseGatePlan,
    HybridReleaseGatePolicy,
    HybridReleaseGateService,
    HybridReleaseGateStore,
    HybridReportPlan,
    HybridReportService,
    HybridReportStore,
    HybridValidationService,
    HybridValidationStore,
    hybrid_finding_approval_digest,
)
from vulnloom.hypotheses import CandidateGenerator
from vulnloom.ingestion import IngestionService
from vulnloom.policy import PolicyEngine
from vulnloom.reporting import (
    DeterministicReportService,
    ReportArtifactStore,
    ReportDraftPlan,
    ReportDraftStore,
    report_draft_plan_digest,
)
from vulnloom.runners import (
    NetworkGrant,
    OfflineSandboxRunner,
    OfflineScenario,
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
    ValidationVerdict,
    candidate_content_digest,
)

HOST = "hybrid-preprod.example.test"
VULNERABLE_BODY = b'{"invoice_id":7,"owner_id":200,"visible_to":100}'
FIXED_BODY = b'{"error":"not_found"}'
IMAGE = "sha256:" + "8" * 64


class _PreproductionHandler(BaseHTTPRequestHandler):
    response_body = VULNERABLE_BODY
    requests = 0

    def do_GET(self):
        type(self).requests += 1
        body = type(self).response_body
        self.send_response(200 if body == VULNERABLE_BODY else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _PinnedResolver:
    implementation_digest = PinnedHttpTransport.implementation_digest

    def __init__(self, address: str):
        self.address = address

    def resolve(self, host: str) -> tuple[str, ...]:
        return (self.address,) if host == HOST else ()


class _EvidenceRunner:
    def __init__(self, evidence_ref: str):
        self.delegate = OfflineSandboxRunner(frozenset({"sandbox.test"}))
        self.evidence_ref = evidence_ref

    def execute(self, request, *, now):
        return self.delegate.execute(
            request,
            now=now,
            scenario=OfflineScenario(evidence_refs=(self.evidence_ref,)),
        )


class _SourceRetestJudge:
    def evaluate(self, *, evidence_refs, **_):
        return ValidationVerdict(
            result=ValidationResult.NOT_REPRODUCED,
            rationale_code="ownership_guard_present",
            evidence_refs=evidence_refs,
        )


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
        if not (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            return str(address)
    return None


def _archive(path: Path, source: str) -> str:
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr("shop/app.py", source)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _task(now, scope, candidate, profile, *, key, allowed_tools):
    return TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=pinned_http_tool_registry().digest,
        input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
        allowed_tools=allowed_tools,
        budget=TaskBudget(wall_seconds=30, model_tokens=0, tool_calls=2),
        deadline=now + timedelta(minutes=2),
        idempotency_key=key,
    )


def _validation_plan(
    now,
    scope,
    candidate,
    *,
    key,
    snapshot_id,
    endpoint=None,
    expected_body=None,
    result=None,
):
    runner_profile = validation_profile(image_digest=IMAGE, snapshot_id=snapshot_id)
    runner_task = _task(
        now,
        scope,
        candidate,
        runner_profile,
        key=f"{key}:runner-task",
        allowed_tools=frozenset({"sandbox.test"}),
    )
    runner_request = SandboxRunRequest(
        task=runner_task,
        profile=runner_profile,
        invocation=ToolInvocation(tool_id="sandbox.test", working_directory="source"),
        environment={"VULNLOOM_TASK_ID": str(runner_task.task_id)},
        idempotency_key=f"{key}:runner",
    )
    calls = ()
    assertion = None
    if endpoint is not None:
        broker_profile = validation_profile(
            image_digest=IMAGE,
            snapshot_id=snapshot_id,
            network_grants=(
                NetworkGrant(
                    host=HOST,
                    ports=frozenset({endpoint.port}),
                    schemes=frozenset({"http"}),
                ),
            ),
        )
        broker_task = _task(
            now,
            scope,
            candidate,
            broker_profile,
            key=f"{key}:broker-task",
            allowed_tools=frozenset({"http.request"}),
        )
        call = BrokerCall(
            task=broker_task,
            profile=broker_profile,
            tool_id="http.request",
            http=HttpRequestPlan(method="GET", url=endpoint.geturl(), test_class="read_only"),
            idempotency_key=f"{key}:broker",
        )
        calls = (call,)
        assertion = HttpResponseAssertion.create(
            call_id=call.call_id,
            expected_status_code=200 if result is ValidationResult.REPRODUCED else 404,
            expected_body_sha256=hashlib.sha256(expected_body).hexdigest(),
            match_result=result,
        )
    return ValidationPlan.create(
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate_content_digest(candidate),
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        selected_by="operator:hybrid-e2e",
        selected_at=now,
        selection_reason="Bounded isolated Hybrid pre-production acceptance",
        runner_request=runner_request,
        broker_calls=calls,
        http_assertion=assertion,
        idempotency_key=key,
    )


@pytest.mark.composition_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_HYBRID_E2E_INTEGRATION") != "1",
    reason="set VULNLOOM_HYBRID_E2E_INTEGRATION=1 for isolated Hybrid preprod E2E",
)
def test_isolated_source_to_preprod_remediation_report_and_release_gate(
    tmp_path, approved_scope, now, request
):
    address = _safe_local_ipv4()
    if address is None:
        pytest.skip("no non-loopback local IPv4 is available for the isolated fixture")
    _PreproductionHandler.response_body = VULNERABLE_BODY
    _PreproductionHandler.requests = 0
    server = ThreadingHTTPServer((address, 0), _PreproductionHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    stopped = False

    def stop_server():
        nonlocal stopped
        if stopped:
            return
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        stopped = True

    request.addfinalizer(stop_server)
    port = server.server_address[1]
    endpoint = f"http://{HOST}:{port}/invoice/7"

    vulnerable_source = """
from flask import Flask
app = Flask(__name__)
@app.get('/invoice/<invoice_id>')
def invoice(invoice_id):
    return Invoice.query.get(invoice_id)
"""
    fixed_source = """
from flask import Flask
app = Flask(__name__)
@app.get('/invoice/<invoice_id>')
def invoice(invoice_id):
    item = Invoice.query.get(invoice_id)
    if item.owner_id != current_user.id:
        raise PermissionError()
    return item
"""
    vulnerable_archive = tmp_path / "vulnerable.zip"
    fixed_archive = tmp_path / "fixed.zip"
    vulnerable_digest = _archive(vulnerable_archive, vulnerable_source)
    fixed_digest = _archive(fixed_archive, fixed_source)
    scope = approved_scope.model_copy(
        update={
            "artifacts": (
                ArtifactScope(
                    kind=ArtifactKind.SOURCE_ARCHIVE,
                    sha256=vulnerable_digest,
                    source_name=vulnerable_archive.name,
                ),
                ArtifactScope(
                    kind=ArtifactKind.SOURCE_ARCHIVE,
                    sha256=fixed_digest,
                    source_name=fixed_archive.name,
                ),
            ),
            "network_targets": (
                NetworkTargetScope(
                    host=HOST,
                    ports=frozenset({port}),
                    schemes=frozenset({"http"}),
                ),
            ),
        }
    )
    target_store = tmp_path / "targets"
    ingestion = IngestionService(target_store)
    vulnerable_snapshot = ingestion.ingest_archive(vulnerable_archive, scope=scope)
    vulnerable_graph = PythonWebSourceMapper().analyze(
        vulnerable_snapshot, target_store, scope=scope
    )
    candidates = CandidateGenerator().generate(vulnerable_graph, scope=scope, now=now)
    assert len(candidates.candidates) == 1
    candidate = candidates.candidates[0]

    fixed_raw = ingestion.ingest_archive(fixed_archive, scope=scope)
    fixed_target = Target(
        target_id=candidate.target_id,
        engagement_id=fixed_raw.target.engagement_id,
        kind=fixed_raw.target.kind,
        source_ref=fixed_raw.target.source_ref,
        version=fixed_raw.target.version,
    )
    fixed_manifest = TargetManifest(
        manifest_id=fixed_raw.manifest.manifest_id,
        artifact_id=fixed_raw.manifest.artifact_id,
        target_id=candidate.target_id,
        target_version=fixed_raw.target.version,
        files=fixed_raw.manifest.files,
        total_size=fixed_raw.manifest.total_size,
    )
    fixed_snapshot = TargetSnapshot(
        target=fixed_target,
        artifact=fixed_raw.artifact,
        manifest=fixed_manifest,
        root_ref=fixed_raw.root_ref,
    )
    fixed_graph = PythonWebSourceMapper().analyze(fixed_snapshot, target_store, scope=scope)
    fixed_candidates = CandidateGenerator().generate(fixed_graph, scope=scope, now=now)
    assert fixed_candidates.candidates == ()

    evidence_store = EvidenceStore(tmp_path / "evidence")
    source_evidence = evidence_store.capture_text(
        "The invoice route reaches an object lookup without an ownership guard",
        kind=EvidenceKind.SOURCE,
        source_ref=f"graph-sha256:{vulnerable_graph.graph_id}",
        producer="hybrid-e2e.source-mapper",
        target_version=candidate.target_version,
        summary="source route and missing ownership predicate",
    )
    deploy_evidence = evidence_store.capture_text(
        "The vulnerable source manifest is deployed to the isolated fixture",
        kind=EvidenceKind.TEST,
        source_ref=f"manifest-sha256:{vulnerable_snapshot.manifest.manifest_id}",
        producer="hybrid-e2e.deployment",
        target_version=candidate.target_version,
        summary="isolated pre-production deployment binding",
    )
    resolver = _PinnedResolver(address)
    broker = ToolBroker(
        scope=scope,
        registry=pinned_http_tool_registry(),
        resolver=resolver,
        http_transport=PinnedHttpTransport(
            EvidenceStoreHttpSink(evidence_store, target_version=candidate.target_version)
        ),
        allowed_resolved_ips=frozenset({address}),
    )
    parsed_endpoint = urlsplit(endpoint)
    initial_plan = _validation_plan(
        now,
        scope,
        candidate,
        key="hybrid-e2e:initial",
        snapshot_id=vulnerable_snapshot.manifest.manifest_id,
        endpoint=parsed_endpoint,
        expected_body=VULNERABLE_BODY,
        result=ValidationResult.REPRODUCED,
    )
    validation_store = ValidationStore(tmp_path / "validations.sqlite3")
    initial_validation = ValidationService(
        scope=scope,
        runner=OfflineSandboxRunner(frozenset({"sandbox.test"})),
        broker=broker,
        store=validation_store,
        evidence_store=evidence_store,
        judge=DeterministicHttpJudge(),
    ).execute(candidate, initial_plan, now=now)
    assert initial_validation.validation_run.result is ValidationResult.REPRODUCED
    live_target_id = uuid4()
    initial_proof = DeploymentProof.create(
        source_target_id=candidate.target_id,
        source_target_version=candidate.target_version,
        source_manifest_digest=vulnerable_snapshot.manifest.manifest_id,
        live_target_id=live_target_id,
        endpoint_url_digest=url_digest(endpoint),
        deployed_artifact_digest=vulnerable_digest,
        attestation_evidence_ref=deploy_evidence.evidence_id,
        attested_by="operator:hybrid-e2e",
        attested_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    hybrid_store = HybridValidationStore(tmp_path / "hybrid.sqlite3")
    hybrid_service = HybridValidationService(
        validation_store=validation_store,
        hybrid_store=hybrid_store,
        evidence_store=evidence_store,
    )
    hybrid_plan = hybrid_service.prepare(
        check_kind=HybridCheckKind.INITIAL,
        candidate=candidate,
        deployment_proof=initial_proof,
        validation_plan=initial_plan,
        source_manifest_digest=vulnerable_snapshot.manifest.manifest_id,
        source_evidence_refs=(source_evidence.evidence_id,),
        scope=scope,
        created_at=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="hybrid-e2e:chain:initial",
    )
    initial_chain = hybrid_service.execute(
        hybrid_plan,
        candidate=candidate,
        deployment_proof=initial_proof,
        scope=scope,
        now=now,
    ).chain
    assert initial_chain is not None

    evidence_catalog = (
        source_evidence,
        deploy_evidence,
        *(
            Evidence(
                evidence_id=ref,
                kind=EvidenceKind.HTTP,
                source_ref="redacted:isolated-preprod",
                producer="hybrid-e2e.http",
                target_version=candidate.target_version,
                redaction_policy="default-v1",
                content_ref=f"objects/{ref}",
                summary="exact isolated endpoint observation",
            )
            for ref in initial_chain.http_evidence_refs
        ),
    )
    assessments = tuple(
        CounterevidenceAssessment(
            angle=angle,
            disposition=CounterevidenceDisposition.RULED_OUT,
            evidence_refs=(initial_chain.evidence_bundle.evidence_refs[0],),
            rationale_code=f"hybrid_e2e_{angle.value}_ruled_out",
        )
        for angle in CounterevidenceAngle
    )
    critic_plan = CriticPlan.create(
        candidate_id=initial_validation.candidate.candidate_id,
        candidate_digest=domain_object_digest(initial_validation.candidate),
        validation_run_id=initial_validation.validation_run.run_id,
        validation_run_digest=domain_object_digest(initial_validation.validation_run),
        evidence_bundle_id=initial_chain.evidence_bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(initial_chain.evidence_bundle),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        validation_context_id="1" * 64,
        review_context_id="2" * 64,
        validation_producer="hybrid-e2e.validator",
        review_producer="hybrid-e2e.critic",
        assessments=assessments,
        created_at=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="hybrid-e2e:critic",
    )
    critic_store = CriticStore(tmp_path / "critic.sqlite3")
    critic = DeterministicCritic(
        scope=scope,
        evidence_store=evidence_store,
        store=critic_store,
    ).review(
        initial_validation.candidate,
        initial_validation.validation_run,
        initial_chain.evidence_bundle,
        evidence_catalog,
        critic_plan,
        now=now,
    )
    duplicate = FindingDuplicateCheck.create(
        candidate_id=critic.candidate.candidate_id,
        candidate_digest=domain_object_digest(critic.candidate),
        target_version_digest=canonical_digest(critic.candidate.target_version),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        result=DuplicateCheckResult.CLEAR,
        duplicate_family_id=None,
        checked_by="operator:hybrid-e2e",
        checked_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    finding_plan = HybridFindingPromotionPlan.create(
        hybrid_chain_id=initial_chain.chain_id,
        hybrid_chain_digest=domain_object_digest(initial_chain),
        critic_plan_id=critic.plan_id,
        critic_outcome_digest=domain_object_digest(critic),
        duplicate_check_id=duplicate.check_id,
        duplicate_check_digest=domain_object_digest(duplicate),
        candidate_id=critic.candidate.candidate_id,
        candidate_digest=domain_object_digest(critic.candidate),
        finding_id=uuid4(),
        root_cause="The invoice handler omits the required ownership predicate",
        affected_versions=(candidate.target_version,),
        impact="The isolated endpoint returned an invoice owned by another identity",
        severity_assessment={"rating": "high", "score": 8.0},
        scope_id=scope.scope_id,
        scope_version=scope.version,
        created_at=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="hybrid-e2e:finding",
    )
    approval = ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        action=ApprovalAction.MUTATE_TARGET_STATE,
        action_digest=hybrid_finding_approval_digest(finding_plan),
        expected_side_effects=HYBRID_FINDING_SIDE_EFFECTS,
        evidence_summary="Approve the isolated Hybrid finding promotion",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="operator:hybrid-e2e",
        decided_at=now,
    )
    finding_store = HybridFindingPromotionStore(tmp_path / "finding.sqlite3")
    finding_outcome = HybridFindingPromotionService(
        scope=scope,
        hybrid_store=hybrid_store,
        validation_store=validation_store,
        critic_store=critic_store,
        evidence_store=evidence_store,
        store=finding_store,
    ).execute(plan=finding_plan, duplicate_check=duplicate, approval=approval, now=now)
    assert finding_outcome.finding is not None
    assert finding_outcome.promoted_candidate is not None

    sections = (
        ReportSection(
            kind=ReportSectionKind.SUMMARY,
            text="Source and isolated live validation confirm the authorization flaw",
        ),
        ReportSection(
            kind=ReportSectionKind.CODE_LOCATION,
            text="The invoice handler omits an ownership predicate",
            evidence_refs=(source_evidence.evidence_id,),
        ),
        ReportSection(
            kind=ReportSectionKind.REQUEST_RESPONSE,
            text="The exact isolated endpoint returned the unauthorized invoice",
            evidence_refs=(initial_chain.http_evidence_refs[0],),
        ),
        ReportSection(
            kind=ReportSectionKind.REPRODUCTION,
            text="Verify the deployment binding and replay the exact read-only request",
            evidence_refs=(
                initial_chain.deployment_evidence_ref,
                initial_chain.http_evidence_refs[0],
            ),
        ),
        ReportSection(
            kind=ReportSectionKind.IMPACT,
            text="The response demonstrates cross-tenant invoice disclosure",
            evidence_refs=(initial_chain.http_evidence_refs[0],),
        ),
        ReportSection(
            kind=ReportSectionKind.REMEDIATION,
            text="Enforce ownership before returning the invoice and repeat both validations",
        ),
    )
    report_plan = ReportDraftPlan.create(
        finding_id=finding_outcome.finding.finding_id,
        finding_digest=domain_object_digest(finding_outcome.finding),
        candidate_id=finding_outcome.promoted_candidate.candidate_id,
        candidate_digest=domain_object_digest(finding_outcome.promoted_candidate),
        evidence_bundle_id=initial_chain.evidence_bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(initial_chain.evidence_bundle),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        channel=ReportChannel.GENERIC,
        title="Authorized Hybrid pre-production finding",
        sections=sections,
        prepared_by="hybrid-e2e.reporter",
        created_at=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="hybrid-e2e:report",
    )
    hybrid_report_plan = HybridReportPlan.create(
        hybrid_finding_plan_id=finding_outcome.plan_id,
        hybrid_finding_outcome_digest=domain_object_digest(finding_outcome),
        hybrid_chain_id=initial_chain.chain_id,
        hybrid_chain_digest=domain_object_digest(initial_chain),
        report_draft_plan_id=report_plan.plan_id,
        report_draft_plan_digest=report_draft_plan_digest(report_plan),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        created_at=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="hybrid-e2e:hybrid-report",
    )
    report_store = ReportDraftStore(tmp_path / "report.sqlite3")
    artifact_store = ReportArtifactStore(tmp_path / "report-artifacts")
    hybrid_report_store = HybridReportStore(tmp_path / "hybrid-report.sqlite3")
    report_outcome = HybridReportService(
        scope=scope,
        hybrid_store=hybrid_store,
        finding_store=finding_store,
        report_service=DeterministicReportService(
            scope=scope,
            evidence_store=evidence_store,
            store=report_store,
            artifact_store=artifact_store,
        ),
        store=hybrid_report_store,
    ).execute(
        plan=hybrid_report_plan,
        report_plan=report_plan,
        evidence=evidence_catalog,
        now=now,
    )
    assert report_outcome.report_outcome is not None

    repaired = candidate.model_copy(update={"target_version": fixed_snapshot.target.version})
    fixed_source_evidence = evidence_store.capture_text(
        "The repaired invoice handler rejects objects not owned by the current identity",
        kind=EvidenceKind.SOURCE,
        source_ref=f"graph-sha256:{fixed_graph.graph_id}",
        producer="hybrid-e2e.source-retest",
        target_version=repaired.target_version,
        summary="ownership regression is not reproducible",
    )
    source_retest_plan = _validation_plan(
        now,
        scope,
        repaired,
        key="hybrid-e2e:source-retest",
        snapshot_id=fixed_snapshot.manifest.manifest_id,
    )
    source_retest = ValidationService(
        scope=scope,
        runner=_EvidenceRunner(fixed_source_evidence.evidence_id),
        broker=broker,
        store=validation_store,
        evidence_store=evidence_store,
        judge=_SourceRetestJudge(),
    ).execute(repaired, source_retest_plan, now=now)
    assert source_retest.validation_run.result is ValidationResult.NOT_REPRODUCED

    _PreproductionHandler.response_body = FIXED_BODY
    repaired_deploy_evidence = evidence_store.capture_text(
        "The repaired source manifest is deployed to the same isolated endpoint",
        kind=EvidenceKind.TEST,
        source_ref=f"manifest-sha256:{fixed_snapshot.manifest.manifest_id}",
        producer="hybrid-e2e.deployment",
        target_version=repaired.target_version,
        summary="repaired isolated deployment binding",
    )
    live_retest_plan = _validation_plan(
        now,
        scope,
        repaired,
        key="hybrid-e2e:live-retest",
        snapshot_id=fixed_snapshot.manifest.manifest_id,
        endpoint=parsed_endpoint,
        expected_body=FIXED_BODY,
        result=ValidationResult.NOT_REPRODUCED,
    )
    repaired_broker = ToolBroker(
        scope=scope,
        registry=pinned_http_tool_registry(),
        resolver=resolver,
        http_transport=PinnedHttpTransport(
            EvidenceStoreHttpSink(evidence_store, target_version=repaired.target_version)
        ),
        allowed_resolved_ips=frozenset({address}),
    )
    live_retest = ValidationService(
        scope=scope,
        runner=OfflineSandboxRunner(frozenset({"sandbox.test"})),
        broker=repaired_broker,
        store=validation_store,
        evidence_store=evidence_store,
        judge=DeterministicHttpJudge(),
    ).execute(repaired, live_retest_plan, now=now)
    assert live_retest.validation_run.result is ValidationResult.NOT_REPRODUCED
    repaired_proof = DeploymentProof.create(
        source_target_id=repaired.target_id,
        source_target_version=repaired.target_version,
        source_manifest_digest=fixed_snapshot.manifest.manifest_id,
        live_target_id=live_target_id,
        endpoint_url_digest=url_digest(endpoint),
        deployed_artifact_digest=fixed_digest,
        attestation_evidence_ref=repaired_deploy_evidence.evidence_id,
        attested_by="operator:hybrid-e2e",
        attested_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    retest_plan = hybrid_service.prepare(
        check_kind=HybridCheckKind.REMEDIATION_RETEST,
        candidate=repaired,
        deployment_proof=repaired_proof,
        validation_plan=live_retest_plan,
        source_validation_plan=source_retest_plan,
        source_manifest_digest=fixed_snapshot.manifest.manifest_id,
        source_evidence_refs=source_retest.verdict.evidence_refs,
        scope=scope,
        created_at=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="hybrid-e2e:chain:retest",
        prior_chain=initial_chain,
    )
    remediated_chain = hybrid_service.execute(
        retest_plan,
        candidate=repaired,
        deployment_proof=repaired_proof,
        scope=scope,
        now=now,
        prior_chain=initial_chain,
    ).chain
    assert remediated_chain is not None

    release_store = HybridReleaseGateStore(tmp_path / "release-gate.sqlite3")
    release_plan = HybridReleaseGatePlan.create(
        chain=remediated_chain,
        deployment_proof=repaired_proof,
        scope=scope,
        policy=HybridReleaseGatePolicy(),
        created_at=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="hybrid-e2e:release-gate",
    )
    response = HybridCiGateAdapter(
        HybridReleaseGateService(
            hybrid_store=hybrid_store,
            release_gate_store=release_store,
        )
    ).evaluate(release_plan, deployment_proof=repaired_proof, scope=scope, now=now)

    assert response.status is HybridCiGateStatus.PASS
    assert response.exit_code == 0
    assert _PreproductionHandler.requests == 2
    assert endpoint not in response.model_dump_json()
    assert artifact_store.read_markdown(report_outcome.report_outcome.artifact)
    stop_server()
    assert not thread.is_alive()

    release_store.close()
    hybrid_report_store.close()
    report_store.close()
    finding_store.close()
    critic_store.close()
    hybrid_store.close()
    validation_store.close()
