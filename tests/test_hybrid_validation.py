from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.broker import (
    BrokerCall,
    HttpRequestPlan,
    OfflineHttpHop,
    OfflineHttpTransport,
    StaticResolver,
    ToolBroker,
    default_tool_registry,
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
    Evidence,
    EvidenceKind,
    ReportChannel,
    ReportSection,
    ReportSectionKind,
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
    HybridCiGateResponse,
    HybridCiGateStatus,
    HybridConclusion,
    HybridEvidenceChain,
    HybridFindingConflict,
    HybridFindingPromotionPlan,
    HybridFindingPromotionRejected,
    HybridFindingPromotionService,
    HybridFindingPromotionStore,
    HybridFindingRecoveryRequired,
    HybridFindingState,
    HybridIdempotencyConflict,
    HybridRecoveryRequired,
    HybridReleaseDecision,
    HybridReleaseGateConflict,
    HybridReleaseGateOutcome,
    HybridReleaseGatePlan,
    HybridReleaseGatePolicy,
    HybridReleaseGateRecoveryRequired,
    HybridReleaseGateResult,
    HybridReleaseGateService,
    HybridReleaseGateState,
    HybridReleaseGateStore,
    HybridReportConflict,
    HybridReportOutcome,
    HybridReportPlan,
    HybridReportRecoveryRequired,
    HybridReportRejected,
    HybridReportService,
    HybridReportState,
    HybridReportStore,
    HybridRunState,
    HybridValidationLimits,
    HybridValidationOutcome,
    HybridValidationPlan,
    HybridValidationRejected,
    HybridValidationService,
    HybridValidationStore,
    SourceRemediationProof,
    hybrid_finding_approval_digest,
)
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
    validation_profile,
)
from vulnloom.runners.models import sandbox_profile_digest
from vulnloom.validation import (
    ValidationPlan,
    ValidationStore,
    ValidationVerdict,
    candidate_content_digest,
)
from vulnloom.validation.service import ValidationService

URL = "https://app.example.test/items/7"
IP = "192.0.2.10"
IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
BODY = hashlib.sha256(b"hybrid response").hexdigest()


class _Judge:
    def __init__(self, result):
        self.result = result

    def evaluate(self, *, evidence_refs, **_):
        return ValidationVerdict(
            result=self.result,
            rationale_code="hybrid_fixture_verdict",
            evidence_refs=evidence_refs,
        )


class _EvidenceRunner:
    def __init__(self, evidence_refs):
        self.delegate = OfflineSandboxRunner(frozenset({"sandbox.test"}))
        self.evidence_refs = evidence_refs

    def execute(self, request, *, now):
        return self.delegate.execute(
            request,
            now=now,
            scenario=OfflineScenario(evidence_refs=self.evidence_refs),
        )


def _validation_plan(now, scope, candidate, *, key, source_only=False):
    runner_profile = validation_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    runner_task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(runner_profile),
        tool_registry_digest=default_tool_registry().digest,
        input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
        allowed_tools=runner_profile.allowed_tools,
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=2),
        deadline=now + timedelta(minutes=1),
        idempotency_key=f"{key}:runner-task",
    )
    runner_request = SandboxRunRequest(
        task=runner_task,
        profile=runner_profile,
        invocation=ToolInvocation(
            tool_id="sandbox.test", arguments=("hybrid-fixture",), working_directory="source"
        ),
        environment={"VULNLOOM_TASK_ID": str(runner_task.task_id)},
        idempotency_key=f"{key}:runner",
    )
    broker_profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id=SNAPSHOT,
        network_grants=(
            NetworkGrant(
                host="app.example.test",
                ports=frozenset({443}),
                schemes=frozenset({"https"}),
            ),
        ),
    )
    broker_task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(broker_profile),
        tool_registry_digest=default_tool_registry().digest,
        input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
        allowed_tools=frozenset({"http.request"}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=2),
        deadline=now + timedelta(minutes=1),
        idempotency_key=f"{key}:broker-task",
    )
    call = BrokerCall(
        task=broker_task,
        profile=broker_profile,
        tool_id="http.request",
        http=HttpRequestPlan(method="GET", url=URL, test_class="read_only"),
        idempotency_key=f"{key}:broker",
    )
    return ValidationPlan.create(
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate_content_digest(candidate),
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        selected_by="operator:hybrid",
        selected_at=now,
        selection_reason="Bind one source Candidate to one exact authorized endpoint",
        runner_request=runner_request,
        broker_calls=() if source_only else (call,),
        idempotency_key=key,
    )


def _completed_validation(
    tmp_path,
    evidence_store,
    scope,
    candidate,
    now,
    *,
    result,
    key,
    store=None,
    source_only=False,
):
    evidence = evidence_store.capture_text(
        "redacted source regression facts"
        if source_only
        else "redacted HTTP validation facts",
        kind=EvidenceKind.SOURCE if source_only else EvidenceKind.HTTP,
        source_ref=(
            "snapshot-sha256:" + "7" * 64
            if source_only
            else "url-sha256:" + url_digest(URL)
        ),
        producer="test.hybrid.source-regression" if source_only else "test.hybrid.http",
        target_version=candidate.target_version,
        summary=(
            "repaired source regression is not reproducible"
            if source_only
            else "redacted exact endpoint result"
        ),
    )
    plan = _validation_plan(now, scope, candidate, key=key, source_only=source_only)
    transport = OfflineHttpTransport(
        {
            URL: OfflineHttpHop(
                status_code=200,
                peer_ip=IP,
                response_bytes=32,
                response_body_sha256=BODY,
                evidence_ref=evidence.evidence_id,
            )
        }
    )
    broker = ToolBroker(
        scope=scope,
        registry=default_tool_registry(),
        resolver=StaticResolver({"app.example.test": (IP,)}),
        http_transport=transport,
    )
    store = store or ValidationStore(tmp_path / f"{key.replace(':', '-')}.sqlite3")
    service = ValidationService(
        scope=scope,
        runner=(
            _EvidenceRunner((evidence.evidence_id,))
            if source_only
            else OfflineSandboxRunner(frozenset({"sandbox.test"}))
        ),
        broker=broker,
        store=store,
        evidence_store=evidence_store,
        judge=_Judge(result),
    )
    outcome = service.execute(candidate, plan, now=now)
    assert outcome.verdict.result is result
    return store, plan


def _proof_and_source(evidence_store, candidate, now, *, live_target_id=None):
    source = evidence_store.capture_text(
        "redacted source route evidence",
        kind=EvidenceKind.SOURCE,
        source_ref="snapshot-sha256:" + "3" * 64,
        producer="test.hybrid.source",
        target_version=candidate.target_version,
        summary="source route reaches the tested handler",
    )
    deploy = evidence_store.capture_text(
        "redacted deployment attestation",
        kind=EvidenceKind.TEST,
        source_ref="deployment-sha256:" + "4" * 64,
        producer="test.hybrid.deploy",
        target_version=candidate.target_version,
        summary="source version deployed to exact endpoint digest",
    )
    proof = DeploymentProof.create(
        source_target_id=candidate.target_id,
        source_target_version=candidate.target_version,
        source_manifest_digest="5" * 64,
        live_target_id=live_target_id or uuid4(),
        endpoint_url_digest=url_digest(URL),
        deployed_artifact_digest="6" * 64,
        attestation_evidence_ref=deploy.evidence_id,
        attested_by="operator:release",
        attested_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(hours=1),
    )
    return proof, source.evidence_id


def _hybrid_runtime(tmp_path, approved_scope, candidate, now, *, result, key, clock=None):
    evidence_store = EvidenceStore(tmp_path / f"evidence-{key.replace(':', '-')}")
    validation_store, validation_plan = _completed_validation(
        tmp_path,
        evidence_store,
        approved_scope,
        candidate,
        now,
        result=result,
        key=key,
    )
    proof, source_ref = _proof_and_source(evidence_store, candidate, now)
    hybrid_store = HybridValidationStore(tmp_path / f"hybrid-{key.replace(':', '-')}.sqlite3")
    kwargs = {
        "validation_store": validation_store,
        "hybrid_store": hybrid_store,
        "evidence_store": evidence_store,
    }
    if clock is not None:
        kwargs["monotonic"] = clock
    service = HybridValidationService(**kwargs)
    plan = service.prepare(
        check_kind=HybridCheckKind.INITIAL,
        candidate=candidate,
        deployment_proof=proof,
        validation_plan=validation_plan,
        source_manifest_digest=proof.source_manifest_digest,
        source_evidence_refs=(source_ref,),
        scope=approved_scope,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=f"hybrid:{key}",
    )
    return service, hybrid_store, validation_store, evidence_store, plan, proof


def _remediated_runtime(tmp_path, approved_scope, candidate, now, *, clock=None):
    initial = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="gate-initial:1",
    )
    service, hybrid_store, initial_validation_store, _, initial_plan, initial_proof = initial
    confirmed = service.execute(
        initial_plan,
        candidate=candidate,
        deployment_proof=initial_proof,
        scope=approved_scope,
        now=now,
    ).chain
    assert confirmed is not None
    initial_validation_store.close()

    repaired = candidate.model_copy(update={"target_version": "d" * 40})
    evidence_store = EvidenceStore(tmp_path / "gate-retest-evidence")
    validation_store, live_plan = _completed_validation(
        tmp_path,
        evidence_store,
        approved_scope,
        repaired,
        now,
        result=ValidationResult.NOT_REPRODUCED,
        key="gate-live-retest:1",
    )
    validation_store, source_plan = _completed_validation(
        tmp_path,
        evidence_store,
        approved_scope,
        repaired,
        now,
        result=ValidationResult.NOT_REPRODUCED,
        key="gate-source-retest:1",
        store=validation_store,
        source_only=True,
    )
    _, source_validation = validation_store.load_completed(source_plan.plan_id)
    repaired_proof, _ = _proof_and_source(
        evidence_store, repaired, now, live_target_id=initial_proof.live_target_id
    )
    retest_service = HybridValidationService(
        validation_store=validation_store,
        hybrid_store=hybrid_store,
        evidence_store=evidence_store,
    )
    retest_plan = retest_service.prepare(
        check_kind=HybridCheckKind.REMEDIATION_RETEST,
        candidate=repaired,
        deployment_proof=repaired_proof,
        validation_plan=live_plan,
        source_validation_plan=source_plan,
        source_manifest_digest=repaired_proof.source_manifest_digest,
        source_evidence_refs=source_validation.verdict.evidence_refs,
        scope=approved_scope,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="hybrid:gate-retest:1",
        prior_chain=confirmed,
    )
    remediated = retest_service.execute(
        retest_plan,
        candidate=repaired,
        deployment_proof=repaired_proof,
        scope=approved_scope,
        now=now,
        prior_chain=confirmed,
    ).chain
    assert remediated is not None
    validation_store.close()
    release_store = HybridReleaseGateStore(tmp_path / "release-gate.sqlite3")
    kwargs = {"hybrid_store": hybrid_store, "release_gate_store": release_store}
    if clock is not None:
        kwargs["monotonic"] = clock
    return (
        HybridReleaseGateService(**kwargs),
        release_store,
        hybrid_store,
        confirmed,
        initial_proof,
        remediated,
        repaired_proof,
    )


def test_hybrid_seals_source_deployment_and_http_evidence_and_replays(
    tmp_path, approved_scope, candidate, now
):
    service, hybrid_store, validation_store, _, plan, proof = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="initial:1",
    )
    first = service.execute(
        plan, candidate=candidate, deployment_proof=proof, scope=approved_scope, now=now
    )
    replay = service.execute(
        plan,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )

    assert replay == first
    assert first.state is HybridRunState.COMPLETED
    assert first.chain is not None
    assert first.chain.conclusion is HybridConclusion.CONFIRMED
    assert len(first.chain.evidence_bundle.evidence_refs) == 3
    assert URL not in first.model_dump_json()
    assert "authorization" not in first.model_dump_json().lower()
    hybrid_store.close()
    validation_store.close()


def test_hybrid_rejects_wrong_result_scope_drift_and_endpoint_drift(
    tmp_path, approved_scope, candidate, now
):
    service, hybrid_store, validation_store, _, plan, proof = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.NOT_REPRODUCED,
        key="reject:1",
    )
    with pytest.raises(HybridValidationRejected, match="provenance"):
        service.execute(
            plan, candidate=candidate, deployment_proof=proof, scope=approved_scope, now=now
        )
    drifted_scope = approved_scope.model_copy(update={"version": approved_scope.version + 1})
    with pytest.raises(HybridValidationRejected, match="provenance"):
        service.execute(
            plan, candidate=candidate, deployment_proof=proof, scope=drifted_scope, now=now
        )
    drifted_proof = proof.model_copy(update={"endpoint_url_digest": "f" * 64})
    with pytest.raises(HybridValidationRejected, match="provenance"):
        service.execute(
            plan, candidate=candidate, deployment_proof=drifted_proof, scope=approved_scope, now=now
        )
    assert hybrid_store.state(plan.plan_id) is None
    hybrid_store.close()
    validation_store.close()


def test_hybrid_timeout_and_evidence_failure_close_with_cleanup(
    tmp_path, approved_scope, candidate, now
):
    ticks = iter((0.0, 31.0))
    runtime = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="timeout:1",
        clock=lambda: next(ticks),
    )
    service, hybrid_store, validation_store, _, plan, proof = runtime
    timed_out = service.execute(
        plan, candidate=candidate, deployment_proof=proof, scope=approved_scope, now=now
    )
    assert timed_out.state is HybridRunState.TIMED_OUT
    assert timed_out.cleanup_complete and timed_out.chain is None
    hybrid_store.close()
    validation_store.close()

    runtime = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="missing:1",
    )
    service, hybrid_store, validation_store, _, plan, proof = runtime
    missing = plan.model_copy(update={"source_evidence_refs": ("f" * 64,)})
    failed = service.execute(
        missing, candidate=candidate, deployment_proof=proof, scope=approved_scope, now=now
    )
    assert failed.state is HybridRunState.FAILED
    assert failed.reason_code == "evidence_integrity_failed"
    assert failed.cleanup_complete
    hybrid_store.close()
    validation_store.close()


def test_hybrid_completed_replay_rechecks_evidence_integrity(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="replay-integrity:1",
    )
    service, hybrid_store, validation_store, evidence_store, plan, proof = runtime
    outcome = service.execute(
        plan, candidate=candidate, deployment_proof=proof, scope=approved_scope, now=now
    )
    assert outcome.chain is not None
    damaged = outcome.chain.source_evidence_refs[0]
    (evidence_store.objects / damaged).unlink()
    with pytest.raises(HybridValidationRejected, match="integrity"):
        service.execute(
            plan,
            candidate=candidate,
            deployment_proof=proof,
            scope=approved_scope,
            now=now + timedelta(seconds=1),
        )
    hybrid_store.close()
    validation_store.close()


def test_hybrid_explicit_recovery_is_bounded_and_idempotency_collisions_fail(
    tmp_path, approved_scope, candidate, now
):
    service, store, validation_store, _, plan, proof = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="recover:1",
    )
    store.claim(plan, now=now)
    with pytest.raises(HybridRecoveryRequired):
        service.execute(
            plan, candidate=candidate, deployment_proof=proof, scope=approved_scope, now=now
        )
    recovered = service.execute(
        plan,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
        recover=True,
    )
    assert recovered.attempt == 2

    collision = plan.model_copy(
        update={"plan_id": "a" * 64, "candidate_digest": "b" * 64}
    )
    with pytest.raises(HybridIdempotencyConflict):
        store.claim(collision, now=now)
    store.close()
    validation_store.close()


def test_hybrid_recovery_exhaustion_closes_started_checkpoint(
    tmp_path, approved_scope, candidate, now
):
    _, store, validation_store, _, plan, _ = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="exhaust:1",
    )
    store.claim(plan, now=now)
    store.recover(plan, now=now + timedelta(seconds=1))
    store.recover(plan, now=now + timedelta(seconds=2))
    with pytest.raises(HybridRecoveryRequired, match="exhausted"):
        store.recover(plan, now=now + timedelta(seconds=3))
    outcome = store.outcome(plan.plan_id)
    assert outcome.state is HybridRunState.FAILED
    assert outcome.reason_code == "recovery_attempts_exhausted"
    assert outcome.cleanup_complete
    store.close()
    validation_store.close()


def test_hybrid_remediation_retest_requires_prior_confirmed_chain_and_new_version(
    tmp_path, approved_scope, candidate, now
):
    initial = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key="retest-initial:1",
    )
    service, store, validation_store, _, plan, proof = initial
    confirmed = service.execute(
        plan, candidate=candidate, deployment_proof=proof, scope=approved_scope, now=now
    ).chain
    assert confirmed is not None
    validation_store.close()

    repaired = candidate.model_copy(update={"target_version": "c" * 40})
    evidence_store = EvidenceStore(tmp_path / "retest-evidence")
    retest_store, validation_plan = _completed_validation(
        tmp_path,
        evidence_store,
        approved_scope,
        repaired,
        now,
        result=ValidationResult.NOT_REPRODUCED,
        key="retest:1",
    )
    retest_store, source_validation_plan = _completed_validation(
        tmp_path,
        evidence_store,
        approved_scope,
        repaired,
        now,
        result=ValidationResult.NOT_REPRODUCED,
        key="retest-source:1",
        store=retest_store,
        source_only=True,
    )
    _, source_validation = retest_store.load_completed(source_validation_plan.plan_id)
    repaired_proof, _ = _proof_and_source(
        evidence_store, repaired, now, live_target_id=proof.live_target_id
    )
    service = HybridValidationService(
        validation_store=retest_store,
        hybrid_store=store,
        evidence_store=evidence_store,
    )
    with pytest.raises(HybridValidationRejected, match="source Validation"):
        service.prepare(
            check_kind=HybridCheckKind.REMEDIATION_RETEST,
            candidate=repaired,
            deployment_proof=repaired_proof,
            validation_plan=validation_plan,
            source_manifest_digest=repaired_proof.source_manifest_digest,
            source_evidence_refs=source_validation.verdict.evidence_refs,
            scope=approved_scope,
            created_at=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="hybrid:retest:missing-source",
            prior_chain=confirmed,
        )
    retest_store, bad_source_plan = _completed_validation(
        tmp_path,
        evidence_store,
        approved_scope,
        repaired,
        now,
        result=ValidationResult.REPRODUCED,
        key="retest-source-still-reproduced:1",
        store=retest_store,
        source_only=True,
    )
    _, bad_source_validation = retest_store.load_completed(bad_source_plan.plan_id)
    bad_plan = service.prepare(
        check_kind=HybridCheckKind.REMEDIATION_RETEST,
        candidate=repaired,
        deployment_proof=repaired_proof,
        validation_plan=validation_plan,
        source_validation_plan=bad_source_plan,
        source_manifest_digest=repaired_proof.source_manifest_digest,
        source_evidence_refs=bad_source_validation.verdict.evidence_refs,
        scope=approved_scope,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="hybrid:retest:source-still-reproduced",
        prior_chain=confirmed,
    )
    with pytest.raises(HybridValidationRejected, match="source remediation"):
        service.execute(
            bad_plan,
            candidate=repaired,
            deployment_proof=repaired_proof,
            scope=approved_scope,
            now=now,
            prior_chain=confirmed,
        )
    assert store.state(bad_plan.plan_id) is None
    with pytest.raises(HybridValidationRejected, match="independent network-free"):
        service.prepare(
            check_kind=HybridCheckKind.REMEDIATION_RETEST,
            candidate=repaired,
            deployment_proof=repaired_proof,
            validation_plan=validation_plan,
            source_validation_plan=validation_plan,
            source_manifest_digest=repaired_proof.source_manifest_digest,
            source_evidence_refs=source_validation.verdict.evidence_refs,
            scope=approved_scope,
            created_at=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="hybrid:retest:shared-validation",
            prior_chain=confirmed,
        )
    plan = service.prepare(
        check_kind=HybridCheckKind.REMEDIATION_RETEST,
        candidate=repaired,
        deployment_proof=repaired_proof,
        validation_plan=validation_plan,
        source_validation_plan=source_validation_plan,
        source_manifest_digest=repaired_proof.source_manifest_digest,
        source_evidence_refs=source_validation.verdict.evidence_refs,
        scope=approved_scope,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="hybrid:retest:1",
        prior_chain=confirmed,
    )
    outcome = service.execute(
        plan,
        candidate=repaired,
        deployment_proof=repaired_proof,
        scope=approved_scope,
        now=now,
        prior_chain=confirmed,
    )
    assert outcome.chain is not None
    assert outcome.chain.conclusion is HybridConclusion.REMEDIATED
    assert outcome.chain.prior_chain_id == confirmed.chain_id
    assert outcome.source_remediation_proof is not None
    assert isinstance(outcome.source_remediation_proof, SourceRemediationProof)
    assert (
        outcome.chain.source_remediation_proof_id
        == outcome.source_remediation_proof.proof_id
    )
    assert outcome.source_remediation_proof.validation_plan_id == source_validation_plan.plan_id
    store.close()
    retest_store.close()


def test_hybrid_contracts_exclude_raw_endpoint_and_credentials():
    schemas = " ".join(
        json.dumps(model.model_json_schema()).lower()
        for model in (
            DeploymentProof,
            HybridValidationPlan,
            HybridValidationLimits,
            HybridEvidenceChain,
            HybridValidationOutcome,
            SourceRemediationProof,
            HybridFindingPromotionPlan,
            HybridReportPlan,
            HybridReportOutcome,
            HybridReleaseGatePolicy,
            HybridReleaseGatePlan,
            HybridReleaseGateResult,
            HybridReleaseGateOutcome,
            HybridCiGateResponse,
        )
    )
    for forbidden in (
        '"url"',
        "authorization",
        "cookie",
        "credential",
        "response_body",
        "api_key",
        "secret",
    ):
        assert forbidden not in schemas


def test_hybrid_release_gate_passes_only_authoritative_remediated_chain_and_replays(
    tmp_path, approved_scope, candidate, now
):
    service, release_store, hybrid_store, _, _, chain, proof = _remediated_runtime(
        tmp_path, approved_scope, candidate, now
    )
    plan = HybridReleaseGatePlan.create(
        chain=chain,
        deployment_proof=proof,
        scope=approved_scope,
        policy=HybridReleaseGatePolicy(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="release-gate:pass:1",
    )
    adapter = HybridCiGateAdapter(service)
    first = adapter.evaluate(plan, deployment_proof=proof, scope=approved_scope, now=now)
    replay = adapter.evaluate(
        plan,
        deployment_proof=proof,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )

    assert replay == first
    assert first.status is HybridCiGateStatus.PASS
    assert first.exit_code == 0
    outcome = release_store.outcome(plan.plan_id)
    assert outcome.state is HybridReleaseGateState.COMPLETED
    assert outcome.result is not None
    assert outcome.result.decision is HybridReleaseDecision.PASSED
    assert outcome.result.source_remediation_proof_id == chain.source_remediation_proof_id
    release_store.close()
    hybrid_store.close()


def test_hybrid_release_gate_blocks_confirmed_unremediated_chain(
    tmp_path, approved_scope, candidate, now
):
    service, release_store, hybrid_store, confirmed, proof, _, _ = _remediated_runtime(
        tmp_path, approved_scope, candidate, now
    )
    plan = HybridReleaseGatePlan.create(
        chain=confirmed,
        deployment_proof=proof,
        scope=approved_scope,
        policy=HybridReleaseGatePolicy(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="release-gate:block:1",
    )
    response = HybridCiGateAdapter(service).evaluate(
        plan, deployment_proof=proof, scope=approved_scope, now=now
    )

    assert response.status is HybridCiGateStatus.BLOCK
    assert response.exit_code == 1
    assert response.reason_codes == ("hybrid_remediation_required",)
    release_store.close()
    hybrid_store.close()


def test_hybrid_release_gate_rejects_drift_without_checkpoint_or_sensitive_output(
    tmp_path, approved_scope, candidate, now
):
    service, release_store, hybrid_store, _, _, chain, proof = _remediated_runtime(
        tmp_path, approved_scope, candidate, now
    )
    plan = HybridReleaseGatePlan.create(
        chain=chain,
        deployment_proof=proof,
        scope=approved_scope,
        policy=HybridReleaseGatePolicy(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="release-gate:drift:1",
    )
    drifted = proof.model_copy(update={"endpoint_url_digest": "f" * 64})
    response = HybridCiGateAdapter(service).evaluate(
        plan, deployment_proof=drifted, scope=approved_scope, now=now
    )

    assert response.status is HybridCiGateStatus.ERROR
    assert response.exit_code == 2
    assert response.reason_codes == ("release_gate_input_rejected",)
    assert release_store.state(plan.plan_id) is None
    encoded = response.model_dump_json().lower()
    assert URL not in encoded
    assert "authorization" not in encoded
    release_store.close()
    hybrid_store.close()


def test_hybrid_release_gate_timeout_closes_with_cleanup(
    tmp_path, approved_scope, candidate, now
):
    ticks = iter((0.0, 11.0))
    service, release_store, hybrid_store, _, _, chain, proof = _remediated_runtime(
        tmp_path, approved_scope, candidate, now, clock=lambda: next(ticks)
    )
    plan = HybridReleaseGatePlan.create(
        chain=chain,
        deployment_proof=proof,
        scope=approved_scope,
        policy=HybridReleaseGatePolicy(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="release-gate:timeout:1",
    )
    response = HybridCiGateAdapter(service).evaluate(
        plan, deployment_proof=proof, scope=approved_scope, now=now
    )

    assert response.status is HybridCiGateStatus.ERROR
    assert response.reason_codes == ("release_gate_budget_elapsed",)
    outcome = release_store.outcome(plan.plan_id)
    assert outcome.state is HybridReleaseGateState.TIMED_OUT
    assert outcome.cleanup_complete
    release_store.close()
    hybrid_store.close()


def test_hybrid_release_gate_requires_explicit_recovery_and_caps_attempts(
    tmp_path, approved_scope, candidate, now
):
    service, release_store, hybrid_store, _, _, chain, proof = _remediated_runtime(
        tmp_path, approved_scope, candidate, now
    )
    plan = HybridReleaseGatePlan.create(
        chain=chain,
        deployment_proof=proof,
        scope=approved_scope,
        policy=HybridReleaseGatePolicy(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="release-gate:recover:1",
    )
    release_store.claim(plan, now=now)
    blocked = HybridCiGateAdapter(service).evaluate(
        plan, deployment_proof=proof, scope=approved_scope, now=now
    )
    assert blocked.status is HybridCiGateStatus.ERROR
    assert blocked.reason_codes == ("release_gate_recovery_required",)
    recovered = service.evaluate(
        plan,
        deployment_proof=proof,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
        recover=True,
    )
    assert recovered.attempt == 2

    collision = plan.model_copy(update={"plan_id": "a" * 64})
    with pytest.raises(HybridReleaseGateConflict):
        release_store.claim(collision, now=now)

    exhausted_plan = HybridReleaseGatePlan.create(
        chain=chain,
        deployment_proof=proof,
        scope=approved_scope,
        policy=HybridReleaseGatePolicy(),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="release-gate:exhaust:1",
    )
    release_store.claim(exhausted_plan, now=now)
    release_store.recover(exhausted_plan, now=now + timedelta(seconds=1))
    release_store.recover(exhausted_plan, now=now + timedelta(seconds=2))
    with pytest.raises(HybridReleaseGateRecoveryRequired, match="exhausted"):
        release_store.recover(exhausted_plan, now=now + timedelta(seconds=3))
    exhausted = release_store.outcome(exhausted_plan.plan_id)
    assert exhausted.state is HybridReleaseGateState.FAILED
    assert exhausted.cleanup_complete
    release_store.close()
    hybrid_store.close()


def _evidence_catalog(chain):
    kinds = {
        **{ref: EvidenceKind.SOURCE for ref in chain.source_evidence_refs},
        chain.deployment_evidence_ref: EvidenceKind.TEST,
        **{ref: EvidenceKind.HTTP for ref in chain.http_evidence_refs},
    }
    return tuple(
        Evidence(
            evidence_id=ref,
            kind=kinds[ref],
            source_ref=f"redacted:{kind.value}",
            producer=f"test.hybrid.{kind.value}",
            target_version=chain.source_target_version,
            redaction_policy="default-v1",
            content_ref=f"objects/{ref}",
            summary=f"redacted {kind.value} evidence",
        )
        for ref, kind in kinds.items()
    )


def _hybrid_finding_runtime(tmp_path, approved_scope, candidate, now, *, key):
    runtime = _hybrid_runtime(
        tmp_path,
        approved_scope,
        candidate,
        now,
        result=ValidationResult.REPRODUCED,
        key=key,
    )
    hybrid_service, hybrid_store, validation_store, evidence_store, hybrid_plan, proof = runtime
    chain = hybrid_service.execute(
        hybrid_plan,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
    ).chain
    assert chain is not None
    _, validation = validation_store.load_completed(chain.validation_plan_id)
    assert validation.evidence_bundle is not None
    assessments = tuple(
        CounterevidenceAssessment(
            angle=angle,
            disposition=CounterevidenceDisposition.RULED_OUT,
            evidence_refs=(chain.evidence_bundle.evidence_refs[0],),
            rationale_code=f"hybrid_{angle.value}_ruled_out",
        )
        for angle in CounterevidenceAngle
    )
    critic_plan = CriticPlan.create(
        candidate_id=validation.candidate.candidate_id,
        candidate_digest=domain_object_digest(validation.candidate),
        validation_run_id=validation.validation_run.run_id,
        validation_run_digest=domain_object_digest(validation.validation_run),
        evidence_bundle_id=chain.evidence_bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(chain.evidence_bundle),
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        validation_context_id="7" * 64,
        review_context_id="8" * 64,
        validation_producer="hybrid.validator",
        review_producer="hybrid.critic",
        assessments=assessments,
        created_at=now + timedelta(seconds=1),
        deadline=now + timedelta(minutes=5),
        idempotency_key=f"critic:{key}",
    )
    critic_store = CriticStore(tmp_path / f"critic-{key.replace(':', '-')}.sqlite3")
    critic = DeterministicCritic(
        scope=approved_scope,
        evidence_store=evidence_store,
        store=critic_store,
    ).review(
        validation.candidate,
        validation.validation_run,
        chain.evidence_bundle,
        _evidence_catalog(chain),
        critic_plan,
        now=now + timedelta(seconds=2),
    )
    duplicate = FindingDuplicateCheck.create(
        candidate_id=critic.candidate.candidate_id,
        candidate_digest=domain_object_digest(critic.candidate),
        target_version_digest=canonical_digest(critic.candidate.target_version),
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        result=DuplicateCheckResult.CLEAR,
        duplicate_family_id=None,
        checked_by="operator:hybrid-reviewer",
        checked_at=now + timedelta(seconds=3),
        expires_at=now + timedelta(minutes=5),
    )
    finding_plan = HybridFindingPromotionPlan.create(
        hybrid_chain_id=chain.chain_id,
        hybrid_chain_digest=domain_object_digest(chain),
        critic_plan_id=critic.plan_id,
        critic_outcome_digest=domain_object_digest(critic),
        duplicate_check_id=duplicate.check_id,
        duplicate_check_digest=domain_object_digest(duplicate),
        candidate_id=critic.candidate.candidate_id,
        candidate_digest=domain_object_digest(critic.candidate),
        finding_id=uuid4(),
        root_cause="The deployed handler omits the required ownership predicate",
        affected_versions=(candidate.target_version,),
        impact="The exact authorized endpoint reproduces cross-tenant object access",
        severity_assessment={"rating": "high", "score": 8.0},
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        created_at=now + timedelta(seconds=3),
        deadline=now + timedelta(minutes=1),
        idempotency_key=f"finding:{key}",
    )
    approval = ApprovalRequest(
        engagement_id=approved_scope.engagement_id,
        target_id=candidate.target_id,
        action=ApprovalAction.MUTATE_TARGET_STATE,
        action_digest=hybrid_finding_approval_digest(finding_plan),
        expected_side_effects=HYBRID_FINDING_SIDE_EFFECTS,
        evidence_summary="Approve exact Hybrid Evidence Chain promotion",
        policy_version=approved_scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="operator:hybrid-approver",
        decided_at=now + timedelta(seconds=4),
    )
    finding_store = HybridFindingPromotionStore(
        tmp_path / f"hybrid-finding-{key.replace(':', '-')}.sqlite3"
    )
    service = HybridFindingPromotionService(
        scope=approved_scope,
        hybrid_store=hybrid_store,
        validation_store=validation_store,
        critic_store=critic_store,
        evidence_store=evidence_store,
        store=finding_store,
    )
    return (
        service,
        finding_store,
        hybrid_store,
        validation_store,
        critic_store,
        evidence_store,
        finding_plan,
        duplicate,
        approval,
        chain,
    )


def test_hybrid_finding_promotes_complete_chain_and_replays(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_finding_runtime(
        tmp_path, approved_scope, candidate, now, key="finding-success:1"
    )
    (
        service,
        store,
        hybrid_store,
        validation_store,
        critic_store,
        _,
        plan,
        duplicate,
        approval,
        chain,
    ) = runtime
    first = service.execute(
        plan=plan,
        duplicate_check=duplicate,
        approval=approval,
        now=now + timedelta(seconds=5),
    )
    replay = service.execute(
        plan=plan,
        duplicate_check=duplicate,
        approval=approval,
        now=now + timedelta(seconds=6),
    )
    assert replay == first
    assert first.state is HybridFindingState.COMPLETED
    assert first.finding is not None
    assert first.finding.evidence_bundle_id == chain.evidence_bundle.bundle_id
    assert first.promoted_candidate is not None
    assert first.promoted_candidate.state.value == "promoted"
    assert URL not in first.model_dump_json()
    store.close()
    hybrid_store.close()
    validation_store.close()
    critic_store.close()


def test_hybrid_finding_rejects_drift_denial_and_corrupt_evidence_before_checkpoint(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_finding_runtime(
        tmp_path, approved_scope, candidate, now, key="finding-reject:1"
    )
    (
        service,
        store,
        hybrid_store,
        validation_store,
        critic_store,
        evidence_store,
        plan,
        duplicate,
        approval,
        chain,
    ) = runtime
    with pytest.raises(HybridFindingPromotionRejected, match="provenance"):
        service.execute(
            plan=plan.model_copy(update={"hybrid_chain_digest": "f" * 64}),
            duplicate_check=duplicate,
            approval=approval,
            now=now + timedelta(seconds=5),
        )
    with pytest.raises(HybridFindingPromotionRejected, match="Approval"):
        service.execute(
            plan=plan,
            duplicate_check=duplicate,
            approval=approval.model_copy(update={"status": ApprovalStatus.DENIED}),
            now=now + timedelta(seconds=5),
        )
    (evidence_store.objects / chain.http_evidence_refs[0]).unlink()
    with pytest.raises(HybridFindingPromotionRejected, match="integrity"):
        service.execute(
            plan=plan,
            duplicate_check=duplicate,
            approval=approval,
            now=now + timedelta(seconds=5),
        )
    assert store.state(plan.plan_id) is None
    store.close()
    hybrid_store.close()
    validation_store.close()
    critic_store.close()


def test_hybrid_finding_timeout_cleanup_recovery_and_collision(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_finding_runtime(
        tmp_path, approved_scope, candidate, now, key="finding-timeout:1"
    )
    (
        service,
        store,
        hybrid_store,
        validation_store,
        critic_store,
        _,
        plan,
        duplicate,
        approval,
        _,
    ) = runtime
    timed_out = service.execute(
        plan=plan,
        duplicate_check=duplicate,
        approval=approval,
        now=now + timedelta(minutes=2),
    )
    assert timed_out.state is HybridFindingState.TIMED_OUT
    assert timed_out.cleanup_complete and timed_out.finding is None
    store.close()
    hybrid_store.close()
    validation_store.close()
    critic_store.close()

    runtime = _hybrid_finding_runtime(
        tmp_path, approved_scope, candidate, now, key="finding-recover:1"
    )
    (
        service,
        store,
        hybrid_store,
        validation_store,
        critic_store,
        _,
        plan,
        duplicate,
        approval,
        _,
    ) = runtime
    approval_digest = domain_object_digest(approval)
    store.claim(
        plan,
        approval_id=approval.approval_id,
        approval_digest=approval_digest,
        now=now + timedelta(seconds=5),
    )
    with pytest.raises(HybridFindingRecoveryRequired):
        service.execute(
            plan=plan,
            duplicate_check=duplicate,
            approval=approval,
            now=now + timedelta(seconds=5),
        )
    recovered = service.execute(
        plan=plan,
        duplicate_check=duplicate,
        approval=approval,
        now=now + timedelta(seconds=5),
        recover=True,
    )
    assert recovered.state is HybridFindingState.COMPLETED
    assert recovered.attempt == 2
    collision = plan.model_copy(update={"plan_id": "a" * 64, "finding_id": uuid4()})
    with pytest.raises(HybridFindingConflict):
        store.claim(
            collision,
            approval_id=approval.approval_id,
            approval_digest=approval_digest,
            now=now + timedelta(seconds=6),
        )
    store.close()
    hybrid_store.close()
    validation_store.close()
    critic_store.close()


def test_hybrid_finding_recovery_exhaustion_closes_with_cleanup(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_finding_runtime(
        tmp_path, approved_scope, candidate, now, key="finding-exhaust:1"
    )
    _, store, hybrid_store, validation_store, critic_store, _, plan, _, approval, _ = runtime
    approval_digest = domain_object_digest(approval)
    claim_args = {
        "approval_id": approval.approval_id,
        "approval_digest": approval_digest,
    }
    store.claim(plan, now=now + timedelta(seconds=5), **claim_args)
    store.recover(plan, now=now + timedelta(seconds=6), **claim_args)
    store.recover(plan, now=now + timedelta(seconds=7), **claim_args)
    with pytest.raises(HybridFindingRecoveryRequired, match="exhausted"):
        store.recover(plan, now=now + timedelta(seconds=8), **claim_args)
    outcome = store.outcome(plan.plan_id)
    assert outcome.state is HybridFindingState.FAILED
    assert outcome.reason_code == "recovery_attempts_exhausted"
    assert outcome.cleanup_complete
    store.close()
    hybrid_store.close()
    validation_store.close()
    critic_store.close()


def _hybrid_report_plans(
    *, approved_scope, finding_outcome, chain, sections, now, key
):
    assert finding_outcome.finding is not None
    assert finding_outcome.promoted_candidate is not None
    report_plan = ReportDraftPlan.create(
        finding_id=finding_outcome.finding.finding_id,
        finding_digest=domain_object_digest(finding_outcome.finding),
        candidate_id=finding_outcome.promoted_candidate.candidate_id,
        candidate_digest=domain_object_digest(finding_outcome.promoted_candidate),
        evidence_bundle_id=chain.evidence_bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(chain.evidence_bundle),
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        channel=ReportChannel.GENERIC,
        title="Authorized Hybrid Finding",
        sections=sections,
        prepared_by="hybrid.reporter",
        created_at=now + timedelta(seconds=6),
        deadline=now + timedelta(minutes=5),
        idempotency_key=f"report:{key}",
    )
    hybrid_plan = HybridReportPlan.create(
        hybrid_finding_plan_id=finding_outcome.plan_id,
        hybrid_finding_outcome_digest=domain_object_digest(finding_outcome),
        hybrid_chain_id=chain.chain_id,
        hybrid_chain_digest=domain_object_digest(chain),
        report_draft_plan_id=report_plan.plan_id,
        report_draft_plan_digest=report_draft_plan_digest(report_plan),
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        created_at=now + timedelta(seconds=6),
        deadline=now + timedelta(minutes=1),
        idempotency_key=f"hybrid-report:{key}",
    )
    return report_plan, hybrid_plan


def _hybrid_report_runtime(tmp_path, approved_scope, candidate, now, *, key):
    finding_runtime = _hybrid_finding_runtime(
        tmp_path, approved_scope, candidate, now, key=key
    )
    (
        finding_service,
        finding_store,
        hybrid_store,
        validation_store,
        critic_store,
        evidence_store,
        finding_plan,
        duplicate,
        approval,
        chain,
    ) = finding_runtime
    finding_outcome = finding_service.execute(
        plan=finding_plan,
        duplicate_check=duplicate,
        approval=approval,
        now=now + timedelta(seconds=5),
    )
    sections = (
        ReportSection(
            kind=ReportSectionKind.SUMMARY,
            text="Source and live validation confirm the same authorization flaw",
        ),
        ReportSection(
            kind=ReportSectionKind.CODE_LOCATION,
            text="The source handler omits the ownership predicate",
            evidence_refs=(chain.source_evidence_refs[0],),
        ),
        ReportSection(
            kind=ReportSectionKind.REQUEST_RESPONSE,
            text="The exact authorized endpoint reproduced the unsafe behavior",
            evidence_refs=(chain.http_evidence_refs[0],),
        ),
        ReportSection(
            kind=ReportSectionKind.REPRODUCTION,
            text="Confirm the deployed build and replay the bounded validation",
            evidence_refs=(
                chain.deployment_evidence_ref,
                chain.http_evidence_refs[0],
            ),
        ),
        ReportSection(
            kind=ReportSectionKind.IMPACT,
            text="The live observation demonstrates cross-tenant data access",
            evidence_refs=(chain.http_evidence_refs[0],),
        ),
        ReportSection(
            kind=ReportSectionKind.REMEDIATION,
            text="Enforce ownership in the handler and repeat source and live validation",
        ),
    )
    report_plan, hybrid_plan = _hybrid_report_plans(
        approved_scope=approved_scope,
        finding_outcome=finding_outcome,
        chain=chain,
        sections=sections,
        now=now,
        key=key,
    )
    report_store = ReportDraftStore(tmp_path / f"report-{key.replace(':', '-')}.sqlite3")
    artifact_store = ReportArtifactStore(
        tmp_path / f"report-artifacts-{key.replace(':', '-')}"
    )
    report_service = DeterministicReportService(
        scope=approved_scope,
        evidence_store=evidence_store,
        store=report_store,
        artifact_store=artifact_store,
    )
    hybrid_report_store = HybridReportStore(
        tmp_path / f"hybrid-report-{key.replace(':', '-')}.sqlite3"
    )
    service = HybridReportService(
        scope=approved_scope,
        hybrid_store=hybrid_store,
        finding_store=finding_store,
        report_service=report_service,
        store=hybrid_report_store,
    )
    return {
        "service": service,
        "store": hybrid_report_store,
        "report_store": report_store,
        "artifact_store": artifact_store,
        "finding_store": finding_store,
        "hybrid_store": hybrid_store,
        "validation_store": validation_store,
        "critic_store": critic_store,
        "evidence_store": evidence_store,
        "report_plan": report_plan,
        "hybrid_plan": hybrid_plan,
        "evidence": _evidence_catalog(chain),
        "finding_outcome": finding_outcome,
        "chain": chain,
    }


def _close_hybrid_report_runtime(runtime):
    runtime["store"].close()
    runtime["report_store"].close()
    runtime["finding_store"].close()
    runtime["hybrid_store"].close()
    runtime["validation_store"].close()
    runtime["critic_store"].close()


def test_hybrid_report_drafts_all_evidence_partitions_and_replays(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_report_runtime(
        tmp_path, approved_scope, candidate, now, key="report-success:1"
    )
    first = runtime["service"].execute(
        plan=runtime["hybrid_plan"],
        report_plan=runtime["report_plan"],
        evidence=runtime["evidence"],
        now=now + timedelta(seconds=7),
    )
    replay = runtime["service"].execute(
        plan=runtime["hybrid_plan"],
        report_plan=runtime["report_plan"],
        evidence=runtime["evidence"],
        now=now + timedelta(seconds=8),
    )
    assert replay == first
    assert first.state is HybridReportState.COMPLETED
    assert first.report_outcome is not None
    assert (
        first.report_outcome.report.evidence_bundle_id
        == runtime["chain"].evidence_bundle.bundle_id
    )
    assert first.report_outcome.report.review_status.value == "draft"
    assert URL not in first.model_dump_json()
    markdown = runtime["artifact_store"].read_markdown(first.report_outcome.artifact)
    assert "Source and live validation" in markdown
    _close_hybrid_report_runtime(runtime)


def test_hybrid_report_rejects_missing_partition_drift_and_corrupt_evidence(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_report_runtime(
        tmp_path, approved_scope, candidate, now, key="report-reject:1"
    )
    chain = runtime["chain"]
    bad_sections = tuple(
        section.model_copy(update={"evidence_refs": (chain.http_evidence_refs[0],)})
        if section.kind is ReportSectionKind.REPRODUCTION
        else section
        for section in runtime["report_plan"].sections
    )
    bad_report_plan, bad_hybrid_plan = _hybrid_report_plans(
        approved_scope=approved_scope,
        finding_outcome=runtime["finding_outcome"],
        chain=chain,
        sections=bad_sections,
        now=now,
        key="report-reject:missing-deployment",
    )
    with pytest.raises(HybridReportRejected, match="do not cover"):
        runtime["service"].execute(
            plan=bad_hybrid_plan,
            report_plan=bad_report_plan,
            evidence=runtime["evidence"],
            now=now + timedelta(seconds=7),
        )
    with pytest.raises(HybridReportRejected, match="input unavailable|provenance"):
        runtime["service"].execute(
            plan=runtime["hybrid_plan"].model_copy(
                update={"hybrid_chain_digest": "f" * 64}
            ),
            report_plan=runtime["report_plan"],
            evidence=runtime["evidence"],
            now=now + timedelta(seconds=7),
        )
    endpoint_sections = tuple(
        section.model_copy(update={"text": f"Unsafe endpoint: {URL}"})
        if section.kind is ReportSectionKind.SUMMARY
        else section
        for section in runtime["report_plan"].sections
    )
    endpoint_report_plan, endpoint_hybrid_plan = _hybrid_report_plans(
        approved_scope=approved_scope,
        finding_outcome=runtime["finding_outcome"],
        chain=chain,
        sections=endpoint_sections,
        now=now,
        key="report-reject:endpoint",
    )
    with pytest.raises(HybridReportRejected, match="full endpoint"):
        runtime["service"].execute(
            plan=endpoint_hybrid_plan,
            report_plan=endpoint_report_plan,
            evidence=runtime["evidence"],
            now=now + timedelta(seconds=7),
        )
    damaged = chain.http_evidence_refs[0]
    (runtime["evidence_store"].objects / damaged).unlink()
    with pytest.raises(HybridReportRejected, match="shared Report"):
        runtime["service"].execute(
            plan=runtime["hybrid_plan"],
            report_plan=runtime["report_plan"],
            evidence=runtime["evidence"],
            now=now + timedelta(seconds=7),
        )
    assert runtime["store"].state(runtime["hybrid_plan"].plan_id) is None
    assert not runtime["report_store"].has_checkpoint(runtime["report_plan"].plan_id)
    _close_hybrid_report_runtime(runtime)


def test_hybrid_report_timeout_cleanup_recovery_and_collision(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_report_runtime(
        tmp_path, approved_scope, candidate, now, key="report-timeout:1"
    )
    timed_out = runtime["service"].execute(
        plan=runtime["hybrid_plan"],
        report_plan=runtime["report_plan"],
        evidence=runtime["evidence"],
        now=now + timedelta(minutes=2),
    )
    assert timed_out.state is HybridReportState.TIMED_OUT
    assert timed_out.cleanup_complete and timed_out.report_outcome is None
    assert not runtime["report_store"].has_checkpoint(runtime["report_plan"].plan_id)
    assert not any(runtime["artifact_store"].objects.iterdir())
    _close_hybrid_report_runtime(runtime)

    runtime = _hybrid_report_runtime(
        tmp_path, approved_scope, candidate, now, key="report-recover:1"
    )
    runtime["store"].claim(runtime["hybrid_plan"], now=now + timedelta(seconds=7))
    with pytest.raises(HybridReportRecoveryRequired):
        runtime["service"].execute(
            plan=runtime["hybrid_plan"],
            report_plan=runtime["report_plan"],
            evidence=runtime["evidence"],
            now=now + timedelta(seconds=7),
        )
    recovered = runtime["service"].execute(
        plan=runtime["hybrid_plan"],
        report_plan=runtime["report_plan"],
        evidence=runtime["evidence"],
        now=now + timedelta(seconds=7),
        recover=True,
    )
    assert recovered.state is HybridReportState.COMPLETED
    assert recovered.attempt == 2
    collision = runtime["hybrid_plan"].model_copy(
        update={"plan_id": "a" * 64, "report_draft_plan_id": "b" * 64}
    )
    with pytest.raises(HybridReportConflict):
        runtime["store"].claim(collision, now=now + timedelta(seconds=8))
    _close_hybrid_report_runtime(runtime)


def test_hybrid_report_recovery_exhaustion_closes_with_cleanup(
    tmp_path, approved_scope, candidate, now
):
    runtime = _hybrid_report_runtime(
        tmp_path, approved_scope, candidate, now, key="report-exhaust:1"
    )
    plan = runtime["hybrid_plan"]
    runtime["store"].claim(plan, now=now + timedelta(seconds=7))
    runtime["store"].recover(plan, now=now + timedelta(seconds=8))
    runtime["store"].recover(plan, now=now + timedelta(seconds=9))
    with pytest.raises(HybridReportRecoveryRequired, match="exhausted"):
        runtime["store"].recover(plan, now=now + timedelta(seconds=10))
    outcome = runtime["store"].outcome(plan.plan_id)
    assert outcome.state is HybridReportState.FAILED
    assert outcome.cleanup_complete
    _close_hybrid_report_runtime(runtime)
