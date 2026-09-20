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
    ValidationResult,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.findings import DuplicateCheckResult, FindingDuplicateCheck
from vulnloom.hybrid import (
    HYBRID_FINDING_SIDE_EFFECTS,
    DeploymentProof,
    HybridCheckKind,
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
    HybridRunState,
    HybridValidationLimits,
    HybridValidationOutcome,
    HybridValidationPlan,
    HybridValidationRejected,
    HybridValidationService,
    HybridValidationStore,
    hybrid_finding_approval_digest,
)
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    NetworkGrant,
    OfflineSandboxRunner,
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


def _validation_plan(now, scope, candidate, *, key):
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
        broker_calls=(call,),
        idempotency_key=key,
    )


def _completed_validation(tmp_path, evidence_store, scope, candidate, now, *, result, key):
    http = evidence_store.capture_text(
        "redacted HTTP validation facts",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + url_digest(URL),
        producer="test.hybrid.http",
        target_version=candidate.target_version,
        summary="redacted exact endpoint result",
    )
    plan = _validation_plan(now, scope, candidate, key=key)
    transport = OfflineHttpTransport(
        {
            URL: OfflineHttpHop(
                status_code=200,
                peer_ip=IP,
                response_bytes=32,
                response_body_sha256=BODY,
                evidence_ref=http.evidence_id,
            )
        }
    )
    broker = ToolBroker(
        scope=scope,
        registry=default_tool_registry(),
        resolver=StaticResolver({"app.example.test": (IP,)}),
        http_transport=transport,
    )
    store = ValidationStore(tmp_path / f"{key.replace(':', '-')}.sqlite3")
    service = ValidationService(
        scope=scope,
        runner=OfflineSandboxRunner(frozenset({"sandbox.test"})),
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
    repaired_proof, source_ref = _proof_and_source(
        evidence_store, repaired, now, live_target_id=proof.live_target_id
    )
    service = HybridValidationService(
        validation_store=retest_store,
        hybrid_store=store,
        evidence_store=evidence_store,
    )
    plan = service.prepare(
        check_kind=HybridCheckKind.REMEDIATION_RETEST,
        candidate=repaired,
        deployment_proof=repaired_proof,
        validation_plan=validation_plan,
        source_manifest_digest=repaired_proof.source_manifest_digest,
        source_evidence_refs=(source_ref,),
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
            HybridFindingPromotionPlan,
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
