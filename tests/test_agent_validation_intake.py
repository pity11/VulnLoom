from __future__ import annotations

import json
import os
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.agent_runtime import (
    AgentSessionAuditArtifactStore,
    AgentSessionAuditBundle,
    AgentSessionBudgetLedger,
    AgentSessionCleanup,
    AgentSessionRecommendation,
    AgentSessionRecommendationDisposition,
    AgentSessionRecommendationReason,
    agent_session_audit_bundle_digest,
)
from vulnloom.broker import (
    BrokerCall,
    HttpRequestPlan,
    OfflineHttpTransport,
    StaticResolver,
    ToolBroker,
    default_tool_registry,
)
from vulnloom.critic import (
    REQUIRED_ANGLES,
    AgentCriticIntakeCommand,
    AgentCriticIntakeDecision,
    AgentCriticIntakePlan,
    AgentCriticIntakeReason,
    AgentCriticIntakeRecord,
    AgentCriticIntakeRecoveryRequired,
    AgentCriticIntakeRejected,
    AgentCriticIntakeService,
    AgentCriticIntakeStore,
    AgentCriticOutcomeBinding,
    AgentCriticOutcomeBindingPlan,
    AgentCriticOutcomeBindingRecoveryRequired,
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
    CandidateState,
    CriticVerdict,
    EvidenceBundle,
    EvidenceKind,
    ReportChannel,
    ReportSection,
    ReportSectionKind,
    ValidationResult,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.findings import (
    AgentFindingIntakeCommand,
    AgentFindingIntakeConflict,
    AgentFindingIntakeDecision,
    AgentFindingIntakePlan,
    AgentFindingIntakeReason,
    AgentFindingIntakeRecord,
    AgentFindingIntakeRecoveryRequired,
    AgentFindingIntakeRejected,
    AgentFindingIntakeService,
    AgentFindingIntakeStore,
    AgentFindingIntakeTimedOut,
    DuplicateCheckResult,
    FindingDuplicateCheck,
    FindingDuplicateCheckStore,
    FindingPromotionConflict,
    FindingPromotionExecutionPlan,
    FindingPromotionPlan,
    FindingPromotionRecoveryRequired,
    FindingPromotionRejected,
    FindingPromotionService,
    FindingPromotionStore,
    FindingPromotionTimedOut,
    agent_finding_intake_plan_digest,
)
from vulnloom.hypotheses import CandidateSet, CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.policy import PolicyEngine
from vulnloom.reporting import (
    AgentReportDraftExecutionConflict,
    AgentReportDraftExecutionPlan,
    AgentReportDraftExecutionRecoveryRequired,
    AgentReportDraftExecutionRejected,
    AgentReportDraftExecutionService,
    AgentReportDraftExecutionStore,
    AgentReportDraftExecutionTimedOut,
    AgentReportDraftOutcomeBinding,
    AgentReportIntakeCommand,
    AgentReportIntakeConflict,
    AgentReportIntakeDecision,
    AgentReportIntakePlan,
    AgentReportIntakeReason,
    AgentReportIntakeRecord,
    AgentReportIntakeRecoveryRequired,
    AgentReportIntakeRejected,
    AgentReportIntakeService,
    AgentReportIntakeStore,
    AgentReportIntakeTimedOut,
    AgentReportReviewIntakeCommand,
    AgentReportReviewIntakeConflict,
    AgentReportReviewIntakeDecision,
    AgentReportReviewIntakePlan,
    AgentReportReviewIntakeReason,
    AgentReportReviewIntakeRecord,
    AgentReportReviewIntakeRecoveryRequired,
    AgentReportReviewIntakeRejected,
    AgentReportReviewIntakeService,
    AgentReportReviewIntakeStore,
    AgentReportReviewIntakeTimedOut,
    DeterministicReportService,
    ReportArtifactStore,
    ReportDraftPlan,
    ReportDraftStore,
    ReportReviewPlan,
    agent_report_intake_plan_digest,
    agent_report_review_intake_plan_digest,
)
from vulnloom.runners import (
    NetworkGrant,
    OfflineSandboxRunner,
    OfflineScenario,
    ToolInvocation,
    validation_profile,
)
from vulnloom.runners.models import SandboxRunRequest, sandbox_profile_digest
from vulnloom.validation import (
    AgentValidationIntakeCommand,
    AgentValidationIntakeDecision,
    AgentValidationIntakePlan,
    AgentValidationIntakeReason,
    AgentValidationIntakeRecord,
    AgentValidationIntakeRecoveryRequired,
    AgentValidationIntakeRejected,
    AgentValidationIntakeService,
    AgentValidationIntakeStore,
    AgentValidationIntakeTimedOut,
    AgentValidationOutcomeBinding,
    AgentValidationOutcomeBindingConflict,
    AgentValidationOutcomeBindingPlan,
    AgentValidationOutcomeBindingRecoveryRequired,
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


def _candidate_set(candidate):
    partial = CandidateSet(
        candidate_set_id="0" * 64,
        source_graph_id=candidate.source_graph_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=candidate.scope_id,
        scope_version=candidate.scope_version,
        generator_version="m8.1-test",
        candidates=(candidate,),
    )
    return partial.model_copy(update={"candidate_set_id": candidate_set_digest(partial)})


def _validation_plan(now, scope, candidate, *, key="validation:m8.1"):
    profile = validation_profile(
        image_digest="sha256:" + "1" * 64,
        snapshot_id="2" * 64,
    )
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest="3" * 64,
        input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
        allowed_tools=profile.allowed_tools,
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(minutes=5),
        idempotency_key=f"{key}:task",
    )
    request = SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(tool_id="sandbox.test", working_directory="source"),
        environment={},
        idempotency_key=f"{key}:runner",
    )
    return ValidationPlan.create(
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate_content_digest(candidate),
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        selected_by="trusted-control-plane",
        selected_at=now,
        selection_reason="Exact local non-executing M8.1 fixture",
        runner_request=request,
        idempotency_key=key,
    )


def _audit_bundle(now, scope, candidate, *, completed=True):
    budget = AgentSessionBudgetLedger(
        original_model_tokens=100,
        original_tool_calls=2,
        consumed_model_tokens=20,
        remaining_model_tokens=80,
        consumed_agent_steps=2,
        consumed_tool_calls=1,
        remaining_tool_calls=1,
        provider_attempts=2,
        broker_attempts=1,
        remaining_wall_seconds=30,
    )
    evidence = ("4" * 64,)
    recommendation_values = {
        "session_id": "5" * 64,
        "disposition": (
            AgentSessionRecommendationDisposition.COMPLETED
            if completed
            else AgentSessionRecommendationDisposition.BLOCKED
        ),
        "reason_code": (
            AgentSessionRecommendationReason.SESSION_COMPLETED
            if completed
            else AgentSessionRecommendationReason.AGENT_BLOCKED
        ),
        "evidence_refs": evidence,
        "budget_digest": canonical_digest(budget.model_dump(mode="python")),
        "projected_at": now,
    }
    recommendation = AgentSessionRecommendation(
        recommendation_id=canonical_digest(recommendation_values),
        **recommendation_values,
    )
    cleanup = AgentSessionCleanup(
        evidence_buffers_released=True,
        context_reverified=True,
        raw_provider_responses_absent=True,
        broker_authorization_enforced=True,
        no_vulnloom_domain_state_changed=True,
    )
    values = {
        "audit_plan_id": "6" * 64,
        "session_id": "5" * 64,
        "session_plan_digest": "7" * 64,
        "session_outcome_id": "8" * 64,
        "session_outcome_digest": "9" * 64,
        "target_id": candidate.target_id,
        "target_version_digest": canonical_digest(candidate.target_version),
        "scope_id": scope.scope_id,
        "scope_version": scope.version,
        "root_plan_id": "a" * 64,
        "root_outcome_digest": "b" * 64,
        "first_handoff_id": "c" * 64,
        "first_handoff_outcome_digest": "d" * 64,
        "round_plan_id": "e" * 64,
        "round_outcome_digest": "f" * 64,
        "authorized_call_set_id": "1" * 64,
        "observation_ids": ("2" * 64,),
        "evidence_refs": evidence,
        "budget": budget,
        "cleanup": cleanup,
        "recommendation": recommendation,
        "completed_at": now,
    }
    partial = AgentSessionAuditBundle.model_construct(bundle_id="0" * 64, **values)
    return AgentSessionAuditBundle(bundle_id=agent_session_audit_bundle_digest(partial), **values)


def _fixture(tmp_path, now, scope, candidate, *, completed=True, validation_plan=None):
    candidate_set = _candidate_set(candidate)
    candidate_store = CandidateSetStore(tmp_path / "candidates")
    candidate_store.put(candidate_set)
    artifact_store = AgentSessionAuditArtifactStore(tmp_path / "audits")
    artifact = artifact_store.put(
        _audit_bundle(now - timedelta(seconds=1), scope, candidate, completed=completed)
    )
    store = AgentValidationIntakeStore(tmp_path / "intake.sqlite3")
    service = AgentValidationIntakeService(
        scope=scope,
        audit_artifact_store=artifact_store,
        candidate_set_store=candidate_store,
        store=store,
    )
    validation_plan = validation_plan or _validation_plan(now, scope, candidate)
    intake_plan = service.prepare(
        audit_artifact=artifact,
        candidate_set_id=candidate_set.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now,
        decision_deadline=now + timedelta(minutes=2),
        idempotency_key="intake:m8.1",
    )
    return service, store, artifact, validation_plan, intake_plan


def _command(plan, now, decision):
    reason = {
        AgentValidationIntakeDecision.ACCEPT: AgentValidationIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
        AgentValidationIntakeDecision.REJECT: AgentValidationIntakeReason.HUMAN_REJECTED,
        AgentValidationIntakeDecision.DEFER: AgentValidationIntakeReason.HUMAN_DEFERRED,
    }[decision]
    return AgentValidationIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_validation_intake_plan_digest(plan),
        audit_bundle_id=plan.audit_bundle_id,
        candidate_id=plan.candidate_id,
        candidate_digest=plan.candidate_digest,
        validation_plan_id=plan.validation_plan_id,
        validation_plan_digest=plan.validation_plan_digest,
        decision=decision,
        reason_code=reason,
        reviewer="human-reviewer",
        decided_at=now,
    )


def _validation_plan_with_approval_gate(now, scope, candidate):
    base = _validation_plan(now, scope, candidate, key="validation:m8.2-policy")
    profile = validation_profile(
        image_digest="sha256:" + "1" * 64,
        snapshot_id="2" * 64,
        network_grants=(
            NetworkGrant(
                host="app.example.test",
                ports=frozenset({443}),
                schemes=frozenset({"https"}),
            ),
        ),
    )
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=default_tool_registry().digest,
        input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
        allowed_tools=frozenset({"http.request"}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(minutes=5),
        idempotency_key="validation:m8.2-policy:broker-task",
    )
    call = BrokerCall(
        task=task,
        profile=profile,
        tool_id="http.request",
        http=HttpRequestPlan(
            method="POST",
            url="https://app.example.test/items/7",
            test_class="idor",
        ),
        idempotency_key="validation:m8.2-policy:broker",
    )
    return ValidationPlan.create(
        candidate_id=base.candidate_id,
        candidate_digest=base.candidate_digest,
        target_id=base.target_id,
        target_version=base.target_version,
        scope_id=base.scope_id,
        scope_version=base.scope_version,
        selected_by=base.selected_by,
        selected_at=base.selected_at,
        selection_reason=base.selection_reason,
        runner_request=base.runner_request,
        broker_calls=(call,),
        idempotency_key="validation:m8.2-policy",
    )


class _CountingScenarioRunner:
    def __init__(self, scenario=None):
        self.delegate = OfflineSandboxRunner(frozenset({"sandbox.test"}))
        self.scenario = scenario
        self.calls = 0

    def execute(self, request, *, now):
        self.calls += 1
        return self.delegate.execute(request, now=now, scenario=self.scenario)


class _FixedResultJudge:
    def __init__(self, result):
        self.result = result

    def evaluate(self, *, evidence_refs, **_):
        return ValidationVerdict(
            result=self.result,
            rationale_code=f"m8_2_{self.result.value}",
            evidence_refs=evidence_refs,
        )


def _completed_binding_case(
    tmp_path,
    now,
    scope,
    candidate,
    result,
    *,
    decision=AgentValidationIntakeDecision.ACCEPT,
):
    validation_plan = (
        _validation_plan_with_approval_gate(now, scope, candidate)
        if result is ValidationResult.POLICY_STOPPED
        else _validation_plan(now, scope, candidate, key=f"validation:m8.2:{result.value}")
    )
    intake_service, intake_store, artifact, validation_plan, intake_plan = _fixture(
        tmp_path,
        now,
        scope,
        candidate,
        validation_plan=validation_plan,
    )
    command = _command(intake_plan, now + timedelta(seconds=1), decision)
    intake_record = intake_service.decide(
        intake_plan,
        command,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=command.decided_at,
    )
    evidence_store = EvidenceStore(tmp_path / "validation-evidence")
    evidence_refs = ()
    if result is ValidationResult.REPRODUCED:
        evidence = evidence_store.capture_text(
            "redacted M8.2 deterministic fixture",
            kind=EvidenceKind.TEST,
            source_ref="m8.2-local-fixture",
            producer="test.m8.2",
            target_version=candidate.target_version,
            summary="M8.2 deterministic fixture",
        )
        evidence_refs = (evidence.evidence_id,)
    scenario = OfflineScenario(
        wall_seconds=120 if result is ValidationResult.TIMED_OUT else 0.01,
        evidence_refs=evidence_refs,
    )
    runner = _CountingScenarioRunner(scenario)
    transport = OfflineHttpTransport({})
    broker = ToolBroker(
        scope=scope,
        registry=default_tool_registry(),
        resolver=StaticResolver({"app.example.test": ("192.0.2.10",)}),
        http_transport=transport,
    )
    judge = (
        _FixedResultJudge(result)
        if result in {ValidationResult.REPRODUCED, ValidationResult.NOT_REPRODUCED}
        else None
    )
    validation_store = ValidationStore(tmp_path / "validation.sqlite3")
    outcome = ValidationService(
        scope=scope,
        runner=runner,
        broker=broker,
        store=validation_store,
        evidence_store=evidence_store,
        judge=judge,
    ).execute(candidate, validation_plan, now=now + timedelta(seconds=2))
    binding_store = AgentValidationOutcomeBindingStore(tmp_path / "bindings.sqlite3")
    binding_service = AgentValidationOutcomeBindingService(
        scope=scope,
        audit_store=intake_service.audit_artifact_store,
        candidate_store=intake_service.candidate_set_store,
        intake_store=intake_store,
        validation_store=validation_store,
        evidence_store=evidence_store,
        binding_store=binding_store,
    )
    return (
        intake_service,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        outcome,
        evidence_store,
        binding_store,
        binding_service,
        runner,
        transport,
    )


@pytest.mark.parametrize("decision", tuple(AgentValidationIntakeDecision))
def test_intake_records_human_decision_without_execution_or_state_change(
    tmp_path, now, approved_scope, candidate, decision
):
    service, store, artifact, validation_plan, plan = _fixture(
        tmp_path, now, approved_scope, candidate
    )
    command = _command(plan, now + timedelta(seconds=1), decision)

    record = service.decide(
        plan,
        command,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=command.decided_at,
    )
    replay = service.decide(
        plan,
        command,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=command.decided_at,
    )

    assert replay == record
    assert record.decision is decision
    assert store.load_completed(plan.intake_plan_id) == record
    assert candidate.state.value == "proposed"
    assert not hasattr(service, "runner")
    assert not hasattr(service, "broker")
    assert (
        store.connection.execute("SELECT state FROM agent_validation_intakes").fetchone()[0]
        == "completed"
    )
    store.close()


def test_completed_validation_is_bound_read_only_after_accepted_intake(
    tmp_path, now, approved_scope, candidate
):
    service, intake_store, artifact, validation_plan, intake_plan = _fixture(
        tmp_path, now, approved_scope, candidate
    )
    command = _command(
        intake_plan, now + timedelta(seconds=1), AgentValidationIntakeDecision.ACCEPT
    )
    record = service.decide(
        intake_plan,
        command,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=command.decided_at,
    )
    validation_store = ValidationStore(tmp_path / "validation.sqlite3")
    evidence_store = EvidenceStore(tmp_path / "validation-evidence")
    outcome = ValidationService(
        scope=approved_scope,
        runner=OfflineSandboxRunner(frozenset({"sandbox.test"})),
        broker=ToolBroker(
            scope=approved_scope,
            registry=default_tool_registry(),
            resolver=StaticResolver({}),
            http_transport=OfflineHttpTransport({}),
        ),
        store=validation_store,
        evidence_store=evidence_store,
    ).execute(candidate, validation_plan, now=now + timedelta(seconds=2))
    binding_store = AgentValidationOutcomeBindingStore(tmp_path / "bindings.sqlite3")
    binding_service = AgentValidationOutcomeBindingService(
        scope=approved_scope,
        audit_store=service.audit_artifact_store,
        candidate_store=service.candidate_set_store,
        intake_store=intake_store,
        validation_store=validation_store,
        evidence_store=evidence_store,
        binding_store=binding_store,
    )
    plan = binding_service.prepare(
        intake_plan_id=intake_plan.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_plan.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key="binding:m8.2",
    )
    expired = plan.model_copy(update={"deadline": now + timedelta(seconds=3)})
    with pytest.raises(AgentValidationOutcomeBindingRejected, match="expired"):
        binding_service.execute(
            expired,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=4),
        )
    binding = binding_service.execute(
        plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=4),
    )

    assert binding.intake_record_id == record.record_id
    assert binding.validation_run_id == outcome.validation_run.run_id
    assert binding.result.value == "inconclusive"
    assert binding.final_candidate_state.value == "inconclusive"
    assert candidate.state.value == "proposed"
    assert (
        binding_service.execute(
            plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=5),
        )
        == binding
    )
    recovery_store = AgentValidationOutcomeBindingStore(tmp_path / "recovery-bindings.sqlite3")
    recovery_store.claim(plan, now=now + timedelta(seconds=4))
    with pytest.raises(AgentValidationOutcomeBindingRecoveryRequired):
        recovery_store.claim(plan, now=now + timedelta(seconds=4))
    recovery_store.close()
    binding_store.close()
    validation_store.close()
    intake_store.close()


@pytest.mark.parametrize("result", tuple(ValidationResult))
def test_outcome_binding_accepts_all_authoritative_validation_results_without_execution(
    tmp_path, now, approved_scope, candidate, result
):
    (
        _,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        outcome,
        _,
        binding_store,
        binding_service,
        runner,
        transport,
    ) = _completed_binding_case(tmp_path, now, approved_scope, candidate, result)
    assert outcome.verdict.result is result
    calls_before_binding = (runner.calls, len(transport.calls))
    plan = binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key=f"binding:m8.2:{result.value}",
    )
    binding = binding_service.execute(
        plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=4),
    )

    assert binding.result is result
    assert binding.validation_run_id == outcome.validation_run.run_id
    assert binding.validation_outcome_digest == canonical_digest(outcome.model_dump(mode="python"))
    assert (runner.calls, len(transport.calls)) == calls_before_binding
    assert candidate.state.value == "proposed"
    assert not hasattr(binding_service, "runner")
    assert not hasattr(binding_service, "broker")
    binding_store.close()
    validation_store.close()
    intake_store.close()


@pytest.mark.parametrize(
    "drift",
    ("plan", "candidate_target", "candidate_scope", "runner", "control", "evidence"),
)
def test_outcome_binding_rejects_authoritative_validation_provenance_drift_before_checkpoint(
    tmp_path, now, approved_scope, candidate, drift
):
    case_root = tmp_path / drift
    (
        _,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        outcome,
        _,
        binding_store,
        binding_service,
        _,
        _,
    ) = _completed_binding_case(
        case_root, now, approved_scope, candidate, ValidationResult.INCONCLUSIVE
    )
    if drift == "plan":
        tampered = outcome.model_copy(update={"plan_id": "0" * 64})
    elif drift == "candidate_target":
        tampered = outcome.model_copy(
            update={"candidate": outcome.candidate.model_copy(update={"target_version": "f" * 40})}
        )
    elif drift == "candidate_scope":
        tampered = outcome.model_copy(
            update={
                "candidate": outcome.candidate.model_copy(
                    update={"scope_version": outcome.candidate.scope_version + 1}
                )
            }
        )
    elif drift == "runner":
        tampered = outcome.model_copy(
            update={"runner_result": outcome.runner_result.model_copy(update={"run_id": uuid4()})}
        )
    elif drift == "control":
        tampered = outcome.model_copy(
            update={
                "validation_run": outcome.validation_run.model_copy(
                    update={"result": ValidationResult.POLICY_STOPPED}
                ),
                "verdict": ValidationVerdict(
                    result=ValidationResult.POLICY_STOPPED,
                    rationale_code="manufactured_policy_stop",
                ),
            }
        )
    else:
        foreign_ref = "f" * 64
        tampered = outcome.model_copy(
            update={
                "validation_run": outcome.validation_run.model_copy(
                    update={"evidence_refs": (foreign_ref,)}
                ),
                "verdict": ValidationVerdict(
                    result=ValidationResult.INCONCLUSIVE,
                    rationale_code="foreign_evidence",
                    evidence_refs=(foreign_ref,),
                ),
                "evidence_bundle": EvidenceBundle(
                    candidate_id=candidate.candidate_id,
                    evidence_refs=(foreign_ref,),
                    sealed_at=outcome.completed_at,
                ),
            }
        )
    with validation_store.connection:
        validation_store.connection.execute(
            "UPDATE validation_executions SET outcome_json = ? WHERE plan_id = ?",
            (tampered.model_dump_json(), validation_plan.plan_id),
        )

    with pytest.raises(AgentValidationOutcomeBindingRejected):
        binding_service.prepare(
            intake_plan_id=intake_record.intake_plan_id,
            audit_artifact=artifact,
            candidate_set_id=intake_record.candidate_set_id,
            candidate_id=candidate.candidate_id,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=3),
            idempotency_key=f"binding:m8.2:drift:{drift}",
        )
    assert (
        binding_store.connection.execute(
            "SELECT count(*) FROM agent_validation_outcome_bindings"
        ).fetchone()[0]
        == 0
    )
    binding_store.close()
    validation_store.close()
    intake_store.close()


@pytest.mark.parametrize("case", ("nonaccepted", "expired", "missing", "started"))
def test_outcome_binding_requires_current_accepted_intake_and_completed_validation(
    tmp_path, now, approved_scope, candidate, case
):
    (
        _,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        _,
        _,
        binding_store,
        binding_service,
        _,
        _,
    ) = _completed_binding_case(
        tmp_path / case,
        now,
        approved_scope,
        candidate,
        ValidationResult.INCONCLUSIVE,
        decision=(
            AgentValidationIntakeDecision.REJECT
            if case == "nonaccepted"
            else AgentValidationIntakeDecision.ACCEPT
        ),
    )
    if case == "missing":
        with validation_store.connection:
            validation_store.connection.execute(
                "DELETE FROM validation_executions WHERE plan_id = ?",
                (validation_plan.plan_id,),
            )
    elif case == "started":
        with validation_store.connection:
            validation_store.connection.execute(
                "UPDATE validation_executions SET state='started', outcome_json=NULL "
                "WHERE plan_id = ?",
                (validation_plan.plan_id,),
            )
    binding_time = now + timedelta(minutes=3) if case == "expired" else now + timedelta(seconds=3)
    with pytest.raises(AgentValidationOutcomeBindingRejected):
        binding_service.prepare(
            intake_plan_id=intake_record.intake_plan_id,
            audit_artifact=artifact,
            candidate_set_id=intake_record.candidate_set_id,
            candidate_id=candidate.candidate_id,
            validation_plan=validation_plan,
            now=binding_time,
            idempotency_key=f"binding:m8.2:{case}",
        )
    assert (
        binding_store.connection.execute(
            "SELECT count(*) FROM agent_validation_outcome_bindings"
        ).fetchone()[0]
        == 0
    )
    binding_store.close()
    validation_store.close()
    intake_store.close()


def test_outcome_binding_rejects_post_prepare_drift_and_duplicate_consumption(
    tmp_path, now, approved_scope, candidate
):
    (
        _,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        outcome,
        _,
        binding_store,
        binding_service,
        _,
        _,
    ) = _completed_binding_case(
        tmp_path, now, approved_scope, candidate, ValidationResult.INCONCLUSIVE
    )
    plan = binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key="binding:m8.2:original",
    )
    drifted_time = outcome.completed_at + timedelta(microseconds=1)
    drifted = outcome.model_copy(
        update={
            "validation_run": outcome.validation_run.model_copy(
                update={"started_at": drifted_time, "finished_at": drifted_time}
            ),
            "completed_at": drifted_time,
        }
    )
    with validation_store.connection:
        validation_store.connection.execute(
            "UPDATE validation_executions SET completed_at=?, outcome_json=? WHERE plan_id=?",
            (drifted_time.isoformat(), drifted.model_dump_json(), validation_plan.plan_id),
        )
    with pytest.raises(AgentValidationOutcomeBindingRejected, match="drifted"):
        binding_service.execute(
            plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=4),
        )
    assert (
        binding_store.connection.execute(
            "SELECT count(*) FROM agent_validation_outcome_bindings"
        ).fetchone()[0]
        == 0
    )
    with validation_store.connection:
        validation_store.connection.execute(
            "UPDATE validation_executions SET completed_at=?, outcome_json=? WHERE plan_id=?",
            (outcome.completed_at.isoformat(), outcome.model_dump_json(), validation_plan.plan_id),
        )
    binding = binding_service.execute(
        plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=4),
    )
    assert (
        binding_service.execute(
            plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=5),
        )
        == binding
    )
    conflicting = binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key="binding:m8.2:conflict",
    )
    with pytest.raises(AgentValidationOutcomeBindingConflict):
        binding_service.execute(
            conflicting,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=4),
        )
    with binding_store.connection:
        binding_store.connection.execute(
            "UPDATE agent_validation_outcome_bindings SET completed_at=? WHERE binding_plan_id=?",
            ((now - timedelta(days=1)).isoformat(), plan.binding_plan_id),
        )
    with pytest.raises(AgentValidationOutcomeBindingRecoveryRequired, match="drifted"):
        binding_service.execute(
            plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=5),
        )
    binding_store.close()
    validation_store.close()
    intake_store.close()


def test_outcome_binding_completion_failure_leaves_started_recovery_checkpoint(
    tmp_path, now, approved_scope, candidate, monkeypatch
):
    (
        _,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        _,
        _,
        binding_store,
        binding_service,
        _,
        _,
    ) = _completed_binding_case(
        tmp_path, now, approved_scope, candidate, ValidationResult.INCONCLUSIVE
    )
    plan = binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key="binding:m8.2:completion-failure",
    )
    monkeypatch.setattr(
        binding_store,
        "complete",
        lambda _binding: (_ for _ in ()).throw(RuntimeError("injected persistence failure")),
    )
    with pytest.raises(RuntimeError, match="injected persistence failure"):
        binding_service.execute(
            plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=4),
        )
    with pytest.raises(AgentValidationOutcomeBindingRecoveryRequired):
        binding_service.execute(
            plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=now + timedelta(seconds=5),
        )
    assert (
        binding_store.connection.execute(
            "SELECT state FROM agent_validation_outcome_bindings"
        ).fetchone()[0]
        == "started"
    )
    binding_store.close()
    validation_store.close()
    intake_store.close()


def test_accept_rejects_non_completed_recommendation_before_checkpoint(
    tmp_path, now, approved_scope, candidate
):
    service, store, artifact, validation_plan, plan = _fixture(
        tmp_path, now, approved_scope, candidate, completed=False
    )
    command = _command(plan, now + timedelta(seconds=1), AgentValidationIntakeDecision.ACCEPT)
    with pytest.raises(AgentValidationIntakeRejected, match="completed"):
        service.decide(
            plan,
            command,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=command.decided_at,
        )
    assert (
        store.connection.execute("SELECT count(*) FROM agent_validation_intakes").fetchone()[0] == 0
    )
    store.close()


def test_intake_rejects_plan_drift_expiry_conflicts_and_started_recovery(
    tmp_path, now, approved_scope, candidate
):
    service, store, artifact, validation_plan, plan = _fixture(
        tmp_path, now, approved_scope, candidate
    )
    command = _command(plan, now + timedelta(seconds=1), AgentValidationIntakeDecision.ACCEPT)
    drifted = validation_plan.model_copy(update={"candidate_digest": "0" * 64})
    with pytest.raises(AgentValidationIntakeRejected, match="drifted"):
        service.decide(
            plan,
            command,
            audit_artifact=artifact,
            validation_plan=drifted,
            now=command.decided_at,
        )
    candidate_path = tmp_path / "candidates" / f"{plan.candidate_set_id}.json"
    os.chmod(candidate_path, 0o600)
    with pytest.raises(AgentValidationIntakeRejected, match="authoritative"):
        service.decide(
            plan,
            command,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=command.decided_at,
        )
    os.chmod(candidate_path, 0o400)
    with pytest.raises(AgentValidationIntakeTimedOut):
        service.decide(
            plan,
            _command(plan, plan.decision_deadline, AgentValidationIntakeDecision.ACCEPT),
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=plan.decision_deadline,
        )
    store.claim(plan, command, now=command.decided_at)
    with pytest.raises(AgentValidationIntakeRecoveryRequired):
        service.decide(
            plan,
            command,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=command.decided_at,
        )
    store.close()


def test_intake_schema_and_sqlite_are_digest_only(tmp_path, now, approved_scope, candidate):
    schemas = " ".join(
        json.dumps(model.model_json_schema()).lower()
        for model in (
            AgentValidationIntakePlan,
            AgentValidationIntakeCommand,
            AgentValidationIntakeRecord,
        )
    )
    for forbidden in (
        '"runner_request"',
        '"broker_calls"',
        '"url"',
        '"credential"',
        '"approval"',
        '"evidence_body"',
        '"agent_summary"',
        '"candidate_state"',
        '"submission"',
    ):
        assert forbidden not in schemas
    service, store, artifact, validation_plan, plan = _fixture(
        tmp_path, now, approved_scope, candidate
    )
    command = _command(plan, now + timedelta(seconds=1), AgentValidationIntakeDecision.ACCEPT)
    service.decide(
        plan,
        command,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=command.decided_at,
    )
    persisted = (tmp_path / "intake.sqlite3").read_bytes()
    for forbidden in (b"https://", b"Authorization", b"Bearer", b"sandbox.test"):
        assert forbidden not in persisted
    store.close()


def test_outcome_binding_schema_and_sqlite_are_digest_only(
    tmp_path, now, approved_scope, candidate
):
    schemas = " ".join(
        json.dumps(model.model_json_schema()).lower()
        for model in (
            AgentValidationOutcomeBindingPlan,
            AgentValidationOutcomeBinding,
            AgentCriticIntakePlan,
            AgentCriticIntakeCommand,
            AgentCriticIntakeRecord,
        )
    )
    for forbidden in (
        '"runner_request"',
        '"runner_result"',
        '"broker_calls"',
        '"broker_results"',
        '"url"',
        '"credential"',
        '"approval"',
        '"evidence_body"',
        '"agent_summary"',
        '"submission"',
    ):
        assert forbidden not in schemas
    (
        _,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        _,
        _,
        binding_store,
        binding_service,
        _,
        _,
    ) = _completed_binding_case(
        tmp_path, now, approved_scope, candidate, ValidationResult.REPRODUCED
    )
    plan = binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key="binding:m8.2:digest-only",
    )
    binding_service.execute(
        plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=4),
    )
    persisted = (tmp_path / "bindings.sqlite3").read_bytes()
    for forbidden in (
        b"https://",
        b"Authorization",
        b"Bearer",
        b"sandbox.test",
        b"redacted M8.2 deterministic fixture",
    ):
        assert forbidden not in persisted
    binding_store.close()
    validation_store.close()
    intake_store.close()


def _critic_plan(now, outcome, evidence_ref):
    bundle = outcome.evidence_bundle
    assert bundle is not None
    assessments = tuple(
        CounterevidenceAssessment(
            angle=angle,
            disposition=CounterevidenceDisposition.RULED_OUT,
            evidence_refs=(evidence_ref,),
            rationale_code=f"{angle.value}_ruled_out",
        )
        for angle in sorted(REQUIRED_ANGLES, key=lambda item: item.value)
    )
    return CriticPlan.create(
        candidate_id=outcome.candidate.candidate_id,
        candidate_digest=domain_object_digest(outcome.candidate),
        validation_run_id=outcome.validation_run.run_id,
        validation_run_digest=domain_object_digest(outcome.validation_run),
        evidence_bundle_id=bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(bundle),
        scope_id=outcome.candidate.scope_id,
        scope_version=outcome.candidate.scope_version,
        validation_context_id="a" * 64,
        review_context_id="b" * 64,
        validation_producer="deterministic-validator/v1",
        review_producer="deterministic-critic/v1",
        assessments=assessments,
        created_at=now + timedelta(seconds=5),
        deadline=now + timedelta(minutes=1),
        idempotency_key="critic:m8.3",
    )


@pytest.mark.parametrize("decision", tuple(AgentCriticIntakeDecision))
def test_critic_intake_records_human_decision_without_critic_or_state_change(
    tmp_path, now, approved_scope, candidate, decision
):
    (
        intake_service,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        outcome,
        evidence_store,
        binding_store,
        binding_service,
        runner,
        transport,
    ) = _completed_binding_case(
        tmp_path, now, approved_scope, candidate, ValidationResult.REPRODUCED
    )
    binding_plan = binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key="binding:m8.3",
    )
    binding = binding_service.execute(
        binding_plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=4),
    )
    critic_plan = _critic_plan(now, outcome, binding.evidence_refs[0])
    critic_store = AgentCriticIntakeStore(tmp_path / "critic-intake.sqlite3")
    service = AgentCriticIntakeService(
        scope=approved_scope,
        audit_store=intake_service.audit_artifact_store,
        candidate_store=intake_service.candidate_set_store,
        outcome_binding_store=binding_store,
        validation_store=validation_store,
        evidence_store=evidence_store,
        store=critic_store,
    )
    plan = service.prepare(
        outcome_binding_plan=binding_plan,
        audit_artifact=artifact,
        critic_plan=critic_plan,
        now=now + timedelta(seconds=5),
        decision_deadline=now + timedelta(seconds=30),
        idempotency_key=f"critic-intake:m8.3:{decision.value}",
    )
    reason = {
        AgentCriticIntakeDecision.ACCEPT: AgentCriticIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
        AgentCriticIntakeDecision.REJECT: AgentCriticIntakeReason.HUMAN_REJECTED,
        AgentCriticIntakeDecision.DEFER: AgentCriticIntakeReason.HUMAN_DEFERRED,
    }[decision]
    command = AgentCriticIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_critic_intake_plan_digest(plan),
        outcome_binding_id=plan.outcome_binding_id,
        candidate_id=plan.candidate_id,
        critic_plan_id=plan.critic_plan_id,
        critic_plan_digest=plan.critic_plan_digest,
        decision=decision,
        reason_code=reason,
        reviewer="human-critic-reviewer",
        decided_at=now + timedelta(seconds=6),
    )
    drifted_critic_plan = critic_plan.model_copy(update={"candidate_digest": "0" * 64})
    with pytest.raises(AgentCriticIntakeRejected):
        service.decide(
            plan,
            command,
            outcome_binding_plan=binding_plan,
            audit_artifact=artifact,
            critic_plan=drifted_critic_plan,
            now=command.decided_at,
        )
    assert (
        critic_store.connection.execute("SELECT count(*) FROM agent_critic_intakes").fetchone()[0]
        == 0
    )
    before = (runner.calls, len(transport.calls), candidate.state)
    record = service.decide(
        plan,
        command,
        outcome_binding_plan=binding_plan,
        audit_artifact=artifact,
        critic_plan=critic_plan,
        now=command.decided_at,
    )
    assert (
        service.decide(
            plan,
            command,
            outcome_binding_plan=binding_plan,
            audit_artifact=artifact,
            critic_plan=critic_plan,
            now=command.decided_at,
        )
        == record
    )
    assert record.decision is decision
    assert (runner.calls, len(transport.calls), candidate.state) == before
    assert not hasattr(service, "critic")
    persisted = (tmp_path / "critic-intake.sqlite3").read_bytes()
    for forbidden in (b"https://", b"sandbox.test", b"deterministic fixture"):
        assert forbidden not in persisted
    recovery_store = AgentCriticIntakeStore(tmp_path / "critic-recovery.sqlite3")
    recovery_store.claim(plan, command, now=command.decided_at)
    with pytest.raises(AgentCriticIntakeRecoveryRequired):
        recovery_store.claim(plan, command, now=command.decided_at)
    recovery_store.close()
    critic_store.close()
    binding_store.close()
    validation_store.close()
    intake_store.close()


def test_critic_intake_rejects_non_reproduced_binding_and_started_recovery(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_binding_case(
        tmp_path / "nonreproduced",
        now,
        approved_scope,
        candidate,
        ValidationResult.NOT_REPRODUCED,
    )
    (
        intake_service,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        outcome,
        evidence_store,
        binding_store,
        binding_service,
        _,
        _,
    ) = case
    binding_plan = binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key="binding:m8.3:nonreproduced",
    )
    binding_service.execute(
        binding_plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=4),
    )
    # A non-reproduced outcome has no admissible CriticPlan and is refused before checkpoint.
    assert outcome.evidence_bundle is None
    store = AgentCriticIntakeStore(tmp_path / "nonreproduced" / "critic.sqlite3")
    service = AgentCriticIntakeService(
        scope=approved_scope,
        audit_store=intake_service.audit_artifact_store,
        candidate_store=intake_service.candidate_set_store,
        outcome_binding_store=binding_store,
        validation_store=validation_store,
        evidence_store=evidence_store,
        store=store,
    )
    with pytest.raises(AgentCriticIntakeRejected):
        service.prepare(
            outcome_binding_plan=binding_plan,
            audit_artifact=artifact,
            critic_plan=object(),
            now=now + timedelta(seconds=5),
            decision_deadline=now + timedelta(seconds=30),
            idempotency_key="x",
        )
    assert store.connection.execute("SELECT count(*) FROM agent_critic_intakes").fetchone()[0] == 0
    store.close()
    binding_store.close()
    validation_store.close()
    intake_store.close()


def _completed_critic_case(tmp_path, now, scope, candidate, verdict):
    case = _completed_binding_case(tmp_path, now, scope, candidate, ValidationResult.REPRODUCED)
    (
        intake_service,
        intake_store,
        intake_record,
        artifact,
        validation_plan,
        validation_store,
        validation_outcome,
        evidence_store,
        validation_binding_store,
        validation_binding_service,
        runner,
        transport,
    ) = case
    validation_binding_plan = validation_binding_service.prepare(
        intake_plan_id=intake_record.intake_plan_id,
        audit_artifact=artifact,
        candidate_set_id=intake_record.candidate_set_id,
        candidate_id=candidate.candidate_id,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=3),
        idempotency_key=f"binding:m8.4:{verdict.value}",
    )
    validation_binding = validation_binding_service.execute(
        validation_binding_plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        now=now + timedelta(seconds=4),
    )
    critic_plan = _critic_plan(now, validation_outcome, validation_binding.evidence_refs[0])
    if verdict is not CriticVerdict.ACCEPTED:
        disposition = (
            CounterevidenceDisposition.CONFIRMED
            if verdict is CriticVerdict.REJECTED
            else CounterevidenceDisposition.INCONCLUSIVE
        )
        assessments = list(critic_plan.assessments)
        assessments[0] = assessments[0].model_copy(
            update={
                "disposition": disposition,
                "evidence_refs": ()
                if disposition is CounterevidenceDisposition.INCONCLUSIVE
                else assessments[0].evidence_refs,
                "rationale_code": f"m8.4_{disposition.value}",
            }
        )
        critic_plan = CriticPlan.create(
            **critic_plan.model_dump(
                mode="python",
                exclude={"plan_id", "assessments", "idempotency_key", "ruleset_digest"},
            ),
            assessments=tuple(assessments),
            idempotency_key=f"critic:m8.4:{verdict.value}",
        )
    critic_intake_store = AgentCriticIntakeStore(tmp_path / "critic-intake-m8.4.sqlite3")
    critic_intake_service = AgentCriticIntakeService(
        scope=scope,
        audit_store=intake_service.audit_artifact_store,
        candidate_store=intake_service.candidate_set_store,
        outcome_binding_store=validation_binding_store,
        validation_store=validation_store,
        evidence_store=evidence_store,
        store=critic_intake_store,
    )
    critic_intake_plan = critic_intake_service.prepare(
        outcome_binding_plan=validation_binding_plan,
        audit_artifact=artifact,
        critic_plan=critic_plan,
        now=now + timedelta(seconds=5),
        decision_deadline=now + timedelta(seconds=30),
        idempotency_key=f"critic-intake:m8.4:{verdict.value}",
    )
    command = AgentCriticIntakeCommand.create(
        intake_plan_id=critic_intake_plan.intake_plan_id,
        intake_plan_digest=agent_critic_intake_plan_digest(critic_intake_plan),
        outcome_binding_id=critic_intake_plan.outcome_binding_id,
        candidate_id=critic_intake_plan.candidate_id,
        critic_plan_id=critic_intake_plan.critic_plan_id,
        critic_plan_digest=critic_intake_plan.critic_plan_digest,
        decision=AgentCriticIntakeDecision.ACCEPT,
        reason_code=AgentCriticIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
        reviewer="human-m8.4-reviewer",
        decided_at=now + timedelta(seconds=6),
    )
    critic_intake_service.decide(
        critic_intake_plan,
        command,
        outcome_binding_plan=validation_binding_plan,
        audit_artifact=artifact,
        critic_plan=critic_plan,
        now=command.decided_at,
    )
    evidence = evidence_store.capture_text(
        "redacted M8.2 deterministic fixture",
        kind=EvidenceKind.TEST,
        source_ref="m8.2-local-fixture",
        producer="test.m8.2",
        target_version=candidate.target_version,
        summary="M8.2 deterministic fixture",
    )
    critic_store = CriticStore(tmp_path / "critic-execution-m8.4.sqlite3")
    critic_outcome = DeterministicCritic(
        scope=scope, evidence_store=evidence_store, store=critic_store
    ).review(
        validation_outcome.candidate,
        validation_outcome.validation_run,
        validation_outcome.evidence_bundle,
        (evidence,),
        critic_plan,
        now=now + timedelta(seconds=7),
    )
    binding_store = AgentCriticOutcomeBindingStore(tmp_path / "critic-outcome-bindings.sqlite3")
    binding_service = AgentCriticOutcomeBindingService(
        scope=scope,
        critic_intake_store=critic_intake_store,
        outcome_binding_store=validation_binding_store,
        validation_store=validation_store,
        critic_store=critic_store,
        evidence_store=evidence_store,
        binding_store=binding_store,
    )
    return (
        critic_intake_plan,
        critic_outcome,
        binding_service,
        binding_store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        intake_store,
        runner,
        transport,
    )


@pytest.mark.parametrize("verdict", tuple(CriticVerdict))
def test_critic_outcome_binding_is_read_only_for_every_verdict(
    tmp_path, now, approved_scope, candidate, verdict
):
    (
        intake_plan,
        critic_outcome,
        service,
        store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        validation_intake_store,
        runner,
        transport,
    ) = _completed_critic_case(tmp_path, now, approved_scope, candidate, verdict)
    before = (runner.calls, len(transport.calls), candidate.state)
    plan = service.prepare(
        critic_intake_plan=intake_plan,
        now=now + timedelta(seconds=8),
        idempotency_key=f"critic-outcome-binding:m8.4:{verdict.value}",
    )
    expired = plan.model_copy(update={"deadline": now + timedelta(seconds=9)})
    with pytest.raises(AgentCriticOutcomeBindingRejected, match="expired"):
        service.execute(expired, critic_intake_plan=intake_plan, now=now + timedelta(seconds=9))
    result = service.execute(plan, critic_intake_plan=intake_plan, now=now + timedelta(seconds=9))
    assert result.verdict is verdict
    assert result.final_candidate_state is critic_outcome.candidate.state
    assert (runner.calls, len(transport.calls), candidate.state) == before
    assert not hasattr(service, "critic")
    assert (
        service.execute(plan, critic_intake_plan=intake_plan, now=now + timedelta(seconds=10))
        == result
    )
    persisted = (tmp_path / "critic-outcome-bindings.sqlite3").read_bytes()
    for forbidden in (b"https://", b"Authorization", b"deterministic fixture"):
        assert forbidden not in persisted
    recovery = AgentCriticOutcomeBindingStore(tmp_path / "critic-binding-recovery.sqlite3")
    recovery.claim(plan, now=now + timedelta(seconds=9))
    with pytest.raises(AgentCriticOutcomeBindingRecoveryRequired):
        recovery.claim(plan, now=now + timedelta(seconds=9))
    recovery.close()
    store.close()
    critic_store.close()
    critic_intake_store.close()
    validation_binding_store.close()
    validation_store.close()
    validation_intake_store.close()


def test_critic_outcome_binding_rejects_completed_outcome_drift_before_checkpoint(
    tmp_path, now, approved_scope, candidate
):
    (
        intake_plan,
        _,
        service,
        store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        validation_intake_store,
        _,
        _,
    ) = _completed_critic_case(tmp_path, now, approved_scope, candidate, CriticVerdict.ACCEPTED)
    row = critic_store.connection.execute(
        "SELECT outcome_json FROM critic_executions WHERE plan_id=?",
        (intake_plan.critic_plan_id,),
    ).fetchone()
    payload = json.loads(row[0])
    payload["review"]["rationale_code"] = "tampered"
    critic_store.connection.execute(
        "UPDATE critic_executions SET outcome_json=? WHERE plan_id=?",
        (json.dumps(payload), intake_plan.critic_plan_id),
    )
    critic_store.connection.commit()
    with pytest.raises(AgentCriticOutcomeBindingRejected, match="drifted"):
        service.prepare(
            critic_intake_plan=intake_plan,
            now=now + timedelta(seconds=8),
            idempotency_key="critic-outcome-binding:m8.4:drift",
        )
    assert (
        store.connection.execute("SELECT count(*) FROM agent_critic_outcome_bindings").fetchone()[0]
        == 0
    )
    store.close()
    critic_store.close()
    critic_intake_store.close()
    validation_binding_store.close()
    validation_store.close()
    validation_intake_store.close()


def test_critic_outcome_binding_contracts_are_digest_only():
    forbidden = {"prompt", "body", "headers", "token", "cookie", "runner", "broker"}
    for model in (AgentCriticOutcomeBindingPlan, AgentCriticOutcomeBinding):
        fields = set(model.model_fields)
        assert not fields & forbidden
        assert all("evidence_ref" not in field for field in fields)


def _completed_m85_case(tmp_path, now, scope, candidate, verdict=CriticVerdict.ACCEPTED):
    (
        critic_intake_plan,
        critic_outcome,
        critic_binding_service,
        critic_binding_store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        validation_intake_store,
        runner,
        transport,
    ) = _completed_critic_case(tmp_path, now, scope, candidate, verdict)
    critic_binding_plan = critic_binding_service.prepare(
        critic_intake_plan=critic_intake_plan,
        now=now + timedelta(seconds=8),
        idempotency_key="critic-outcome-binding:m8.5",
    )
    critic_binding = critic_binding_service.execute(
        critic_binding_plan,
        critic_intake_plan=critic_intake_plan,
        now=now + timedelta(seconds=9),
    )
    reviewed = critic_outcome.candidate
    duplicate_check = FindingDuplicateCheck.create(
        candidate_id=reviewed.candidate_id,
        candidate_digest=domain_object_digest(reviewed),
        target_version_digest=canonical_digest(reviewed.target_version),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        result=DuplicateCheckResult.CLEAR,
        duplicate_family_id=None,
        checked_by="human-duplicate-reviewer",
        checked_at=now + timedelta(seconds=9),
        expires_at=now + timedelta(seconds=40),
    )
    duplicate_check_store = FindingDuplicateCheckStore(tmp_path / "duplicate-checks.sqlite3")
    duplicate_check_store.publish(duplicate_check)
    validation_binding = validation_binding_store.load_completed_by_binding_id(
        critic_binding.outcome_binding_id
    )
    _, validation_outcome = validation_store.load_completed(validation_binding.validation_plan_id)
    evidence_bundle = validation_outcome.evidence_bundle
    assert evidence_bundle is not None
    promotion_plan = FindingPromotionPlan.create(
        critic_outcome_binding_plan_id=critic_binding_plan.binding_plan_id,
        critic_outcome_binding_id=critic_binding.binding_id,
        critic_outcome_binding_digest=agent_critic_outcome_binding_digest(critic_binding),
        candidate_id=reviewed.candidate_id,
        candidate_digest=domain_object_digest(reviewed),
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
        root_cause="trusted control-plane root cause",
        affected_versions=(reviewed.target_version,),
        impact="trusted control-plane impact",
        severity_assessment={"rating": "high", "score": 8.1},
        scope_id=scope.scope_id,
        scope_version=scope.version,
        created_at=now + timedelta(seconds=10),
        deadline=now + timedelta(seconds=35),
        idempotency_key="finding-promotion:m8.5",
    )
    finding_store = AgentFindingIntakeStore(tmp_path / "finding-intake.sqlite3")
    service = AgentFindingIntakeService(
        scope=scope,
        critic_binding_store=critic_binding_store,
        validation_binding_store=validation_binding_store,
        validation_store=validation_store,
        critic_store=critic_store,
        evidence_store=critic_binding_service.evidence_store,
        duplicate_check_store=duplicate_check_store,
        store=finding_store,
    )
    return (
        service,
        finding_store,
        critic_binding_plan,
        promotion_plan,
        duplicate_check,
        critic_outcome,
        critic_binding_store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        validation_intake_store,
        runner,
        transport,
    )


@pytest.mark.parametrize("decision", tuple(AgentFindingIntakeDecision))
def test_finding_intake_records_human_decision_without_promotion(
    tmp_path, now, approved_scope, candidate, decision
):
    (
        service,
        store,
        binding_plan,
        promotion_plan,
        duplicate_check,
        critic_outcome,
        critic_binding_store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        validation_intake_store,
        runner,
        transport,
    ) = _completed_m85_case(tmp_path, now, approved_scope, candidate)
    plan = service.prepare(
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        now=now + timedelta(seconds=10),
        decision_deadline=now + timedelta(seconds=30),
        idempotency_key=f"finding-intake:m8.5:{decision.value}",
    )
    reason = {
        AgentFindingIntakeDecision.ACCEPT: AgentFindingIntakeReason.HUMAN_ACCEPTED_EXACT_PROMOTION,
        AgentFindingIntakeDecision.REJECT: AgentFindingIntakeReason.HUMAN_REJECTED,
        AgentFindingIntakeDecision.DEFER: AgentFindingIntakeReason.HUMAN_DEFERRED,
    }[decision]
    command = AgentFindingIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_finding_intake_plan_digest(plan),
        critic_outcome_binding_id=plan.critic_outcome_binding_id,
        promotion_plan_id=plan.promotion_plan_id,
        promotion_plan_digest=plan.promotion_plan_digest,
        candidate_id=plan.candidate_id,
        finding_id=plan.finding_id,
        decision=decision,
        reason_code=reason,
        reviewer="human-finding-reviewer",
        decided_at=now + timedelta(seconds=11),
    )
    expired = AgentFindingIntakePlan.create(
        **plan.model_dump(mode="python", exclude={"intake_plan_id", "decision_deadline"}),
        decision_deadline=command.decided_at,
    )
    with pytest.raises(AgentFindingIntakeTimedOut):
        service.decide(
            expired,
            command,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            now=command.decided_at,
        )
    before = (
        candidate.state,
        critic_outcome.candidate.state,
        runner.calls,
        len(transport.calls),
    )
    record = service.decide(
        plan,
        command,
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        now=command.decided_at,
    )
    assert (
        service.decide(
            plan,
            command,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            now=command.decided_at,
        )
        == record
    )
    assert record.decision is decision
    assert (
        candidate.state,
        critic_outcome.candidate.state,
        runner.calls,
        len(transport.calls),
    ) == before
    assert not hasattr(service, "promote_candidate")
    conflicting_decision = (
        AgentFindingIntakeDecision.REJECT
        if decision is AgentFindingIntakeDecision.ACCEPT
        else AgentFindingIntakeDecision.ACCEPT
    )
    conflicting_reason = {
        AgentFindingIntakeDecision.ACCEPT: AgentFindingIntakeReason.HUMAN_ACCEPTED_EXACT_PROMOTION,
        AgentFindingIntakeDecision.REJECT: AgentFindingIntakeReason.HUMAN_REJECTED,
    }[conflicting_decision]
    conflicting_command = AgentFindingIntakeCommand.create(
        **command.model_dump(
            mode="python",
            exclude={"command_id", "decision", "reason_code", "reviewer"},
        ),
        decision=conflicting_decision,
        reason_code=conflicting_reason,
        reviewer="second-human-finding-reviewer",
    )
    with pytest.raises(AgentFindingIntakeConflict):
        service.decide(
            plan,
            conflicting_command,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            now=conflicting_command.decided_at,
        )
    persisted = (tmp_path / "finding-intake.sqlite3").read_bytes()
    for forbidden in (
        b"trusted control-plane root cause",
        b"trusted control-plane impact",
        b"https://",
        b"Authorization",
    ):
        assert forbidden not in persisted
    recovery = AgentFindingIntakeStore(tmp_path / "finding-intake-recovery.sqlite3")
    recovery.claim(plan, command, now=command.decided_at)
    with pytest.raises(AgentFindingIntakeRecoveryRequired):
        recovery.claim(plan, command, now=command.decided_at)
    recovery.close()
    store.close()
    service.duplicate_check_store.close()
    critic_binding_store.close()
    critic_store.close()
    critic_intake_store.close()
    validation_binding_store.close()
    validation_store.close()
    validation_intake_store.close()


def test_finding_intake_rejects_duplicate_or_promotion_drift_before_checkpoint(
    tmp_path, now, approved_scope, candidate
):
    (
        service,
        store,
        binding_plan,
        promotion_plan,
        duplicate_check,
        _,
        critic_binding_store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        validation_intake_store,
        _,
        _,
    ) = _completed_m85_case(tmp_path, now, approved_scope, candidate)
    drifted = promotion_plan.model_copy(update={"impact": "drifted after sealing"})
    with pytest.raises(AgentFindingIntakeRejected, match="drifted"):
        service.prepare(
            critic_binding_plan=binding_plan,
            promotion_plan=drifted,
            duplicate_check=duplicate_check,
            now=now + timedelta(seconds=10),
            decision_deadline=now + timedelta(seconds=30),
            idempotency_key="finding-intake:m8.5:drift",
        )
    duplicate = FindingDuplicateCheck.create(
        **duplicate_check.model_dump(
            mode="python",
            exclude={
                "check_id",
                "result",
                "duplicate_family_id",
                "checked_at",
            },
        ),
        result=DuplicateCheckResult.DUPLICATE,
        duplicate_family_id=uuid4(),
        checked_at=now + timedelta(seconds=10),
    )
    service.duplicate_check_store.publish(duplicate)
    with pytest.raises(AgentFindingIntakeRejected, match="drifted"):
        service.prepare(
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate,
            now=now + timedelta(seconds=10),
            decision_deadline=now + timedelta(seconds=30),
            idempotency_key="finding-intake:m8.5:duplicate",
        )
    with pytest.raises(AgentFindingIntakeRejected, match="unavailable"):
        service.prepare(
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            now=now + timedelta(seconds=10),
            decision_deadline=now + timedelta(seconds=30),
            idempotency_key="finding-intake:m8.5:stale-clear",
        )
    assert store.connection.execute("SELECT count(*) FROM agent_finding_intakes").fetchone()[0] == 0
    store.close()
    service.duplicate_check_store.close()
    critic_binding_store.close()
    critic_store.close()
    critic_intake_store.close()
    validation_binding_store.close()
    validation_store.close()
    validation_intake_store.close()


@pytest.mark.parametrize("verdict", (CriticVerdict.REJECTED, CriticVerdict.INCONCLUSIVE))
def test_finding_intake_requires_an_accepted_critic_binding(
    tmp_path, now, approved_scope, candidate, verdict
):
    (
        service,
        store,
        binding_plan,
        promotion_plan,
        duplicate_check,
        _,
        critic_binding_store,
        critic_store,
        critic_intake_store,
        validation_binding_store,
        validation_store,
        validation_intake_store,
        _,
        _,
    ) = _completed_m85_case(tmp_path, now, approved_scope, candidate, verdict)
    with pytest.raises(AgentFindingIntakeRejected, match="drifted"):
        service.prepare(
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            now=now + timedelta(seconds=10),
            decision_deadline=now + timedelta(seconds=30),
            idempotency_key=f"finding-intake:m8.5:{verdict.value}",
        )
    assert store.connection.execute("SELECT count(*) FROM agent_finding_intakes").fetchone()[0] == 0
    store.close()
    service.duplicate_check_store.close()
    critic_binding_store.close()
    critic_store.close()
    critic_intake_store.close()
    validation_binding_store.close()
    validation_store.close()
    validation_intake_store.close()


def test_finding_intake_contracts_and_sqlite_are_digest_only():
    forbidden = {
        "root_cause",
        "affected_versions",
        "impact",
        "severity_assessment",
        "prompt",
        "runner",
        "broker",
        "token",
    }
    for model in (AgentFindingIntakePlan, AgentFindingIntakeRecord):
        assert not set(model.model_fields) & forbidden


def _accepted_m85_case(tmp_path, now, scope, candidate):
    case = _completed_m85_case(tmp_path, now, scope, candidate)
    service, _, binding_plan, promotion_plan, duplicate_check, *_ = case
    plan = service.prepare(
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        now=now + timedelta(seconds=10),
        decision_deadline=now + timedelta(seconds=30),
        idempotency_key="finding-intake:m8.6",
    )
    command = AgentFindingIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_finding_intake_plan_digest(plan),
        critic_outcome_binding_id=plan.critic_outcome_binding_id,
        promotion_plan_id=plan.promotion_plan_id,
        promotion_plan_digest=plan.promotion_plan_digest,
        candidate_id=plan.candidate_id,
        finding_id=plan.finding_id,
        decision=AgentFindingIntakeDecision.ACCEPT,
        reason_code=AgentFindingIntakeReason.HUMAN_ACCEPTED_EXACT_PROMOTION,
        reviewer="human-finding-reviewer",
        decided_at=now + timedelta(seconds=11),
    )
    record = service.decide(
        plan,
        command,
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        now=command.decided_at,
    )
    return case, plan, record


def _close_m85_case(case):
    service = case[0]
    for store in (case[1], service.duplicate_check_store, *case[6:12]):
        store.close()


def _promotion_approval(
    service, record, promotion_plan, scope, now, *, status=ApprovalStatus.GRANTED
):
    action = service.approval_action(record=record, promotion_plan=promotion_plan)
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=service._candidate_target_id(promotion_plan),
        action=ApprovalAction.MUTATE_TARGET_STATE,
        action_digest=action.action_id,
        expected_side_effects=("candidate:promoted", "finding:created"),
        evidence_summary="Human approved the exact sealed local promotion action",
        policy_version=scope.version,
        expires_at=now + timedelta(seconds=29),
        status=status,
        decided_by="human-approval-reviewer" if status is ApprovalStatus.GRANTED else None,
        decided_at=now + timedelta(seconds=12) if status is ApprovalStatus.GRANTED else None,
    )


def test_finding_promotion_requires_exact_approval_and_binds_result(
    tmp_path, now, approved_scope, candidate
):
    case, intake_plan, record = _accepted_m85_case(tmp_path, now, approved_scope, candidate)
    intake_service, _, binding_plan, promotion_plan, duplicate_check, critic_outcome, *tail = case
    store = FindingPromotionStore(tmp_path / "finding-promotions.sqlite3")
    service = FindingPromotionService(intake_service=intake_service, store=store)
    approval = _promotion_approval(service, record, promotion_plan, approved_scope, now)
    plan = service.prepare(
        intake_plan=intake_plan,
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        approval=approval,
        now=now + timedelta(seconds=13),
        deadline=now + timedelta(seconds=28),
        idempotency_key="finding-promotion:m8.6",
    )
    runner, transport = tail[-2:]
    calls_before = (runner.calls, len(transport.calls))
    outcome = service.execute(
        plan,
        intake_plan=intake_plan,
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        approval=approval,
        now=now + timedelta(seconds=14),
    )
    assert outcome.promoted_candidate.state is CandidateState.PROMOTED
    assert outcome.finding.finding_id == promotion_plan.finding_id
    assert outcome.finding.state == "verified"
    assert outcome.finding.validation_run_ids == promotion_plan.validation_run_ids
    assert service.store.load_completed(plan.execution_plan_id) == outcome
    assert (
        service.execute(
            plan,
            intake_plan=intake_plan,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=now + timedelta(seconds=15),
        )
        == outcome
    )
    assert candidate.state is CandidateState.PROPOSED
    assert critic_outcome.candidate.state is CandidateState.CRITIC_REVIEWED
    assert (runner.calls, len(transport.calls)) == calls_before
    persisted = (tmp_path / "finding-promotions.sqlite3").read_bytes()
    assert b"Human approved the exact sealed" not in persisted
    assert b"Authorization" not in persisted
    conflicting = FindingPromotionExecutionPlan.create(
        **plan.model_dump(mode="python", exclude={"execution_plan_id", "idempotency_key"}),
        idempotency_key="finding-promotion:m8.6:conflict",
    )
    with pytest.raises(FindingPromotionConflict):
        store.claim(conflicting, now=now + timedelta(seconds=16))
    store.close()
    _close_m85_case(case)


@pytest.mark.parametrize(
    "status", (ApprovalStatus.PENDING, ApprovalStatus.DENIED, ApprovalStatus.REVOKED)
)
def test_finding_promotion_rejects_missing_grant_before_checkpoint(
    tmp_path, now, approved_scope, candidate, status
):
    case, intake_plan, record = _accepted_m85_case(tmp_path, now, approved_scope, candidate)
    intake_service, _, binding_plan, promotion_plan, duplicate_check, *_ = case
    store = FindingPromotionStore(tmp_path / "finding-promotions.sqlite3")
    service = FindingPromotionService(intake_service=intake_service, store=store)
    approval = _promotion_approval(
        service, record, promotion_plan, approved_scope, now, status=status
    )
    with pytest.raises(FindingPromotionRejected, match="Approval"):
        service.prepare(
            intake_plan=intake_plan,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=now + timedelta(seconds=13),
            deadline=now + timedelta(seconds=28),
            idempotency_key=f"finding-promotion:m8.6:{status.value}",
        )
    assert store.connection.execute("SELECT count(*) FROM finding_promotions").fetchone()[0] == 0
    store.close()
    _close_m85_case(case)


def test_finding_promotion_timeout_drift_and_started_recovery(
    tmp_path, now, approved_scope, candidate
):
    case, intake_plan, record = _accepted_m85_case(tmp_path, now, approved_scope, candidate)
    intake_service, _, binding_plan, promotion_plan, duplicate_check, *_ = case
    store = FindingPromotionStore(tmp_path / "finding-promotions.sqlite3")
    service = FindingPromotionService(intake_service=intake_service, store=store)
    approval = _promotion_approval(service, record, promotion_plan, approved_scope, now)
    plan = service.prepare(
        intake_plan=intake_plan,
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        approval=approval,
        now=now + timedelta(seconds=13),
        deadline=now + timedelta(seconds=20),
        idempotency_key="finding-promotion:m8.6:recovery",
    )
    with pytest.raises(FindingPromotionTimedOut):
        service.execute(
            plan,
            intake_plan=intake_plan,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=plan.deadline,
        )
    with pytest.raises(FindingPromotionRejected, match="drifted"):
        service.execute(
            plan.model_copy(update={"candidate_digest": "f" * 64}),
            intake_plan=intake_plan,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=now + timedelta(seconds=14),
        )
    assert store.connection.execute("SELECT count(*) FROM finding_promotions").fetchone()[0] == 0
    store.claim(plan, now=now + timedelta(seconds=14))
    with pytest.raises(FindingPromotionRecoveryRequired):
        service.execute(
            plan,
            intake_plan=intake_plan,
            critic_binding_plan=binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=now + timedelta(seconds=15),
        )
    store.close()
    _close_m85_case(case)


def test_finding_promotion_rejects_expired_or_wrong_action_approval(
    tmp_path, now, approved_scope, candidate
):
    case, intake_plan, record = _accepted_m85_case(tmp_path, now, approved_scope, candidate)
    intake_service, _, binding_plan, promotion_plan, duplicate_check, *_ = case
    store = FindingPromotionStore(tmp_path / "finding-promotions.sqlite3")
    service = FindingPromotionService(intake_service=intake_service, store=store)
    approval = _promotion_approval(service, record, promotion_plan, approved_scope, now)
    for drifted in (
        approval.model_copy(update={"expires_at": now + timedelta(seconds=13)}),
        approval.model_copy(update={"action_digest": "0" * 64}),
        approval.model_copy(update={"target_id": uuid4()}),
    ):
        with pytest.raises(FindingPromotionRejected, match="Approval"):
            service.prepare(
                intake_plan=intake_plan,
                critic_binding_plan=binding_plan,
                promotion_plan=promotion_plan,
                duplicate_check=duplicate_check,
                approval=drifted,
                now=now + timedelta(seconds=13),
                deadline=now + timedelta(seconds=20),
                idempotency_key="finding-promotion:m8.6:invalid-approval",
            )
    assert store.connection.execute("SELECT count(*) FROM finding_promotions").fetchone()[0] == 0
    store.close()
    _close_m85_case(case)


def test_finding_promotion_execution_schema_has_no_agent_or_tool_parameters():
    schema = json.dumps(FindingPromotionExecutionPlan.model_json_schema()).lower()
    for forbidden in ("prompt", "runner", "broker", "url", "credential", "token", "submission"):
        assert forbidden not in schema


def _completed_m86_case(tmp_path, now, scope, candidate):
    case, finding_intake_plan, record = _accepted_m85_case(tmp_path, now, scope, candidate)
    intake_service, _, binding_plan, promotion_plan, duplicate_check, *_ = case
    promotion_store = FindingPromotionStore(tmp_path / "finding-promotions.sqlite3")
    promotion_service = FindingPromotionService(
        intake_service=intake_service, store=promotion_store
    )
    approval = _promotion_approval(promotion_service, record, promotion_plan, scope, now)
    execution_plan = promotion_service.prepare(
        intake_plan=finding_intake_plan,
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        approval=approval,
        now=now + timedelta(seconds=13),
        deadline=now + timedelta(seconds=28),
        idempotency_key="finding-promotion:m8.7",
    )
    outcome = promotion_service.execute(
        execution_plan,
        intake_plan=finding_intake_plan,
        critic_binding_plan=binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
        approval=approval,
        now=now + timedelta(seconds=14),
    )
    critic_binding = case[6].load_completed(binding_plan.binding_plan_id)
    validation_binding = case[9].load_completed_by_binding_id(critic_binding.outcome_binding_id)
    _, validation_outcome = case[10].load_completed(validation_binding.validation_plan_id)
    bundle = validation_outcome.evidence_bundle
    assert bundle is not None
    evidence_ref = bundle.evidence_refs[0]
    sections = (
        ReportSection(kind=ReportSectionKind.SUMMARY, text="trusted report summary"),
        ReportSection(
            kind=ReportSectionKind.CODE_LOCATION,
            text="trusted code location",
            evidence_refs=(evidence_ref,),
        ),
        ReportSection(
            kind=ReportSectionKind.REQUEST_RESPONSE,
            text="trusted request response",
            evidence_refs=(evidence_ref,),
        ),
        ReportSection(
            kind=ReportSectionKind.REPRODUCTION,
            text="trusted reproduction",
            evidence_refs=(evidence_ref,),
        ),
        ReportSection(
            kind=ReportSectionKind.IMPACT,
            text="trusted report impact",
            evidence_refs=(evidence_ref,),
        ),
        ReportSection(kind=ReportSectionKind.REMEDIATION, text="trusted remediation"),
    )
    report_plan = ReportDraftPlan.create(
        finding_id=outcome.finding.finding_id,
        finding_digest=domain_object_digest(outcome.finding),
        candidate_id=outcome.promoted_candidate.candidate_id,
        candidate_digest=domain_object_digest(outcome.promoted_candidate),
        evidence_bundle_id=bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(bundle),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        channel=ReportChannel.GENERIC,
        title="trusted exact report title",
        sections=sections,
        prepared_by="trusted-control-plane",
        created_at=now + timedelta(seconds=15),
        deadline=now + timedelta(seconds=40),
        idempotency_key="report-draft:m8.7",
    )
    return case, promotion_store, execution_plan, outcome, binding_plan, bundle, report_plan


@pytest.mark.parametrize("decision", tuple(AgentReportIntakeDecision))
def test_report_intake_records_human_selection_without_drafting(
    tmp_path, now, approved_scope, candidate, decision
):
    case = _completed_m86_case(tmp_path, now, approved_scope, candidate)
    m85_case, promotion_store, execution_plan, outcome, binding_plan, bundle, report_plan = case
    store = AgentReportIntakeStore(tmp_path / "report-intakes.sqlite3")
    service = AgentReportIntakeService(
        scope=approved_scope,
        finding_promotion_store=promotion_store,
        critic_binding_store=m85_case[6],
        validation_binding_store=m85_case[9],
        validation_store=m85_case[10],
        evidence_store=m85_case[0].evidence_store,
        store=store,
    )
    plan = service.prepare(
        finding_execution_plan=execution_plan,
        critic_binding_plan=binding_plan,
        report_draft_plan=report_plan,
        now=now + timedelta(seconds=16),
        decision_deadline=now + timedelta(seconds=30),
        idempotency_key=f"report-intake:m8.7:{decision.value}",
    )
    reason = {
        AgentReportIntakeDecision.ACCEPT: AgentReportIntakeReason.HUMAN_ACCEPTED_EXACT_DRAFT,
        AgentReportIntakeDecision.REJECT: AgentReportIntakeReason.HUMAN_REJECTED,
        AgentReportIntakeDecision.DEFER: AgentReportIntakeReason.HUMAN_DEFERRED,
    }[decision]
    command = AgentReportIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_report_intake_plan_digest(plan),
        finding_promotion_outcome_id=outcome.outcome_id,
        report_draft_plan_id=report_plan.plan_id,
        report_draft_plan_digest=plan.report_draft_plan_digest,
        report_family_id=report_plan.report_family_id,
        report_version=report_plan.version,
        finding_id=outcome.finding.finding_id,
        decision=decision,
        reason_code=reason,
        reviewer="human-report-reviewer",
        decided_at=now + timedelta(seconds=17),
    )
    before = (
        outcome.promoted_candidate,
        outcome.finding,
        m85_case[-2].calls,
        len(m85_case[-1].calls),
    )
    record = service.decide(
        plan,
        command,
        finding_execution_plan=execution_plan,
        critic_binding_plan=binding_plan,
        report_draft_plan=report_plan,
        now=command.decided_at,
    )
    assert (
        service.decide(
            plan,
            command,
            finding_execution_plan=execution_plan,
            critic_binding_plan=binding_plan,
            report_draft_plan=report_plan,
            now=command.decided_at,
        )
        == record
    )
    assert record.decision is decision
    assert store.load_completed(plan.intake_plan_id) == record
    assert not hasattr(service, "draft")
    assert before == (
        outcome.promoted_candidate,
        outcome.finding,
        m85_case[-2].calls,
        len(m85_case[-1].calls),
    )
    persisted = (tmp_path / "report-intakes.sqlite3").read_bytes()
    for forbidden in (
        b"trusted exact report title",
        b"trusted report summary",
        b"trusted reproduction",
        b"https://",
        b"Authorization",
    ):
        assert forbidden not in persisted
    conflicting_command = AgentReportIntakeCommand.create(
        **command.model_dump(mode="python", exclude={"command_id", "reviewer"}),
        reviewer="second-human-report-reviewer",
    )
    with pytest.raises(AgentReportIntakeConflict):
        service.decide(
            plan,
            conflicting_command,
            finding_execution_plan=execution_plan,
            critic_binding_plan=binding_plan,
            report_draft_plan=report_plan,
            now=conflicting_command.decided_at,
        )
    store.close()
    promotion_store.close()
    _close_m85_case(m85_case)


def test_report_intake_rejects_plan_drift_timeout_and_started_recovery(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_m86_case(tmp_path, now, approved_scope, candidate)
    m85_case, promotion_store, execution_plan, outcome, binding_plan, _, report_plan = case
    store = AgentReportIntakeStore(tmp_path / "report-intakes.sqlite3")
    service = AgentReportIntakeService(
        scope=approved_scope,
        finding_promotion_store=promotion_store,
        critic_binding_store=m85_case[6],
        validation_binding_store=m85_case[9],
        validation_store=m85_case[10],
        evidence_store=m85_case[0].evidence_store,
        store=store,
    )
    with pytest.raises(AgentReportIntakeRejected):
        service.prepare(
            finding_execution_plan=execution_plan,
            critic_binding_plan=binding_plan,
            report_draft_plan=report_plan.model_copy(update={"title": "drifted"}),
            now=now + timedelta(seconds=16),
            decision_deadline=now + timedelta(seconds=30),
            idempotency_key="report-intake:m8.7:drift",
        )
    plan = service.prepare(
        finding_execution_plan=execution_plan,
        critic_binding_plan=binding_plan,
        report_draft_plan=report_plan,
        now=now + timedelta(seconds=16),
        decision_deadline=now + timedelta(seconds=20),
        idempotency_key="report-intake:m8.7:recovery",
    )
    command = AgentReportIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_report_intake_plan_digest(plan),
        finding_promotion_outcome_id=outcome.outcome_id,
        report_draft_plan_id=report_plan.plan_id,
        report_draft_plan_digest=plan.report_draft_plan_digest,
        report_family_id=report_plan.report_family_id,
        report_version=report_plan.version,
        finding_id=outcome.finding.finding_id,
        decision=AgentReportIntakeDecision.ACCEPT,
        reason_code=AgentReportIntakeReason.HUMAN_ACCEPTED_EXACT_DRAFT,
        reviewer="human-report-reviewer",
        decided_at=now + timedelta(seconds=17),
    )
    with pytest.raises(AgentReportIntakeTimedOut):
        service.decide(
            plan,
            command,
            finding_execution_plan=execution_plan,
            critic_binding_plan=binding_plan,
            report_draft_plan=report_plan,
            now=plan.decision_deadline,
        )
    assert store.connection.execute("SELECT count(*) FROM agent_report_intakes").fetchone()[0] == 0
    store.claim(plan, command, now=command.decided_at)
    with pytest.raises(AgentReportIntakeRecoveryRequired):
        service.decide(
            plan,
            command,
            finding_execution_plan=execution_plan,
            critic_binding_plan=binding_plan,
            report_draft_plan=report_plan,
            now=command.decided_at,
        )
    store.close()
    promotion_store.close()
    _close_m85_case(m85_case)


@pytest.mark.parametrize("tamper", ("missing", "promotion", "evidence"))
def test_report_intake_rejects_missing_or_corrupt_authoritative_inputs(
    tmp_path, now, approved_scope, candidate, tamper
):
    case = _completed_m86_case(tmp_path, now, approved_scope, candidate)
    m85_case, promotion_store, execution_plan, _, binding_plan, bundle, report_plan = case
    active_promotion_store = promotion_store
    if tamper == "missing":
        active_promotion_store = FindingPromotionStore(
            tmp_path / "missing-finding-promotions.sqlite3"
        )
    elif tamper == "promotion":
        row = promotion_store.connection.execute(
            "SELECT outcome_json FROM finding_promotions WHERE execution_plan_id=?",
            (execution_plan.execution_plan_id,),
        ).fetchone()
        payload = json.loads(row[0])
        payload["finding"]["state"] = "tampered"
        promotion_store.connection.execute(
            "UPDATE finding_promotions SET outcome_json=? WHERE execution_plan_id=?",
            (json.dumps(payload), execution_plan.execution_plan_id),
        )
        promotion_store.connection.commit()
    else:
        (m85_case[0].evidence_store.objects / bundle.evidence_refs[0]).write_bytes(b"tampered")
    store = AgentReportIntakeStore(tmp_path / "report-intakes.sqlite3")
    service = AgentReportIntakeService(
        scope=approved_scope,
        finding_promotion_store=active_promotion_store,
        critic_binding_store=m85_case[6],
        validation_binding_store=m85_case[9],
        validation_store=m85_case[10],
        evidence_store=m85_case[0].evidence_store,
        store=store,
    )
    with pytest.raises(AgentReportIntakeRejected):
        service.prepare(
            finding_execution_plan=execution_plan,
            critic_binding_plan=binding_plan,
            report_draft_plan=report_plan,
            now=now + timedelta(seconds=16),
            decision_deadline=now + timedelta(seconds=30),
            idempotency_key=f"report-intake:m8.7:{tamper}",
        )
    assert store.connection.execute("SELECT count(*) FROM agent_report_intakes").fetchone()[0] == 0
    store.close()
    if active_promotion_store is not promotion_store:
        active_promotion_store.close()
    promotion_store.close()
    _close_m85_case(m85_case)


def test_report_intake_contracts_and_sqlite_are_digest_only():
    forbidden = {
        "title",
        "sections",
        "text",
        "prompt",
        "runner",
        "broker",
        "url",
        "credential",
        "token",
        "submission",
    }
    for model in (AgentReportIntakePlan, AgentReportIntakeRecord):
        assert not set(model.model_fields) & forbidden


def _completed_m87_case(
    tmp_path,
    now,
    scope,
    candidate,
    *,
    decision=AgentReportIntakeDecision.ACCEPT,
):
    m86_case = _completed_m86_case(tmp_path, now, scope, candidate)
    m85_case, promotion_store, execution_plan, outcome, binding_plan, bundle, report_plan = m86_case
    intake_store = AgentReportIntakeStore(tmp_path / "report-intakes-m8.8.sqlite3")
    intake_service = AgentReportIntakeService(
        scope=scope,
        finding_promotion_store=promotion_store,
        critic_binding_store=m85_case[6],
        validation_binding_store=m85_case[9],
        validation_store=m85_case[10],
        evidence_store=m85_case[0].evidence_store,
        store=intake_store,
    )
    intake_plan = intake_service.prepare(
        finding_execution_plan=execution_plan,
        critic_binding_plan=binding_plan,
        report_draft_plan=report_plan,
        now=now + timedelta(seconds=16),
        decision_deadline=now + timedelta(seconds=30),
        idempotency_key=f"report-intake:m8.8:{decision.value}",
    )
    reason = {
        AgentReportIntakeDecision.ACCEPT: AgentReportIntakeReason.HUMAN_ACCEPTED_EXACT_DRAFT,
        AgentReportIntakeDecision.REJECT: AgentReportIntakeReason.HUMAN_REJECTED,
        AgentReportIntakeDecision.DEFER: AgentReportIntakeReason.HUMAN_DEFERRED,
    }[decision]
    command = AgentReportIntakeCommand.create(
        intake_plan_id=intake_plan.intake_plan_id,
        intake_plan_digest=agent_report_intake_plan_digest(intake_plan),
        finding_promotion_outcome_id=outcome.outcome_id,
        report_draft_plan_id=report_plan.plan_id,
        report_draft_plan_digest=intake_plan.report_draft_plan_digest,
        report_family_id=report_plan.report_family_id,
        report_version=report_plan.version,
        finding_id=outcome.finding.finding_id,
        decision=decision,
        reason_code=reason,
        reviewer="human-report-execution-reviewer",
        decided_at=now + timedelta(seconds=17),
    )
    record = intake_service.decide(
        intake_plan,
        command,
        finding_execution_plan=execution_plan,
        critic_binding_plan=binding_plan,
        report_draft_plan=report_plan,
        now=command.decided_at,
    )
    evidence_store = m85_case[0].evidence_store
    evidence_ref = bundle.evidence_refs[0]
    evidence = evidence_store.capture_text(
        evidence_store.read_text_ref(evidence_ref),
        kind=EvidenceKind.TEST,
        source_ref="m8.8-authoritative-local-evidence",
        producer="test.m8.8",
        target_version=candidate.target_version,
        summary="M8.8 authoritative Evidence metadata",
    )
    assert evidence.evidence_id == evidence_ref
    return m86_case, intake_store, intake_service, intake_plan, record, (evidence,)


def _report_execution_service(tmp_path, scope, intake_service):
    report_store = ReportDraftStore(tmp_path / "report-drafts-m8.8.sqlite3")
    artifact_store = ReportArtifactStore(tmp_path / "report-artifacts-m8.8")
    report_service = DeterministicReportService(
        scope=scope,
        evidence_store=intake_service.evidence_store,
        store=report_store,
        artifact_store=artifact_store,
    )
    execution_store = AgentReportDraftExecutionStore(
        tmp_path / "agent-report-draft-executions.sqlite3"
    )
    service = AgentReportDraftExecutionService(
        intake_service=intake_service,
        report_service=report_service,
        store=execution_store,
    )
    return service, execution_store, report_store, artifact_store


def _close_m88_case(case, execution_store=None, report_store=None):
    m86_case, intake_store, *_ = case
    if execution_store is not None:
        execution_store.close()
    if report_store is not None:
        report_store.close()
    intake_store.close()
    m85_case, promotion_store, *_ = m86_case
    promotion_store.close()
    _close_m85_case(m85_case)


def test_accepted_report_intake_executes_one_local_draft_and_binds_result(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_m87_case(tmp_path, now, approved_scope, candidate)
    m86_case, _, intake_service, intake_plan, record, evidence = case
    m85_case, _, finding_plan, promotion_outcome, critic_plan, _, report_plan = m86_case
    service, store, report_store, artifact_store = _report_execution_service(
        tmp_path, approved_scope, intake_service
    )
    plan = service.prepare(
        report_intake_plan=intake_plan,
        finding_execution_plan=finding_plan,
        critic_binding_plan=critic_plan,
        report_draft_plan=report_plan,
        evidence=evidence,
        now=now + timedelta(seconds=18),
        deadline=now + timedelta(seconds=29),
        idempotency_key="report-draft-execution:m8.8",
    )
    calls_before = (m85_case[-2].calls, len(m85_case[-1].calls))
    binding = service.execute(
        plan,
        report_intake_plan=intake_plan,
        finding_execution_plan=finding_plan,
        critic_binding_plan=critic_plan,
        report_draft_plan=report_plan,
        evidence=evidence,
        now=now + timedelta(seconds=19),
    )
    outcome = report_store.load_completed(report_plan.plan_id)
    assert binding == store.load_completed(plan.execution_plan_id)
    assert binding.report_id == outcome.report.report_id
    assert binding.review_status.value == "draft"
    assert artifact_store.read_report(outcome.artifact) == outcome.report
    assert "trusted exact report title" in artifact_store.read_markdown(outcome.artifact)
    assert promotion_outcome.promoted_candidate.state is CandidateState.PROMOTED
    assert candidate.state is CandidateState.PROPOSED
    assert (m85_case[-2].calls, len(m85_case[-1].calls)) == calls_before
    assert (
        service.execute(
            plan,
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=now + timedelta(seconds=20),
        )
        == binding
    )
    persisted = (tmp_path / "agent-report-draft-executions.sqlite3").read_bytes()
    for forbidden in (
        b"trusted exact report title",
        b"trusted report summary",
        b"trusted reproduction",
        b"Authorization",
        b"submission",
    ):
        assert forbidden not in persisted
    conflicting = AgentReportDraftExecutionPlan.create(
        **plan.model_dump(mode="python", exclude={"execution_plan_id", "idempotency_key"}),
        idempotency_key="report-draft-execution:m8.8:conflict",
    )
    with pytest.raises(AgentReportDraftExecutionConflict):
        store.claim(conflicting, now=now + timedelta(seconds=21))
    assert record.decision is AgentReportIntakeDecision.ACCEPT
    _close_m88_case(case, store, report_store)


@pytest.mark.parametrize(
    "decision", (AgentReportIntakeDecision.REJECT, AgentReportIntakeDecision.DEFER)
)
def test_report_draft_execution_rejects_nonaccepted_intake_before_checkpoint(
    tmp_path, now, approved_scope, candidate, decision
):
    case = _completed_m87_case(tmp_path, now, approved_scope, candidate, decision=decision)
    m86_case, _, intake_service, intake_plan, _, evidence = case
    _, _, finding_plan, _, critic_plan, _, report_plan = m86_case
    service, store, report_store, _ = _report_execution_service(
        tmp_path, approved_scope, intake_service
    )
    with pytest.raises(AgentReportDraftExecutionRejected, match="Intake"):
        service.prepare(
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=now + timedelta(seconds=18),
            deadline=now + timedelta(seconds=29),
            idempotency_key=f"report-draft-execution:m8.8:{decision.value}",
        )
    assert (
        store.connection.execute("SELECT count(*) FROM agent_report_draft_executions").fetchone()[0]
        == 0
    )
    assert not report_store.has_checkpoint(report_plan.plan_id)
    _close_m88_case(case, store, report_store)


def test_report_draft_execution_refuses_drift_timeout_and_started_recovery(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_m87_case(tmp_path, now, approved_scope, candidate)
    m86_case, _, intake_service, intake_plan, _, evidence = case
    _, _, finding_plan, _, critic_plan, _, report_plan = m86_case
    service, store, report_store, _ = _report_execution_service(
        tmp_path, approved_scope, intake_service
    )
    plan = service.prepare(
        report_intake_plan=intake_plan,
        finding_execution_plan=finding_plan,
        critic_binding_plan=critic_plan,
        report_draft_plan=report_plan,
        evidence=evidence,
        now=now + timedelta(seconds=18),
        deadline=now + timedelta(seconds=25),
        idempotency_key="report-draft-execution:m8.8:recovery",
    )
    with pytest.raises(AgentReportDraftExecutionTimedOut):
        service.execute(
            plan,
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=plan.deadline,
        )
    with pytest.raises(AgentReportDraftExecutionRejected, match="drifted"):
        service.execute(
            plan.model_copy(update={"evidence_catalog_digest": "f" * 64}),
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=now + timedelta(seconds=19),
        )
    assert not report_store.has_checkpoint(report_plan.plan_id)
    store.claim(plan, now=now + timedelta(seconds=19))
    with pytest.raises(AgentReportDraftExecutionRecoveryRequired):
        service.execute(
            plan,
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=now + timedelta(seconds=20),
        )
    _close_m88_case(case, store, report_store)


def test_report_draft_execution_refuses_preexisting_unbound_draft(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_m87_case(tmp_path, now, approved_scope, candidate)
    m86_case, _, intake_service, intake_plan, _, evidence = case
    _, _, finding_plan, promotion_outcome, critic_plan, bundle, report_plan = m86_case
    service, store, report_store, _ = _report_execution_service(
        tmp_path, approved_scope, intake_service
    )
    service.report_service.draft(
        promotion_outcome.finding,
        promotion_outcome.promoted_candidate,
        bundle,
        evidence,
        report_plan,
        now=now + timedelta(seconds=18),
    )
    plan = service.prepare(
        report_intake_plan=intake_plan,
        finding_execution_plan=finding_plan,
        critic_binding_plan=critic_plan,
        report_draft_plan=report_plan,
        evidence=evidence,
        now=now + timedelta(seconds=19),
        deadline=now + timedelta(seconds=29),
        idempotency_key="report-draft-execution:m8.8:preexisting",
    )
    with pytest.raises(AgentReportDraftExecutionRejected, match="predates"):
        service.execute(
            plan,
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=now + timedelta(seconds=20),
        )
    assert (
        store.connection.execute("SELECT count(*) FROM agent_report_draft_executions").fetchone()[0]
        == 0
    )
    _close_m88_case(case, store, report_store)


def test_report_draft_execution_failure_cleans_artifacts_and_requires_recovery(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_m87_case(tmp_path, now, approved_scope, candidate)
    m86_case, _, intake_service, intake_plan, _, evidence = case
    _, _, finding_plan, _, critic_plan, _, report_plan = m86_case
    report_store = ReportDraftStore(tmp_path / "report-drafts-m8.8.sqlite3")
    artifact_store = ReportArtifactStore(tmp_path / "report-artifacts-m8.8", max_artifact_bytes=1)
    execution_store = AgentReportDraftExecutionStore(
        tmp_path / "agent-report-draft-executions.sqlite3"
    )
    service = AgentReportDraftExecutionService(
        intake_service=intake_service,
        report_service=DeterministicReportService(
            scope=approved_scope,
            evidence_store=intake_service.evidence_store,
            store=report_store,
            artifact_store=artifact_store,
        ),
        store=execution_store,
    )
    plan = service.prepare(
        report_intake_plan=intake_plan,
        finding_execution_plan=finding_plan,
        critic_binding_plan=critic_plan,
        report_draft_plan=report_plan,
        evidence=evidence,
        now=now + timedelta(seconds=18),
        deadline=now + timedelta(seconds=29),
        idempotency_key="report-draft-execution:m8.8:artifact-failure",
    )
    with pytest.raises(AgentReportDraftExecutionRejected, match="failed"):
        service.execute(
            plan,
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=now + timedelta(seconds=19),
        )
    assert not tuple(artifact_store.objects.iterdir())
    with pytest.raises(AgentReportDraftExecutionRecoveryRequired):
        service.execute(
            plan,
            report_intake_plan=intake_plan,
            finding_execution_plan=finding_plan,
            critic_binding_plan=critic_plan,
            report_draft_plan=report_plan,
            evidence=evidence,
            now=now + timedelta(seconds=20),
        )
    _close_m88_case(case, execution_store, report_store)


def test_report_draft_execution_contracts_are_digest_only():
    forbidden = {
        "title",
        "sections",
        "text",
        "prompt",
        "runner",
        "broker",
        "url",
        "credential",
        "token",
        "submission",
    }
    for model in (AgentReportDraftExecutionPlan, AgentReportDraftOutcomeBinding):
        assert not set(model.model_fields) & forbidden


def _completed_m88_case(tmp_path, now, scope, candidate):
    m87_case = _completed_m87_case(tmp_path, now, scope, candidate)
    m86_case, _, intake_service, intake_plan, _, evidence = m87_case
    _, _, finding_plan, _, critic_plan, bundle, report_plan = m86_case
    execution_service, execution_store, report_store, artifact_store = _report_execution_service(
        tmp_path, scope, intake_service
    )
    execution_plan = execution_service.prepare(
        report_intake_plan=intake_plan,
        finding_execution_plan=finding_plan,
        critic_binding_plan=critic_plan,
        report_draft_plan=report_plan,
        evidence=evidence,
        now=now + timedelta(seconds=18),
        deadline=now + timedelta(seconds=29),
        idempotency_key="report-draft-execution:m8.9",
    )
    binding = execution_service.execute(
        execution_plan,
        report_intake_plan=intake_plan,
        finding_execution_plan=finding_plan,
        critic_binding_plan=critic_plan,
        report_draft_plan=report_plan,
        evidence=evidence,
        now=now + timedelta(seconds=19),
    )
    outcome = report_store.load_completed(report_plan.plan_id)
    review_plan = ReportReviewPlan.create(
        report=outcome.report,
        artifact=outcome.artifact,
        evidence_bundle_digest=domain_object_digest(bundle),
        reviewer="future-human-report-reviewer",
        diff_id=None,
        created_at=now + timedelta(seconds=20),
        deadline=now + timedelta(seconds=28),
        approval_expires_at=now + timedelta(seconds=29),
        idempotency_key="report-review:m8.9",
    )
    return (
        m87_case,
        execution_store,
        report_store,
        artifact_store,
        execution_plan,
        binding,
        outcome,
        bundle,
        evidence,
        review_plan,
    )


def _close_m89_case(case, review_intake_store=None):
    m87_case, execution_store, report_store, *_ = case
    if review_intake_store is not None:
        review_intake_store.close()
    _close_m88_case(m87_case, execution_store, report_store)


def _report_review_intake_service(tmp_path, scope, case):
    (
        m87_case,
        execution_store,
        report_store,
        artifact_store,
        *_,
    ) = case
    evidence_store = m87_case[2].evidence_store
    store = AgentReportReviewIntakeStore(tmp_path / "report-review-intakes-m8.9.sqlite3")
    service = AgentReportReviewIntakeService(
        scope=scope,
        draft_execution_store=execution_store,
        report_store=report_store,
        artifact_store=artifact_store,
        evidence_store=evidence_store,
        store=store,
    )
    return service, store


@pytest.mark.parametrize("decision", tuple(AgentReportReviewIntakeDecision))
def test_report_review_intake_records_human_selection_without_reviewing(
    tmp_path, now, approved_scope, candidate, decision
):
    case = _completed_m88_case(tmp_path, now, approved_scope, candidate)
    (
        m87_case,
        _,
        report_store,
        _,
        execution_plan,
        binding,
        outcome,
        bundle,
        evidence,
        review_plan,
    ) = case
    service, store = _report_review_intake_service(tmp_path, approved_scope, case)
    plan = service.prepare(
        draft_execution_plan=execution_plan,
        report_review_plan=review_plan,
        evidence_bundle=bundle,
        evidence=evidence,
        now=now + timedelta(seconds=21),
        decision_deadline=now + timedelta(seconds=27),
        idempotency_key=f"report-review-intake:m8.9:{decision.value}",
    )
    reason = {
        AgentReportReviewIntakeDecision.ACCEPT: (
            AgentReportReviewIntakeReason.HUMAN_ACCEPTED_EXACT_REVIEW
        ),
        AgentReportReviewIntakeDecision.REJECT: AgentReportReviewIntakeReason.HUMAN_REJECTED,
        AgentReportReviewIntakeDecision.DEFER: AgentReportReviewIntakeReason.HUMAN_DEFERRED,
    }[decision]
    command = AgentReportReviewIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_report_review_intake_plan_digest(plan),
        draft_outcome_binding_id=binding.binding_id,
        report_review_plan_id=review_plan.plan_id,
        report_review_plan_digest=plan.report_review_plan_digest,
        report_id=outcome.report.report_id,
        report_digest=plan.report_digest,
        decision=decision,
        reason_code=reason,
        reviewer="human-review-intake-reviewer",
        decided_at=now + timedelta(seconds=22),
    )
    m85_case = m87_case[0][0]
    calls_before = (m85_case[-2].calls, len(m85_case[-1].calls))
    record = service.decide(
        plan,
        command,
        draft_execution_plan=execution_plan,
        report_review_plan=review_plan,
        evidence_bundle=bundle,
        evidence=evidence,
        now=command.decided_at,
    )
    assert record.decision is decision
    assert store.load_completed(plan.intake_plan_id) == record
    assert (
        service.decide(
            plan,
            command,
            draft_execution_plan=execution_plan,
            report_review_plan=review_plan,
            evidence_bundle=bundle,
            evidence=evidence,
            now=now + timedelta(seconds=23),
        )
        == record
    )
    assert report_store.load_completed(outcome.plan_id).report.review_status.value == "draft"
    assert candidate.state is CandidateState.PROPOSED
    assert (m85_case[-2].calls, len(m85_case[-1].calls)) == calls_before
    assert not hasattr(service, "review")
    persisted = (tmp_path / "report-review-intakes-m8.9.sqlite3").read_bytes()
    for forbidden in (
        b"trusted exact report title",
        b"trusted report summary",
        b"trusted reproduction",
        b"Authorization",
        b"submission",
    ):
        assert forbidden not in persisted
    conflicting_command = AgentReportReviewIntakeCommand.create(
        **command.model_dump(mode="python", exclude={"command_id", "reviewer"}),
        reviewer="second-human-review-intake-reviewer",
    )
    with pytest.raises(AgentReportReviewIntakeConflict):
        service.decide(
            plan,
            conflicting_command,
            draft_execution_plan=execution_plan,
            report_review_plan=review_plan,
            evidence_bundle=bundle,
            evidence=evidence,
            now=now + timedelta(seconds=23),
        )
    _close_m89_case(case, store)


def test_report_review_intake_rejects_drift_timeout_and_started_recovery(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_m88_case(tmp_path, now, approved_scope, candidate)
    *_, execution_plan, binding, outcome, bundle, evidence, review_plan = case
    service, store = _report_review_intake_service(tmp_path, approved_scope, case)
    with pytest.raises(AgentReportReviewIntakeRejected):
        service.prepare(
            draft_execution_plan=execution_plan,
            report_review_plan=review_plan.model_copy(update={"reviewer": "drifted"}),
            evidence_bundle=bundle,
            evidence=evidence,
            now=now + timedelta(seconds=21),
            decision_deadline=now + timedelta(seconds=27),
            idempotency_key="report-review-intake:m8.9:drift",
        )
    plan = service.prepare(
        draft_execution_plan=execution_plan,
        report_review_plan=review_plan,
        evidence_bundle=bundle,
        evidence=evidence,
        now=now + timedelta(seconds=21),
        decision_deadline=now + timedelta(seconds=25),
        idempotency_key="report-review-intake:m8.9:recovery",
    )
    command = AgentReportReviewIntakeCommand.create(
        intake_plan_id=plan.intake_plan_id,
        intake_plan_digest=agent_report_review_intake_plan_digest(plan),
        draft_outcome_binding_id=binding.binding_id,
        report_review_plan_id=review_plan.plan_id,
        report_review_plan_digest=plan.report_review_plan_digest,
        report_id=outcome.report.report_id,
        report_digest=plan.report_digest,
        decision=AgentReportReviewIntakeDecision.ACCEPT,
        reason_code=AgentReportReviewIntakeReason.HUMAN_ACCEPTED_EXACT_REVIEW,
        reviewer="human-review-intake-reviewer",
        decided_at=now + timedelta(seconds=22),
    )
    with pytest.raises(AgentReportReviewIntakeTimedOut):
        service.decide(
            plan,
            command,
            draft_execution_plan=execution_plan,
            report_review_plan=review_plan,
            evidence_bundle=bundle,
            evidence=evidence,
            now=plan.decision_deadline,
        )
    assert (
        store.connection.execute("SELECT count(*) FROM agent_report_review_intakes").fetchone()[0]
        == 0
    )
    store.claim(plan, command, now=command.decided_at)
    with pytest.raises(AgentReportReviewIntakeRecoveryRequired):
        service.decide(
            plan,
            command,
            draft_execution_plan=execution_plan,
            report_review_plan=review_plan,
            evidence_bundle=bundle,
            evidence=evidence,
            now=command.decided_at,
        )
    _close_m89_case(case, store)


def test_report_review_intake_rejects_corrupt_draft_artifact_before_checkpoint(
    tmp_path, now, approved_scope, candidate
):
    case = _completed_m88_case(tmp_path, now, approved_scope, candidate)
    _, _, _, artifact_store, execution_plan, _, outcome, bundle, evidence, review_plan = case
    service, store = _report_review_intake_service(tmp_path, approved_scope, case)
    artifact_path = artifact_store.root / outcome.artifact.markdown_ref
    artifact_path.chmod(0o600)
    artifact_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(AgentReportReviewIntakeRejected, match="unavailable"):
        service.prepare(
            draft_execution_plan=execution_plan,
            report_review_plan=review_plan,
            evidence_bundle=bundle,
            evidence=evidence,
            now=now + timedelta(seconds=21),
            decision_deadline=now + timedelta(seconds=27),
            idempotency_key="report-review-intake:m8.9:artifact",
        )
    assert (
        store.connection.execute("SELECT count(*) FROM agent_report_review_intakes").fetchone()[0]
        == 0
    )
    _close_m89_case(case, store)


def test_report_review_intake_contracts_are_digest_only():
    forbidden = {
        "title",
        "sections",
        "text",
        "prompt",
        "runner",
        "broker",
        "url",
        "credential",
        "token",
        "approval",
        "submission",
    }
    for model in (
        AgentReportReviewIntakePlan,
        AgentReportReviewIntakeRecord,
    ):
        assert not set(model.model_fields) & forbidden
