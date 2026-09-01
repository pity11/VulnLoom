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
    CounterevidenceAssessment,
    CounterevidenceDisposition,
    CriticPlan,
    agent_critic_intake_plan_digest,
    domain_object_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import EvidenceBundle, EvidenceKind, ValidationResult
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.hypotheses import CandidateSet, CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.policy import PolicyEngine
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
