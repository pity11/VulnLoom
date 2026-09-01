from __future__ import annotations

import json
import os
from datetime import timedelta

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
from vulnloom.broker import OfflineHttpTransport, StaticResolver, ToolBroker, default_tool_registry
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.hypotheses import CandidateSet, CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.policy import PolicyEngine
from vulnloom.runners import OfflineSandboxRunner, ToolInvocation, validation_profile
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
    AgentValidationOutcomeBindingRecoveryRequired,
    AgentValidationOutcomeBindingRejected,
    AgentValidationOutcomeBindingService,
    AgentValidationOutcomeBindingStore,
    ValidationPlan,
    ValidationService,
    ValidationStore,
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


def _fixture(tmp_path, now, scope, candidate, *, completed=True):
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
    validation_plan = _validation_plan(now, scope, candidate)
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
