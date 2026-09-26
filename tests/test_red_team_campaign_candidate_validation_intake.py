from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    ScopeState,
)
from vulnloom.red_team.campaign_candidate_models import (
    CampaignCandidate,
    CampaignCandidateIntakeLimits,
    CampaignCandidateIntakeOutcome,
    CampaignCandidateIntakePlan,
)
from vulnloom.red_team.campaign_candidate_state_machine import (
    CampaignCandidateTransitionRejected,
    admit_campaign_candidate_validation,
)
from vulnloom.red_team.campaign_candidate_validation_models import (
    REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS,
    CampaignCandidateLifecycleCheckpoint,
    CampaignCandidateValidationIntakeLimits,
    CampaignCandidateValidationIntakeOutcome,
    CampaignCandidateValidationIntakePlan,
    CampaignCandidateValidationIntakeState,
)
from vulnloom.red_team.campaign_candidate_validation_service import (
    CampaignCandidateValidationIntakeRejected,
    CampaignCandidateValidationIntakeService,
    CampaignCandidateValidationIntakeTimedOut,
)
from vulnloom.red_team.campaign_candidate_validation_store import (
    CampaignCandidateValidationIntakeRecoveryRequired,
    CampaignCandidateValidationIntakeStore,
)
from vulnloom.red_team.evidence_requirement_models import VulnerabilityClass


def _digest(number: int) -> str:
    return f"{number:064x}"


class _Source:
    def __init__(self, plan, outcome):
        self._plan = plan
        self._outcome = outcome

    def plan(self, plan_id):
        if plan_id != self._plan.intake_plan_id:
            raise KeyError(plan_id)
        return self._plan

    def outcome(self, plan_id):
        self.plan(plan_id)
        return self._outcome


def _candidate_source(scope, now):
    closure_id = _digest(1)
    candidate_id = uuid5(NAMESPACE_URL, f"vulnloom:campaign-candidate:{closure_id}")
    target_id = uuid4()
    target_version = _digest(2)
    vulnerability_class = VulnerabilityClass.UNAUTHENTICATED_SENSITIVE_DATA_EXPOSURE
    cwe = "CWE-200"
    evidence_refs = tuple(_digest(10 + index) for index in range(5))
    fingerprint = canonical_digest(
        {
            "target_id": target_id,
            "target_version": target_version,
            "vulnerability_class": vulnerability_class,
            "cwe": cwe,
        }
    )
    plan = CampaignCandidateIntakePlan.create(
        orchestration_plan_id=_digest(20),
        orchestration_plan_digest=_digest(21),
        orchestration_outcome_digest=_digest(22),
        closure_id=closure_id,
        assessment_plan_id=_digest(23),
        assessment_plan_digest=_digest(24),
        assessment_id=_digest(25),
        assessment_outcome_digest=_digest(26),
        candidate_id=candidate_id,
        target_id=target_id,
        target_version=target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        vulnerability_class=vulnerability_class,
        cwe=cwe,
        hypothesis_digest=_digest(27),
        evidence_refs=evidence_refs,
        duplicate_fingerprint=fingerprint,
        limits=CampaignCandidateIntakeLimits(),
        created_at=now - timedelta(minutes=2),
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.7:candidate-intake",
    )
    candidate = CampaignCandidate.create(
        candidate_id=candidate_id,
        target_id=target_id,
        target_version=target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        vulnerability_class=vulnerability_class,
        cwe=cwe,
        hypothesis_digest=plan.hypothesis_digest,
        duplicate_fingerprint=fingerprint,
        orchestration_plan_id=plan.orchestration_plan_id,
        closure_id=closure_id,
        assessment_id=plan.assessment_id,
        evidence_refs=evidence_refs,
        created_at=now - timedelta(minutes=1),
    )
    outcome = CampaignCandidateIntakeOutcome.create(
        intake_plan_id=plan.intake_plan_id,
        approval_id=uuid4(),
        candidate=candidate,
        attempt=1,
        completed_at=now - timedelta(minutes=1),
    )
    return plan, outcome


def _bundle(scope, now, *, monotonic=None, after_claim=None):
    candidate_plan, candidate_outcome = _candidate_source(scope, now)
    connection = sqlite3.connect(":memory:")
    store = CampaignCandidateValidationIntakeStore(connection)
    service = CampaignCandidateValidationIntakeService(
        candidate_source=_Source(candidate_plan, candidate_outcome),
        store=store,
        after_claim=after_claim,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    return service, store, connection, candidate_plan, candidate_outcome


def _prepare(service, candidate_plan, scope, now):
    return service.prepare(
        candidate_intake_plan_id=candidate_plan.intake_plan_id,
        scope=scope,
        limits=CampaignCandidateValidationIntakeLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.7:validation-intake",
    )


def _approval(plan, scope, now, *, action=None, status=ApprovalStatus.GRANTED):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.target_id,
        action=action or ApprovalAction.QUEUE_CAMPAIGN_CANDIDATE_VALIDATION,
        action_digest=plan.validation_intake_plan_id,
        expected_side_effects=("queue campaign candidate validation",),
        evidence_summary="reviewed exact fresh validation intake",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=status,
        decided_by="operator",
        decided_at=now,
    )


def test_exact_queue_approval_advances_only_to_validation_pending(approved_scope, now):
    service, store, connection, candidate_plan, candidate_outcome = _bundle(approved_scope, now)
    plan = _prepare(service, candidate_plan, approved_scope, now)
    outcome = service.execute(
        plan,
        approval=_approval(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    checkpoint = outcome.checkpoint
    assert candidate_outcome.candidate.state is CandidateState.PROPOSED
    assert checkpoint.previous_state is CandidateState.PROPOSED
    assert checkpoint.state is CandidateState.VALIDATION_PENDING
    assert checkpoint.required_fresh_facts == REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
    assert checkpoint.prior_campaign_evidence_accepted_as_validation is False
    assert outcome.validation_admitted is True
    assert outcome.validation_started is False
    assert outcome.validation_run_created is False
    assert outcome.finding_created is False
    assert store.checkpoint(plan.candidate_id) == checkpoint
    assert store.state(plan.validation_intake_plan_id) == (
        CampaignCandidateValidationIntakeState.COMPLETED,
        1,
    )
    assert (
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
        == outcome
    )
    connection.close()


def test_run_validation_approval_cannot_be_reused_for_queue(approved_scope, now):
    service, store, connection, candidate_plan, _ = _bundle(approved_scope, now)
    plan = _prepare(service, candidate_plan, approved_scope, now)
    with pytest.raises(CampaignCandidateValidationIntakeRejected, match="Approval"):
        service.execute(
            plan,
            approval=_approval(
                plan,
                approved_scope,
                now,
                action=ApprovalAction.RUN_VALIDATION,
            ),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.validation_intake_plan_id) is None
    connection.close()


def test_scope_and_candidate_source_drift_fail_before_state_change(approved_scope, now):
    service, store, connection, candidate_plan, candidate_outcome = _bundle(approved_scope, now)
    plan = _prepare(service, candidate_plan, approved_scope, now)
    approval = _approval(plan, approved_scope, now)
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(CampaignCandidateValidationIntakeRejected, match="approved Scope"):
        service.execute(plan, approval=approval, scope=revoked, now=now)

    candidate = candidate_outcome.candidate.model_copy(update={"state": CandidateState.PROMOTED})
    service.candidate_source._outcome = candidate_outcome.model_copy(
        update={"candidate": candidate}
    )
    with pytest.raises(CampaignCandidateValidationIntakeRejected, match="source binding"):
        service.execute(plan, approval=approval, scope=approved_scope, now=now)
    assert store.state(plan.validation_intake_plan_id) is None
    with pytest.raises(KeyError):
        store.checkpoint(plan.candidate_id)
    connection.close()


def test_timeout_leaves_no_lifecycle_checkpoint(approved_scope, now):
    ticks = iter((0.0, 11.0))
    service, store, connection, candidate_plan, _ = _bundle(
        approved_scope, now, monotonic=lambda: next(ticks)
    )
    plan = _prepare(service, candidate_plan, approved_scope, now)
    with pytest.raises(CampaignCandidateValidationIntakeTimedOut):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.validation_intake_plan_id) is None
    with pytest.raises(KeyError):
        store.checkpoint(plan.candidate_id)
    connection.close()


def test_interrupted_validation_intake_recovers_without_duplicate_transition(approved_scope, now):
    def interrupt():
        raise RuntimeError("fixture interruption")

    service, store, connection, candidate_plan, _ = _bundle(
        approved_scope, now, after_claim=interrupt
    )
    plan = _prepare(service, candidate_plan, approved_scope, now)
    approval = _approval(plan, approved_scope, now)
    with pytest.raises(RuntimeError, match="fixture interruption"):
        service.execute(plan, approval=approval, scope=approved_scope, now=now)
    assert store.state(plan.validation_intake_plan_id) == (
        CampaignCandidateValidationIntakeState.STARTED,
        1,
    )
    service.after_claim = None
    outcome = service.execute(plan, approval=approval, scope=approved_scope, now=now)
    assert outcome.attempt == 2
    assert store.checkpoint(plan.candidate_id) == outcome.checkpoint
    connection.close()


def test_recovery_limit_state_machine_and_schema_are_fail_closed(approved_scope, now):
    def interrupt():
        raise RuntimeError("fixture interruption")

    service, store, connection, candidate_plan, _ = _bundle(
        approved_scope, now, after_claim=interrupt
    )
    plan = _prepare(service, candidate_plan, approved_scope, now)
    approval = _approval(plan, approved_scope, now)
    for _ in range(3):
        with pytest.raises(RuntimeError, match="fixture interruption"):
            service.execute(plan, approval=approval, scope=approved_scope, now=now)
    with pytest.raises(CampaignCandidateValidationIntakeRecoveryRequired, match="exhausted"):
        service.execute(plan, approval=approval, scope=approved_scope, now=now)
    with pytest.raises(CampaignCandidateTransitionRejected):
        admit_campaign_candidate_validation(CandidateState.VALIDATED)

    schemas = json.dumps(
        {
            model.__name__: model.model_json_schema()
            for model in (
                CampaignCandidateValidationIntakePlan,
                CampaignCandidateLifecycleCheckpoint,
                CampaignCandidateValidationIntakeOutcome,
            )
        }
    ).lower()
    for forbidden in (
        "target_url",
        "cookie",
        "password",
        "model_token",
        "docker_socket",
        "raw_response",
        "payload",
        "command",
    ):
        assert forbidden not in schemas
    with pytest.raises(ValidationError):
        CampaignCandidateValidationIntakePlan.model_validate(
            plan.model_dump(mode="python")
            | {
                "prior_campaign_evidence_accepted_as_validation": True,
                "validation_execution_requested": True,
                "critic_bypass_requested": True,
                "finding_creation_requested": True,
            }
        )
    connection.close()
