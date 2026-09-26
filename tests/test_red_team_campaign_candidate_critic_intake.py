from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import pytest
from pydantic import ValidationError
from test_red_team_campaign_candidate_validation_execution import (
    _approval as validation_approval,
)
from test_red_team_campaign_candidate_validation_execution import _bundle, _digest

from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    ScopeState,
)
from vulnloom.red_team.campaign_candidate_critic_models import (
    REQUIRED_CAMPAIGN_CRITIC_ANGLES,
    CampaignCandidateCriticIntakeCheckpoint,
    CampaignCandidateCriticIntakeLimits,
    CampaignCandidateCriticIntakeOutcome,
    CampaignCandidateCriticIntakePlan,
    CampaignCandidateCriticLifecycleState,
)
from vulnloom.red_team.campaign_candidate_critic_service import (
    CampaignCandidateCriticIntakeRejected,
    CampaignCandidateCriticIntakeService,
    CampaignCandidateCriticIntakeTimedOut,
)
from vulnloom.red_team.campaign_candidate_critic_store import (
    CampaignCandidateCriticIntakeRecoveryRequired,
    CampaignCandidateCriticIntakeState,
    CampaignCandidateCriticIntakeStore,
)
from vulnloom.red_team.campaign_candidate_state_machine import (
    CampaignCandidateTransitionRejected,
    admit_campaign_candidate_critic,
)


def _case(scope, now, *, monotonic=None):
    validation_service, validation_store, validation_connection, validation_plan, *_ = _bundle(
        scope, now
    )
    validation_outcome = validation_service.execute(
        validation_plan,
        approval=validation_approval(validation_plan, scope, now),
        scope=scope,
        now=now,
    )
    connection = sqlite3.connect(":memory:")
    store = CampaignCandidateCriticIntakeStore(connection)
    service = CampaignCandidateCriticIntakeService(
        validation_source=validation_store,
        store=store,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    plan = service.prepare(
        validation_execution_plan_id=validation_plan.execution_plan_id,
        review_producer_digest=_digest(200),
        scope=scope,
        limits=CampaignCandidateCriticIntakeLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.9:critic-intake",
    )
    return (
        service,
        store,
        connection,
        plan,
        validation_outcome,
        validation_connection,
    )


def _approval(plan, scope, now, *, action=ApprovalAction.QUEUE_CAMPAIGN_CANDIDATE_CRITIC):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.target_id,
        action=action,
        action_digest=plan.critic_intake_plan_id,
        expected_side_effects=("queue independent campaign candidate critic",),
        evidence_summary="reviewed exact independent Campaign Candidate Critic Intake",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="operator",
        decided_at=now,
    )


def _close(connection, validation_connection):
    connection.close()
    validation_connection.close()


def test_exact_queue_approval_admits_independent_pending_critic(approved_scope, now):
    service, store, connection, plan, validation, validation_connection = _case(approved_scope, now)
    outcome = service.execute(
        plan,
        approval=_approval(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )

    assert validation.checkpoint.state is CandidateState.VALIDATED
    assert outcome.checkpoint.candidate_state is CandidateState.VALIDATED
    assert outcome.checkpoint.critic_state is CampaignCandidateCriticLifecycleState.PENDING
    assert plan.review_context_digest != plan.validation_context_digest
    assert plan.review_producer_digest != plan.validation_producer_digest
    assert plan.required_counterevidence_angles == REQUIRED_CAMPAIGN_CRITIC_ANGLES
    assert plan.validation_evidence_accepted_as_counterevidence is False
    assert outcome.critic_admitted is True
    assert outcome.critic_started is False
    assert outcome.critic_review_created is False
    assert outcome.finding_created is False
    assert outcome.submission_authorized is False
    assert store.checkpoint(plan.candidate_id) == outcome.checkpoint
    assert store.plan(plan.critic_intake_plan_id) == plan
    assert store.outcome(plan.critic_intake_plan_id) == outcome
    assert store.state(plan.critic_intake_plan_id) == (
        CampaignCandidateCriticIntakeState.COMPLETED,
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
    _close(connection, validation_connection)


def test_run_critic_approval_scope_drift_and_same_producer_fail_closed(approved_scope, now):
    service, store, connection, plan, _, validation_connection = _case(approved_scope, now)
    with pytest.raises(CampaignCandidateCriticIntakeRejected, match="Approval"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now, action=ApprovalAction.RUN_CRITIC),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(CampaignCandidateCriticIntakeRejected, match="source binding"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope.model_copy(update={"state": ScopeState.REVOKED}),
            now=now,
        )
    with pytest.raises(CampaignCandidateCriticIntakeRejected, match="independent"):
        service.prepare(
            validation_execution_plan_id=plan.validation_execution_plan_id,
            review_producer_digest=plan.validation_producer_digest,
            scope=approved_scope,
            limits=CampaignCandidateCriticIntakeLimits(),
            now=now,
            deadline=now + timedelta(minutes=5),
            idempotency_key="b5.9:same-producer",
        )
    assert store.state(plan.critic_intake_plan_id) is None
    _close(connection, validation_connection)


def test_timeout_publishes_no_pending_critic_checkpoint(approved_scope, now):
    ticks = iter((0.0, 11.0))
    service, store, connection, plan, _, validation_connection = _case(
        approved_scope, now, monotonic=lambda: next(ticks)
    )
    with pytest.raises(CampaignCandidateCriticIntakeTimedOut):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.critic_intake_plan_id) is None
    with pytest.raises(KeyError):
        store.checkpoint(plan.candidate_id)
    _close(connection, validation_connection)


def test_interrupted_intake_recovers_without_duplicate_checkpoint(approved_scope, now):
    service, store, connection, plan, _, validation_connection = _case(approved_scope, now)

    def interrupt():
        raise RuntimeError("fixture interruption")

    service.after_claim = interrupt
    with pytest.raises(RuntimeError, match="fixture interruption"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    service.after_claim = None
    outcome = service.execute(
        plan,
        approval=_approval(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    assert outcome.attempt == 2
    assert store.checkpoint(plan.candidate_id) == outcome.checkpoint
    _close(connection, validation_connection)


def test_recovery_state_machine_and_schema_boundaries_fail_closed(approved_scope, now):
    service, _, connection, plan, _, validation_connection = _case(approved_scope, now)

    def interrupt():
        raise RuntimeError("fixture interruption")

    service.after_claim = interrupt
    for _ in range(3):
        with pytest.raises(RuntimeError, match="fixture interruption"):
            service.execute(
                plan,
                approval=_approval(plan, approved_scope, now),
                scope=approved_scope,
                now=now,
            )
    with pytest.raises(CampaignCandidateCriticIntakeRecoveryRequired, match="exhausted"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(CampaignCandidateTransitionRejected):
        admit_campaign_candidate_critic(CandidateState.VALIDATION_PENDING)

    schemas = json.dumps(
        {
            model.__name__: model.model_json_schema()
            for model in (
                CampaignCandidateCriticIntakePlan,
                CampaignCandidateCriticIntakeCheckpoint,
                CampaignCandidateCriticIntakeOutcome,
            )
        }
    ).lower()
    for forbidden in (
        "target_url",
        "cookie",
        "password",
        "docker_socket",
        "raw_response",
        "payload",
    ):
        assert forbidden not in schemas
    with pytest.raises(ValidationError):
        CampaignCandidateCriticIntakePlan.model_validate(
            plan.model_dump(mode="python")
            | {
                "validation_evidence_accepted_as_counterevidence": True,
                "critic_execution_requested": True,
                "finding_creation_requested": True,
                "submission_requested": True,
            }
        )
    _close(connection, validation_connection)
