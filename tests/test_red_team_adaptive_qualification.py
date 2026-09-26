from __future__ import annotations

import json
import sqlite3
import time
from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    ScopeState,
)
from vulnloom.red_team import (
    AdaptiveFlowQualificationPlan,
    AdaptiveFlowQualificationService,
    AdaptiveQualificationLimits,
    AdaptiveQualificationRecoveryRequired,
    AdaptiveQualificationRejected,
    AdaptiveQualificationState,
    AdaptiveQualificationStore,
    AdaptiveQualificationTimedOut,
    OfflineRedTeamReconAdapter,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamReconObservation,
    RedTeamReplanningService,
    RedTeamReplanProposal,
    RedTeamService,
    RedTeamStore,
    ServiceIdentitySnapshot,
    ServiceTlsVersion,
)
from vulnloom.workflows import AutonomyLevel, Visibility

_CONNECTIONS: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while _CONNECTIONS:
        _CONNECTIONS.pop().close()


def _connection():
    connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(connection)
    return connection


def _proposal(view, now, *, key, kind):
    return RedTeamReplanProposal.create(
        tool_view_id=view.tool_view_id,
        source_observation_ids=view.observation_ids,
        action_kind=kind,
        test_class="read_only",
        rationale_digest=canonical_digest({"round": key}),
        ttl_seconds=30,
        proposed_at=now,
        idempotency_key=key,
    )


def _approval(admission, plan, scope, now):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.target.target_id,
        action=ApprovalAction.EXECUTE_RED_TEAM_ACTION,
        action_digest=admission.required_approval_digest,
        expected_side_effects=("one offline adaptive fixture observation",),
        evidence_summary="Operator approved the exact adaptive fixture action",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="red-team-operator",
        decided_at=now,
    )


class _OfflineTlsAdapter:
    def __init__(self, *, plan, scope):
        self.plan = plan
        self.scope = scope

    def execute(self, action, *, now):
        identity = ServiceIdentitySnapshot.create(
            plan_id=action.plan_id,
            action_id=action.action_id,
            target_id=self.plan.target.target_id,
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            endpoint_url_digest=canonical_digest(action.target_url),
            peer_ip="192.0.2.10",
            tls_version=ServiceTlsVersion.TLS_1_3,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            leaf_certificate_sha256="c" * 64,
            evidence_refs=("d" * 64,),
            policy_record_digests=("e" * 64,),
            captured_at=now,
        )
        return RedTeamReconObservation.create(
            action_id=action.action_id,
            outcome=ReconOutcome.SUCCEEDED,
            status_code=None,
            reason_code="offline_tls_identity_observed",
            cleanup_complete=True,
            service_identity=identity,
            observed_at=now,
        )


def _adaptive_trace(tmp_path, scope, now, *, max_actions=3):
    red_store = RedTeamStore(tmp_path / "adaptive-trace.sqlite3")
    flow_service = RedTeamService(store=red_store)
    plan = flow_service.prepare(
        scope=scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=max_actions,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:security-owner",
        now=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key=f"adaptive-flow:{max_actions}",
    )
    checkpoint = flow_service.create_and_start(plan, scope=scope, now=now)
    seed = flow_service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key="adaptive-seed",
    )
    flow_service.execute_recon(
        command=seed,
        scope=scope,
        adapter=OfflineRedTeamReconAdapter(),
        now=now,
    )
    replan = RedTeamReplanningService(store=red_store)
    admissions = []
    for index, kind in enumerate(
        (RedTeamActionKind.TLS_INSPECT, RedTeamActionKind.HTTP_HEAD), start=1
    ):
        step_at = now + timedelta(seconds=index * 2 - 1)
        view = replan.issue_tool_view(
            flow_plan_id=plan.plan_id,
            scope=scope,
            now=step_at,
        )
        admission = replan.admit(
            proposal=_proposal(
                view,
                step_at,
                key=f"adaptive-round-{index}",
                kind=kind,
            ),
            scope=scope,
            now=step_at,
        )
        replan.execute(
            admission=admission,
            command=admission.command,
            approval=_approval(admission, plan, scope, step_at),
            scope=scope,
            adapter=(
                _OfflineTlsAdapter(plan=plan, scope=scope)
                if kind is RedTeamActionKind.TLS_INSPECT
                else OfflineRedTeamReconAdapter()
            ),
            now=step_at + timedelta(seconds=1),
        )
        admissions.append(admission)
    receipts = tuple(
        red_store.replan_execution_receipt_for_admission(item.admission_id)
        for item in admissions
    )
    assert all(item is not None for item in receipts)
    return red_store, plan, tuple(admissions), receipts


def _runtime(tmp_path, approved_scope, now):
    red_store, flow, admissions, receipts = _adaptive_trace(
        tmp_path, approved_scope, now
    )
    service = AdaptiveFlowQualificationService(
        red_team_store=red_store,
        store=AdaptiveQualificationStore(_connection()),
    )
    receipt_ids = tuple(item.receipt_id for item in receipts if item is not None)
    plan = service.prepare(
        flow_plan_id=flow.plan_id,
        replan_execution_receipt_ids=receipt_ids,
        scope=approved_scope,
        limits=AdaptiveQualificationLimits(),
        now=now + timedelta(seconds=5),
        deadline=now + timedelta(minutes=5),
        idempotency_key="adaptive-qualification",
    )
    return red_store, flow, admissions, receipts, service, plan


def test_two_authoritative_replans_qualify_a3_and_materialize_coverage(
    tmp_path, approved_scope, now
):
    red_store, flow, admissions, receipts, service, plan = _runtime(
        tmp_path, approved_scope, now
    )

    outcome = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=6)
    )
    replay = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=7)
    )

    assert replay == outcome
    assert outcome.qualified_autonomy is AutonomyLevel.ADAPTIVE_FLOW
    assert outcome.campaign_qualified is False
    assert outcome.execution_authority_granted is False
    assert outcome.candidate_created is False
    assert outcome.finding_created is False
    assert tuple(item.admission_id for item in outcome.coverage_ledger.rounds) == tuple(
        item.admission_id for item in admissions
    )
    assert outcome.coverage_ledger.covered_action_kinds == (
        RedTeamActionKind.HTTP_HEAD,
        RedTeamActionKind.TLS_INSPECT,
    )
    assert outcome.coverage_ledger.source_observation_count == 1
    assert outcome.coverage_ledger.produced_observation_count == 2
    assert all(item.exact_approval_proven for item in outcome.coverage_ledger.rounds)
    assert all(item.cleanup_proven for item in outcome.coverage_ledger.rounds)
    assert service.store.state(plan.plan_id) == (
        AdaptiveQualificationState.COMPLETED,
        1,
    )
    for admission, receipt in zip(admissions, receipts, strict=True):
        assert receipt is not None
        assert receipt.approval_digest == admission.required_approval_digest
        assert red_store.replan_execution_receipt(receipt.receipt_id) == receipt

    serialized = "".join(
        service.store.connection.execute(
            "SELECT plan_json,outcome_json FROM red_team_adaptive_qualifications"
        ).fetchone()
    ).lower()
    assert flow.target.url.lower() not in serialized
    assert "password" not in serialized
    assert "cookie" not in serialized
    red_store.close()


def test_one_round_cannot_be_presented_as_adaptive_flow(tmp_path, approved_scope, now):
    red_store, flow, _, receipts = _adaptive_trace(tmp_path, approved_scope, now)
    service = AdaptiveFlowQualificationService(
        red_team_store=red_store,
        store=AdaptiveQualificationStore(_connection()),
    )
    with pytest.raises(AdaptiveQualificationRejected, match="bounded unique trace"):
        service.prepare(
            flow_plan_id=flow.plan_id,
            replan_execution_receipt_ids=(receipts[0].receipt_id,),
            scope=approved_scope,
            limits=AdaptiveQualificationLimits(),
            now=now + timedelta(seconds=5),
            deadline=now + timedelta(minutes=5),
            idempotency_key="one-round",
        )
    assert service.store.connection.execute(
        "SELECT COUNT(*) FROM red_team_adaptive_qualifications"
    ).fetchone()[0] == 0
    red_store.close()


def test_reordered_or_missing_execution_proof_is_rejected(
    tmp_path, approved_scope, now
):
    red_store, flow, _, receipts = _adaptive_trace(tmp_path, approved_scope, now)
    service = AdaptiveFlowQualificationService(
        red_team_store=red_store,
        store=AdaptiveQualificationStore(_connection()),
    )
    with pytest.raises(AdaptiveQualificationRejected, match="provenance"):
        service.prepare(
            flow_plan_id=flow.plan_id,
            replan_execution_receipt_ids=(
                receipts[1].receipt_id,
                receipts[0].receipt_id,
            ),
            scope=approved_scope,
            limits=AdaptiveQualificationLimits(),
            now=now + timedelta(seconds=5),
            deadline=now + timedelta(minutes=5),
            idempotency_key="reordered",
        )
    red_store.connection.execute(
        "DELETE FROM red_team_replan_execution_receipts WHERE receipt_id=?",
        (receipts[1].receipt_id,),
    )
    red_store.connection.commit()
    with pytest.raises(AdaptiveQualificationRejected, match="unavailable"):
        service.prepare(
            flow_plan_id=flow.plan_id,
            replan_execution_receipt_ids=tuple(item.receipt_id for item in receipts),
            scope=approved_scope,
            limits=AdaptiveQualificationLimits(),
            now=now + timedelta(seconds=5),
            deadline=now + timedelta(minutes=5),
            idempotency_key="missing-proof",
        )
    red_store.close()


def test_non_terminal_trace_and_revoked_scope_fail_before_checkpoint(
    tmp_path, approved_scope, now
):
    red_store, flow, _, receipts = _adaptive_trace(
        tmp_path, approved_scope, now, max_actions=4
    )
    service = AdaptiveFlowQualificationService(
        red_team_store=red_store,
        store=AdaptiveQualificationStore(_connection()),
    )
    receipt_ids = tuple(item.receipt_id for item in receipts)
    with pytest.raises(AdaptiveQualificationRejected, match="cleanly terminal"):
        service.prepare(
            flow_plan_id=flow.plan_id,
            replan_execution_receipt_ids=receipt_ids,
            scope=approved_scope,
            limits=AdaptiveQualificationLimits(),
            now=now + timedelta(seconds=5),
            deadline=now + timedelta(minutes=5),
            idempotency_key="running-trace",
        )
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(AdaptiveQualificationRejected, match="unavailable"):
        service.prepare(
            flow_plan_id=flow.plan_id,
            replan_execution_receipt_ids=receipt_ids,
            scope=revoked,
            limits=AdaptiveQualificationLimits(),
            now=now + timedelta(seconds=5),
            deadline=now + timedelta(minutes=5),
            idempotency_key="revoked-scope",
        )
    assert service.store.connection.execute(
        "SELECT COUNT(*) FROM red_team_adaptive_qualifications"
    ).fetchone()[0] == 0
    red_store.close()


def test_timeout_keeps_started_and_explicit_recovery_completes(
    tmp_path, approved_scope, now
):
    red_store, _, _, _, service, plan = _runtime(tmp_path, approved_scope, now)
    ticks = iter((0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(AdaptiveQualificationTimedOut):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=6))
    assert service.store.state(plan.plan_id) == (
        AdaptiveQualificationState.STARTED,
        1,
    )

    service.monotonic = time.monotonic
    outcome = service.recover(
        plan, scope=approved_scope, now=now + timedelta(seconds=7)
    )
    assert outcome.attempt == 2
    red_store.close()


def test_timeout_recovery_is_bounded_at_three_attempts(
    tmp_path, approved_scope, now
):
    red_store, _, _, _, service, plan = _runtime(tmp_path, approved_scope, now)
    ticks = iter((0.0, 100.0, 0.0, 100.0, 0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(AdaptiveQualificationTimedOut):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=6))
    with pytest.raises(AdaptiveQualificationTimedOut):
        service.recover(plan, scope=approved_scope, now=now + timedelta(seconds=7))
    with pytest.raises(AdaptiveQualificationTimedOut):
        service.recover(plan, scope=approved_scope, now=now + timedelta(seconds=8))
    with pytest.raises(AdaptiveQualificationRecoveryRequired, match="exhausted"):
        service.recover(plan, scope=approved_scope, now=now + timedelta(seconds=9))
    assert service.store.state(plan.plan_id) == (
        AdaptiveQualificationState.STARTED,
        3,
    )
    red_store.close()


def test_schema_cannot_claim_a4_authority_or_retain_raw_target(
    tmp_path, approved_scope, now
):
    red_store, flow, _, _, _, plan = _runtime(tmp_path, approved_scope, now)
    payload = plan.model_dump(mode="python")
    payload["campaign_qualification_requested"] = True
    payload["plan_id"] = "0" * 64
    with pytest.raises(ValidationError):
        AdaptiveFlowQualificationPlan.model_validate(payload)

    schema_object = AdaptiveFlowQualificationPlan.model_json_schema()
    schema = json.dumps(schema_object).lower()
    assert "target_url" not in schema_object["properties"]
    for forbidden in (
        "password",
        "cookie",
        "authorization_header",
        "credential_value",
        "provider_token",
        "submission",
    ):
        assert forbidden not in schema
    assert flow.target.url not in plan.model_dump_json()
    red_store.close()
