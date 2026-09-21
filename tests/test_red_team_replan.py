from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
)
from vulnloom.red_team import (
    OfflineReconScenario,
    OfflineRedTeamReconAdapter,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamFlowStatus,
    RedTeamReconObservation,
    RedTeamReplanningService,
    RedTeamReplanProposal,
    RedTeamReplanRejected,
    RedTeamService,
    RedTeamStore,
    ServiceIdentitySnapshot,
    ServiceTlsVersion,
)
from vulnloom.workflows import Visibility


def _observed_flow(tmp_path, scope, now, *, max_actions=3):
    store = RedTeamStore(tmp_path / "replan.sqlite3")
    flow = RedTeamService(store=store)
    plan = flow.prepare(
        scope=scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=max_actions,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:security-owner",
        now=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key=f"red-team:replan:flow:{max_actions}",
    )
    checkpoint = flow.create_and_start(plan, scope=scope, now=now)
    command = flow.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key="red-team:replan:seed-observation",
    )
    checkpoint, observation = flow.execute_recon(
        command=command,
        scope=scope,
        adapter=OfflineRedTeamReconAdapter(),
        now=now,
    )
    return store, flow, plan, checkpoint, observation


def _proposal(
    view,
    now,
    *,
    key="proposal-1",
    kind=RedTeamActionKind.HTTP_HEAD,
    rationale="follow the sealed observation",
):
    return RedTeamReplanProposal.create(
        tool_view_id=view.tool_view_id,
        source_observation_ids=view.observation_ids,
        action_kind=kind,
        test_class="read_only",
        rationale_digest=canonical_digest(rationale),
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
        expected_side_effects=("execute one observation-driven read-only action",),
        evidence_summary="Operator reviewed exact replanned action",
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
        self.calls = 0

    def execute(self, action, *, now):
        self.calls += 1
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


def test_observation_driven_replan_is_sealed_approved_and_executable(
    tmp_path, approved_scope, now
):
    store, _, plan, checkpoint, observation = _observed_flow(
        tmp_path, approved_scope, now
    )
    service = RedTeamReplanningService(store=store)
    view = service.issue_tool_view(
        flow_plan_id=plan.plan_id,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    proposal = _proposal(view, now + timedelta(seconds=1))
    admission = service.admit(
        proposal=proposal,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )

    assert view.observation_ids == (observation.observation_id,)
    assert view.checkpoint_id == checkpoint.checkpoint_id
    assert view.remaining_actions == 2
    assert "target_url" not in view.model_dump()
    assert admission.command.action.target_url == plan.target.url
    assert admission.required_approval_digest == admission.command.action.action_id
    assert service.admit(
        proposal=proposal,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    ) == admission

    adapter = OfflineRedTeamReconAdapter()
    advanced, replanned_observation = service.execute(
        admission=admission,
        command=admission.command,
        approval=_approval(admission, plan, approved_scope, now),
        scope=approved_scope,
        adapter=adapter,
        now=now + timedelta(seconds=2),
    )
    replayed, replayed_observation = service.execute(
        admission=admission,
        command=admission.command,
        approval=_approval(admission, plan, approved_scope, now),
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(
            OfflineReconScenario(outcome=ReconOutcome.FAILED, status_code=None)
        ),
        now=now + timedelta(seconds=2),
    )

    assert advanced.actions_used == 2
    assert replanned_observation.action_id == admission.command.action.action_id
    assert (replayed, replayed_observation) == (advanced, replanned_observation)
    assert adapter.calls == 1
    assert store.replan_admission_state(admission.admission_id) == "consumed"
    assert service.admit(
        proposal=proposal,
        scope=approved_scope,
        now=now + timedelta(minutes=2),
    ) == admission
    store.close()


def test_two_replanning_rounds_change_action_kind_without_expanding_target(
    tmp_path, approved_scope, now
):
    store, _, plan, checkpoint, seed_observation = _observed_flow(
        tmp_path, approved_scope, now, max_actions=3
    )
    service = RedTeamReplanningService(store=store)
    first_view = service.issue_tool_view(
        flow_plan_id=plan.plan_id,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    tls_admission = service.admit(
        proposal=_proposal(
            first_view,
            now + timedelta(seconds=1),
            key="proposal-tls",
            kind=RedTeamActionKind.TLS_INSPECT,
        ),
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    checkpoint, tls_observation = service.execute(
        admission=tls_admission,
        command=tls_admission.command,
        approval=_approval(tls_admission, plan, approved_scope, now),
        scope=approved_scope,
        adapter=_OfflineTlsAdapter(plan=plan, scope=approved_scope),
        now=now + timedelta(seconds=2),
    )
    second_view = service.issue_tool_view(
        flow_plan_id=plan.plan_id,
        scope=approved_scope,
        now=now + timedelta(seconds=3),
    )
    head_admission = service.admit(
        proposal=_proposal(
            second_view,
            now + timedelta(seconds=3),
            key="proposal-head",
            kind=RedTeamActionKind.HTTP_HEAD,
        ),
        scope=approved_scope,
        now=now + timedelta(seconds=3),
    )
    terminal, head_observation = service.execute(
        admission=head_admission,
        command=head_admission.command,
        approval=_approval(head_admission, plan, approved_scope, now),
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(),
        now=now + timedelta(seconds=4),
    )

    assert checkpoint.actions_used == 2
    assert second_view.observation_ids == tuple(
        sorted((seed_observation.observation_id, tls_observation.observation_id))
    )
    assert second_view.remaining_actions == 1
    assert tls_admission.command.action.kind is RedTeamActionKind.TLS_INSPECT
    assert head_admission.command.action.kind is RedTeamActionKind.HTTP_HEAD
    assert tls_admission.command.action.target_url == head_admission.command.action.target_url
    assert tls_admission.required_approval_digest != head_admission.required_approval_digest
    assert head_observation.action_id == head_admission.command.action.action_id
    assert terminal.status is RedTeamFlowStatus.COMPLETED
    assert terminal.stop_reason == "action_budget_reached"
    store.close()


def test_replan_rejects_target_fields_missing_observation_and_stale_view(
    tmp_path, approved_scope, now
):
    store = RedTeamStore(tmp_path / "empty.sqlite3")
    flow = RedTeamService(store=store)
    plan = flow.prepare(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=3,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:security-owner",
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="red-team:replan:empty",
    )
    flow.create_and_start(plan, scope=approved_scope, now=now)
    with pytest.raises(RedTeamReplanRejected, match="requires an Observation"):
        RedTeamReplanningService(store=store).issue_tool_view(
            flow_plan_id=plan.plan_id, scope=approved_scope, now=now
        )
    store.close()

    store, flow, plan, checkpoint, _ = _observed_flow(
        tmp_path / "stale", approved_scope, now, max_actions=4
    )
    service = RedTeamReplanningService(store=store)
    view = service.issue_tool_view(
        flow_plan_id=plan.plan_id,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    with pytest.raises(ValidationError, match="Extra inputs"):
        RedTeamReplanProposal.model_validate(
            _proposal(view, now + timedelta(seconds=1)).model_dump()
            | {"target_url": "https://outside.example/"}
        )
    next_command = flow.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=approved_scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now + timedelta(seconds=2),
        ttl_seconds=30,
        idempotency_key="red-team:replan:stale-action",
    )
    flow.execute_recon(
        command=next_command,
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(),
        now=now + timedelta(seconds=2),
    )
    with pytest.raises(RedTeamReplanRejected, match="Tool View"):
        service.admit(
            proposal=_proposal(view, now + timedelta(seconds=1)),
            scope=approved_scope,
            now=now + timedelta(seconds=3),
        )
    store.close()


def test_replan_reserves_budget_and_requires_exact_approval(
    tmp_path, approved_scope, now
):
    store, _, plan, _, _ = _observed_flow(
        tmp_path, approved_scope, now, max_actions=2
    )
    service = RedTeamReplanningService(store=store)
    view = service.issue_tool_view(
        flow_plan_id=plan.plan_id,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    admission = service.admit(
        proposal=_proposal(view, now + timedelta(seconds=1)),
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    with pytest.raises(RedTeamReplanRejected, match="authority is unavailable"):
        service.admit(
            proposal=_proposal(
                view,
                now + timedelta(seconds=1),
                rationale="different proposal reusing the same key",
            ),
            scope=approved_scope,
            now=now + timedelta(seconds=1),
        )
    over_budget = _proposal(
        view, now + timedelta(seconds=1), key="proposal-over-budget"
    )
    with pytest.raises(RedTeamReplanRejected, match="admission was rejected"):
        service.admit(
            proposal=over_budget,
            scope=approved_scope,
            now=now + timedelta(seconds=1),
        )
    wrong = _approval(admission, plan, approved_scope, now).model_copy(
        update={"action_digest": "f" * 64}
    )
    with pytest.raises(RedTeamReplanRejected, match="lacks exact Approval"):
        service.execute(
            admission=admission,
            command=admission.command,
            approval=wrong,
            scope=approved_scope,
            adapter=OfflineRedTeamReconAdapter(),
            now=now + timedelta(seconds=2),
        )
    assert store.replan_admission_state(admission.admission_id) == "reserved"
    assert store.latest(plan.plan_id).actions_used == 1
    service.cancel(
        admission=admission,
        scope=approved_scope,
        now=now + timedelta(seconds=2),
    )
    assert store.replan_admission_state(admission.admission_id) == "cancelled"
    replacement = service.admit(
        proposal=over_budget,
        scope=approved_scope,
        now=now + timedelta(seconds=2),
    )
    with pytest.raises(RedTeamReplanRejected, match="not expired"):
        service.expire(
            admission=replacement,
            scope=approved_scope,
            now=now + timedelta(seconds=2),
        )
    service.expire(
        admission=replacement,
        scope=approved_scope,
        now=replacement.command.action.deadline,
    )
    assert store.replan_admission_state(replacement.admission_id) == "expired"
    assert store.remaining_action_budget(plan.plan_id) == 1
    store.close()


@pytest.mark.parametrize(
    ("scenario", "status", "reason"),
    [
        (
            OfflineReconScenario(
                outcome=ReconOutcome.TIMED_OUT,
                status_code=None,
                reason_code="offline_timeout",
            ),
            RedTeamFlowStatus.TIMED_OUT,
            "action_timed_out",
        ),
        (
            OfflineReconScenario(
                outcome=ReconOutcome.FAILED,
                status_code=None,
                reason_code="cleanup_failed",
                cleanup_complete=False,
            ),
            RedTeamFlowStatus.FAILED,
            "cleanup_unproven",
        ),
    ],
)
def test_replanned_timeout_and_cleanup_failure_are_terminal(
    tmp_path, approved_scope, now, scenario, status, reason
):
    store, _, plan, _, _ = _observed_flow(tmp_path, approved_scope, now)
    service = RedTeamReplanningService(store=store)
    view = service.issue_tool_view(
        flow_plan_id=plan.plan_id,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    admission = service.admit(
        proposal=_proposal(view, now + timedelta(seconds=1)),
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    terminal, _ = service.execute(
        admission=admission,
        command=admission.command,
        approval=_approval(admission, plan, approved_scope, now),
        scope=approved_scope,
        adapter=OfflineRedTeamReconAdapter(scenario),
        now=now + timedelta(seconds=2),
    )

    assert terminal.status is status
    assert terminal.stop_reason == reason
    assert store.replan_admission_state(admission.admission_id) == "consumed"
    store.close()
