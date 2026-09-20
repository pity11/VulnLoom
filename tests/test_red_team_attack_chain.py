from __future__ import annotations

import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus
from vulnloom.red_team import (
    AttackAction,
    AttackActionAdapterInterrupted,
    AttackActionKind,
    AttackActionOutcome,
    AttackAuditDecision,
    AttackChainRejected,
    AttackChainService,
    AttackChainStatus,
    AttackChainStore,
    AttackGraph,
    AttackImpact,
    AttackNodeStatus,
    AttackObjective,
    AttackObjectiveKind,
    OfflineAttackActionAdapter,
    OfflineAttackScenario,
    RedTeamPhase,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.workflows import Visibility


def _setup(tmp_path, approved_scope, now):
    flow_store = RedTeamStore(tmp_path / "flow.sqlite3")
    flow_service = RedTeamService(store=flow_store)
    flow_plan = flow_service.prepare_attack_flow(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("idor",),
        max_actions=6,
        max_consecutive_failures=1,
        emergency_contact_ref="contact:security-owner",
        now=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="r11:flow",
    )
    flow_checkpoint = flow_service.create_and_start(flow_plan, scope=approved_scope, now=now)
    objective = AttackObjective.create(
        kind=AttackObjectiveKind.PROVE_PROTECTED_RESOURCE_ACCESS,
        evidence_requirement="protected_resource_digest_observed",
    )
    first = AttackAction.create(
        flow_plan_id=flow_plan.plan_id,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        ordinal=1,
        kind=AttackActionKind.INITIAL_ACCESS_ATTEMPT,
        phase=RedTeamPhase.INITIAL_ACCESS,
        target_id=flow_plan.target.target_id,
        target_path="/lab/session",
        test_class="idor",
        impact=AttackImpact.STATE_CHANGE,
        objective_id=objective.objective_id,
    )
    second = AttackAction.create(
        flow_plan_id=flow_plan.plan_id,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        ordinal=2,
        kind=AttackActionKind.VERIFY_TEST_SESSION,
        phase=RedTeamPhase.POST_EXPLOITATION,
        target_id=flow_plan.target.target_id,
        target_path="/lab/session/status",
        test_class="idor",
        impact=AttackImpact.READ_ONLY,
        prerequisite_action_ids=(first.action_id,),
        objective_id=objective.objective_id,
    )
    third = AttackAction.create(
        flow_plan_id=flow_plan.plan_id,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        ordinal=3,
        kind=AttackActionKind.VERIFY_OBJECTIVE,
        phase=RedTeamPhase.POST_EXPLOITATION,
        target_id=flow_plan.target.target_id,
        target_path="/lab/protected-proof",
        test_class="idor",
        impact=AttackImpact.READ_ONLY,
        prerequisite_action_ids=(second.action_id,),
        objective_id=objective.objective_id,
    )
    graph = AttackGraph.create(
        flow_plan_id=flow_plan.plan_id,
        target_id=flow_plan.target.target_id,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        objective=objective,
        actions=(first, second, third),
    )
    chain_store = AttackChainStore(tmp_path / "chain.sqlite3")
    service = AttackChainService(flow_store=flow_store, chain_store=chain_store)
    plan = service.prepare(
        flow_plan=flow_plan,
        flow_checkpoint_id=flow_checkpoint.checkpoint_id,
        graph=graph,
        scope=approved_scope,
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="r11:chain",
    )
    checkpoint = service.create_and_start(plan, scope=approved_scope, now=now)
    return (
        flow_service,
        flow_store,
        flow_plan,
        flow_checkpoint,
        chain_store,
        service,
        plan,
        checkpoint,
    )


def _approvals(service, plan, action, scope, now):
    authorization = service.authorization(plan=plan, action=action, scope=scope, now=now)
    approvals = [
        ApprovalRequest(
            engagement_id=scope.engagement_id,
            target_id=plan.graph.target_id,
            action=ApprovalAction.EXECUTE_RED_TEAM_ACTION,
            action_digest=action.action_id,
            expected_side_effects=(action.impact.value,),
            evidence_summary="Operator approved this exact sealed action",
            policy_version=scope.version,
            expires_at=now + timedelta(minutes=2),
            status=ApprovalStatus.GRANTED,
            decided_by="security-owner",
            decided_at=now,
        )
    ]
    for required in authorization.required_policy_approvals:
        approvals.append(
            ApprovalRequest(
                engagement_id=scope.engagement_id,
                target_id=plan.graph.target_id,
                action=required,
                action_digest=authorization.policy_action_digest,
                expected_side_effects=(action.impact.value,),
                evidence_summary="Operator approved policy impact for this exact action",
                policy_version=scope.version,
                expires_at=now + timedelta(minutes=2),
                status=ApprovalStatus.GRANTED,
                decided_by="security-owner",
                decided_at=now,
            )
        )
    return tuple(approvals)


def test_sealed_attack_graph_reaches_objective_with_per_action_approval(
    tmp_path, approved_scope, now
):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    for offset, action in enumerate(plan.graph.actions):
        at = now + timedelta(seconds=offset)
        command = service.command(plan=plan, checkpoint=checkpoint, action=action)
        adapter = OfflineAttackActionAdapter()
        checkpoint, observation = service.execute(
            command=command,
            scope=approved_scope,
            approvals=_approvals(service, plan, action, approved_scope, at),
            adapter=adapter,
            now=at,
        )
        assert observation.sensitive_data_redacted
        assert adapter.calls == 1

    assert checkpoint.status is AttackChainStatus.GOAL_REACHED
    assert checkpoint.stop_reason == "objective_evidence_recorded"
    assert all(node.status is AttackNodeStatus.SUCCEEDED for node in checkpoint.nodes)
    assert len(chain_store.audits(plan.chain_plan_id)) == 3

    replay_adapter = OfflineAttackActionAdapter(
        OfflineAttackScenario(outcome=AttackActionOutcome.FAILED)
    )
    replay_checkpoint, replay = service.execute(
        command=command,
        scope=approved_scope,
        approvals=(),
        adapter=replay_adapter,
        now=now + timedelta(seconds=10),
    )
    assert replay_checkpoint == checkpoint
    assert replay.goal_reached
    assert replay_adapter.calls == 0
    chain_store.close()
    flow_store.close()


def test_missing_or_wrong_approval_is_rejected_and_audited_without_adapter_call(
    tmp_path, approved_scope, now
):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    action = plan.graph.actions[0]
    command = service.command(plan=plan, checkpoint=checkpoint, action=action)
    adapter = OfflineAttackActionAdapter()
    with pytest.raises(AttackChainRejected, match="exact execution Approval"):
        service.execute(
            command=command,
            scope=approved_scope,
            approvals=(),
            adapter=adapter,
            now=now,
        )
    assert adapter.calls == 0
    audit = chain_store.audits(plan.chain_plan_id)
    assert audit[-1].decision is AttackAuditDecision.REJECTED
    assert audit[-1].reason_code == "execution_approval_missing"
    assert chain_store.latest(plan.chain_plan_id) == checkpoint
    chain_store.close()
    flow_store.close()


def test_attack_graph_rejects_skips_lateral_targets_and_raw_sensitive_output(
    tmp_path, approved_scope, now
):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    skipped = plan.graph.actions[1]
    command = service.command(plan=plan, checkpoint=checkpoint, action=skipped)
    adapter = OfflineAttackActionAdapter()
    with pytest.raises(AttackChainRejected, match="prerequisites|sequence"):
        service.execute(
            command=command,
            scope=approved_scope,
            approvals=_approvals(service, plan, skipped, approved_scope, now),
            adapter=adapter,
            now=now,
        )
    assert adapter.calls == 0
    assert chain_store.audits(plan.chain_plan_id)[-1].reason_code == "prerequisite_incomplete"

    first = plan.graph.actions[0]
    with pytest.raises(ValidationError, match="Extra inputs"):
        first.__class__.model_validate(
            first.model_dump(mode="python") | {"callback_url": "https://outside.example/callback"}
        )
    with pytest.raises(ValidationError, match="read_only.*state_change"):
        AttackAction.model_validate(
            first.model_dump(mode="python")
            | {
                "kind": AttackActionKind.VERIFY_TEST_SESSION,
                "phase": RedTeamPhase.POST_EXPLOITATION,
                "impact": "lateral_movement",
            }
        )
    chain_store.close()
    flow_store.close()


@pytest.mark.parametrize(
    ("scenario", "status", "reason"),
    [
        (
            OfflineAttackScenario(
                outcome=AttackActionOutcome.TIMED_OUT,
                reason_code="offline_timeout",
            ),
            AttackChainStatus.TIMED_OUT,
            "action_timed_out",
        ),
        (
            OfflineAttackScenario(
                outcome=AttackActionOutcome.FAILED,
                cleanup_complete=False,
            ),
            AttackChainStatus.FAILED,
            "cleanup_unproven",
        ),
    ],
)
def test_attack_action_timeout_and_cleanup_failure_stop_chain(
    tmp_path, approved_scope, now, scenario, status, reason
):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    action = plan.graph.actions[0]
    command = service.command(plan=plan, checkpoint=checkpoint, action=action)
    checkpoint, _ = service.execute(
        command=command,
        scope=approved_scope,
        approvals=_approvals(service, plan, action, approved_scope, now),
        adapter=OfflineAttackActionAdapter(scenario),
        now=now,
    )
    assert checkpoint.status is status
    assert checkpoint.stop_reason == reason
    chain_store.close()
    flow_store.close()


def test_flow_kill_switch_blocks_next_action_and_leaves_audit(tmp_path, approved_scope, now):
    setup = _setup(tmp_path, approved_scope, now)
    (
        flow_service,
        flow_store,
        flow_plan,
        flow_checkpoint,
        chain_store,
        service,
        plan,
        checkpoint,
    ) = setup
    action = plan.graph.actions[0]
    approvals = _approvals(service, plan, action, approved_scope, now + timedelta(seconds=1))
    killed = flow_service.kill(
        flow_plan,
        flow_checkpoint,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    assert killed.status.value == "killed"
    command = service.command(plan=plan, checkpoint=checkpoint, action=action)
    with pytest.raises(AttackChainRejected, match="invalid or stopped"):
        service.execute(
            command=command,
            scope=approved_scope,
            approvals=approvals,
            adapter=OfflineAttackActionAdapter(),
            now=now + timedelta(seconds=1),
        )
    assert chain_store.latest(plan.chain_plan_id).status is AttackChainStatus.KILLED
    assert chain_store.audits(plan.chain_plan_id)[-1].decision is AttackAuditDecision.REJECTED
    chain_store.close()
    flow_store.close()


def test_interruption_requires_bounded_recovery_and_exhaustion_proves_failure(
    tmp_path, approved_scope, now
):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    action = plan.graph.actions[0]
    command = service.command(plan=plan, checkpoint=checkpoint, action=action)
    approvals = _approvals(service, plan, action, approved_scope, now)
    with pytest.raises(AttackActionAdapterInterrupted):
        service.execute(
            command=command,
            scope=approved_scope,
            approvals=approvals,
            adapter=OfflineAttackActionAdapter(OfflineAttackScenario(interrupt=True)),
            now=now,
        )
    retry = service.command(plan=plan, checkpoint=checkpoint, action=action, attempt=2)
    failed, observation = service.execute(
        command=retry,
        scope=approved_scope,
        approvals=approvals,
        adapter=OfflineAttackActionAdapter(OfflineAttackScenario(interrupt=True)),
        now=now + timedelta(seconds=1),
    )
    assert observation.reason_code == "adapter_attempts_exhausted"
    assert not observation.cleanup_complete
    assert failed.status is AttackChainStatus.FAILED
    chain_store.close()
    flow_store.close()


def test_attack_chain_public_schemas_cannot_carry_payloads_or_secrets():
    models = (
        AttackAction,
        AttackGraph,
    )
    rendered = json.dumps({model.__name__: model.model_json_schema() for model in models}).lower()
    for forbidden in (
        "authorization",
        "cookie",
        "credential",
        "callback_url",
        "response_body",
        "request_body",
        "payload",
        "shell",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize("path", ("/a//b", "/a/%2e%2e/b", "/a b"))
def test_attack_action_rejects_ambiguous_paths(path, tmp_path, approved_scope, now):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, _, plan, _ = setup
    values = plan.graph.actions[0].model_dump(mode="python", exclude={"action_id"})
    with pytest.raises(ValidationError, match="canonical path"):
        AttackAction.create(**(values | {"target_path": path}))
    chain_store.close()
    flow_store.close()
