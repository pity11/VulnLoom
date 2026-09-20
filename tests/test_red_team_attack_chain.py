from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.broker import (
    EvidenceStoreHttpSink,
    OfflineHttpHop,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.broker.implementation import PINNED_HTTP_IMPLEMENTATION_DIGEST
from vulnloom.broker.models import HttpMethod, url_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    EvidenceKind,
    NetworkTargetScope,
    Scope,
    ScopeState,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    AttackAction,
    AttackActionAdapterInterrupted,
    AttackActionHttpBinding,
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
    IsolatedAttackChainAdmission,
    IsolatedLocalAttackChainAdapter,
    OfflineAttackActionAdapter,
    OfflineAttackScenario,
    RedTeamPhase,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.runners import NetworkGrant, validation_profile
from vulnloom.workflows import Visibility


class _AttackResolver:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def resolve(self, host):
        return ("10.23.45.67",) if host == "app.example.test" else ()


class _AttackTransport:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def __init__(self, hops):
        self.hops = iter(hops)
        self.calls = []

    def send(self, request):
        self.calls.append(request)
        return next(self.hops)


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
    fourth = AttackAction.create(
        flow_plan_id=flow_plan.plan_id,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        ordinal=4,
        kind=AttackActionKind.CLEANUP_TEST_SESSION,
        phase=RedTeamPhase.POST_EXPLOITATION,
        target_id=flow_plan.target.target_id,
        target_path="/lab/session",
        test_class="idor",
        impact=AttackImpact.STATE_CHANGE,
        prerequisite_action_ids=(third.action_id,),
        objective_id=objective.objective_id,
    )
    graph = AttackGraph.create(
        flow_plan_id=flow_plan.plan_id,
        target_id=flow_plan.target.target_id,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        objective=objective,
        actions=(first, second, third, fourth),
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


def _live_adapter(tmp_path, approved_scope, plan, now, *, elapsed_seconds=0.01):
    bodies = ("session-created", "session-active", "objective-proof", "")
    evidence_store = EvidenceStore(tmp_path / "attack-evidence")
    hops = []
    bindings = []
    methods = (HttpMethod.POST, HttpMethod.GET, HttpMethod.GET, HttpMethod.DELETE)
    statuses = (201, 200, 200, 204)
    for action, method, status, body in zip(
        plan.graph.actions, methods, statuses, bodies, strict=True
    ):
        body_digest = hashlib.sha256(body.encode()).hexdigest()
        evidence = evidence_store.capture_text(
            f"redacted:{action.kind.value}:{body_digest}",
            kind=EvidenceKind.HTTP,
            source_ref=f"action-sha256:{action.action_id}",
            producer="test.attack-chain.pinned",
            target_version=plan.graph.graph_id,
            summary="redacted admitted action response",
        )
        hops.append(
            OfflineHttpHop(
                status_code=status,
                peer_ip="10.23.45.67",
                response_bytes=len(body.encode()),
                response_body_sha256=body_digest,
                evidence_ref=evidence.evidence_id,
                elapsed_seconds=elapsed_seconds,
            )
        )
        bindings.append(
            AttackActionHttpBinding.create(
                action_id=action.action_id,
                method=method,
                url_digest=url_digest(f"https://app.example.test{action.target_path}"),
                expected_status_code=status,
                expected_content_sha256=body_digest,
            )
        )
    transport = _AttackTransport(hops)
    broker = ToolBroker(
        scope=approved_scope,
        registry=pinned_http_tool_registry(),
        resolver=_AttackResolver(),
        http_transport=transport,
        allowed_resolved_ips=frozenset({"10.23.45.67"}),
    )
    profile = validation_profile(
        image_digest="sha256:" + "1" * 64,
        snapshot_id=plan.graph.graph_id,
        network_grants=(
            NetworkGrant(
                host="app.example.test",
                ports=frozenset({443}),
                schemes=frozenset({"https"}),
            ),
        ),
    )
    admission = IsolatedAttackChainAdmission.create(
        chain_plan_id=plan.chain_plan_id,
        graph_id=plan.graph.graph_id,
        fixture_ref="fixture:r11-attack-chain-v1",
        host="app.example.test",
        port=443,
        scheme="https",
        allowed_peer_ips=("10.23.45.67",),
        action_bindings=tuple(bindings),
        expires_at=now + timedelta(minutes=4),
    )
    adapter = IsolatedLocalAttackChainAdapter(
        plan=plan,
        broker=broker,
        profile=profile,
        admission=admission,
        evidence_store=evidence_store,
    )
    return adapter, transport, admission


def test_isolated_attack_chain_routes_exact_methods_and_cleans_up(tmp_path, approved_scope, now):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    adapter, transport, _ = _live_adapter(tmp_path, approved_scope, plan, now)

    for offset, action in enumerate(plan.graph.actions):
        at = now + timedelta(seconds=offset)
        command = service.command(plan=plan, checkpoint=checkpoint, action=action)
        checkpoint, observation = service.execute(
            command=command,
            scope=approved_scope,
            approvals=_approvals(service, plan, action, approved_scope, at),
            adapter=adapter,
            now=at,
        )
        assert observation.evidence_refs

    assert checkpoint.status is AttackChainStatus.GOAL_REACHED
    assert [call.method for call in transport.calls] == [
        HttpMethod.POST,
        HttpMethod.GET,
        HttpMethod.GET,
        HttpMethod.DELETE,
    ]
    assert all(not call.headers and call.credential_ref is None for call in transport.calls)
    serialized = "\n".join(
        item.model_dump_json() for item in chain_store.audits(plan.chain_plan_id)
    )
    assert "https://" not in serialized
    assert "authorization" not in serialized.lower()
    chain_store.close()
    flow_store.close()


def test_isolated_attack_chain_timeout_requires_approved_cleanup(tmp_path, approved_scope, now):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    adapter, transport, _ = _live_adapter(tmp_path, approved_scope, plan, now, elapsed_seconds=31)
    action = plan.graph.actions[0]
    command = service.command(plan=plan, checkpoint=checkpoint, action=action)
    checkpoint, observation = service.execute(
        command=command,
        scope=approved_scope,
        approvals=_approvals(service, plan, action, approved_scope, now),
        adapter=adapter,
        now=now,
    )

    assert observation.outcome is AttackActionOutcome.TIMED_OUT
    assert not observation.evidence_refs
    assert checkpoint.status is AttackChainStatus.CLEANUP_REQUIRED
    assert len(transport.calls) == 1
    cleanup = plan.graph.actions[-1]
    cleanup_command = service.command(plan=plan, checkpoint=checkpoint, action=cleanup)
    refused_adapter = OfflineAttackActionAdapter()
    with pytest.raises(AttackChainRejected, match="exact execution Approval"):
        service.execute(
            command=cleanup_command,
            scope=approved_scope,
            approvals=(),
            adapter=refused_adapter,
            now=now + timedelta(seconds=1),
        )
    assert refused_adapter.calls == 0
    assert chain_store.latest(plan.chain_plan_id).status is AttackChainStatus.CLEANUP_REQUIRED
    checkpoint, cleanup_observation = service.execute(
        command=cleanup_command,
        scope=approved_scope,
        approvals=_approvals(service, plan, cleanup, approved_scope, now + timedelta(seconds=1)),
        adapter=OfflineAttackActionAdapter(),
        now=now + timedelta(seconds=1),
    )
    assert cleanup_observation.cleanup_complete
    assert checkpoint.status is AttackChainStatus.TIMED_OUT
    assert checkpoint.stop_reason == "action_timed_out_after_cleanup"
    chain_store.close()
    flow_store.close()


def test_isolated_attack_chain_rejects_binding_drift_before_dispatch(tmp_path, approved_scope, now):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, _, plan, _ = setup
    adapter, transport, admission = _live_adapter(tmp_path, approved_scope, plan, now)
    changed = admission.action_bindings[0].model_copy(
        update={"url_digest": "f" * 64, "binding_id": "0" * 64}
    )
    changed = AttackActionHttpBinding.create(
        **changed.model_dump(mode="python", exclude={"binding_id"})
    )
    drifted = IsolatedAttackChainAdmission.create(
        **admission.model_dump(mode="python", exclude={"admission_id", "action_bindings"}),
        action_bindings=(changed, *admission.action_bindings[1:]),
    )
    with pytest.raises(AttackChainRejected, match="binding is invalid"):
        IsolatedLocalAttackChainAdapter(
            plan=plan,
            broker=ToolBroker(
                scope=approved_scope,
                registry=pinned_http_tool_registry(),
                resolver=_AttackResolver(),
                http_transport=transport,
                allowed_resolved_ips=frozenset({"10.23.45.67"}),
            ),
            profile=adapter.profile,
            admission=drifted,
            evidence_store=EvidenceStore(tmp_path / "unused-evidence"),
        )
    assert transport.calls == []
    chain_store.close()
    flow_store.close()


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
    assert checkpoint.stop_reason == "objective_evidence_and_cleanup_recorded"
    assert checkpoint.objective_observation_id is not None
    assert all(node.status is AttackNodeStatus.SUCCEEDED for node in checkpoint.nodes)
    assert len(chain_store.audits(plan.chain_plan_id)) == 4

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
    assert not replay.goal_reached
    assert replay.action_id == plan.graph.actions[-1].action_id
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
            "action_timed_out_after_cleanup",
        ),
        (
            OfflineAttackScenario(
                outcome=AttackActionOutcome.FAILED,
                cleanup_complete=False,
            ),
            AttackChainStatus.FAILED,
            "action_failed_after_cleanup",
        ),
    ],
)
def test_attack_action_failure_requires_cleanup_before_terminal_state(
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
    assert checkpoint.status is AttackChainStatus.CLEANUP_REQUIRED
    assert checkpoint.stop_reason is None
    cleanup = plan.graph.actions[-1]
    cleanup_command = service.command(plan=plan, checkpoint=checkpoint, action=cleanup)
    checkpoint, _ = service.execute(
        command=cleanup_command,
        scope=approved_scope,
        approvals=_approvals(service, plan, cleanup, approved_scope, now + timedelta(seconds=1)),
        adapter=OfflineAttackActionAdapter(),
        now=now + timedelta(seconds=1),
    )
    assert checkpoint.status is status
    assert checkpoint.stop_reason == reason
    chain_store.close()
    flow_store.close()


def test_failed_compensating_cleanup_closes_as_unproven(tmp_path, approved_scope, now):
    setup = _setup(tmp_path, approved_scope, now)
    _, flow_store, _, _, chain_store, service, plan, checkpoint = setup
    first = plan.graph.actions[0]
    first_command = service.command(plan=plan, checkpoint=checkpoint, action=first)
    checkpoint, _ = service.execute(
        command=first_command,
        scope=approved_scope,
        approvals=_approvals(service, plan, first, approved_scope, now),
        adapter=OfflineAttackActionAdapter(
            OfflineAttackScenario(outcome=AttackActionOutcome.FAILED)
        ),
        now=now,
    )
    cleanup = plan.graph.actions[-1]
    cleanup_command = service.command(plan=plan, checkpoint=checkpoint, action=cleanup)
    checkpoint, observation = service.execute(
        command=cleanup_command,
        scope=approved_scope,
        approvals=_approvals(service, plan, cleanup, approved_scope, now + timedelta(seconds=1)),
        adapter=OfflineAttackActionAdapter(
            OfflineAttackScenario(
                outcome=AttackActionOutcome.FAILED,
                cleanup_complete=False,
            )
        ),
        now=now + timedelta(seconds=1),
    )
    assert observation.outcome is AttackActionOutcome.FAILED
    assert checkpoint.status is AttackChainStatus.FAILED
    assert checkpoint.stop_reason == "cleanup_unproven"
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
    assert failed.status is AttackChainStatus.CLEANUP_REQUIRED
    chain_store.close()
    flow_store.close()


def test_attack_chain_public_schemas_cannot_carry_payloads_or_secrets():
    models = (
        AttackAction,
        AttackActionHttpBinding,
        AttackGraph,
        IsolatedAttackChainAdmission,
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


def _private_local_ipv4() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        candidates = (probe.getsockname()[0],)
    except OSError:
        try:
            records = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET)
        except OSError:
            return None
        candidates = tuple(record[4][0] for record in records)
    finally:
        probe.close()
    for value in candidates:
        address = ipaddress.ip_address(value)
        if address.is_private and not address.is_loopback and not address.is_link_local:
            return str(address)
    return None


@pytest.mark.red_team_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_R11_ATTACK_CHAIN_INTEGRATION") != "1",
    reason="set VULNLOOM_R11_ATTACK_CHAIN_INTEGRATION=1 for isolated R11 chain",
)
def test_real_private_fixture_chain_reaches_goal_only_after_cleanup(tmp_path: Path):
    address = _private_local_ipv4()
    if address is None:
        pytest.skip("no private non-loopback IPv4 is available")
    program = r"""
import http.server
import sys
active = False
class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, status, body):
        payload = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Set-Cookie', 'session=must-not-persist')
        self.send_header('X-Authorization', 'Bearer must-not-persist')
        self.end_headers()
        if payload:
            self.wfile.write(payload)
    def do_POST(self):
        global active
        if self.path != '/lab/session':
            return self.reply(404, '{}')
        active = True
        self.reply(201, '{"session":"created"}')
        print('POST /lab/session active=1', flush=True)
    def do_GET(self):
        if self.path == '/lab/session/status' and active:
            self.reply(200, '{"session":"active"}')
        elif self.path == '/lab/protected-proof' and active:
            self.reply(200, '{"objective":"proved"}')
        else:
            self.reply(404, '{}')
        print(f'GET {self.path} active={int(active)}', flush=True)
    def do_DELETE(self):
        global active
        if self.path != '/lab/session':
            return self.reply(404, '{}')
        active = False
        self.reply(204, '')
        print('DELETE /lab/session active=0', flush=True)
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer((sys.argv[1], 0), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", program, address],
        env={"PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    flow_store = None
    chain_store = None
    try:
        assert process.stdout is not None
        port = int(process.stdout.readline().strip())
        host = "fixture.internal.test"
        now = datetime.now(UTC)
        scope = Scope(
            engagement_id=uuid4(),
            authority_reference="isolated-r11-private-fixture",
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=10),
            network_targets=(
                NetworkTargetScope(
                    host=host,
                    ports=frozenset({port}),
                    schemes=frozenset({"http"}),
                ),
            ),
            allowed_test_classes=frozenset({"idor"}),
            state=ScopeState.APPROVED,
            approved_by="integration-owner",
            approved_at=now,
        )
        flow_store = RedTeamStore(tmp_path / "real-flow.sqlite3")
        flow_service = RedTeamService(store=flow_store)
        flow = flow_service.prepare_attack_flow(
            scope=scope,
            target_url=f"http://{host}:{port}/",
            visibility=Visibility.BLACK_BOX,
            allowed_test_classes=("idor",),
            max_actions=4,
            max_consecutive_failures=1,
            emergency_contact_ref="contact:fixture-owner",
            now=now,
            deadline=now + timedelta(minutes=2),
            idempotency_key="r11:real-private-flow",
        )
        flow_checkpoint = flow_service.create_and_start(flow, scope=scope, now=now)
        objective = AttackObjective.create(
            kind=AttackObjectiveKind.PROVE_PROTECTED_RESOURCE_ACCESS,
            evidence_requirement="protected_resource_digest_observed",
        )
        action_specs = (
            (AttackActionKind.INITIAL_ACCESS_ATTEMPT, "/lab/session", AttackImpact.STATE_CHANGE),
            (AttackActionKind.VERIFY_TEST_SESSION, "/lab/session/status", AttackImpact.READ_ONLY),
            (AttackActionKind.VERIFY_OBJECTIVE, "/lab/protected-proof", AttackImpact.READ_ONLY),
            (AttackActionKind.CLEANUP_TEST_SESSION, "/lab/session", AttackImpact.STATE_CHANGE),
        )
        actions = []
        for ordinal, (kind, path, impact) in enumerate(action_specs, start=1):
            actions.append(
                AttackAction.create(
                    flow_plan_id=flow.plan_id,
                    scope_id=scope.scope_id,
                    scope_version=scope.version,
                    ordinal=ordinal,
                    kind=kind,
                    phase=RedTeamPhase.INITIAL_ACCESS
                    if ordinal == 1
                    else RedTeamPhase.POST_EXPLOITATION,
                    target_id=flow.target.target_id,
                    target_path=path,
                    test_class="idor",
                    impact=impact,
                    prerequisite_action_ids=(actions[-1].action_id,) if actions else (),
                    objective_id=objective.objective_id,
                )
            )
        graph = AttackGraph.create(
            flow_plan_id=flow.plan_id,
            target_id=flow.target.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            objective=objective,
            actions=tuple(actions),
        )
        chain_store = AttackChainStore(tmp_path / "real-chain.sqlite3")
        service = AttackChainService(flow_store=flow_store, chain_store=chain_store)
        plan = service.prepare(
            flow_plan=flow,
            flow_checkpoint_id=flow_checkpoint.checkpoint_id,
            graph=graph,
            scope=scope,
            now=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="r11:real-private-chain",
        )
        checkpoint = service.create_and_start(plan, scope=scope, now=now)
        bodies = ('{"session":"created"}', '{"session":"active"}', '{"objective":"proved"}', "")
        methods = (HttpMethod.POST, HttpMethod.GET, HttpMethod.GET, HttpMethod.DELETE)
        statuses = (201, 200, 200, 204)
        bindings = tuple(
            AttackActionHttpBinding.create(
                action_id=action.action_id,
                method=method,
                url_digest=url_digest(f"http://{host}:{port}{action.target_path}"),
                expected_status_code=status,
                expected_content_sha256=hashlib.sha256(body.encode()).hexdigest(),
            )
            for action, method, status, body in zip(actions, methods, statuses, bodies, strict=True)
        )
        evidence_store = EvidenceStore(tmp_path / "real-evidence")
        sink = EvidenceStoreHttpSink(evidence_store, target_version=graph.graph_id)

        class Resolver:
            implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

            def resolve(self, requested_host):
                return (address,) if requested_host == host else ()

        broker = ToolBroker(
            scope=scope,
            registry=pinned_http_tool_registry(),
            resolver=Resolver(),
            http_transport=PinnedHttpTransport(sink),
            allowed_resolved_ips=frozenset({address}),
        )
        profile = validation_profile(
            image_digest="sha256:" + "1" * 64,
            snapshot_id=graph.graph_id,
            network_grants=(
                NetworkGrant(host=host, ports=frozenset({port}), schemes=frozenset({"http"})),
            ),
        )
        admission = IsolatedAttackChainAdmission.create(
            chain_plan_id=plan.chain_plan_id,
            graph_id=graph.graph_id,
            fixture_ref="fixture:r11-real-private-v1",
            host=host,
            port=port,
            scheme="http",
            allowed_peer_ips=(address,),
            action_bindings=bindings,
            expires_at=now + timedelta(seconds=50),
        )
        adapter = IsolatedLocalAttackChainAdapter(
            plan=plan,
            broker=broker,
            profile=profile,
            admission=admission,
            evidence_store=evidence_store,
        )
        for offset, action in enumerate(actions):
            at = now + timedelta(seconds=offset)
            command = service.command(plan=plan, checkpoint=checkpoint, action=action)
            checkpoint, observation = service.execute(
                command=command,
                scope=scope,
                approvals=_approvals(service, plan, action, scope, at),
                adapter=adapter,
                now=at,
            )
            assert observation.outcome is AttackActionOutcome.SUCCEEDED
            if action.kind is AttackActionKind.VERIFY_OBJECTIVE:
                assert checkpoint.status is AttackChainStatus.RUNNING
        assert checkpoint.status is AttackChainStatus.GOAL_REACHED
        assert tuple(process.stdout.readline().strip() for _ in range(4)) == (
            "POST /lab/session active=1",
            "GET /lab/session/status active=1",
            "GET /lab/protected-proof active=1",
            "DELETE /lab/session active=0",
        )
        evidence_text = "\n".join(
            evidence_store.read_text(record) for record in sink.records.values()
        ).lower()
        assert "must-not-persist" not in evidence_text
        assert "authorization" not in evidence_text
        persisted = (tmp_path / "real-chain.sqlite3").read_text(errors="ignore").lower()
        assert f"http://{host}:{port}" not in persisted
        assert "must-not-persist" not in persisted
    finally:
        if chain_store is not None:
            chain_store.close()
        if flow_store is not None:
            flow_store.close()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    assert process.poll() is not None
