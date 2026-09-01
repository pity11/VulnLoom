from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import (
    AgentModelRegistration,
    AgentRunLimits,
    AgentRunPlan,
    AgentRunStatus,
    AgentRunStore,
    AgentStepRequest,
    AgentToolHandoffIdempotencyConflict,
    AgentToolHandoffLimits,
    AgentToolHandoffOutcome,
    AgentToolHandoffPlan,
    AgentToolHandoffRecoveryRequired,
    AgentToolHandoffRejected,
    AgentToolHandoffRetryRejected,
    AgentToolHandoffService,
    AgentToolHandoffStatus,
    AgentToolHandoffStore,
    AgentToolHandoffTimedOut,
    OfflineAgentRuntime,
    OfflineReplayModelAdapter,
    ReplayTurn,
    agent_broker_call_commitment,
    agent_tool_intent_for_broker_call,
)
from vulnloom.broker import (
    BrokerCall,
    HttpRequestPlan,
    OfflineHttpHop,
    OfflineHttpTransport,
    StaticResolver,
    ToolBroker,
    default_tool_registry,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import ActionRequest, PolicyEngine
from vulnloom.runners import NetworkGrant, sandbox_profile_digest, validation_profile

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
EVIDENCE = "3" * 64
BODY_SHA256 = "7" * 64
IP = "192.0.2.10"
URL = "https://app.example.test/items?id=7"


def _fixture(tmp_path, now, scope, *, http=None, hop=None):
    registry = default_tool_registry()
    profile = validation_profile(
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
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=uuid4(),
        target_version="4" * 40,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=registry.digest,
        input_refs=("candidate:" + "5" * 64,),
        allowed_tools=frozenset({"http.request"}),
        budget=TaskBudget(wall_seconds=60, model_tokens=100, tool_calls=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="validator:agent-handoff:1",
    )
    registration = AgentModelRegistration.create(
        provider_id="offline",
        model="handoff-replay-v1",
        adapter_digest=canonical_digest("agent-handoff-fixture"),
        supported_roles=(WorkerRole.VALIDATOR,),
        max_output_tokens=64,
    )
    agent_plan = AgentRunPlan.create(
        task=task,
        registration=registration,
        limits=AgentRunLimits(
            max_steps=1,
            max_output_tokens_per_step=64,
            timeout_seconds=30,
        ),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="agent:handoff:1",
    )
    call = BrokerCall(
        task=task,
        profile=profile,
        tool_id="http.request",
        http=http
        or HttpRequestPlan(method="GET", url=URL, test_class="read_only"),
        idempotency_key="broker:handoff:1",
    )
    commitment = agent_broker_call_commitment(call)
    request = AgentStepRequest.create(
        plan=agent_plan,
        step=1,
        remaining_model_tokens=task.budget.model_tokens,
    )
    turn = ReplayTurn(
        expected_request_digest=canonical_digest(request.model_dump(mode="python")),
        structured_output={
            "kind": "propose_tool",
            "tool_call": {
                "tool_id": call.tool_id,
                "arguments": [commitment],
                "working_directory": "source",
            },
        },
        input_tokens=3,
        output_tokens=2,
        latency_seconds=0.1,
    )
    agent_store = AgentRunStore(tmp_path / "agent-runs.sqlite3")
    agent_adapter = OfflineReplayModelAdapter(
        registration=registration,
        turns=(turn,),
    )
    agent_outcome = OfflineAgentRuntime(
        store=agent_store,
        registration=registration,
        adapter=agent_adapter,
    ).execute(agent_plan, now=now)
    assert agent_outcome.status is AgentRunStatus.TOOL_PROPOSED
    assert agent_outcome.tool_intent == agent_tool_intent_for_broker_call(call)
    handoff_store = AgentToolHandoffStore(tmp_path / "handoffs.sqlite3")
    transport = OfflineHttpTransport(
        {
            call.http.url: hop
            or OfflineHttpHop(
                status_code=200,
                peer_ip=IP,
                response_bytes=128,
                response_body_sha256=BODY_SHA256,
                evidence_ref=EVIDENCE,
            )
        }
    )
    resolver = StaticResolver(
        {"app.example.test": (IP,), "outside.example.test": (IP,)}
    )
    broker = ToolBroker(
        scope=scope,
        registry=registry,
        resolver=resolver,
        http_transport=transport,
    )
    service = AgentToolHandoffService(
        agent_store=agent_store,
        handoff_store=handoff_store,
        broker=broker,
    )
    return {
        "task": task,
        "registration": registration,
        "agent_plan": agent_plan,
        "agent_outcome": agent_outcome,
        "agent_store": agent_store,
        "agent_adapter": agent_adapter,
        "handoff_store": handoff_store,
        "call": call,
        "transport": transport,
        "resolver": resolver,
        "broker": broker,
        "service": service,
    }


def _handoff(fixture, now, *, call=None, key="handoff:1", attempt=1, previous=None):
    return AgentToolHandoffPlan.create(
        agent_plan=fixture["agent_plan"],
        agent_outcome=fixture["agent_outcome"],
        broker_call=call or fixture["call"],
        limits=AgentToolHandoffLimits(),
        created_at=now,
        deadline=now + timedelta(seconds=45),
        idempotency_key=key,
        attempt=attempt,
        previous_handoff_id=previous,
    )


def _close(fixture):
    fixture["agent_store"].close()
    fixture["handoff_store"].close()


def test_handoff_executes_one_precommitted_call_and_imports_digest_only_observation(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _handoff(fixture, now)

    first = fixture["service"].execute(plan, now=now + timedelta(seconds=1))
    replay = fixture["service"].execute(plan, now=now + timedelta(seconds=2))

    assert first == replay
    assert first.status is AgentToolHandoffStatus.COMPLETED
    assert first.cleanup.complete
    assert first.observation is not None
    assert first.observation.evidence_refs == (EVIDENCE,)
    assert first.observation.response_body_sha256 == BODY_SHA256
    assert first.observation.final_url_digest != URL
    assert len(fixture["transport"].calls) == 1
    persisted = (tmp_path / "handoffs.sqlite3").read_bytes()
    agent_persisted = (tmp_path / "agent-runs.sqlite3").read_bytes()
    assert URL.encode() not in persisted
    assert agent_broker_call_commitment(fixture["call"]).encode() not in persisted
    assert URL.encode() not in agent_persisted
    assert agent_broker_call_commitment(fixture["call"]).encode() not in agent_persisted
    assert b"raw-tool-response" not in persisted
    _close(fixture)


def test_handoff_outcome_rejects_observation_result_drift(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    outcome = fixture["service"].execute(
        _handoff(fixture, now), now=now + timedelta(seconds=1)
    )
    payload = outcome.model_dump(mode="python")
    observation = dict(payload["observation"])
    observation["response_body_sha256"] = "6" * 64
    observation["observation_id"] = canonical_digest(
        {key: value for key, value in observation.items() if key != "observation_id"}
    )
    payload["observation"] = observation
    payload["outcome_id"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "outcome_id"}
    )

    with pytest.raises(ValidationError, match="Observation Broker result binding"):
        AgentToolHandoffOutcome.model_validate(payload)
    _close(fixture)


def test_handoff_rejects_intent_or_broker_call_drift_before_checkpoint(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    drifted = fixture["call"].model_copy(
        update={
            "http": HttpRequestPlan(
                method="GET",
                url="https://app.example.test/drifted",
                test_class="read_only",
            ),
            "idempotency_key": "broker:drifted",
        }
    )
    plan = _handoff(fixture, now, call=drifted)

    with pytest.raises(AgentToolHandoffRejected, match="commitment"):
        fixture["service"].execute(plan, now=now + timedelta(seconds=1))

    count = fixture["handoff_store"].connection.execute(
        "SELECT count(*) FROM agent_tool_handoffs"
    ).fetchone()[0]
    assert count == 0
    assert fixture["resolver"].calls == []
    assert fixture["transport"].calls == []
    _close(fixture)


def test_handoff_scope_denial_is_terminal_and_creates_no_observation(
    tmp_path, approved_scope, now
):
    http = HttpRequestPlan(
        method="GET",
        url="https://outside.example.test/",
        test_class="read_only",
    )
    fixture = _fixture(tmp_path, now, approved_scope, http=http)
    plan = _handoff(fixture, now)

    outcome = fixture["service"].execute(plan, now=now + timedelta(seconds=1))

    assert outcome.status is AgentToolHandoffStatus.DENIED
    assert outcome.observation is None
    assert outcome.broker_result.error_codes == ("scope_policy_not_satisfied",)
    assert fixture["transport"].calls == []
    with pytest.raises(AgentToolHandoffRetryRejected):
        fixture["handoff_store"].claim(
            _handoff(
                fixture,
                now,
                call=fixture["call"].model_copy(
                    update={"idempotency_key": "broker:retry-denied"}
                ),
                key="handoff:retry-denied",
                attempt=2,
                previous=plan.handoff_id,
            ),
            now=now + timedelta(seconds=2),
        )
    _close(fixture)


def test_handoff_allows_one_approval_bound_retry_for_state_change(
    tmp_path, approved_scope, now
):
    http = HttpRequestPlan(
        method="POST",
        url=URL,
        test_class="idor",
        body_ref="8" * 64,
        body_bytes=32,
    )
    fixture = _fixture(tmp_path, now, approved_scope, http=http)
    first_plan = _handoff(fixture, now)
    first = fixture["service"].execute(
        first_plan, now=now + timedelta(seconds=1)
    )
    assert first.status is AgentToolHandoffStatus.APPROVAL_REQUIRED
    assert fixture["transport"].calls == []

    second_call = fixture["call"].model_copy(
        update={"call_id": uuid4(), "idempotency_key": "broker:handoff:approved"}
    )
    second_plan = _handoff(
        fixture,
        now,
        call=second_call,
        key="handoff:approved",
        attempt=2,
        previous=first_plan.handoff_id,
    )
    action = ActionRequest(
        engagement_id=second_call.task.engagement_id,
        target_id=second_call.task.target_id,
        action=second_call.tool_id,
        requested_at=now + timedelta(seconds=2),
        url=second_call.http.url,
        test_class=second_call.http.test_class,
        mutates_state=True,
    )
    approval = ApprovalRequest(
        engagement_id=second_call.task.engagement_id,
        target_id=second_call.task.target_id,
        action=ApprovalAction.MUTATE_TARGET_STATE,
        action_digest=action.digest(),
        expected_side_effects=("authorized HTTP validation",),
        evidence_summary="controlled validation approved",
        policy_version=second_call.task.scope_version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="reviewer",
        decided_at=now,
    )

    second = fixture["service"].execute(
        second_plan,
        now=now + timedelta(seconds=2),
        approvals=(approval,),
    )

    assert second.status is AgentToolHandoffStatus.COMPLETED
    assert second.observation is not None
    assert len(fixture["transport"].calls) == 1
    third = second_call.model_copy(
        update={"call_id": uuid4(), "idempotency_key": "broker:handoff:third"}
    )
    with pytest.raises(AgentToolHandoffRetryRejected):
        fixture["handoff_store"].claim(
            _handoff(
                fixture,
                now,
                call=third,
                key="handoff:third",
                attempt=2,
                previous=second_plan.handoff_id,
            ),
            now=now + timedelta(seconds=3),
        )
    _close(fixture)


def test_handoff_maps_broker_timeout_and_preserves_cleanup(
    tmp_path, approved_scope, now
):
    hop = OfflineHttpHop(
        status_code=200,
        peer_ip=IP,
        response_bytes=128,
        response_body_sha256=BODY_SHA256,
        evidence_ref=EVIDENCE,
        elapsed_seconds=16,
    )
    fixture = _fixture(tmp_path, now, approved_scope, hop=hop)

    outcome = fixture["service"].execute(
        _handoff(fixture, now), now=now + timedelta(seconds=1)
    )

    assert outcome.status is AgentToolHandoffStatus.TIMED_OUT
    assert outcome.observation is None
    assert outcome.cleanup.complete
    assert outcome.broker_result.error_codes == ("http_total_timeout",)
    _close(fixture)


def test_handoff_maps_broker_transport_failure_without_observation(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    fixture["broker"].http_transport = OfflineHttpTransport({})

    outcome = fixture["service"].execute(
        _handoff(fixture, now), now=now + timedelta(seconds=1)
    )

    assert outcome.status is AgentToolHandoffStatus.FAILED
    assert outcome.observation is None
    assert outcome.cleanup.complete
    assert outcome.broker_result.error_codes == ("http_transport_failed",)
    _close(fixture)


def test_handoff_deadline_and_unfinished_agent_fail_before_handoff_checkpoint(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _handoff(fixture, now)
    with pytest.raises(AgentToolHandoffTimedOut):
        fixture["service"].execute(plan, now=plan.deadline)
    assert fixture["handoff_store"].connection.execute(
        "SELECT count(*) FROM agent_tool_handoffs"
    ).fetchone()[0] == 0
    _close(fixture)

    unfinished = _fixture(tmp_path / "unfinished", now, approved_scope)
    unfinished["agent_store"].connection.execute(
        "UPDATE agent_runs SET state = 'started', outcome_json = NULL"
    )
    unfinished["agent_store"].connection.commit()
    with pytest.raises(AgentToolHandoffRejected, match="authoritative"):
        unfinished["service"].execute(
            _handoff(unfinished, now), now=now + timedelta(seconds=1)
        )
    assert unfinished["resolver"].calls == []
    _close(unfinished)


def test_handoff_checkpoint_conflict_and_recovery_are_fail_closed(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _handoff(fixture, now)
    assert fixture["handoff_store"].claim(plan, now=now).created

    with pytest.raises(AgentToolHandoffRecoveryRequired):
        fixture["service"].execute(plan, now=now + timedelta(seconds=1))

    different = plan.model_copy(
        update={
            "handoff_id": "0" * 64,
            "idempotency_key": plan.idempotency_key,
        }
    )
    with pytest.raises(AgentToolHandoffIdempotencyConflict):
        fixture["handoff_store"].claim(different, now=now)
    assert fixture["resolver"].calls == []
    assert fixture["transport"].calls == []
    _close(fixture)
