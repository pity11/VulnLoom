from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import (
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextStore,
    AgentContinuationIdempotencyConflict,
    AgentContinuationObservationConflict,
    AgentContinuationRecoveryRequired,
    AgentContinuationRejected,
    AgentContinuationService,
    AgentContinuationStatus,
    AgentContinuationStore,
    AgentContinuationTimedOut,
    AgentMessageRenderer,
    AgentModelRegistration,
    AgentModelReply,
    AgentProviderTransportRejected,
    AgentProviderTransportTimedOut,
    AgentRunLimits,
    AgentRunPlan,
    AgentRunStatus,
    AgentRunStore,
    AgentStepRequest,
    AgentToolHandoffLimits,
    AgentToolHandoffPlan,
    AgentToolHandoffService,
    AgentToolHandoffStatus,
    AgentToolHandoffStore,
    OfflineAgentRuntime,
    OfflineReplayModelAdapter,
    ReplayTurn,
    agent_broker_call_commitment,
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
from vulnloom.domain.models import EvidenceKind
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkGrant, sandbox_profile_digest, validation_profile

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
IP = "192.0.2.10"
URL = "https://app.example.test/items?id=7"
SECRET = "continuation-secret-value"


class StaticContinuationAdapter:
    def __init__(self, registration, decision, *, error=None):
        self.registration = registration
        self.decision = decision
        self.error = error
        self.requests = []
        self.envelopes = []

    def complete(self, request, *, message_envelope=None):
        self.requests.append(request)
        self.envelopes.append(message_envelope)
        if self.error is not None:
            raise self.error
        return AgentModelReply(
            structured_output=self.decision,
            provider_id=self.registration.provider_id,
            model=self.registration.model,
            input_tokens=4,
            output_tokens=3,
            latency_seconds=0.1,
        )


def _fixture(tmp_path, now, scope, *, decision=None, error=None, model_tokens=100):
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
        budget=TaskBudget(
            wall_seconds=60, model_tokens=model_tokens, tool_calls=1
        ),
        deadline=now + timedelta(minutes=2),
        idempotency_key="validator:continuation:root",
    )
    registration = AgentModelRegistration.create(
        provider_id="offline",
        model="continuation-replay-v1",
        adapter_digest=canonical_digest("agent-continuation-fixture"),
        supported_roles=(WorkerRole.VALIDATOR,),
        max_output_tokens=64,
    )
    root_plan = AgentRunPlan.create(
        task=task,
        registration=registration,
        limits=AgentRunLimits(
            max_steps=1,
            max_output_tokens_per_step=min(64, model_tokens),
            timeout_seconds=30,
        ),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="agent:continuation:root",
    )
    call = BrokerCall(
        task=task,
        profile=profile,
        tool_id="http.request",
        http=HttpRequestPlan(method="GET", url=URL, test_class="read_only"),
        idempotency_key="broker:continuation:root",
    )
    commitment = agent_broker_call_commitment(call)
    request = AgentStepRequest.create(
        plan=root_plan,
        step=1,
        remaining_model_tokens=task.budget.model_tokens,
    )
    root_adapter = OfflineReplayModelAdapter(
        registration=registration,
        turns=(
            ReplayTurn(
                expected_request_digest=canonical_digest(
                    request.model_dump(mode="python")
                ),
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
            ),
        ),
    )
    root_store = AgentRunStore(tmp_path / "root-runs.sqlite3")
    root_outcome = OfflineAgentRuntime(
        store=root_store,
        registration=registration,
        adapter=root_adapter,
    ).execute(root_plan, now=now)
    assert root_outcome.status is AgentRunStatus.TOOL_PROPOSED

    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        f"status: 200\nAuthorization: Bearer {SECRET}\nobject owner mismatch",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "6" * 64,
        producer="broker.http.pinned-v1",
        target_version=task.target_version,
        summary="authorized response",
    )
    transport = OfflineHttpTransport(
        {
            URL: OfflineHttpHop(
                status_code=200,
                peer_ip=IP,
                response_bytes=128,
                response_body_sha256="7" * 64,
                evidence_ref=evidence.evidence_id,
            )
        }
    )
    broker = ToolBroker(
        scope=scope,
        registry=registry,
        resolver=StaticResolver({"app.example.test": (IP,)}),
        http_transport=transport,
    )
    handoff_store = AgentToolHandoffStore(tmp_path / "handoffs.sqlite3")
    handoff_plan = AgentToolHandoffPlan.create(
        agent_plan=root_plan,
        agent_outcome=root_outcome,
        broker_call=call,
        limits=AgentToolHandoffLimits(),
        created_at=now,
        deadline=now + timedelta(seconds=45),
        idempotency_key="handoff:continuation:root",
    )
    handoff_outcome = AgentToolHandoffService(
        agent_store=root_store,
        handoff_store=handoff_store,
        broker=broker,
    ).execute(handoff_plan, now=now + timedelta(seconds=1))
    assert handoff_outcome.status is AgentToolHandoffStatus.COMPLETED

    context_store = AgentContextStore(tmp_path / "contexts")
    continuation_run_store = AgentRunStore(tmp_path / "continuation-runs.sqlite3")
    adapter = StaticContinuationAdapter(
        registration,
        decision
        or {
            "kind": "complete",
            "summary_digest": "8" * 64,
            "supporting_ref_digests": [evidence.evidence_id],
        },
        error=error,
    )
    continuation_runtime = OfflineAgentRuntime(
        store=continuation_run_store,
        registration=registration,
        adapter=adapter,
        context_store=context_store,
        message_renderer=AgentMessageRenderer(),
    )
    continuation_store = AgentContinuationStore(tmp_path / "continuations.sqlite3")
    continuation_service = AgentContinuationService(
        root_agent_store=root_store,
        handoff_store=handoff_store,
        continuation_store=continuation_store,
        continuation_runtime=continuation_runtime,
        evidence_store=evidence_store,
        context_store=context_store,
        context_assembler=AgentContextAssembler(),
    )
    return {
        "root_plan": root_plan,
        "root_outcome": root_outcome,
        "root_store": root_store,
        "handoff_plan": handoff_plan,
        "handoff_outcome": handoff_outcome,
        "handoff_store": handoff_store,
        "evidence": evidence,
        "evidence_store": evidence_store,
        "context_store": context_store,
        "continuation_run_store": continuation_run_store,
        "continuation_store": continuation_store,
        "adapter": adapter,
        "service": continuation_service,
    }


def _prepare(fixture, now, *, key="continuation:1", run_key="agent:continuation:1"):
    return fixture["service"].prepare(
        root_plan=fixture["root_plan"],
        handoff_id=fixture["handoff_plan"].handoff_id,
        now=now + timedelta(seconds=2),
        idempotency_key=key,
        continuation_run_key=run_key,
        continuation_task_id=uuid4(),
    )


def _close(fixture):
    fixture["root_store"].close()
    fixture["handoff_store"].close()
    fixture["continuation_run_store"].close()
    fixture["continuation_store"].close()


def test_continuation_consumes_one_sealed_observation_and_terminates(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)

    first = fixture["service"].execute(plan, now=now + timedelta(seconds=3))
    replay = fixture["service"].execute(plan, now=now + timedelta(seconds=4))

    assert first == replay
    assert first.status is AgentContinuationStatus.COMPLETED
    assert first.cleanup.complete
    assert first.agent_outcome.status is AgentRunStatus.COMPLETED
    assert plan.continuation_plan.task.allowed_tools == frozenset()
    assert plan.continuation_plan.task.budget.tool_calls == 0
    assert plan.continuation_plan.task.budget.model_tokens == 95
    assert plan.budget.consumed_tool_calls == 1
    assert len(fixture["adapter"].requests) == 1
    envelope = fixture["adapter"].envelopes[0]
    assert envelope is not None
    assert '"allowed_tools":[]' in envelope.messages[1].content
    assert '"tool_call_budget":0' in envelope.messages[1].content
    assert SECRET not in envelope.messages[1].content
    assert "[REDACTED]" in envelope.messages[1].content
    persisted = (tmp_path / "continuations.sqlite3").read_bytes()
    assert SECRET.encode() not in persisted
    assert b"object owner mismatch" not in persisted
    assert URL.encode() not in persisted
    _close(fixture)


def test_continuation_accepts_blocked_terminal_decision(tmp_path, approved_scope, now):
    fixture = _fixture(
        tmp_path,
        now,
        approved_scope,
        decision={"kind": "blocked", "summary_digest": "9" * 64},
    )
    outcome = fixture["service"].execute(
        _prepare(fixture, now), now=now + timedelta(seconds=3)
    )

    assert outcome.status is AgentContinuationStatus.BLOCKED
    assert outcome.agent_outcome.status is AgentRunStatus.BLOCKED
    _close(fixture)


def test_continuation_rejects_recursive_tool_proposal_as_failed(
    tmp_path, approved_scope, now
):
    fixture = _fixture(
        tmp_path,
        now,
        approved_scope,
        decision={
            "kind": "propose_tool",
            "tool_call": {
                "tool_id": "http.request",
                "arguments": ["untrusted"],
                "working_directory": "source",
            },
        },
    )
    outcome = fixture["service"].execute(
        _prepare(fixture, now), now=now + timedelta(seconds=3)
    )

    assert outcome.status is AgentContinuationStatus.FAILED
    assert outcome.agent_outcome.error_codes == ("tool_proposal_not_allowed",)
    assert outcome.agent_outcome.tool_intent is None
    _close(fixture)


def test_continuation_rejects_missing_evidence_before_checkpoint(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    os.unlink(
        fixture["evidence_store"].objects / fixture["evidence"].evidence_id
    )

    with pytest.raises(AgentContinuationRejected, match="Evidence"):
        _prepare(fixture, now)

    count = fixture["continuation_store"].connection.execute(
        "SELECT count(*) FROM agent_continuations"
    ).fetchone()[0]
    assert count == 0
    assert fixture["adapter"].requests == []
    _close(fixture)


def test_continuation_rechecks_read_only_context_before_checkpoint(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    path = fixture["context_store"].objects / plan.context_snapshot.snapshot_id
    os.chmod(path, 0o600)

    with pytest.raises(AgentContinuationRejected, match="context revalidation"):
        fixture["service"].execute(plan, now=now + timedelta(seconds=3))

    count = fixture["continuation_store"].connection.execute(
        "SELECT count(*) FROM agent_continuations"
    ).fetchone()[0]
    assert count == 0
    assert fixture["adapter"].requests == []
    _close(fixture)


def test_continuation_rejects_plan_drift_at_typed_boundary(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    payload = plan.model_dump(mode="python")
    payload["continuation_plan"]["task"]["policy_digest"] = "0" * 64

    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)
    _close(fixture)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("root_plan_digest", "root plan digest"),
        ("root_outcome_digest", "root outcome digest"),
        ("handoff_outcome_digest", "handoff outcome digest"),
        ("continuation_plan_digest", "run plan digest"),
    ],
)
def test_continuation_plan_rejects_each_authoritative_digest_drift(
    tmp_path, approved_scope, now, field, message
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    payload = plan.model_dump(mode="python")
    payload[field] = "0" * 64
    payload["continuation_id"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "continuation_id"}
    )

    with pytest.raises(ValidationError, match=message):
        type(plan).model_validate(payload)
    _close(fixture)


def test_continuation_service_revalidates_plan_before_checkpoint(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now).model_copy(
        update={"root_plan_digest": "0" * 64}
    )

    with pytest.raises(AgentContinuationRejected, match="boundary validation"):
        fixture["service"].execute(plan, now=now + timedelta(seconds=3))

    count = fixture["continuation_store"].connection.execute(
        "SELECT count(*) FROM agent_continuations"
    ).fetchone()[0]
    assert count == 0
    _close(fixture)


def test_continuation_rejects_context_limit_before_checkpoint(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)

    with pytest.raises(AgentContinuationRejected, match="materialization failed"):
        fixture["service"].prepare(
            root_plan=fixture["root_plan"],
            handoff_id=fixture["handoff_plan"].handoff_id,
            now=now + timedelta(seconds=2),
            idempotency_key="continuation:limited",
            continuation_run_key="agent:continuation:limited",
            context_limits=AgentContextLimits(
                max_fragments=1,
                max_source_bytes_per_fragment=8,
                max_fragment_bytes=8,
                max_total_bytes=8,
            ),
        )

    assert fixture["adapter"].requests == []
    _close(fixture)


def test_continuation_outcome_rejects_status_run_and_cleanup_drift(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    outcome = fixture["service"].execute(
        _prepare(fixture, now), now=now + timedelta(seconds=3)
    )
    cases = []

    status = outcome.model_dump(mode="python")
    status["status"] = "blocked"
    cases.append((status, "statuses do not match"))

    run = outcome.model_dump(mode="python")
    run["agent_outcome"]["plan_id"] = "0" * 64
    cases.append((run, "run outcome binding"))

    cleanup = outcome.model_dump(mode="python")
    cleanup["cleanup"]["context_reverified"] = False
    cases.append((cleanup, "cleanup is incomplete"))

    for payload, message in cases:
        payload["outcome_id"] = canonical_digest(
            {key: value for key, value in payload.items() if key != "outcome_id"}
        )
        with pytest.raises(ValidationError, match=message):
            type(outcome).model_validate(payload)
    _close(fixture)


def test_continuation_refuses_exhausted_budget_and_expired_deadline(
    tmp_path, approved_scope, now
):
    exhausted = _fixture(
        tmp_path / "exhausted", now, approved_scope, model_tokens=5
    )
    with pytest.raises(AgentContinuationRejected, match="budget is exhausted"):
        _prepare(exhausted, now)
    _close(exhausted)

    expired = _fixture(tmp_path / "expired", now, approved_scope)
    with pytest.raises(AgentContinuationTimedOut, match="deadline expired"):
        expired["service"].prepare(
            root_plan=expired["root_plan"],
            handoff_id=expired["handoff_plan"].handoff_id,
            now=now + timedelta(minutes=3),
            idempotency_key="continuation:expired",
            continuation_run_key="agent:continuation:expired",
        )
    _close(expired)


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (
            AgentProviderTransportTimedOut("timeout"),
            AgentContinuationStatus.TIMED_OUT,
            "provider_transport_timeout",
        ),
        (
            AgentProviderTransportRejected("rejected"),
            AgentContinuationStatus.FAILED,
            "provider_transport_rejected",
        ),
    ],
)
def test_continuation_maps_provider_terminal_failures(
    tmp_path, approved_scope, now, error, expected_status, expected_code
):
    fixture = _fixture(tmp_path, now, approved_scope, error=error)
    outcome = fixture["service"].execute(
        _prepare(fixture, now), now=now + timedelta(seconds=3)
    )

    assert outcome.status is expected_status
    assert outcome.agent_outcome.error_codes == (expected_code,)
    assert outcome.cleanup.complete
    _close(fixture)


def test_continuation_checkpoint_conflict_recovery_and_single_consumption(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    first = _prepare(fixture, now)
    second = fixture["service"].prepare(
        root_plan=fixture["root_plan"],
        handoff_id=fixture["handoff_plan"].handoff_id,
        now=now + timedelta(seconds=2),
        idempotency_key="continuation:2",
        continuation_run_key="agent:continuation:2",
        continuation_task_id=uuid4(),
    )
    fixture["continuation_store"].claim(first, now=now + timedelta(seconds=3))

    with pytest.raises(AgentContinuationRecoveryRequired):
        fixture["continuation_store"].claim(first, now=now + timedelta(seconds=4))
    with pytest.raises(AgentContinuationObservationConflict):
        fixture["continuation_store"].claim(second, now=now + timedelta(seconds=4))

    payload = second.model_dump(mode="python")
    payload["idempotency_key"] = first.idempotency_key
    payload["continuation_id"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "continuation_id"}
    )
    conflicting = type(second).model_validate(payload)
    with pytest.raises(AgentContinuationIdempotencyConflict):
        fixture["continuation_store"].claim(
            conflicting, now=now + timedelta(seconds=4)
        )
    _close(fixture)


def test_continuation_checkpoint_rejects_persisted_outcome_binding_drift(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    outcome = fixture["service"].execute(plan, now=now + timedelta(seconds=3))
    payload = outcome.model_dump(mode="python")
    payload["root_plan_id"] = "0" * 64
    payload["outcome_id"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "outcome_id"}
    )
    drifted = type(outcome).model_validate(payload)
    with fixture["continuation_store"].connection:
        fixture["continuation_store"].connection.execute(
            "UPDATE agent_continuations SET outcome_json = ? WHERE continuation_id = ?",
            (drifted.model_dump_json(), plan.continuation_id),
        )

    with pytest.raises(AgentContinuationRecoveryRequired, match="binding mismatch"):
        fixture["continuation_store"].claim(
            plan, now=now + timedelta(seconds=4)
        )
    _close(fixture)
