from __future__ import annotations

import json
import os
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import (
    AgentContextAssembler,
    AgentContextStore,
    AgentContinuationService,
    AgentContinuationStore,
    AgentMessageRenderer,
    AgentModelRegistration,
    AgentModelReply,
    AgentProviderTransportRejected,
    AgentProviderTransportTimedOut,
    AgentRunLimits,
    AgentRunPlan,
    AgentRunStore,
    AgentSessionAuditArtifact,
    AgentSessionAuditArtifactStore,
    AgentSessionAuditBundle,
    AgentSessionAuditIdempotencyConflict,
    AgentSessionAuditLimits,
    AgentSessionAuditOutcome,
    AgentSessionAuditPlan,
    AgentSessionAuditRecoveryRequired,
    AgentSessionAuditRejected,
    AgentSessionAuditService,
    AgentSessionAuditStore,
    AgentSessionAuditTimedOut,
    AgentSessionCallTemplate,
    AgentSessionIdempotencyConflict,
    AgentSessionObservationConflict,
    AgentSessionRecommendation,
    AgentSessionRecoveryRequired,
    AgentSessionRejected,
    AgentSessionService,
    AgentSessionStatus,
    AgentSessionStore,
    AgentSessionTimedOut,
    AgentStepRequest,
    AgentToolHandoffLimits,
    AgentToolHandoffPlan,
    AgentToolHandoffService,
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
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    EvidenceKind,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.policy.engine import ActionRequest
from vulnloom.runners import NetworkGrant, sandbox_profile_digest, validation_profile

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
IP = "192.0.2.10"
URL1 = "https://app.example.test/first"
URL2 = "https://app.example.test/second"
SECRET = "session-secret-value"


class QueueAdapter:
    def __init__(self, registration):
        self.registration = registration
        self.decisions = []
        self.requests = []
        self.envelopes = []
        self.latency_seconds = 0.1

    def complete(self, request, *, message_envelope=None):
        self.requests.append(request)
        self.envelopes.append(message_envelope)
        if not self.decisions:
            raise AssertionError("unexpected provider turn")
        decision = self.decisions.pop(0)
        if isinstance(decision, Exception):
            raise decision
        return AgentModelReply(
            structured_output=decision,
            provider_id=self.registration.provider_id,
            model=self.registration.model,
            input_tokens=4,
            output_tokens=3,
            latency_seconds=self.latency_seconds,
        )


def _fixture(tmp_path, now, scope, *, model_tokens=100, tool_calls=2):
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
            wall_seconds=60,
            model_tokens=model_tokens,
            tool_calls=tool_calls,
        ),
        deadline=now + timedelta(minutes=2),
        idempotency_key="validator:session:root",
    )
    registration = AgentModelRegistration.create(
        provider_id="offline",
        model="session-replay-v1",
        adapter_digest=canonical_digest("agent-session-fixture"),
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
        idempotency_key="agent:session:root",
    )
    call1 = BrokerCall(
        task=task,
        profile=profile,
        tool_id="http.request",
        http=HttpRequestPlan(method="GET", url=URL1, test_class="read_only"),
        idempotency_key="broker:session:first",
    )
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
                        "tool_id": call1.tool_id,
                        "arguments": [agent_broker_call_commitment(call1)],
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
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence1 = evidence_store.capture_text(
        f"status: 200\nAuthorization: Bearer {SECRET}\nfirst result",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "6" * 64,
        producer="broker.http.pinned-v1",
        target_version=task.target_version,
        summary="first authorized response",
    )
    evidence2 = evidence_store.capture_text(
        "status: 200\nsecond result",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "7" * 64,
        producer="broker.http.pinned-v1",
        target_version=task.target_version,
        summary="second authorized response",
    )
    transport = OfflineHttpTransport(
        {
            URL1: OfflineHttpHop(
                status_code=200,
                peer_ip=IP,
                response_bytes=64,
                response_body_sha256="8" * 64,
                evidence_ref=evidence1.evidence_id,
            ),
            URL2: OfflineHttpHop(
                status_code=200,
                peer_ip=IP,
                response_bytes=96,
                response_body_sha256="9" * 64,
                evidence_ref=evidence2.evidence_id,
            ),
        }
    )
    broker = ToolBroker(
        scope=scope,
        registry=registry,
        resolver=StaticResolver({"app.example.test": (IP,)}),
        http_transport=transport,
    )
    handoff_store = AgentToolHandoffStore(tmp_path / "handoffs.sqlite3")
    first_handoff_plan = AgentToolHandoffPlan.create(
        agent_plan=root_plan,
        agent_outcome=root_outcome,
        broker_call=call1,
        limits=AgentToolHandoffLimits(),
        created_at=now,
        deadline=now + timedelta(seconds=45),
        idempotency_key="handoff:session:first",
    )
    first_handoff = AgentToolHandoffService(
        agent_store=root_store,
        handoff_store=handoff_store,
        broker=broker,
    ).execute(first_handoff_plan, now=now + timedelta(seconds=1))
    context_store = AgentContextStore(tmp_path / "contexts")
    round_store = AgentRunStore(tmp_path / "session-runs.sqlite3")
    adapter = QueueAdapter(registration)
    runtime = OfflineAgentRuntime(
        store=round_store,
        registration=registration,
        adapter=adapter,
        context_store=context_store,
        message_renderer=AgentMessageRenderer(),
    )
    continuation_store = AgentContinuationStore(tmp_path / "continuations.sqlite3")
    handoff_service = AgentToolHandoffService(
        agent_store=round_store,
        handoff_store=handoff_store,
        broker=broker,
    )
    continuation_service = AgentContinuationService(
        root_agent_store=round_store,
        handoff_store=handoff_store,
        continuation_store=continuation_store,
        continuation_runtime=runtime,
        evidence_store=evidence_store,
        context_store=context_store,
        context_assembler=AgentContextAssembler(),
    )
    session_store = AgentSessionStore(tmp_path / "sessions.sqlite3")
    service = AgentSessionService(
        root_agent_store=root_store,
        handoff_store=handoff_store,
        session_store=session_store,
        round_runtime=runtime,
        round_handoff_service=handoff_service,
        terminal_continuation_service=continuation_service,
        evidence_store=evidence_store,
        context_store=context_store,
        context_assembler=AgentContextAssembler(),
    )
    template = AgentSessionCallTemplate.create(
        profile=profile,
        tool_id="http.request",
        http=HttpRequestPlan(method="GET", url=URL2, test_class="read_only"),
        idempotency_key="broker:session:second",
    )
    return {
        "root_plan": root_plan,
        "root_outcome": root_outcome,
        "call1": call1,
        "profile": profile,
        "first_handoff_plan": first_handoff_plan,
        "first_handoff": first_handoff,
        "evidence1": evidence1,
        "evidence2": evidence2,
        "evidence_store": evidence_store,
        "root_store": root_store,
        "handoff_store": handoff_store,
        "round_store": round_store,
        "continuation_store": continuation_store,
        "session_store": session_store,
        "context_store": context_store,
        "adapter": adapter,
        "service": service,
        "template": template,
    }


def _prepare(fixture, now, *, key="session:1", run_key="agent:session:round-2"):
    return fixture["service"].prepare(
        root_plan=fixture["root_plan"],
        first_handoff_id=fixture["first_handoff_plan"].handoff_id,
        call_templates=(fixture["template"],),
        now=now + timedelta(seconds=2),
        idempotency_key=key,
        round_run_key=run_key,
        round_task_id=uuid4(),
    )


def _execute(fixture, plan, now):
    return fixture["service"].execute(
        plan,
        now=now + timedelta(seconds=3),
        terminal_continuation_key="session:terminal",
        terminal_run_key="agent:session:terminal",
    )


def _close(fixture):
    fixture["root_store"].close()
    fixture["handoff_store"].close()
    fixture["round_store"].close()
    fixture["continuation_store"].close()
    fixture["session_store"].close()


def test_session_executes_exactly_two_tools_then_terminates(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    commitment = plan.authorized_calls.options[0].call_commitment
    fixture["adapter"].decisions.extend(
        [
            {
                "kind": "propose_tool",
                "tool_call": {
                    "tool_id": "http.request",
                    "arguments": [commitment],
                    "working_directory": "source",
                },
            },
            {
                "kind": "complete",
                "summary_digest": "a" * 64,
                "supporting_ref_digests": [fixture["evidence2"].evidence_id],
            },
        ]
    )

    first = _execute(fixture, plan, now)
    replay = _execute(fixture, plan, now + timedelta(seconds=1))

    assert first == replay
    assert first.status is AgentSessionStatus.COMPLETED
    assert first.budget.provider_attempts == 3
    assert first.budget.broker_attempts == 2
    assert first.budget.consumed_tool_calls == 2
    assert first.budget.remaining_tool_calls == 0
    assert first.second_handoff_outcome is not None
    assert first.terminal_continuation is not None
    assert len(fixture["adapter"].requests) == 2
    round_envelope = fixture["adapter"].envelopes[0]
    assert round_envelope.authorized_call_set_id == plan.authorized_calls.call_set_id
    assert round_envelope.authorized_call_commitments == (commitment,)
    assert commitment in round_envelope.messages[1].content
    terminal_envelope = fixture["adapter"].envelopes[1]
    assert terminal_envelope.authorized_call_set_id is None
    assert terminal_envelope.tool_call_budget == 0
    persisted = (tmp_path / "sessions.sqlite3").read_bytes()
    assert SECRET.encode() not in persisted
    assert URL1.encode() not in persisted
    assert URL2.encode() not in persisted
    _close(fixture)


def test_session_third_tool_proposal_fails_without_third_handoff(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    commitment = plan.authorized_calls.options[0].call_commitment
    proposal = {
        "kind": "propose_tool",
        "tool_call": {
            "tool_id": "http.request",
            "arguments": [commitment],
            "working_directory": "source",
        },
    }
    fixture["adapter"].decisions.extend([proposal, proposal])

    outcome = _execute(fixture, plan, now)

    assert outcome.status is AgentSessionStatus.FAILED
    assert outcome.terminal_continuation is not None
    assert outcome.terminal_continuation.agent_outcome.error_codes == (
        "tool_proposal_not_allowed",
    )
    assert outcome.budget.broker_attempts == 2
    assert len(fixture["adapter"].requests) == 2
    _close(fixture)


def test_session_rejects_unlisted_commitment_without_broker_call(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    fixture["adapter"].decisions.append(
        {
            "kind": "propose_tool",
            "tool_call": {
                "tool_id": "http.request",
                "arguments": ["b" * 64],
                "working_directory": "source",
            },
        }
    )

    outcome = _execute(fixture, plan, now)

    assert outcome.status is AgentSessionStatus.FAILED
    assert outcome.selected_call_commitment is None
    assert outcome.second_handoff_outcome is None
    assert outcome.budget.broker_attempts == 1
    count = fixture["handoff_store"].connection.execute(
        "SELECT count(*) FROM agent_tool_handoffs"
    ).fetchone()[0]
    assert count == 1
    _close(fixture)


def test_session_accepts_early_blocked_terminal_decision(tmp_path, approved_scope, now):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    fixture["adapter"].decisions.append(
        {"kind": "blocked", "summary_digest": "c" * 64}
    )

    outcome = _execute(fixture, plan, now)

    assert outcome.status is AgentSessionStatus.BLOCKED
    assert outcome.second_handoff_outcome is None
    assert outcome.budget.provider_attempts == 2
    assert outcome.budget.consumed_tool_calls == 1
    _close(fixture)


def test_session_rejects_repeated_or_mutating_call_templates(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    with pytest.raises(AgentSessionRejected, match="unique"):
        fixture["service"].prepare(
            root_plan=fixture["root_plan"],
            first_handoff_id=fixture["first_handoff_plan"].handoff_id,
            call_templates=(fixture["template"], fixture["template"]),
            now=now + timedelta(seconds=2),
            idempotency_key="session:repeat",
            round_run_key="agent:session:repeat",
        )
    with pytest.raises(ValidationError, match="read-only"):
        AgentSessionCallTemplate.create(
            profile=fixture["profile"],
            tool_id="http.request",
            http=HttpRequestPlan(method="POST", url=URL2, test_class="state_change"),
            idempotency_key="broker:session:mutating",
        )
    _close(fixture)


def test_session_requires_exactly_two_root_tool_calls(tmp_path, approved_scope, now):
    fixture = _fixture(tmp_path, now, approved_scope, tool_calls=1)
    with pytest.raises(AgentSessionRejected, match="remaining tool round"):
        _prepare(fixture, now)
    _close(fixture)


def test_session_rejects_empty_oversized_exhausted_and_expired_prepare(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path / "base", now, approved_scope)
    kwargs = {
        "root_plan": fixture["root_plan"],
        "first_handoff_id": fixture["first_handoff_plan"].handoff_id,
        "now": now + timedelta(seconds=2),
        "idempotency_key": "session:bad-prepare",
        "round_run_key": "agent:session:bad-prepare",
    }
    with pytest.raises(AgentSessionRejected, match="authorized call set"):
        fixture["service"].prepare(call_templates=(), **kwargs)
    with pytest.raises(AgentSessionRejected, match="too large"):
        fixture["service"].prepare(
            call_templates=(fixture["template"],) * 9, **kwargs
        )
    with pytest.raises(AgentSessionTimedOut, match="deadline expired"):
        fixture["service"].prepare(
            call_templates=(fixture["template"],),
            **{**kwargs, "now": fixture["root_plan"].deadline},
        )
    _close(fixture)

    exhausted = _fixture(
        tmp_path / "exhausted", now, approved_scope, model_tokens=5
    )
    with pytest.raises(AgentSessionRejected, match="budget is exhausted"):
        _prepare(exhausted, now)
    _close(exhausted)


def test_session_rejects_missing_evidence_and_broker_preflight(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path / "evidence", now, approved_scope)
    os.unlink(
        fixture["evidence_store"].objects / fixture["evidence1"].evidence_id
    )
    with pytest.raises(AgentSessionRejected, match="materialization"):
        _prepare(fixture, now)
    _close(fixture)

    fixture = _fixture(tmp_path / "broker", now, approved_scope)
    wrong_profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id="f" * 64,
        network_grants=fixture["profile"].network_grants,
    )
    bad_template = AgentSessionCallTemplate.create(
        profile=wrong_profile,
        tool_id="http.request",
        http=fixture["template"].http,
        idempotency_key="broker:session:wrong-profile",
    )
    with pytest.raises(AgentSessionRejected, match="Broker preflight"):
        fixture["service"].prepare(
            root_plan=fixture["root_plan"],
            first_handoff_id=fixture["first_handoff_plan"].handoff_id,
            call_templates=(bad_template,),
            now=now + timedelta(seconds=2),
            idempotency_key="session:wrong-profile",
            round_run_key="agent:session:wrong-profile",
        )
    _close(fixture)


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (AgentProviderTransportRejected("rejected"), AgentSessionStatus.FAILED),
        (AgentProviderTransportTimedOut("timeout"), AgentSessionStatus.TIMED_OUT),
    ],
)
def test_session_normalizes_provider_failure_without_a_broker_call(
    tmp_path, approved_scope, now, error, status
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    fixture["adapter"].decisions.append(error)

    outcome = _execute(fixture, plan, now)

    assert outcome.status is status
    assert outcome.second_handoff_outcome is None
    assert outcome.budget.provider_attempts == 2
    assert outcome.budget.broker_attempts == 1
    _close(fixture)


def test_session_normalizes_round_wall_timeout(tmp_path, approved_scope, now):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    fixture["adapter"].latency_seconds = 31
    fixture["adapter"].decisions.append(
        {"kind": "complete", "summary_digest": "d" * 64}
    )

    outcome = _execute(fixture, plan, now)

    assert outcome.status is AgentSessionStatus.TIMED_OUT
    assert outcome.round_agent_outcome.error_codes == (
        "agent_wall_time_budget_exceeded",
    )
    _close(fixture)


def test_session_pauses_for_explicit_credential_approval_then_resumes_once(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    fixture["template"] = AgentSessionCallTemplate.create(
        profile=fixture["profile"],
        tool_id="http.request",
        http=HttpRequestPlan(
            method="GET",
            url=URL2,
            test_class="read_only",
            credential_ref="e" * 64,
        ),
        idempotency_key="broker:session:credentialed",
    )
    plan = _prepare(fixture, now)
    commitment = plan.authorized_calls.options[0].call_commitment
    fixture["adapter"].decisions.extend(
        [
            {
                "kind": "propose_tool",
                "tool_call": {
                    "tool_id": "http.request",
                    "arguments": [commitment],
                    "working_directory": "source",
                },
            },
            {"kind": "complete", "summary_digest": "f" * 64},
        ]
    )
    waiting = _execute(fixture, plan, now)

    assert waiting.status is AgentSessionStatus.APPROVAL_REQUIRED
    assert waiting.second_handoff_outcome is not None
    assert waiting.budget.broker_attempts == 2
    assert waiting.budget.consumed_tool_calls == 1
    replay = _execute(fixture, plan, now + timedelta(seconds=1))
    assert replay == waiting
    assert len(fixture["adapter"].requests) == 1

    call = plan.authorized_calls.options[0].broker_call
    resume_at = now + timedelta(seconds=5)
    action = ActionRequest(
        engagement_id=call.task.engagement_id,
        target_id=call.task.target_id,
        action=call.tool_id,
        requested_at=resume_at,
        url=call.http.url,
        test_class=call.http.test_class,
        mutates_state=False,
        uses_real_credentials=True,
    )
    approval = ApprovalRequest(
        engagement_id=call.task.engagement_id,
        target_id=call.task.target_id,
        action=ApprovalAction.USE_REAL_CREDENTIALS,
        action_digest=action.digest(),
        expected_side_effects=("authorized credentialed validation",),
        evidence_summary="explicitly approved credential use",
        policy_version=call.task.scope_version,
        expires_at=now + timedelta(minutes=1),
        status=ApprovalStatus.GRANTED,
        decided_by="reviewer",
        decided_at=now,
    )
    completed = fixture["service"].resume_after_approval(
        plan,
        waiting,
        approvals=(approval,),
        now=resume_at,
        retry_idempotency_key="session:approval-retry",
        terminal_continuation_key="session:approval-terminal",
        terminal_run_key="agent:session:approval-terminal",
    )
    replay_completed = fixture["service"].resume_after_approval(
        plan,
        waiting,
        approvals=(approval,),
        now=resume_at + timedelta(seconds=1),
        retry_idempotency_key="session:approval-retry",
        terminal_continuation_key="session:approval-terminal",
        terminal_run_key="agent:session:approval-terminal",
    )

    assert completed == replay_completed
    assert completed.status is AgentSessionStatus.COMPLETED
    assert completed.approval_handoff_outcome == waiting.second_handoff_outcome
    assert completed.approval_digests == (
        canonical_digest(approval.model_dump(mode="python")),
    )
    assert completed.second_handoff_outcome is not None
    assert completed.second_handoff_outcome.attempt == 2
    assert completed.budget.broker_attempts == 3
    assert completed.budget.consumed_tool_calls == 2
    assert completed.budget.remaining_tool_calls == 0
    assert len(fixture["adapter"].requests) == 2
    _close(fixture)


def test_session_call_set_and_budget_contracts_reject_digest_drift(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)

    template_payload = fixture["template"].model_dump(mode="python")
    template_payload["template_id"] = "0" * 64
    with pytest.raises(ValidationError, match="template content digest"):
        type(fixture["template"]).model_validate(template_payload)

    option = plan.authorized_calls.options[0]
    for field, message in (
        ("call_commitment", "commitment mismatch"),
        ("broker_call_digest", "Broker call digest"),
    ):
        payload = option.model_dump(mode="python")
        payload[field] = "0" * 64
        with pytest.raises(ValidationError, match=message):
            type(option).model_validate(payload)

    duplicate = plan.authorized_calls.model_dump(mode="python")
    duplicate["options"] = duplicate["options"] * 2
    duplicate["call_set_id"] = canonical_digest(
        {key: value for key, value in duplicate.items() if key != "call_set_id"}
    )
    with pytest.raises(ValidationError, match="unique and sorted"):
        type(plan.authorized_calls).model_validate(duplicate)

    call_set_digest = plan.authorized_calls.model_dump(mode="python")
    call_set_digest["call_set_id"] = "0" * 64
    with pytest.raises(ValidationError, match="call set content digest"):
        type(plan.authorized_calls).model_validate(call_set_digest)

    for field, value, message in (
        ("remaining_model_tokens", plan.budget.remaining_model_tokens - 1, "model budget"),
        ("remaining_tool_calls", 0, "tool budget"),
    ):
        payload = plan.budget.model_dump(mode="python")
        payload[field] = value
        with pytest.raises(ValidationError, match=message):
            type(plan.budget).model_validate(payload)
    _close(fixture)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("root_plan_digest", "root plan digest"),
        ("root_outcome_digest", "root outcome digest"),
        ("first_handoff_outcome_digest", "first handoff digest"),
        ("round_plan_digest", "round plan digest"),
    ],
)
def test_session_plan_rejects_each_authoritative_digest_drift(
    tmp_path, approved_scope, now, field, message
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    payload = plan.model_dump(mode="python")
    payload[field] = "0" * 64
    payload["session_id"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "session_id"}
    )
    with pytest.raises(ValidationError, match=message):
        type(plan).model_validate(payload)
    _close(fixture)


def test_session_outcome_rejects_selected_call_status_and_cleanup_drift(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    commitment = plan.authorized_calls.options[0].call_commitment
    fixture["adapter"].decisions.extend(
        [
            {
                "kind": "propose_tool",
                "tool_call": {
                    "tool_id": "http.request",
                    "arguments": [commitment],
                    "working_directory": "source",
                },
            },
            {"kind": "complete", "summary_digest": "1" * 64},
        ]
    )
    outcome = _execute(fixture, plan, now)
    cases = []

    selected = outcome.model_dump(mode="python")
    selected["selected_broker_call_digest"] = None
    cases.append((selected, "selected call binding"))

    status = outcome.model_dump(mode="python")
    status["status"] = "blocked"
    cases.append((status, "terminal continuation binding"))

    cleanup = outcome.model_dump(mode="python")
    cleanup["cleanup"]["context_reverified"] = False
    cases.append((cleanup, "cleanup is incomplete"))

    attempts = outcome.model_dump(mode="python")
    attempts["budget"]["provider_attempts"] = 2
    cases.append((attempts, "provider attempt ledger"))

    for payload, message in cases:
        payload["outcome_id"] = canonical_digest(
            {key: value for key, value in payload.items() if key != "outcome_id"}
        )
        with pytest.raises(ValidationError, match=message):
            type(outcome).model_validate(payload)
    _close(fixture)


def test_session_revalidates_context_before_checkpoint(tmp_path, approved_scope, now):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    os.chmod(
        fixture["context_store"].objects / plan.context_snapshot.snapshot_id,
        0o600,
    )
    with pytest.raises(AgentSessionRejected, match="context revalidation"):
        _execute(fixture, plan, now)
    count = fixture["session_store"].connection.execute(
        "SELECT count(*) FROM agent_sessions"
    ).fetchone()[0]
    assert count == 0
    assert fixture["adapter"].requests == []
    _close(fixture)


def test_session_rejects_plan_drift_and_expired_deadline(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    drifted = plan.model_copy(update={"round_plan_digest": "0" * 64})
    with pytest.raises(AgentSessionRejected, match="boundary validation"):
        _execute(fixture, drifted, now)
    with pytest.raises(AgentSessionTimedOut, match="wall budget"):
        fixture["service"].execute(
            plan,
            now=plan.deadline,
            terminal_continuation_key="session:late",
            terminal_run_key="agent:session:late",
        )
    _close(fixture)


def test_session_store_refuses_started_recovery_and_conflicting_reuse(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    plan = _prepare(fixture, now)
    fixture["session_store"].claim(plan, now=now + timedelta(seconds=3))
    with pytest.raises(AgentSessionRecoveryRequired):
        fixture["session_store"].claim(plan, now=now + timedelta(seconds=4))

    fixture2 = _fixture(tmp_path / "other", now, approved_scope)
    plan2 = _prepare(fixture2, now, key=plan.idempotency_key)
    with pytest.raises(AgentSessionIdempotencyConflict):
        fixture["session_store"].claim(plan2, now=now + timedelta(seconds=4))

    payload = plan.model_dump(mode="python")
    payload["idempotency_key"] = "session:other-key"
    payload["session_id"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "session_id"}
    )
    observation_reuse = type(plan).model_validate(payload)
    with pytest.raises(AgentSessionObservationConflict):
        fixture["session_store"].claim(
            observation_reuse, now=now + timedelta(seconds=4)
        )
    _close(fixture2)
    _close(fixture)


def _completed_session(fixture, now, *, terminal_kind="complete"):
    plan = _prepare(fixture, now)
    commitment = plan.authorized_calls.options[0].call_commitment
    terminal = {"kind": terminal_kind, "summary_digest": "a" * 64}
    if terminal_kind == "complete":
        terminal["supporting_ref_digests"] = [fixture["evidence2"].evidence_id]
    fixture["adapter"].decisions.extend(
        [
            {
                "kind": "propose_tool",
                "tool_call": {
                    "tool_id": "http.request",
                    "arguments": [commitment],
                    "working_directory": "source",
                },
            },
            terminal,
        ]
    )
    return plan, _execute(fixture, plan, now)


def _audit_service(fixture, tmp_path):
    audit_store = AgentSessionAuditStore(tmp_path / "audits.sqlite3")
    artifact_store = AgentSessionAuditArtifactStore(tmp_path / "audit-artifacts")
    service = AgentSessionAuditService(
        session_store=fixture["session_store"],
        root_agent_store=fixture["root_store"],
        round_agent_store=fixture["round_store"],
        handoff_store=fixture["handoff_store"],
        continuation_store=fixture["continuation_store"],
        evidence_store=fixture["evidence_store"],
        audit_store=audit_store,
        artifact_store=artifact_store,
    )
    return service, audit_store, artifact_store


@pytest.mark.parametrize(
    ("terminal_kind", "disposition", "reason"),
    [
        ("complete", "completed", "session_completed"),
        ("blocked", "blocked", "agent_blocked"),
    ],
)
def test_session_audit_builds_digest_only_immutable_artifacts(
    tmp_path, approved_scope, now, terminal_kind, disposition, reason
):
    fixture = _fixture(tmp_path, now, approved_scope)
    session_plan, _ = _completed_session(fixture, now, terminal_kind=terminal_kind)
    service, audit_store, artifact_store = _audit_service(fixture, tmp_path)
    audit_plan = service.prepare(
        session_plan=session_plan,
        now=now + timedelta(seconds=4),
        idempotency_key="audit:session:1",
    )

    outcome = service.execute(
        audit_plan,
        session_plan=session_plan,
        now=now + timedelta(seconds=5),
    )
    replay = service.execute(
        audit_plan,
        session_plan=session_plan,
        now=now + timedelta(seconds=6),
    )

    assert replay == outcome
    assert outcome.bundle.recommendation.disposition.value == disposition
    assert outcome.bundle.recommendation.reason_code.value == reason
    assert outcome.bundle.observation_ids[0] == (
        session_plan.first_handoff_outcome.observation.observation_id
    )
    assert len(outcome.bundle.observation_ids) == 2
    assert outcome.bundle.evidence_refs == tuple(
        sorted((fixture["evidence1"].evidence_id, fixture["evidence2"].evidence_id))
    )
    assert artifact_store.read_bundle(outcome.artifact) == outcome.bundle
    markdown = artifact_store.read_markdown(outcome.artifact)
    persisted = (tmp_path / "audits.sqlite3").read_bytes()
    artifact_bytes = (
        artifact_store.root / outcome.artifact.json_ref
    ).read_bytes() + markdown.encode()
    for forbidden in (SECRET, URL1, URL2, "Authorization", "Bearer"):
        assert forbidden.encode() not in persisted
        assert forbidden.encode() not in artifact_bytes
    directory = artifact_store.objects / outcome.bundle.bundle_id
    assert directory.stat().st_mode & 0o222 == 0
    assert all(item.stat().st_mode & 0o222 == 0 for item in directory.iterdir())
    audit_store.close()
    _close(fixture)


@pytest.mark.parametrize(
    ("error", "disposition", "reason"),
    [
        (AgentProviderTransportRejected("rejected"), "failed", "session_failed"),
        (AgentProviderTransportTimedOut("timeout"), "timed_out", "session_timed_out"),
    ],
)
def test_session_audit_projects_provider_failure_and_timeout(
    tmp_path, approved_scope, now, error, disposition, reason
):
    fixture = _fixture(tmp_path, now, approved_scope)
    session_plan = _prepare(fixture, now)
    fixture["adapter"].decisions.append(error)
    _execute(fixture, session_plan, now)
    service, audit_store, _ = _audit_service(fixture, tmp_path)
    audit_plan = service.prepare(
        session_plan=session_plan,
        now=now + timedelta(seconds=4),
        idempotency_key=f"audit:{disposition}",
    )

    outcome = service.execute(
        audit_plan,
        session_plan=session_plan,
        now=now + timedelta(seconds=5),
    )

    assert outcome.bundle.recommendation.disposition.value == disposition
    assert outcome.bundle.recommendation.reason_code.value == reason
    assert outcome.bundle.observation_ids == (
        session_plan.first_handoff_outcome.observation.observation_id,
    )
    audit_store.close()
    _close(fixture)


def test_session_audit_schemas_cannot_carry_raw_or_domain_state_fields():
    schemas = " ".join(
        json.dumps(model.model_json_schema()).lower()
        for model in (
            AgentSessionAuditLimits,
            AgentSessionAuditPlan,
            AgentSessionRecommendation,
            AgentSessionAuditBundle,
            AgentSessionAuditArtifact,
            AgentSessionAuditOutcome,
        )
    )
    for forbidden in (
        '"url"',
        '"credential"',
        '"provider_request"',
        '"provider_response"',
        '"tool_arguments"',
        '"candidate"',
        '"finding"',
        '"submission"',
    ):
        assert forbidden not in schemas


def test_session_audit_rejects_authoritative_chain_and_evidence_drift(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    session_plan, _ = _completed_session(fixture, now)
    service, audit_store, _ = _audit_service(fixture, tmp_path)
    evidence_path = (
        fixture["evidence_store"].objects / fixture["evidence2"].evidence_id
    )
    original = evidence_path.read_bytes()
    evidence_path.write_bytes(original + b"drift")

    with pytest.raises(AgentSessionAuditRejected, match="Evidence verification"):
        service.prepare(
            session_plan=session_plan,
            now=now + timedelta(seconds=4),
            idempotency_key="audit:drift",
        )
    assert audit_store.connection.execute(
        "SELECT count(*) FROM agent_session_audits"
    ).fetchone()[0] == 0
    audit_store.close()
    _close(fixture)


def test_session_audit_rejects_plan_drift_timeout_and_writable_artifact(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    session_plan, _ = _completed_session(fixture, now)
    service, audit_store, artifact_store = _audit_service(fixture, tmp_path)
    with pytest.raises(AgentSessionAuditRejected, match="precede Session completion"):
        service.prepare(
            session_plan=session_plan,
            now=now + timedelta(seconds=2),
            idempotency_key="audit:early",
        )
    plan = service.prepare(
        session_plan=session_plan,
        now=now + timedelta(seconds=4),
        idempotency_key="audit:boundaries",
    )
    drifted = plan.model_copy(update={"session_outcome_digest": "0" * 64})
    with pytest.raises(AgentSessionAuditRejected, match="boundary validation"):
        service.execute(
            drifted,
            session_plan=session_plan,
            now=now + timedelta(seconds=5),
        )
    with pytest.raises(AgentSessionAuditTimedOut, match="wall budget"):
        service.execute(plan, session_plan=session_plan, now=plan.deadline)

    outcome = service.execute(
        plan,
        session_plan=session_plan,
        now=now + timedelta(seconds=5),
    )
    json_path = artifact_store.root / outcome.artifact.json_ref
    os.chmod(json_path, 0o600)
    with pytest.raises(ValueError, match="unavailable or unsafe"):
        artifact_store.read_bundle(outcome.artifact)
    audit_store.close()
    _close(fixture)


def test_session_audit_store_refuses_recovery_and_conflicting_reuse(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    session_plan, _ = _completed_session(fixture, now)
    service, audit_store, _ = _audit_service(fixture, tmp_path)
    plan = service.prepare(
        session_plan=session_plan,
        now=now + timedelta(seconds=4),
        idempotency_key="audit:store",
    )
    audit_store.claim(plan, now=now + timedelta(seconds=5))
    with pytest.raises(AgentSessionAuditRecoveryRequired):
        audit_store.claim(plan, now=now + timedelta(seconds=6))

    payload = plan.model_dump(mode="python")
    payload["audit_plan_id"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "audit_plan_id"}
    )
    with pytest.raises(AgentSessionAuditRecoveryRequired):
        audit_store.claim(type(plan).model_validate(payload), now=now + timedelta(seconds=6))

    fixture2 = _fixture(tmp_path / "other", now, approved_scope)
    session_plan2, _ = _completed_session(fixture2, now)
    service2, audit_store2, _ = _audit_service(fixture2, tmp_path / "other")
    plan2 = service2.prepare(
        session_plan=session_plan2,
        now=now + timedelta(seconds=4),
        idempotency_key=plan.idempotency_key,
    )
    with pytest.raises(AgentSessionAuditIdempotencyConflict):
        audit_store.claim(plan2, now=now + timedelta(seconds=6))
    audit_store2.close()
    _close(fixture2)
    audit_store.close()
    _close(fixture)


def test_session_audit_artifact_limit_failure_keeps_recovery_checkpoint(
    tmp_path, approved_scope, now
):
    fixture = _fixture(tmp_path, now, approved_scope)
    session_plan, _ = _completed_session(fixture, now)
    service, audit_store, _ = _audit_service(fixture, tmp_path)
    plan = service.prepare(
        session_plan=session_plan,
        now=now + timedelta(seconds=4),
        idempotency_key="audit:limit",
        limits=AgentSessionAuditLimits(max_artifact_bytes=1024),
    )
    with pytest.raises(AgentSessionAuditRejected, match="artifact exceeds"):
        service.execute(
            plan,
            session_plan=session_plan,
            now=now + timedelta(seconds=5),
        )
    with pytest.raises(AgentSessionAuditRecoveryRequired):
        service.execute(
            plan,
            session_plan=session_plan,
            now=now + timedelta(seconds=6),
        )
    assert not any((tmp_path / "audit-artifacts" / "objects").iterdir())
    audit_store.close()
    _close(fixture)
