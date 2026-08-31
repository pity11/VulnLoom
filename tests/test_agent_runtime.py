from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import (
    AgentModelRegistration,
    AgentRunIdempotencyConflict,
    AgentRunLimits,
    AgentRunPlan,
    AgentRunRecoveryRequired,
    AgentRunStatus,
    AgentRunStore,
    AgentRuntimeAdapterFailure,
    AgentRuntimeRejected,
    AgentStepRequest,
    OfflineAgentRuntime,
    OfflineReplayModelAdapter,
    ReplayTurn,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole


def _registration(*, roles: tuple[WorkerRole, ...] = (WorkerRole.HYPOTHESIS,)):
    return AgentModelRegistration.create(
        provider_id="offline",
        model="replay-v1",
        adapter_digest=canonical_digest({"fixture": "m7.1a"}),
        supported_roles=roles,
        max_output_tokens=64,
    )


def _task(now, *, allowed_tools=frozenset({"source.search"}), tool_calls=1):
    return TaskEnvelope(
        engagement_id=uuid4(),
        target_id=uuid4(),
        target_version="a" * 40,
        scope_id=uuid4(),
        worker_role=WorkerRole.HYPOTHESIS,
        scope_version=1,
        policy_digest="a" * 64,
        sandbox_profile_digest="b" * 64,
        tool_registry_digest="c" * 64,
        input_refs=("observation:" + "d" * 64,),
        allowed_tools=allowed_tools,
        budget=TaskBudget(wall_seconds=30, model_tokens=100, tool_calls=tool_calls),
        deadline=now + timedelta(minutes=2),
        idempotency_key="worker:hypothesis:1",
    )


def _plan(now, *, task=None, registration=None, key="agent:hypothesis:1", steps=2):
    registration = registration or _registration()
    return AgentRunPlan.create(
        task=task or _task(now),
        registration=registration,
        limits=AgentRunLimits(
            max_steps=steps, max_output_tokens_per_step=64, timeout_seconds=20
        ),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )


def _turn(plan, *, step, remaining, output, input_tokens=3, output_tokens=2, latency=0.1):
    request = AgentStepRequest.create(
        plan=plan, step=step, remaining_model_tokens=remaining
    )
    return ReplayTurn(
        expected_request_digest=canonical_digest(request.model_dump(mode="python")),
        structured_output=output,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_seconds=latency,
    )


def _runtime(tmp_path, registration, turns):
    store = AgentRunStore(tmp_path / "agent-runs.sqlite3")
    adapter = OfflineReplayModelAdapter(registration=registration, turns=turns)
    return store, adapter, OfflineAgentRuntime(
        store=store, registration=registration, adapter=adapter
    )


def test_agent_runtime_completes_idempotently_without_persisting_raw_response(
    tmp_path, now
):
    registration = _registration()
    plan = _plan(now, registration=registration)
    secret = "raw-provider-secret-must-not-persist"
    turn = _turn(
        plan,
        step=1,
        remaining=100,
        output={
            "kind": "complete",
            "summary_digest": canonical_digest(secret),
            "supporting_ref_digests": ["e" * 64],
        },
    )
    store, adapter, runtime = _runtime(tmp_path, registration, (turn,))

    outcome = runtime.execute(plan, now=now + timedelta(seconds=1))
    replayed = runtime.execute(plan, now=now + timedelta(seconds=2))

    assert outcome.status is AgentRunStatus.COMPLETED
    assert replayed == outcome
    assert len(adapter.requests) == 1
    assert outcome.cleanup.complete
    assert secret.encode() not in (tmp_path / "agent-runs.sqlite3").read_bytes()
    store.close()


def test_agent_runtime_returns_digest_only_tool_intent_and_executes_nothing(tmp_path, now):
    registration = _registration()
    plan = _plan(now, registration=registration)
    raw_argument = "src/private-route.py"
    turn = _turn(
        plan,
        step=1,
        remaining=100,
        output={
            "kind": "propose_tool",
            "tool_call": {
                "tool_id": "source.search",
                "arguments": [raw_argument],
                "working_directory": "source",
            },
        },
    )
    store, adapter, runtime = _runtime(tmp_path, registration, (turn,))

    outcome = runtime.execute(plan, now=now + timedelta(seconds=1))

    assert outcome.status is AgentRunStatus.TOOL_PROPOSED
    assert outcome.tool_intent is not None
    assert outcome.tool_intent.argument_digests == (canonical_digest(raw_argument),)
    assert outcome.cleanup.no_tool_executed
    assert adapter.requests[0].allowed_tools == {"source.search"}
    assert raw_argument.encode() not in (tmp_path / "agent-runs.sqlite3").read_bytes()
    store.close()


@pytest.mark.parametrize(
    ("allowed_tools", "tool_calls"),
    [(frozenset(), 1), (frozenset({"source.search"}), 0)],
)
def test_agent_runtime_rejects_unauthorized_tool_proposals(
    tmp_path, now, allowed_tools, tool_calls
):
    registration = _registration()
    task = _task(now, allowed_tools=allowed_tools, tool_calls=tool_calls)
    plan = _plan(now, task=task, registration=registration)
    turn = _turn(
        plan,
        step=1,
        remaining=100,
        output={
            "kind": "propose_tool",
            "tool_call": {
                "tool_id": "source.search",
                "arguments": [],
                "working_directory": "source",
            },
        },
    )
    store, _, runtime = _runtime(tmp_path, registration, (turn,))

    outcome = runtime.execute(plan, now=now + timedelta(seconds=1))

    assert outcome.status is AgentRunStatus.FAILED
    assert outcome.error_codes == ("tool_proposal_not_allowed",)
    assert outcome.cleanup.no_tool_executed
    store.close()


def test_agent_runtime_retries_invalid_structure_with_remaining_budget(tmp_path, now):
    registration = _registration()
    plan = _plan(now, registration=registration)
    first = _turn(
        plan,
        step=1,
        remaining=100,
        output={"kind": "ignore_schema", "raw": "do not persist this"},
        input_tokens=4,
        output_tokens=6,
    )
    second = _turn(
        plan,
        step=2,
        remaining=90,
        output={"kind": "blocked", "summary_digest": "f" * 64},
    )
    store, adapter, runtime = _runtime(tmp_path, registration, (first, second))

    outcome = runtime.execute(plan, now=now + timedelta(seconds=1))

    assert outcome.status is AgentRunStatus.BLOCKED
    assert outcome.steps == 2
    assert [request.remaining_model_tokens for request in adapter.requests] == [100, 90]
    assert b"do not persist this" not in (tmp_path / "agent-runs.sqlite3").read_bytes()
    store.close()


def test_agent_runtime_enforces_token_timeout_and_structured_size_budgets(tmp_path, now):
    registration = _registration()
    cases = (
        ("token", 80, 30, 0.1, {"kind": "complete", "summary_digest": "f" * 64}),
        ("timeout", 1, 1, 21.0, {"kind": "complete", "summary_digest": "f" * 64}),
        (
            "size",
            1,
            1,
            0.1,
            {"kind": "complete", "summary_digest": "f" * 64, "padding": "x" * 5000},
        ),
    )
    expected = {
        "token": (AgentRunStatus.FAILED, "model_token_budget_exceeded"),
        "timeout": (AgentRunStatus.TIMED_OUT, "agent_wall_time_budget_exceeded"),
        "size": (AgentRunStatus.FAILED, "structured_output_size_exceeded"),
    }
    for name, input_tokens, output_tokens, latency, output in cases:
        plan = _plan(now, registration=registration, key=f"agent:{name}")
        turn = _turn(
            plan,
            step=1,
            remaining=100,
            output=output,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency=latency,
        )
        case_dir = tmp_path / name
        store, _, runtime = _runtime(case_dir, registration, (turn,))
        outcome = runtime.execute(plan, now=now + timedelta(seconds=1))
        assert (outcome.status, outcome.error_codes[0]) == expected[name]
        store.close()


def test_agent_runtime_rejects_expired_plan_before_checkpoint(tmp_path, now):
    registration = _registration()
    plan = _plan(now, registration=registration)
    store, adapter, runtime = _runtime(tmp_path, registration, ())

    with pytest.raises(AgentRuntimeRejected, match="not active"):
        runtime.execute(plan, now=now + timedelta(minutes=1))

    assert adapter.requests == []
    count = store.connection.execute("SELECT count(*) FROM agent_runs").fetchone()[0]
    assert count == 0
    store.close()


def test_agent_runtime_adapter_failure_requires_explicit_recovery(tmp_path, now):
    registration = _registration()
    plan = _plan(now, registration=registration)
    store, _, runtime = _runtime(tmp_path, registration, ())

    with pytest.raises(AgentRuntimeAdapterFailure):
        runtime.execute(plan, now=now + timedelta(seconds=1))
    with pytest.raises(AgentRunRecoveryRequired, match="unfinished STARTED"):
        runtime.execute(plan, now=now + timedelta(seconds=2))

    state = store.connection.execute("SELECT state FROM agent_runs").fetchone()[0]
    assert state == "started"
    store.close()


def test_agent_runtime_detects_idempotency_conflict(tmp_path, now):
    registration = _registration()
    first = _plan(now, registration=registration, key="same-key")
    second = _plan(
        now,
        task=_task(now),
        registration=registration,
        key="same-key",
    )
    store = AgentRunStore(tmp_path / "agent-runs.sqlite3")
    assert store.claim(first, now=now).created

    with pytest.raises(AgentRunIdempotencyConflict):
        store.claim(second, now=now)
    store.close()


def test_agent_runtime_rejects_invalid_tool_arguments_without_persisting_them(
    tmp_path, now
):
    registration = _registration()
    plan = _plan(now, registration=registration)
    turn = _turn(
        plan,
        step=1,
        remaining=100,
        output={
            "kind": "propose_tool",
            "tool_call": {
                "tool_id": "source.search",
                "arguments": ["bad\x00argument"],
                "working_directory": "source",
            },
        },
    )
    store, _, runtime = _runtime(tmp_path, registration, (turn,))

    outcome = runtime.execute(plan, now=now + timedelta(seconds=1))

    assert outcome.error_codes == ("tool_proposal_invalid",)
    assert b"bad\x00argument" not in (tmp_path / "agent-runs.sqlite3").read_bytes()
    store.close()


def test_agent_contracts_reject_unsealed_or_unsupported_configuration(now):
    registration = _registration()
    with pytest.raises(ValueError, match="does not support"):
        _plan(
            now,
            task=_task(now).model_copy(update={"worker_role": WorkerRole.REPORTER}),
            registration=registration,
        )
    with pytest.raises(ValidationError, match="content digest mismatch"):
        AgentStepRequest(
            request_id="0" * 64,
            plan_id="1" * 64,
            task_id=uuid4(),
            step=1,
            worker_role=WorkerRole.HYPOTHESIS,
            context_digest="2" * 64,
            allowed_tools=frozenset(),
            decision_schema_digest="3" * 64,
            remaining_model_tokens=1,
            max_output_tokens=1,
        )
    fields = set(AgentModelRegistration.model_fields) | set(AgentRunPlan.model_fields)
    assert not fields & {"api_key", "token", "base_url", "endpoint"}


def test_agent_checkpoint_database_has_no_provider_configuration(tmp_path):
    store = AgentRunStore(tmp_path / "agent-runs.sqlite3")
    columns = {
        row[1]
        for row in store.connection.execute("PRAGMA table_info(agent_runs)").fetchall()
    }
    assert not columns & {"api_key", "token", "base_url", "endpoint", "response"}
    store.close()
