from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.adapters import (
    EnvironmentModelCredentialProvider,
    ModelCredentialReference,
)
from vulnloom.agent_runtime import (
    AgentModelRegistration,
    AgentRunLimits,
    AgentRunPlan,
    AgentRunRecoveryRequired,
    AgentRunStatus,
    AgentRunStore,
    AgentRuntimeAdapterFailure,
    AgentStepRequest,
    LocalFakeModelAdapter,
    LocalFakeProviderMismatch,
    LocalFakeTurn,
    OfflineAgentRuntime,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole


def _reference():
    return ModelCredentialReference.create(
        environment_variable="VULNLOOM_LOCAL_FAKE_MODEL_KEY"
    )


def _registration(reference):
    return AgentModelRegistration.create_local_fake(
        provider_id="local",
        model="credential-bound-fake-v1",
        adapter_digest=canonical_digest({"adapter": "local-fake", "version": 1}),
        credential_reference_id=reference.reference_id,
        supported_roles=(WorkerRole.HYPOTHESIS,),
        max_output_tokens=64,
    )


def _plan(now, registration):
    task = TaskEnvelope(
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
        allowed_tools=frozenset({"source.search"}),
        budget=TaskBudget(wall_seconds=20, model_tokens=100, tool_calls=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="worker:local-fake:1",
    )
    return AgentRunPlan.create(
        task=task,
        registration=registration,
        limits=AgentRunLimits(
            max_steps=1, max_output_tokens_per_step=64, timeout_seconds=10
        ),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="agent:local-fake:1",
    )


def _turn(plan, secret, *, latency=0.1):
    request = AgentStepRequest.create(
        plan=plan, step=1, remaining_model_tokens=100
    )
    return LocalFakeTurn(
        expected_request_digest=canonical_digest(request.model_dump(mode="python")),
        expected_credential_digest=hashlib.sha256(secret.encode()).hexdigest(),
        structured_output={"kind": "complete", "summary_digest": "f" * 64},
        input_tokens=3,
        output_tokens=2,
        latency_seconds=latency,
    )


def _runtime(tmp_path, *, secret="lease-only-secret", turn_secret=None, latency=0.1):
    reference = _reference()
    registration = _registration(reference)
    plan = _plan(datetime.now(UTC), registration)
    expected = secret if turn_secret is None else turn_secret
    provider = EnvironmentModelCredentialProvider(
        {
            reference.environment_variable: secret,
            "UNRELATED_PROVIDER_TOKEN": "must-never-be-copied",
        },
        allowed_references=(reference,),
    )
    adapter = LocalFakeModelAdapter(
        registration=registration,
        credential_reference=reference,
        credential_provider=provider,
        turns=(_turn(plan, expected, latency=latency),),
    )
    store = AgentRunStore(tmp_path / "agent-provider.sqlite3")
    runtime = OfflineAgentRuntime(
        store=store, registration=registration, adapter=adapter
    )
    return reference, registration, plan, store, adapter, runtime


def test_local_fake_provider_releases_credential_and_persists_no_secret(tmp_path):
    secret = "lease-only-secret"
    reference, registration, plan, store, adapter, runtime = _runtime(
        tmp_path, secret=secret
    )

    outcome = runtime.execute(plan, now=plan.created_at + timedelta(seconds=1))

    assert outcome.status is AgentRunStatus.COMPLETED
    assert adapter.released_leases[0].released
    assert adapter.released_leases[0].zeroed
    assert len(adapter.requests) == 1
    serialized = "".join(
        (
            reference.model_dump_json(),
            registration.model_dump_json(),
            adapter.requests[0].model_dump_json(),
            outcome.model_dump_json(),
        )
    )
    assert secret not in serialized
    assert "must-never-be-copied" not in serialized
    assert secret.encode() not in (tmp_path / "agent-provider.sqlite3").read_bytes()
    store.close()


def test_local_fake_provider_wrong_credential_fails_closed_and_zeroes_lease(tmp_path):
    _, _, plan, store, adapter, runtime = _runtime(
        tmp_path, secret="wrong-secret", turn_secret="expected-secret"
    )

    with pytest.raises(AgentRuntimeAdapterFailure) as failure:
        runtime.execute(plan, now=plan.created_at + timedelta(seconds=1))

    assert "wrong-secret" not in str(failure.value)
    assert adapter.released_leases[0].zeroed
    with pytest.raises(AgentRunRecoveryRequired):
        runtime.execute(plan, now=plan.created_at + timedelta(seconds=2))
    store.close()


def test_local_fake_provider_missing_credential_leaves_recoverable_checkpoint(tmp_path):
    reference = _reference()
    registration = _registration(reference)
    now = datetime.now(UTC)
    plan = _plan(now, registration)
    adapter = LocalFakeModelAdapter(
        registration=registration,
        credential_reference=reference,
        credential_provider=EnvironmentModelCredentialProvider(
            {}, allowed_references=(reference,)
        ),
        turns=(_turn(plan, "unused"),),
    )
    store = AgentRunStore(tmp_path / "missing.sqlite3")
    runtime = OfflineAgentRuntime(
        store=store, registration=registration, adapter=adapter
    )

    with pytest.raises(AgentRuntimeAdapterFailure, match="after STARTED"):
        runtime.execute(plan, now=now + timedelta(seconds=1))

    assert adapter.released_leases == []
    assert store.connection.execute("SELECT state FROM agent_runs").fetchone()[0] == "started"
    store.close()


def test_local_fake_provider_timeout_still_releases_credential(tmp_path):
    _, _, plan, store, adapter, runtime = _runtime(tmp_path, latency=11)

    outcome = runtime.execute(plan, now=plan.created_at + timedelta(seconds=1))

    assert outcome.status is AgentRunStatus.TIMED_OUT
    assert outcome.cleanup.complete
    assert adapter.released_leases[0].zeroed
    store.close()


def test_local_fake_registration_rejects_credential_binding_drift():
    reference = _reference()
    registration = _registration(reference)
    other = ModelCredentialReference.create(environment_variable="OTHER_MODEL_KEY")

    with pytest.raises(ValueError, match="registration binding mismatch"):
        LocalFakeModelAdapter(
            registration=registration,
            credential_reference=other,
            credential_provider=EnvironmentModelCredentialProvider(
                {}, allowed_references=(other,)
            ),
            turns=(),
        )
    with pytest.raises(ValidationError, match="content digest mismatch"):
        ModelCredentialReference(
            reference_id="0" * 64,
            environment_variable=reference.environment_variable,
        )


def test_local_fake_request_mismatch_does_not_acquire_credential(tmp_path):
    _, _, plan, store, adapter, _ = _runtime(tmp_path)
    mismatched = AgentStepRequest.create(
        plan=plan, step=1, remaining_model_tokens=99
    )

    with pytest.raises(LocalFakeProviderMismatch, match="request digest"):
        adapter.complete(mismatched)

    assert adapter.released_leases == []
    store.close()


def test_offline_replay_registration_cannot_bind_credential():
    reference = _reference()
    registration = AgentModelRegistration.create(
        provider_id="offline",
        model="replay-v1",
        adapter_digest="a" * 64,
        supported_roles=(WorkerRole.HYPOTHESIS,),
        max_output_tokens=64,
    )

    with pytest.raises(ValidationError, match="cannot bind"):
        AgentModelRegistration.model_validate(
            {
                **registration.model_dump(mode="python"),
                "credential_reference_id": reference.reference_id,
            }
        )
