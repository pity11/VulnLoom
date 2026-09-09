from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.adapters import EnvironmentModelCredentialProvider, ModelCredentialReference
from vulnloom.agent_runtime import (
    SUBPROCESS_HTTPS_ADAPTER_DIGEST,
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextSource,
    AgentContextSourceKind,
    AgentMessageRenderer,
    AgentModelRegistration,
    AgentProviderCodecLimits,
    AgentProviderCodecRejected,
    AgentProviderCodecTimedOut,
    AgentProviderEgressAuthority,
    AgentProviderEgressIssuerPolicy,
    AgentProviderEgressPurpose,
    AgentProviderEgressStore,
    AgentProviderTransportAdmission,
    AgentProviderTransportLimits,
    AgentProviderTransportMode,
    AgentProviderTransportRejected,
    AgentProviderTransportStatus,
    AgentProviderTransportTimedOut,
    AgentRunLimits,
    AgentRunPlan,
    AgentStepRequest,
    OpenAIChatCompletionsCodecRegistration,
    OpenAIChatCompletionsFeatureDisabled,
    OpenAIChatCompletionsFeatureGate,
    OpenAIChatCompletionsV1Codec,
    ProviderProcessExecutionError,
    ProviderProcessResult,
    SubprocessHttpsProviderAdapter,
)
from vulnloom.agent_runtime.provider_diagnostics import ProviderDiagnostic
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole


def _decision(*, tool: bool = False) -> dict[str, object]:
    if tool:
        return {
            "kind": "propose_tool",
            "summary_digest": None,
            "supporting_ref_digests": [],
            "tool_call": {
                "arguments": ["query"],
                "tool_id": "source.search",
                "working_directory": "source",
            },
        }
    return {
        "kind": "complete",
        "summary_digest": "f" * 64,
        "supporting_ref_digests": [],
        "tool_call": None,
    }


def _chat_response(
    *,
    model: str = "test-model",
    decision: dict[str, object] | None = None,
    finish_reason: str = "stop",
    message_extra: dict[str, object] | None = None,
    usage: dict[str, object] | None = None,
    root_extra: dict[str, object] | None = None,
) -> bytearray:
    payload = {
        "choices": [
            {
                "finish_reason": finish_reason,
                "index": 0,
                "message": {
                    "content": json.dumps(
                        decision or _decision(), separators=(",", ":"), sort_keys=True
                    ),
                    "role": "assistant",
                    **(message_extra or {}),
                },
            }
        ],
        "created": 1,
        "id": "chatcmpl_test",
        "model": model,
        "object": "chat.completion",
        "usage": usage
        or {"completion_tokens": 2, "prompt_tokens": 3, "total_tokens": 5},
        **(root_extra or {}),
    }
    return bytearray(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())


def _codec_fixture(*, limits: AgentProviderCodecLimits | None = None):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    source_ref = "observation:" + "d" * 64
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
        input_refs=(source_ref,),
        allowed_tools=frozenset({"source.search"}),
        budget=TaskBudget(wall_seconds=30, model_tokens=100, tool_calls=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="openai-chat:task:1",
    )
    snapshot = AgentContextAssembler().assemble(
        task=task,
        sources=(
            AgentContextSource(
                source_ref=source_ref,
                kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                text="Bounded synthetic context.",
            ),
        ),
        limits=AgentContextLimits(),
        now=now,
        deadline=now + timedelta(minutes=1),
    )
    codec_registration = OpenAIChatCompletionsCodecRegistration.create(
        provider_id="test-provider",
        request_model="test-model",
        limits=limits,
    )
    registration = AgentModelRegistration.create_subprocess_https(
        provider_id="test-provider",
        model="test-model",
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        credential_reference_id="b" * 64,
        transport_admission_id="c" * 64,
        egress_grant_id="d" * 64,
        provider_codec_id=codec_registration.codec_id,
        supported_roles=(WorkerRole.HYPOTHESIS,),
        max_output_tokens=64,
    )
    plan = AgentRunPlan.create(
        task=task,
        registration=registration,
        limits=AgentRunLimits(
            max_steps=1,
            max_output_tokens_per_step=64,
            timeout_seconds=10,
        ),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="openai-chat:plan:1",
        context_snapshot=snapshot,
    )
    request = AgentStepRequest.create(plan=plan, step=1, remaining_model_tokens=100)
    envelope = AgentMessageRenderer().render(
        plan=plan,
        snapshot=snapshot,
        request=request,
    )
    return codec_registration, registration, envelope


def _enabled_codec(
    registration: OpenAIChatCompletionsCodecRegistration,
    *,
    clock=None,
) -> OpenAIChatCompletionsV1Codec:
    values = {
        "registration": registration,
        "feature_gate": OpenAIChatCompletionsFeatureGate.create(enabled=True),
    }
    if clock is not None:
        values["clock"] = clock
    return OpenAIChatCompletionsV1Codec(**values)


def test_chat_codec_is_disabled_by_default():
    codec_registration, _, _ = _codec_fixture()

    with pytest.raises(OpenAIChatCompletionsFeatureDisabled):
        OpenAIChatCompletionsV1Codec(
            codec_registration,
            feature_gate=OpenAIChatCompletionsFeatureGate.create(),
        )


def test_chat_codec_encodes_only_the_sealed_messages_and_bounded_options():
    codec_registration, model_registration, envelope = _codec_fixture()
    body = _enabled_codec(codec_registration).encode(
        model_registration=model_registration,
        envelope=envelope,
    )
    payload = json.loads(body)

    assert set(payload) == {"max_tokens", "messages", "model", "stream"}
    assert payload["model"] == "test-model"
    assert payload["stream"] is False
    assert payload["max_tokens"] == 64
    assert [item["role"] for item in payload["messages"]] == ["system", "user"]
    assert "tools" not in payload
    assert "tool_choice" not in payload
    assert "temperature" not in payload


def test_chat_codec_normalizes_terminal_and_inert_tool_decisions():
    codec_registration, model_registration, _ = _codec_fixture()
    codec = _enabled_codec(codec_registration)

    terminal = codec.decode(
        _chat_response(),
        model_registration=model_registration,
        latency_seconds=0.2,
    )
    tool_proposal = codec.decode(
        _chat_response(decision=_decision(tool=True)),
        model_registration=model_registration,
        latency_seconds=0.2,
    )

    assert terminal.structured_output == {
        "kind": "complete",
        "summary_digest": "f" * 64,
        "supporting_ref_digests": [],
    }
    assert tool_proposal.structured_output["kind"] == "propose_tool"
    assert tool_proposal.structured_output["tool_call"]["tool_id"] == "source.search"
    assert terminal.input_tokens == 3
    assert terminal.output_tokens == 2


@pytest.mark.parametrize(
    "response",
    [
        _chat_response(model="drifted-model"),
        _chat_response(finish_reason="length"),
        _chat_response(message_extra={"refusal": "refused"}),
        _chat_response(message_extra={"tool_calls": [{"name": "forbidden"}]}),
        _chat_response(root_extra={"unknown_field": True}),
        _chat_response(
            usage={"completion_tokens": 2, "prompt_tokens": 3, "total_tokens": 99}
        ),
    ],
)
def test_chat_codec_rejects_identity_incomplete_refusal_native_tools_and_drift(response):
    codec_registration, model_registration, _ = _codec_fixture()

    with pytest.raises(AgentProviderCodecRejected):
        _enabled_codec(codec_registration).decode(
            response,
            model_registration=model_registration,
            latency_seconds=0.1,
        )


def test_chat_codec_accepts_only_registered_empty_compatibility_extensions():
    codec_registration = OpenAIChatCompletionsCodecRegistration.create(
        provider_id="test-provider",
        request_model="test-model",
        allowed_empty_root_fields=("metrics",),
        allowed_empty_message_fields=("tool_calls",),
    )
    model_registration = AgentModelRegistration.create_subprocess_https(
        provider_id="test-provider",
        model="test-model",
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        credential_reference_id="b" * 64,
        transport_admission_id="c" * 64,
        egress_grant_id="d" * 64,
        provider_codec_id=codec_registration.codec_id,
        supported_roles=(WorkerRole.HYPOTHESIS,),
        max_output_tokens=64,
    )
    codec = _enabled_codec(codec_registration)

    reply = codec.decode(
        _chat_response(
            message_extra={"tool_calls": []},
            root_extra={"metrics": {}},
        ),
        model_registration=model_registration,
        latency_seconds=0.1,
    )

    assert reply.structured_output["kind"] == "complete"
    with pytest.raises(AgentProviderCodecRejected):
        codec.decode(
            _chat_response(message_extra={"tool_calls": [{"name": "forbidden"}]}),
            model_registration=model_registration,
            latency_seconds=0.1,
        )


def test_chat_codec_rejects_duplicate_json_and_enforces_wall_budget():
    codec_registration, model_registration, envelope = _codec_fixture(
        limits=AgentProviderCodecLimits(timeout_seconds=1)
    )
    with pytest.raises(AgentProviderCodecRejected, match="strict JSON"):
        _enabled_codec(codec_registration).decode(
            bytearray(b'{"id":"one","id":"two"}'),
            model_registration=model_registration,
            latency_seconds=0.1,
        )

    ticks = iter((0.0, 1.0))
    with pytest.raises(AgentProviderCodecTimedOut):
        _enabled_codec(codec_registration, clock=lambda: next(ticks)).encode(
            model_registration=model_registration,
            envelope=envelope,
        )


def test_chat_registration_safeguards_and_binding_are_sealed():
    codec_registration, model_registration, envelope = _codec_fixture()
    values = codec_registration.model_dump(mode="python")
    values["native_tools_allowed"] = True
    values["codec_id"] = canonical_digest(
        {key: value for key, value in values.items() if key != "codec_id"}
    )

    with pytest.raises(ValidationError, match="safeguards"):
        OpenAIChatCompletionsCodecRegistration.model_validate(values)
    other = OpenAIChatCompletionsCodecRegistration.create(
        provider_id="other-provider",
        request_model="test-model",
    )
    with pytest.raises(AgentProviderCodecRejected, match="binding"):
        _enabled_codec(other).encode(
            model_registration=model_registration,
            envelope=envelope,
        )


class _Resolver:
    def resolve(self, hostname: str) -> tuple[str, ...]:
        assert hostname == "api.provider.example"
        return ("8.8.8.8",)


class _ChatProcessRunner:
    def __init__(self, *, secret: str, response: bytearray | None = None, error=None):
        self.secret_digest = hashlib.sha256(secret.encode()).hexdigest()
        self.response = response or _chat_response()
        self.error = error
        self.calls: list[dict[str, object]] = []

    def exchange(self, **values):
        assert hashlib.sha256(values["credential"]).hexdigest() == self.secret_digest
        self.calls.append(
            {
                "hostname": values["hostname"],
                "request_path": values["request_path"],
                "request_body": bytes(values["request_body"]),
            }
        )
        if self.error is not None:
            raise self.error
        return ProviderProcessResult(
            response_body=bytearray(self.response),
            latency_seconds=0.1,
            peer_ip="8.8.8.8",
            tls_version="TLSv1.3",
        )


def _transport_fixture(tmp_path, *, runner: _ChatProcessRunner):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    source_ref = "observation:" + "e" * 64
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
        input_refs=(source_ref,),
        allowed_tools=frozenset({"source.search"}),
        budget=TaskBudget(wall_seconds=30, model_tokens=100, tool_calls=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="openai-chat:transport-task:1",
    )
    snapshot = AgentContextAssembler().assemble(
        task=task,
        sources=(
            AgentContextSource(
                source_ref=source_ref,
                kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                text="Synthetic provider transport fixture.",
            ),
        ),
        limits=AgentContextLimits(),
        now=now,
        deadline=now + timedelta(minutes=1),
    )
    credential_reference = ModelCredentialReference.create(
        environment_variable="VULNLOOM_OPENAI_CHAT_FAKE_KEY"
    )
    admission = AgentProviderTransportAdmission.create_live_https(
        provider_id="test-provider",
        hostname="api.provider.example",
        request_path="/v1/chat/completions",
        credential_reference_id=credential_reference.reference_id,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        limits=AgentProviderTransportLimits(timeout_seconds=5),
    )
    issuer_policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="test-security-operator",
        allowed_provider_ids=(admission.provider_id,),
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=3600,
    )
    egress_store = AgentProviderEgressStore(tmp_path / "chat-egress")
    grant = AgentProviderEgressAuthority(
        store=egress_store,
        issuer_policies=(issuer_policy,),
    ).issue(
        admission=admission,
        issuer_policy_id=issuer_policy.policy_id,
        purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
        now=now,
        expires_at=now + timedelta(minutes=30),
        deadline=now + timedelta(seconds=10),
        idempotency_key="openai-chat:egress:1",
    )
    codec_registration = OpenAIChatCompletionsCodecRegistration.create(
        provider_id="test-provider",
        request_model="test-model",
    )
    registration = AgentModelRegistration.create_subprocess_https(
        provider_id="test-provider",
        model="test-model",
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        credential_reference_id=credential_reference.reference_id,
        transport_admission_id=admission.admission_id,
        egress_grant_id=grant.grant_id,
        provider_codec_id=codec_registration.codec_id,
        supported_roles=(WorkerRole.HYPOTHESIS,),
        max_output_tokens=64,
    )
    plan = AgentRunPlan.create(
        task=task,
        registration=registration,
        limits=AgentRunLimits(
            max_steps=1,
            max_output_tokens_per_step=64,
            timeout_seconds=10,
        ),
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="openai-chat:transport-plan:1",
        context_snapshot=snapshot,
    )
    base_request = AgentStepRequest.create(plan=plan, step=1, remaining_model_tokens=100)
    envelope = AgentMessageRenderer().render(
        plan=plan,
        snapshot=snapshot,
        request=base_request,
    )
    request = AgentStepRequest.create(
        plan=plan,
        step=1,
        remaining_model_tokens=100,
        message_envelope_id=envelope.envelope_id,
    )
    secret = "local-fake-provider-secret"
    adapter = SubprocessHttpsProviderAdapter(
        registration=registration,
        admission=admission,
        credential_reference=credential_reference,
        credential_provider=EnvironmentModelCredentialProvider(
            {
                credential_reference.environment_variable: secret,
                "UNRELATED_PROVIDER_TOKEN": "must-not-cross-boundary",
            },
            allowed_references=(credential_reference,),
        ),
        egress_store=egress_store,
        provider_codec=_enabled_codec(codec_registration),
        resolver=_Resolver(),
        process_runner=runner,
        now=lambda: now + timedelta(seconds=1),
    )
    return adapter, request, envelope, egress_store


def test_chat_codec_runs_through_fake_process_transport_and_cleans_buffers(tmp_path):
    runner = _ChatProcessRunner(secret="local-fake-provider-secret")
    adapter, request, envelope, egress_store = _transport_fixture(tmp_path, runner=runner)

    reply = adapter.complete(request, message_envelope=envelope)

    assert reply.structured_output["kind"] == "complete"
    assert json.loads(runner.calls[0]["request_body"])["stream"] is False
    assert runner.calls[0]["request_path"] == "/v1/chat/completions"
    assert adapter.attempts[0].status is AgentProviderTransportStatus.COMPLETED
    assert adapter.released_leases[0].zeroed
    assert not any(adapter.released_request_bodies[0])
    assert not any(adapter.discarded_response_bodies[0])
    assert adapter.receipts[0].model == "test-model"
    egress_store.close()


@pytest.mark.parametrize("status", [401, 429])
def test_chat_fake_transport_rejects_auth_and_rate_limit_with_cleanup(tmp_path, status):
    diagnostic = ProviderDiagnostic(
        failure_stage="http_status",
        error_code="http_non_200",
        http_status=status,
        network_opened=True,
        captured_response_bytes=0,
        tls_version="TLSv1.3",
    )
    runner = _ChatProcessRunner(
        secret="local-fake-provider-secret",
        error=ProviderProcessExecutionError(
            "provider_https_rejected",
            diagnostic=diagnostic,
        ),
    )
    adapter, request, envelope, egress_store = _transport_fixture(tmp_path, runner=runner)

    with pytest.raises(AgentProviderTransportRejected):
        adapter.complete(request, message_envelope=envelope)

    assert adapter.diagnostic.http_status == status
    assert adapter.attempts[0].status is AgentProviderTransportStatus.REJECTED
    assert adapter.released_leases[0].zeroed
    assert not any(adapter.released_request_bodies[0])
    assert adapter.receipts == []
    egress_store.close()


def test_chat_fake_transport_timeout_and_malformed_response_clean_up(tmp_path):
    timeout_runner = _ChatProcessRunner(
        secret="local-fake-provider-secret",
        error=ProviderProcessExecutionError("provider_process_timeout", timed_out=True),
    )
    adapter, request, envelope, egress_store = _transport_fixture(
        tmp_path / "timeout", runner=timeout_runner
    )

    with pytest.raises(AgentProviderTransportTimedOut):
        adapter.complete(request, message_envelope=envelope)
    assert adapter.attempts[0].status is AgentProviderTransportStatus.TIMED_OUT
    assert adapter.released_leases[0].zeroed
    assert not any(adapter.released_request_bodies[0])
    egress_store.close()

    malformed_runner = _ChatProcessRunner(
        secret="local-fake-provider-secret",
        response=bytearray(b"not-json"),
    )
    adapter, request, envelope, egress_store = _transport_fixture(
        tmp_path / "malformed", runner=malformed_runner
    )
    with pytest.raises(AgentProviderTransportRejected):
        adapter.complete(request, message_envelope=envelope)
    assert adapter.attempts[0].status is AgentProviderTransportStatus.REJECTED
    assert adapter.released_leases[0].zeroed
    assert not any(adapter.released_request_bodies[0])
    assert not any(adapter.discarded_response_bodies[0])
    egress_store.close()
