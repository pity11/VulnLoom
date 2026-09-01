from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import (
    AgentModelRegistration,
    AgentProviderCodecLimits,
    AgentProviderCodecRegistration,
    AgentProviderCodecRejected,
    AgentProviderCodecTimedOut,
    AgentProviderMessage,
    AgentProviderMessageRole,
    OpenAIResponsesV1Codec,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.protocol import WorkerRole


def _codec_fixture(*, limits=None, provider_id="openai"):
    codec_registration = AgentProviderCodecRegistration.create(
        provider_id=provider_id,
        limits=limits,
    )
    model_registration = AgentModelRegistration.create_subprocess_https(
        provider_id=provider_id,
        model="gpt-test-1",
        adapter_digest="a" * 64,
        credential_reference_id="b" * 64,
        transport_admission_id="c" * 64,
        egress_grant_id="d" * 64,
        provider_codec_id=codec_registration.codec_id,
        supported_roles=(WorkerRole.HYPOTHESIS,),
        max_output_tokens=128,
    )
    messages = (
        AgentProviderMessage(
            role=AgentProviderMessageRole.SYSTEM,
            content="sealed system",
            content_digest=canonical_digest("sealed system"),
            byte_size=len(b"sealed system"),
            contains_untrusted_context=False,
        ),
        AgentProviderMessage(
            role=AgentProviderMessageRole.USER,
            content='{"untrusted_context":[]}',
            content_digest=canonical_digest('{"untrusted_context":[]}'),
            byte_size=len(b'{"untrusted_context":[]}'),
            contains_untrusted_context=True,
        ),
    )
    envelope = SimpleNamespace(messages=messages, max_output_tokens=64)
    return codec_registration, model_registration, envelope


def _response(*, model="gpt-test-1", status="completed", output=None, **extra):
    decision = json.dumps(
        {
            "kind": "complete",
            "summary_digest": "f" * 64,
            "supporting_ref_digests": [],
            "tool_call": None,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    payload = {
        "id": "resp_test",
        "model": model,
        "object": "response",
        "output": output
        if output is not None
        else [
            {
                "content": [{"annotations": [], "text": decision, "type": "output_text"}],
                "id": "msg_test",
                "role": "assistant",
                "status": "completed",
                "type": "message",
            }
        ],
        "status": status,
        "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
        **extra,
    }
    return bytearray(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())


def test_codec_registration_and_request_are_content_addressed_and_sealed():
    codec_registration, model_registration, envelope = _codec_fixture()
    codec = OpenAIResponsesV1Codec(codec_registration)

    encoded = codec.encode(
        model_registration=model_registration,
        envelope=envelope,
    )
    payload = json.loads(encoded)

    assert payload["model"] == "gpt-test-1"
    assert payload["store"] is False
    assert payload["stream"] is False
    assert payload["truncation"] == "disabled"
    assert "tools" not in payload
    assert "tool_choice" not in payload
    assert "metadata" not in payload
    assert payload["input"][0] == {
        "content": [{"text": "sealed system", "type": "input_text"}],
        "role": "system",
    }
    assert payload["text"]["format"]["type"] == "json_schema"
    assert payload["text"]["format"]["strict"] is True
    assert payload["text"]["format"]["schema"]["additionalProperties"] is False
    assert codec_registration.codec_id == canonical_digest(
        codec_registration.model_dump(mode="python", exclude={"codec_id"})
    )


def test_codec_decodes_one_completed_assistant_output_text():
    codec_registration, model_registration, _ = _codec_fixture()

    reply = OpenAIResponsesV1Codec(codec_registration).decode(
        _response(),
        model_registration=model_registration,
        latency_seconds=0.25,
    )

    assert reply.provider_id == "openai"
    assert reply.model == "gpt-test-1"
    assert reply.input_tokens == 3
    assert reply.output_tokens == 2
    assert reply.structured_output == {
        "kind": "complete",
        "summary_digest": "f" * 64,
        "supporting_ref_digests": [],
    }


@pytest.mark.parametrize(
    "raw",
    [
        _response(status="incomplete", incomplete_details={"reason": "max_output_tokens"}),
        _response(
            output=[
                {
                    "id": "call_test",
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "forbidden",
                    "arguments": "{}",
                }
            ]
        ),
        _response(
            output=[
                {
                    "content": [{"refusal": "no", "type": "refusal"}],
                    "id": "msg_test",
                    "role": "assistant",
                    "status": "completed",
                    "type": "message",
                }
            ]
        ),
        _response(model="drifted-model"),
        _response(unrecognized_protocol_field=True),
    ],
)
def test_codec_rejects_incomplete_tool_refusal_identity_and_protocol_drift(raw):
    codec_registration, model_registration, _ = _codec_fixture()

    with pytest.raises(AgentProviderCodecRejected):
        OpenAIResponsesV1Codec(codec_registration).decode(
            raw,
            model_registration=model_registration,
            latency_seconds=0.1,
        )


def test_codec_rejects_duplicate_json_keys_and_oversized_structured_output():
    codec_registration, model_registration, _ = _codec_fixture(
        limits=AgentProviderCodecLimits(max_structured_output_bytes=64)
    )
    codec = OpenAIResponsesV1Codec(codec_registration)

    with pytest.raises(AgentProviderCodecRejected, match="strict JSON"):
        codec.decode(
            bytearray(b'{"id":"a","id":"b"}'),
            model_registration=model_registration,
            latency_seconds=0.1,
        )
    with pytest.raises(AgentProviderCodecRejected, match="byte limit"):
        codec.decode(
            _response(),
            model_registration=model_registration,
            latency_seconds=0.1,
        )


def test_codec_binding_and_safeguard_drift_fail_closed():
    codec_registration, model_registration, envelope = _codec_fixture()
    other_codec = AgentProviderCodecRegistration.create(provider_id="other")

    with pytest.raises(AgentProviderCodecRejected, match="binding"):
        OpenAIResponsesV1Codec(other_codec).encode(
            model_registration=model_registration,
            envelope=envelope,
        )
    values = codec_registration.model_dump(mode="python")
    values["tools_allowed"] = True
    values["codec_id"] = canonical_digest(
        {key: value for key, value in values.items() if key != "codec_id"}
    )
    with pytest.raises(ValidationError, match="safeguards"):
        AgentProviderCodecRegistration.model_validate(values)


def test_codec_wall_budget_is_enforced():
    codec_registration, model_registration, envelope = _codec_fixture(
        limits=AgentProviderCodecLimits(timeout_seconds=0.5)
    )
    times = iter((0.0, 1.0))

    with pytest.raises(AgentProviderCodecTimedOut):
        OpenAIResponsesV1Codec(codec_registration, clock=lambda: next(times)).encode(
            model_registration=model_registration,
            envelope=envelope,
        )
