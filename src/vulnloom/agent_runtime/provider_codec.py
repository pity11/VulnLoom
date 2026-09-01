"""Content-addressed OpenAI Responses wire codec with a sealed JSON contract."""

from __future__ import annotations

import json
from collections.abc import Callable
from enum import StrEnum
from time import monotonic
from typing import Self

from pydantic import Field, ValidationError, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .messages import AgentMessageEnvelope
from .models import (
    AGENT_DECISION_SCHEMA_DIGEST,
    AgentDecisionPayload,
    AgentModelRegistration,
    AgentModelReply,
)


class AgentProviderCodecRejected(ValueError):
    pass


class AgentProviderCodecTimedOut(TimeoutError):
    pass


class AgentProviderWireProtocol(StrEnum):
    OPENAI_RESPONSES_V1 = "openai-responses-v1"


class AgentProviderCodecLimits(DomainModel):
    max_structured_output_bytes: int = Field(default=262_144, gt=0, le=1_048_576)
    timeout_seconds: float = Field(default=2.0, gt=0, le=30)


class AgentProviderCodecRegistration(DomainModel):
    codec_id: Digest
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    protocol: AgentProviderWireProtocol = AgentProviderWireProtocol.OPENAI_RESPONSES_V1
    request_path: str = "/v1/responses"
    decision_schema_digest: Digest = AGENT_DECISION_SCHEMA_DIGEST
    implementation_digest: Digest
    limits: AgentProviderCodecLimits
    streaming_allowed: bool = False
    storage_allowed: bool = False
    tools_allowed: bool = False
    arbitrary_parameters_allowed: bool = False

    @model_validator(mode="after")
    def sealed_codec(self) -> Self:
        if (
            self.protocol is not AgentProviderWireProtocol.OPENAI_RESPONSES_V1
            or self.request_path != "/v1/responses"
            or self.decision_schema_digest != AGENT_DECISION_SCHEMA_DIGEST
            or self.implementation_digest != OPENAI_RESPONSES_V1_IMPLEMENTATION_DIGEST
            or self.streaming_allowed
            or self.storage_allowed
            or self.tools_allowed
            or self.arbitrary_parameters_allowed
        ):
            raise ValueError("provider codec safeguards cannot drift")
        if self.codec_id != agent_provider_codec_registration_digest(self):
            raise ValueError("provider codec registration content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        limits: AgentProviderCodecLimits | None = None,
    ) -> AgentProviderCodecRegistration:
        values = {
            "provider_id": provider_id,
            "protocol": AgentProviderWireProtocol.OPENAI_RESPONSES_V1,
            "request_path": "/v1/responses",
            "decision_schema_digest": AGENT_DECISION_SCHEMA_DIGEST,
            "implementation_digest": OPENAI_RESPONSES_V1_IMPLEMENTATION_DIGEST,
            "limits": limits or AgentProviderCodecLimits(),
            "streaming_allowed": False,
            "storage_allowed": False,
            "tools_allowed": False,
            "arbitrary_parameters_allowed": False,
        }
        digest_values = {
            **values,
            "limits": values["limits"].model_dump(mode="python"),
        }
        return cls(codec_id=canonical_digest(digest_values), **values)


def agent_provider_codec_registration_digest(
    registration: AgentProviderCodecRegistration,
) -> str:
    return canonical_digest(registration.model_dump(mode="python", exclude={"codec_id"}))


_DECISION_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "kind": {"type": "string", "enum": ["propose_tool", "complete", "blocked"]},
        "tool_call": {
            "anyOf": [
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "tool_id": {"type": "string", "pattern": "^[a-z][a-z0-9_.-]{0,127}$"},
                        "arguments": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 128,
                        },
                        "working_directory": {
                            "type": "string",
                            "enum": ["source", "output", "temp"],
                        },
                    },
                    "required": ["tool_id", "arguments", "working_directory"],
                },
                {"type": "null"},
            ]
        },
        "summary_digest": {
            "anyOf": [
                {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                {"type": "null"},
            ]
        },
        "supporting_ref_digests": {
            "type": "array",
            "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "maxItems": 1024,
        },
    },
    "required": ["kind", "tool_call", "summary_digest", "supporting_ref_digests"],
}

OPENAI_RESPONSES_V1_IMPLEMENTATION_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.openai-responses-codec",
        "version": 1,
        "request_path": "/v1/responses",
        "request": {
            "store": False,
            "stream": False,
            "truncation": "disabled",
            "tools": False,
            "arbitrary_parameters": False,
        },
        "decision_schema": _DECISION_SCHEMA,
        "response": {
            "status": "completed",
            "output": "single_assistant_output_text",
            "refusal": False,
            "tool_calls": False,
            "strict_json": True,
        },
    }
)


class OpenAIResponsesV1Codec:
    def __init__(
        self,
        registration: AgentProviderCodecRegistration,
        *,
        clock: Callable[[], float] = monotonic,
    ):
        self.registration = registration
        self.clock = clock

    def encode(
        self,
        *,
        model_registration: AgentModelRegistration,
        envelope: AgentMessageEnvelope,
    ) -> bytearray:
        started = self.clock()
        self._assert_binding(model_registration)
        payload = {
            "input": [
                {
                    "role": item.role.value,
                    "content": [{"type": "input_text", "text": item.content}],
                }
                for item in envelope.messages
            ],
            "max_output_tokens": envelope.max_output_tokens,
            "model": model_registration.model,
            "store": False,
            "stream": False,
            "text": {
                "format": {
                    "name": "vulnloom_agent_decision",
                    "schema": _DECISION_SCHEMA,
                    "strict": True,
                    "type": "json_schema",
                }
            },
            "truncation": "disabled",
        }
        encoded = bytearray(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        )
        try:
            self._check_timeout(started)
        except AgentProviderCodecTimedOut:
            encoded[:] = b"\x00" * len(encoded)
            raise
        return encoded

    def decode(
        self,
        raw: bytearray,
        *,
        model_registration: AgentModelRegistration,
        latency_seconds: float,
    ) -> AgentModelReply:
        started = self.clock()
        self._assert_binding(model_registration)
        payload = _strict_json(raw, "provider response")
        if not isinstance(payload, dict) or not (
            _RESPONSE_REQUIRED <= set(payload) <= _RESPONSE_ALLOWED
        ):
            raise AgentProviderCodecRejected("provider response shape mismatch")
        if (
            payload["object"] != "response"
            or payload["status"] != "completed"
            or payload["model"] != model_registration.model
            or payload.get("error") is not None
            or payload.get("incomplete_details") is not None
        ):
            raise AgentProviderCodecRejected("provider response state or identity mismatch")
        output = payload["output"]
        if not isinstance(output, list) or len(output) != 1:
            raise AgentProviderCodecRejected("provider response must contain one output message")
        message = output[0]
        if not isinstance(message, dict) or set(message) != {
            "content",
            "id",
            "role",
            "status",
            "type",
        }:
            raise AgentProviderCodecRejected("provider output message shape mismatch")
        if (
            message["type"] != "message"
            or message["role"] != "assistant"
            or message["status"] != "completed"
        ):
            raise AgentProviderCodecRejected("provider output is not a completed assistant message")
        content = message["content"]
        if not isinstance(content, list) or len(content) != 1:
            raise AgentProviderCodecRejected("provider response must contain one output_text item")
        item = content[0]
        if not isinstance(item, dict) or set(item) != {"annotations", "text", "type"}:
            raise AgentProviderCodecRejected("provider output content shape mismatch")
        text = item["text"]
        if item["type"] != "output_text" or item["annotations"] != [] or not isinstance(text, str):
            raise AgentProviderCodecRejected("provider output text or annotations rejected")
        if len(text.encode("utf-8")) > self.registration.limits.max_structured_output_bytes:
            raise AgentProviderCodecRejected("provider structured output exceeds the byte limit")
        structured_output = _strict_json(text, "provider structured output")
        if not isinstance(structured_output, dict):
            raise AgentProviderCodecRejected("provider structured output shape mismatch")
        try:
            decision = AgentDecisionPayload.model_validate(structured_output)
        except ValidationError as exc:
            raise AgentProviderCodecRejected(
                "provider structured output validation failed"
            ) from exc
        usage = payload["usage"]
        if not isinstance(usage, dict) or not {"input_tokens", "output_tokens"} <= set(usage):
            raise AgentProviderCodecRejected("provider usage shape mismatch")
        input_tokens = usage["input_tokens"]
        output_tokens = usage["output_tokens"]
        if (
            isinstance(input_tokens, bool)
            or isinstance(output_tokens, bool)
            or not isinstance(input_tokens, int)
            or not isinstance(output_tokens, int)
            or input_tokens < 0
            or output_tokens < 0
        ):
            raise AgentProviderCodecRejected("provider usage values rejected")
        self._check_timeout(started)
        return AgentModelReply(
            structured_output=decision.model_dump(mode="json", exclude_none=True),
            provider_id=model_registration.provider_id,
            model=model_registration.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_seconds=latency_seconds,
        )

    def _assert_binding(self, registration: AgentModelRegistration) -> None:
        if (
            registration.provider_codec_id != self.registration.codec_id
            or registration.provider_id != self.registration.provider_id
        ):
            raise AgentProviderCodecRejected("provider codec binding mismatch")

    def _check_timeout(self, started: float) -> None:
        if self.clock() - started > self.registration.limits.timeout_seconds:
            raise AgentProviderCodecTimedOut("provider codec exceeded the wall budget")


def _strict_json(raw: bytearray | str, label: str) -> object:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentProviderCodecRejected(f"{label} is not strict JSON") from exc


_RESPONSE_REQUIRED = {"id", "model", "object", "output", "status", "usage"}
_RESPONSE_ALLOWED = _RESPONSE_REQUIRED | {
    "background",
    "billing",
    "completed_at",
    "created_at",
    "error",
    "incomplete_details",
    "instructions",
    "max_output_tokens",
    "max_tool_calls",
    "metadata",
    "parallel_tool_calls",
    "previous_response_id",
    "prompt",
    "prompt_cache_key",
    "prompt_cache_retention",
    "reasoning",
    "safety_identifier",
    "service_tier",
    "store",
    "temperature",
    "text",
    "tool_choice",
    "tools",
    "top_logprobs",
    "top_p",
    "truncation",
    "user",
}
