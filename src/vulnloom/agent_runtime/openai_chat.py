"""Feature-gated OpenAI-compatible Chat Completions Agent codec.

The codec normalizes provider responses into the existing typed Agent decision
contract. It never executes provider-native tools and does not own network or
credential authority.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from contextlib import suppress
from time import monotonic
from typing import Annotated, Literal, Self

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
from .provider_codec import (
    AgentProviderCodecLimits,
    AgentProviderCodecRejected,
    AgentProviderCodecTimedOut,
    AgentProviderWireProtocol,
    _strict_json,
)

OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.openai-compatible-chat-completions",
        "version": 2,
        "request": {
            "messages": "sealed_agent_envelope",
            "stream": False,
            "native_tools": False,
            "arbitrary_parameters": False,
        },
        "response": {
            "object": "chat.completion",
            "choice": "single_stop_assistant",
            "content": "strict_agent_decision_json",
            "refusal": False,
            "native_tools": False,
            "usage": "bounded_exact_totals_with_explicit_reviewed_extensions",
        },
        "decision_schema_digest": AGENT_DECISION_SCHEMA_DIGEST,
    }
)


class OpenAIChatCompletionsFeatureDisabled(ValueError):
    pass


class OpenAIChatCompletionsFeatureGate(DomainModel):
    gate_digest: Digest
    enabled: bool = False
    implementation_digest: Digest = OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.implementation_digest != OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST:
            raise ValueError("OpenAI Chat feature implementation digest drifted")
        if self.gate_digest != canonical_digest(
            self.model_dump(mode="python", exclude={"gate_digest"})
        ):
            raise ValueError("OpenAI Chat feature gate content digest mismatch")
        return self

    @classmethod
    def create(cls, *, enabled: bool = False) -> OpenAIChatCompletionsFeatureGate:
        values = {
            "enabled": enabled,
            "implementation_digest": OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST,
        }
        return cls(gate_digest=canonical_digest(values), **values)


class OpenAIChatCompletionsCodecRegistration(DomainModel):
    codec_id: Digest
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    protocol: Literal[AgentProviderWireProtocol.OPENAI_CHAT_COMPLETIONS_V1] = (
        AgentProviderWireProtocol.OPENAI_CHAT_COMPLETIONS_V1
    )
    request_path: Literal["/v1/chat/completions"] = "/v1/chat/completions"
    request_model: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
    accepted_response_models: Annotated[tuple[str, ...], Field(min_length=1, max_length=8)]
    implementation_digest: Digest = OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST
    decision_schema_digest: Digest = AGENT_DECISION_SCHEMA_DIGEST
    limits: AgentProviderCodecLimits
    allowed_empty_root_fields: Annotated[tuple[str, ...], Field(max_length=32)] = ()
    allowed_empty_choice_fields: Annotated[tuple[str, ...], Field(max_length=32)] = ()
    allowed_empty_message_fields: Annotated[tuple[str, ...], Field(max_length=32)] = ()
    reviewed_usage_extensions_allowed: bool = False
    streaming_allowed: bool = False
    native_tools_allowed: bool = False
    arbitrary_parameters_allowed: bool = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.implementation_digest != OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST
            or self.decision_schema_digest != AGENT_DECISION_SCHEMA_DIGEST
            or self.streaming_allowed
            or self.native_tools_allowed
            or self.arbitrary_parameters_allowed
        ):
            raise ValueError("OpenAI Chat codec safeguards cannot drift")
        for name, values in (
            ("accepted response models", self.accepted_response_models),
            ("empty root fields", self.allowed_empty_root_fields),
            ("empty choice fields", self.allowed_empty_choice_fields),
            ("empty message fields", self.allowed_empty_message_fields),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{name} must be unique and sorted")
        extension_fields = (
            self.allowed_empty_root_fields
            + self.allowed_empty_choice_fields
            + self.allowed_empty_message_fields
        )
        if any(not _FIELD_NAME.fullmatch(item) for item in extension_fields):
            raise ValueError("OpenAI Chat extension field name rejected")
        if set(self.allowed_empty_root_fields) & (_ROOT_REQUIRED | _ROOT_OPTIONAL):
            raise ValueError("OpenAI Chat root extension overlaps a protocol field")
        if set(self.allowed_empty_choice_fields) & (_CHOICE_REQUIRED | {"logprobs"}):
            raise ValueError("OpenAI Chat choice extension overlaps a protocol field")
        if set(self.allowed_empty_message_fields) & (
            _MESSAGE_REQUIRED | {"refusal", "reasoning_content"}
        ):
            raise ValueError("OpenAI Chat message extension overlaps a protocol field")
        if self.codec_id != openai_chat_codec_registration_digest(self):
            raise ValueError("OpenAI Chat codec registration content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        request_model: str,
        accepted_response_models: tuple[str, ...] | None = None,
        limits: AgentProviderCodecLimits | None = None,
        allowed_empty_root_fields: tuple[str, ...] = (),
        allowed_empty_choice_fields: tuple[str, ...] = (),
        allowed_empty_message_fields: tuple[str, ...] = (),
        reviewed_usage_extensions_allowed: bool = False,
    ) -> OpenAIChatCompletionsCodecRegistration:
        values = {
            "provider_id": provider_id,
            "protocol": AgentProviderWireProtocol.OPENAI_CHAT_COMPLETIONS_V1,
            "request_path": "/v1/chat/completions",
            "request_model": request_model,
            "accepted_response_models": tuple(
                sorted(set(accepted_response_models or (request_model,)))
            ),
            "implementation_digest": OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST,
            "decision_schema_digest": AGENT_DECISION_SCHEMA_DIGEST,
            "limits": limits or AgentProviderCodecLimits(),
            "allowed_empty_root_fields": tuple(sorted(set(allowed_empty_root_fields))),
            "allowed_empty_choice_fields": tuple(sorted(set(allowed_empty_choice_fields))),
            "allowed_empty_message_fields": tuple(sorted(set(allowed_empty_message_fields))),
            "reviewed_usage_extensions_allowed": reviewed_usage_extensions_allowed,
            "streaming_allowed": False,
            "native_tools_allowed": False,
            "arbitrary_parameters_allowed": False,
        }
        digest_values = {**values, "limits": values["limits"].model_dump(mode="python")}
        return cls(codec_id=canonical_digest(digest_values), **values)


def openai_chat_codec_registration_digest(
    registration: OpenAIChatCompletionsCodecRegistration,
) -> str:
    return canonical_digest(registration.model_dump(mode="python", exclude={"codec_id"}))


class OpenAIChatCompletionsV1Codec:
    def __init__(
        self,
        registration: OpenAIChatCompletionsCodecRegistration,
        *,
        feature_gate: OpenAIChatCompletionsFeatureGate,
        clock: Callable[[], float] = monotonic,
    ):
        if not feature_gate.enabled:
            raise OpenAIChatCompletionsFeatureDisabled(
                "OpenAI Chat adapter feature is disabled"
            )
        self.registration = OpenAIChatCompletionsCodecRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        self.feature_gate = feature_gate
        self.clock = clock
        self.diagnostic_code = "response_shape_mismatch"
        self.response_model: str | None = None

    def encode(
        self,
        *,
        model_registration: AgentModelRegistration,
        envelope: AgentMessageEnvelope,
    ) -> bytearray:
        started = self.clock()
        self._assert_binding(model_registration)
        envelope = AgentMessageEnvelope.model_validate(envelope.model_dump(mode="python"))
        if (
            envelope.model_registration_id != model_registration.registration_id
            or envelope.max_output_tokens > model_registration.max_output_tokens
        ):
            raise AgentProviderCodecRejected("OpenAI Chat envelope binding mismatch")
        payload = {
            "max_tokens": envelope.max_output_tokens,
            "messages": [
                {"content": item.content, "role": item.role.value}
                for item in envelope.messages
            ],
            "model": self.registration.request_model,
            "stream": False,
        }
        body = bytearray(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        try:
            self._check_timeout(started)
        except AgentProviderCodecTimedOut:
            body[:] = b"\x00" * len(body)
            raise
        return body

    def decode(
        self,
        raw: bytearray,
        *,
        model_registration: AgentModelRegistration,
        latency_seconds: float,
    ) -> AgentModelReply:
        started = self.clock()
        self.diagnostic_code = "response_shape_mismatch"
        self.response_model = None
        self._assert_binding(model_registration)
        if len(raw) > self.registration.limits.max_structured_output_bytes:
            self.diagnostic_code = "response_shape_mismatch"
            raise AgentProviderCodecRejected("OpenAI Chat response exceeds the byte limit")
        payload = _strict_json(raw, "OpenAI Chat response")
        self._require(isinstance(payload, dict), "response_shape_mismatch")
        root_allowed = _ROOT_REQUIRED | _ROOT_OPTIONAL | set(
            self.registration.allowed_empty_root_fields
        )
        self._require(_ROOT_REQUIRED <= set(payload) <= root_allowed, "response_shape_mismatch")
        self._require(
            _extensions_are_empty(payload, self.registration.allowed_empty_root_fields),
            "response_shape_mismatch",
        )
        self._require(
            payload["object"] == "chat.completion"
            and isinstance(payload["id"], str)
            and bool(payload["id"])
            and type(payload["created"]) is int
            and payload["created"] >= 0,
            "response_shape_mismatch",
        )
        self._require(
            payload["model"] in self.registration.accepted_response_models,
            "response_identity_mismatch",
        )
        self._require(
            all(
                payload.get(name) is None or isinstance(payload[name], str)
                for name in _ROOT_OPTIONAL
            ),
            "response_shape_mismatch",
        )

        choices = payload["choices"]
        self._require(isinstance(choices, list) and len(choices) == 1, "response_shape_mismatch")
        choice = choices[0]
        self._require(isinstance(choice, dict), "response_shape_mismatch")
        choice_allowed = _CHOICE_REQUIRED | {"logprobs"} | set(
            self.registration.allowed_empty_choice_fields
        )
        self._require(
            _CHOICE_REQUIRED <= set(choice) <= choice_allowed,
            "response_shape_mismatch",
        )
        self._require(
            _extensions_are_empty(choice, self.registration.allowed_empty_choice_fields),
            "response_shape_mismatch",
        )
        self._require(
            type(choice["index"]) is int
            and choice["index"] == 0
            and choice["finish_reason"] == "stop"
            and choice.get("logprobs") is None,
            "response_shape_mismatch",
        )

        message = choice["message"]
        self._require(isinstance(message, dict), "response_shape_mismatch")
        message_allowed = _MESSAGE_REQUIRED | {"refusal", "reasoning_content"} | set(
            self.registration.allowed_empty_message_fields
        )
        self._require(
            _MESSAGE_REQUIRED <= set(message) <= message_allowed,
            "response_shape_mismatch",
        )
        self._require(
            _extensions_are_empty(message, self.registration.allowed_empty_message_fields),
            "response_shape_mismatch",
        )
        content = message["content"]
        self._require(
            message["role"] == "assistant"
            and isinstance(content, str)
            and message.get("refusal") is None
            and (
                message.get("reasoning_content") is None
                or isinstance(message["reasoning_content"], str)
            ),
            "response_content_mismatch",
        )
        self._require(
            len(content.encode("utf-8"))
            <= self.registration.limits.max_structured_output_bytes,
            "response_content_mismatch",
        )
        structured_output = _strict_json(content, "OpenAI Chat structured output")
        decision: AgentDecisionPayload | None = None
        with suppress(ValidationError):
            decision = AgentDecisionPayload.model_validate(structured_output)
        if decision is None:
            self.diagnostic_code = "response_content_mismatch"
            raise AgentProviderCodecRejected(
                "OpenAI Chat structured output validation failed"
            )

        usage = payload["usage"]
        allowed_usage = _USAGE_FIELDS | (
            _REVIEWED_USAGE_EXTENSION_FIELDS
            if self.registration.reviewed_usage_extensions_allowed
            else set()
        )
        self._require(
            isinstance(usage, dict)
            and _USAGE_FIELDS <= set(usage) <= allowed_usage,
            "usage_mismatch",
        )
        counts = tuple(usage[name] for name in sorted(_USAGE_FIELDS))
        self._require(
            all(type(value) is int and 0 <= value <= 10_000_000 for value in counts),
            "usage_mismatch",
        )
        self._require(
            usage["completion_tokens"] <= model_registration.max_output_tokens,
            "usage_mismatch",
        )
        self._require(
            usage["total_tokens"]
            == usage["prompt_tokens"] + usage["completion_tokens"],
            "usage_total_mismatch",
        )
        self._require(_reviewed_usage_extensions_valid(usage), "usage_details_mismatch")
        self._check_timeout(started)
        self.response_model = payload["model"]
        return AgentModelReply(
            structured_output=decision.model_dump(mode="json", exclude_none=True),
            provider_id=model_registration.provider_id,
            model=model_registration.model,
            input_tokens=usage["prompt_tokens"],
            output_tokens=usage["completion_tokens"],
            latency_seconds=latency_seconds,
        )

    def _assert_binding(self, registration: AgentModelRegistration) -> None:
        if (
            registration.provider_codec_id != self.registration.codec_id
            or registration.provider_id != self.registration.provider_id
            or registration.model != self.registration.request_model
        ):
            raise AgentProviderCodecRejected("OpenAI Chat codec binding mismatch")

    def _require(self, condition: bool, code: str) -> None:
        if not condition:
            self.diagnostic_code = code
            raise AgentProviderCodecRejected("OpenAI Chat response rejected")

    def _check_timeout(self, started: float) -> None:
        if self.clock() - started >= self.registration.limits.timeout_seconds:
            raise AgentProviderCodecTimedOut("OpenAI Chat codec exceeded the wall budget")


def _extensions_are_empty(value: dict[str, object], names: tuple[str, ...]) -> bool:
    return all(
        name not in value or value[name] is None or value[name] in ("", [], {})
        for name in names
    )


_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_ROOT_REQUIRED = {"id", "object", "created", "model", "choices", "usage"}
_ROOT_OPTIONAL = {"service_tier", "system_fingerprint"}
_CHOICE_REQUIRED = {"index", "message", "finish_reason"}
_MESSAGE_REQUIRED = {"role", "content"}
_USAGE_FIELDS = {"prompt_tokens", "completion_tokens", "total_tokens"}
_REVIEWED_USAGE_EXTENSION_FIELDS = {
    "completion_tokens_details",
    "prompt_cache_hit_tokens",
    "prompt_cache_miss_tokens",
    "prompt_tokens_details",
    "reasoning_tokens",
    "time_per_output_token_ms",
    "time_to_first_token_ms",
    "tokens_per_second",
}
_PROMPT_DETAIL_FIELDS = {"audio_tokens", "cached_tokens"}
_COMPLETION_DETAIL_FIELDS = {
    "accepted_prediction_tokens",
    "audio_tokens",
    "reasoning_tokens",
    "rejected_prediction_tokens",
}
_METRIC_LIMITS = {
    "time_per_output_token_ms": 10_000,
    "time_to_first_token_ms": 10_000,
    "tokens_per_second": 1_000_000,
}


def _reviewed_usage_extensions_valid(usage: dict[str, object]) -> bool:
    prompt = usage["prompt_tokens"]
    completion = usage["completion_tokens"]
    for name, limit in _METRIC_LIMITS.items():
        value = usage.get(name)
        if value is not None and (
            type(value) not in (int, float)
            or (type(value) is float and not math.isfinite(value))
            or not 0 <= value <= limit
        ):
            return False
    for name in ("prompt_cache_hit_tokens", "prompt_cache_miss_tokens"):
        value = usage.get(name)
        if value is not None and (type(value) is not int or not 0 <= value <= prompt):
            return False
    cache_names = {"prompt_cache_hit_tokens", "prompt_cache_miss_tokens"}
    if cache_names <= set(usage) and sum(usage[name] for name in cache_names) != prompt:
        return False
    reasoning = usage.get("reasoning_tokens")
    if reasoning is not None and (
        type(reasoning) is not int or not 0 <= reasoning <= completion
    ):
        return False
    for name, allowed, bound in (
        ("prompt_tokens_details", _PROMPT_DETAIL_FIELDS, prompt),
        ("completion_tokens_details", _COMPLETION_DETAIL_FIELDS, completion),
    ):
        details = usage.get(name)
        if details is not None and (
            not isinstance(details, dict)
            or not set(details) <= allowed
            or any(type(value) is not int or not 0 <= value <= bound for value in details.values())
        ):
            return False
    return True
