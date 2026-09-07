"""CUC-only fixed PONG codec. Not a general Chat Completions Agent adapter."""

import json
from time import monotonic
from typing import Literal, Self

from pydantic import Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import WorkerRole
from vulnloom.runners.models import Digest

from .messages import AgentMessageEnvelope
from .models import AgentModelReply
from .provider_codec import (
    AgentProviderCodecLimits,
    AgentProviderCodecRejected,
    AgentProviderCodecTimedOut,
    _strict_json,
)
from .provider_probe_fixture import CUC_PROBE_TEXT, CUC_RESPONSE_MODELS, PROBE_SUMMARY

CUC_PROBE_CODEC_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.cuc-chat-pong-probe",
        "version": 1,
        "request_model": "cuc/deepseek",
        "response_models": CUC_RESPONSE_MODELS,
        "path": "/v1/chat/completions",
        "request_text": CUC_PROBE_TEXT,
        "expected_content": "PONG",
        "stream": False,
        "tools": False,
        "usage": "bounded_nonnegative_integer_counts",
        "choice": "single_stop_assistant",
    }
)


class CucChatProbeCodecRegistration(DomainModel):
    codec_id: Digest
    provider_id: Literal["cuc"] = "cuc"
    protocol: Literal["cuc-chat-pong-probe-v1"] = "cuc-chat-pong-probe-v1"
    request_path: Literal["/v1/chat/completions"] = "/v1/chat/completions"
    request_model: Literal["cuc/deepseek"] = "cuc/deepseek"
    accepted_response_models: tuple[str, str] = CUC_RESPONSE_MODELS
    implementation_digest: Digest = CUC_PROBE_CODEC_DIGEST
    limits: AgentProviderCodecLimits = Field(
        default_factory=lambda: AgentProviderCodecLimits(
            max_structured_output_bytes=32768,
            timeout_seconds=2,
        )
    )

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.accepted_response_models != CUC_RESPONSE_MODELS
            or self.implementation_digest != CUC_PROBE_CODEC_DIGEST
            or self.limits.max_structured_output_bytes > 32768
            or self.limits.timeout_seconds > 2
            or self.codec_id
            != canonical_digest(self.model_dump(mode="python", exclude={"codec_id"}))
        ):
            raise ValueError("CUC probe codec identity or limits drifted")
        return self

    @classmethod
    def create(cls):
        partial = cls.model_construct(codec_id="0" * 64)
        values = partial.model_dump(mode="python", exclude={"codec_id"})
        return cls(codec_id=canonical_digest(values), **values)


class CucChatProbeCodec:
    def __init__(self, registration: CucChatProbeCodecRegistration, *, clock=monotonic):
        self.registration = CucChatProbeCodecRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        self.clock = clock
        self.response_model = None

    def _check(self, started):
        if self.clock() - started >= self.registration.limits.timeout_seconds:
            raise AgentProviderCodecTimedOut("CUC probe codec timed out")

    def _binding(self, model_registration):
        if (
            model_registration.provider_codec_id != self.registration.codec_id
            or model_registration.provider_id != "cuc"
            or model_registration.model != "cuc/deepseek"
            or model_registration.supported_roles != (WorkerRole.REPORTER,)
            or model_registration.max_output_tokens > 512
        ):
            raise AgentProviderCodecRejected("CUC probe registration mismatch")

    def encode(self, *, model_registration, envelope):
        started = self.clock()
        self._binding(model_registration)
        envelope = AgentMessageEnvelope.model_validate(envelope.model_dump(mode="python"))
        user = _strict_json(envelope.messages[1].content, "CUC probe message")
        fragments = user["untrusted_context"]
        if (
            envelope.model_registration_id != model_registration.registration_id
            or envelope.worker_role is not WorkerRole.REPORTER
            or envelope.allowed_tools
            or envelope.tool_call_budget != 0
            or envelope.authorized_call_set_id is not None
            or envelope.authorized_call_commitments
            or len(fragments) != 1
            or fragments[0]["text"] != CUC_PROBE_TEXT
            or envelope.max_output_tokens > model_registration.max_output_tokens
        ):
            raise AgentProviderCodecRejected("CUC codec only accepts the fixed tool-free probe")
        payload = {
            "model": "cuc/deepseek",
            "messages": [{"role": "user", "content": CUC_PROBE_TEXT}],
            "stream": False,
            "max_tokens": envelope.max_output_tokens,
        }
        body = bytearray(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        try:
            self._check(started)
        except AgentProviderCodecTimedOut:
            body[:] = b"\x00" * len(body)
            raise
        return body

    def decode(self, raw, *, model_registration, latency_seconds):
        started = self.clock()
        self.response_model = None
        self._binding(model_registration)
        if len(raw) > self.registration.limits.max_structured_output_bytes:
            raise AgentProviderCodecRejected("CUC probe response over budget")
        payload = _strict_json(raw, "CUC probe response")
        required = {"id", "object", "created", "model", "choices", "usage"}
        allowed = required | {"system_fingerprint", "service_tier"}
        if (
            not isinstance(payload, dict)
            or not required <= set(payload) <= allowed
            or payload["object"] != "chat.completion"
            or payload["model"] not in CUC_RESPONSE_MODELS
            or not isinstance(payload["id"], str)
            or type(payload["created"]) is not int
            or payload["created"] < 0
        ):
            raise AgentProviderCodecRejected("CUC probe response identity or shape rejected")
        choices = payload["choices"]
        if not isinstance(choices, list) or len(choices) != 1:
            raise AgentProviderCodecRejected("CUC probe requires one choice")
        choice = choices[0]
        if (
            not isinstance(choice, dict)
            or not {"index", "message", "finish_reason"}
            <= set(choice)
            <= {"index", "message", "finish_reason", "logprobs"}
            or type(choice["index"]) is not int
            or choice["index"] != 0
            or choice["finish_reason"] != "stop"
            or choice.get("logprobs") is not None
        ):
            raise AgentProviderCodecRejected("CUC probe choice rejected")
        message = choice["message"]
        if (
            not isinstance(message, dict)
            or not {"role", "content"}
            <= set(message)
            <= {"role", "content", "refusal", "reasoning_content"}
            or message["role"] != "assistant"
            or message["content"] != "PONG"
            or message.get("refusal") is not None
            or (
                message.get("reasoning_content") is not None
                and not isinstance(message["reasoning_content"], str)
            )
        ):
            raise AgentProviderCodecRejected("CUC probe message rejected")
        # Optional reasoning text is discarded with the raw response, never returned or persisted.
        usage = payload["usage"]
        usage_keys = {"prompt_tokens", "completion_tokens", "total_tokens"}
        if (
            not isinstance(usage, dict)
            or not usage_keys <= set(usage)
            or any(type(usage[k]) is not int or usage[k] < 0 for k in usage_keys)
            or usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]
            or usage["prompt_tokens"] > 32768
            or usage["completion_tokens"] > model_registration.max_output_tokens
        ):
            raise AgentProviderCodecRejected("CUC probe usage rejected")
        self._check(started)
        self.response_model = payload["model"]
        return AgentModelReply(
            provider_id="cuc",
            model="cuc/deepseek",
            input_tokens=usage["prompt_tokens"],
            output_tokens=usage["completion_tokens"],
            latency_seconds=latency_seconds,
            structured_output={
                "kind": "complete",
                "summary_digest": PROBE_SUMMARY,
                "tool_call": None,
                "supporting_ref_digests": [],
            },
        )
