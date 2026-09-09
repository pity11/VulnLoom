"""CUC-only fixed PONG codec. Not a general Chat Completions Agent adapter."""

import json
import math
from time import monotonic
from typing import ClassVar, Literal, Self

from pydantic import Field, ValidationError, model_validator

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
from .provider_diagnostics import MetricIssue, observe_usage_keys
from .provider_probe_fixture import (
    CUC_PROBE_TEXT,
    CUC_RESPONSE_MODELS,
    CUC_STRUCTURED_PROBE_TEXT,
    PROBE_SUMMARY,
)

# Reviewed vLLM extension subset; values are unused and must be null or typed empty.
ROOT_EMPTY_FIELDS = {
    "prompt_logprobs": list,
    "prompt_token_ids": list,
    "prompt_text": str,
    "kv_transfer_params": dict,
    "ec_transfer_params": dict,
    "metrics": dict,
}
CHOICE_EMPTY_FIELDS = {"stop_reason": str, "token_ids": list, "routed_experts": str}
MESSAGE_EMPTY_FIELDS = {
    "annotations": dict,
    "audio": dict,
    "function_call": type(None),
    "tool_calls": list,
    "reasoning": str,
}
USAGE_METRIC_LIMITS = {
    "time_per_output_token_ms": 10000,
    "time_to_first_token_ms": 10000,
    "tokens_per_second": 1000000,
}
USAGE_OPTIONAL_FIELDS = {
    **{name: (int, float) for name in USAGE_METRIC_LIMITS},
    "prompt_tokens_details": dict,
    "completion_tokens_details": dict,
    "reasoning_tokens": int,
    "prompt_cache_hit_tokens": int,
    "prompt_cache_miss_tokens": int,
}
PROMPT_DETAIL_FIELDS = frozenset({"cached_tokens", "audio_tokens"})
COMPLETION_DETAIL_FIELDS = frozenset(
    {
        "reasoning_tokens",
        "audio_tokens",
        "accepted_prediction_tokens",
        "rejected_prediction_tokens",
    }
)


def classify_pong_content(content):
    if not isinstance(content, str):
        return "response_content_type"
    if content == "PONG":
        return "response_content_exact"
    if content.strip() == "PONG":
        return "response_content_trimmed_match"
    if content.strip().casefold() == "pong":
        return "response_content_casefold_match"
    if content.strip() in {"PONG.", "PONG!", "`PONG`"}:
        return "response_content_punctuation_match"
    return "response_content_empty" if not content else "response_content_other"


def _metric_issue(value, maximum):
    if type(value) not in (int, float):
        return "type"
    if type(value) is float and not math.isfinite(value):
        return "non_finite"
    if value < 0:
        return "negative"
    if value > maximum:
        return "above_limit"
    return None


def _valid_metric(value, maximum):
    # Avoid converting arbitrarily large JSON integers to float.
    return _metric_issue(value, maximum) is None


def _usage_error(usage, max_output_tokens):
    core = {"prompt_tokens", "completion_tokens", "total_tokens"}
    if not isinstance(usage, dict) or not core <= set(usage):
        return "usage_mismatch"
    if set(usage) - (core | set(USAGE_OPTIONAL_FIELDS)):
        return "usage_unknown_fields"
    if any(type(usage[k]) is not int or usage[k] < 0 for k in core):
        return "usage_mismatch"
    if usage["prompt_tokens"] > 32768 or usage["completion_tokens"] > max_output_tokens:
        return "usage_mismatch"
    if usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]:
        return "usage_total_mismatch"
    if "reasoning_tokens" in usage and (
        type(usage["reasoning_tokens"]) is not int
        or not 0 <= usage["reasoning_tokens"] <= usage["completion_tokens"]
    ):
        return "usage_details_mismatch"
    for name, maximum in USAGE_METRIC_LIMITS.items():
        if name in usage and not _valid_metric(usage[name], maximum):
            return "usage_metrics_mismatch"
    cache_fields = {"prompt_cache_hit_tokens", "prompt_cache_miss_tokens"}
    for name in cache_fields & set(usage):
        if type(usage[name]) is not int or not 0 <= usage[name] <= usage["prompt_tokens"]:
            return "usage_cache_mismatch"
    if cache_fields <= set(usage) and usage["prompt_tokens"] != sum(
        usage[name] for name in cache_fields
    ):
        return "usage_cache_mismatch"
    for name, allowed, bound in (
        ("prompt_tokens_details", PROMPT_DETAIL_FIELDS, usage["prompt_tokens"]),
        ("completion_tokens_details", COMPLETION_DETAIL_FIELDS, usage["completion_tokens"]),
    ):
        detail = usage.get(name)
        if detail is not None and (
            not isinstance(detail, dict)
            or not set(detail) <= allowed
            or any(type(v) is not int or not 0 <= v <= bound for v in detail.values())
        ):
            return "usage_details_mismatch"
    return None


def _empty_extensions(value, fields):
    return all(
        value.get(key) is None or (type(value[key]) is kind and not value[key])
        for key, kind in fields.items()
    )


CUC_PROBE_CODEC_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.cuc-chat-pong-probe",
        "version": 6,
        "usage_metric_limits": USAGE_METRIC_LIMITS,
        "usage_metric_numbers": "finite_int_or_float_excluding_bool",
        "request_model": "cuc/deepseek",
        "response_models": CUC_RESPONSE_MODELS,
        "path": "/v1/chat/completions",
        "request_text": CUC_PROBE_TEXT,
        "expected_content_after_strip": ["PONG", "PONG.", "PONG!", "`PONG`"],
        "cache_usage": "integer_within_prompt_and_hit_plus_miss_equals_prompt_if_both",
        "usage_details": {
            "prompt": sorted(PROMPT_DETAIL_FIELDS),
            "completion": sorted(COMPLETION_DETAIL_FIELDS),
            "reasoning": "nonnegative_integer_within_completion",
        },
        "stream": False,
        "tools": False,
        "usage": "bounded_nonnegative_integer_counts",
        "choice": "single_stop_assistant",
        "empty_extensions": {
            level: {
                key: ([t.__name__ for t in kind] if isinstance(kind, tuple) else kind.__name__)
                for key, kind in fields.items()
            }
            for level, fields in (
                ("root", ROOT_EMPTY_FIELDS),
                ("choice", CHOICE_EMPTY_FIELDS),
                ("message", MESSAGE_EMPTY_FIELDS),
                ("usage", USAGE_OPTIONAL_FIELDS),
            )
        },
    }
)

OPENAI_COMPAT_TASK_WIRE_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.openai-compatible-task-wire",
        "version": 1,
        "provider_and_model": "registration_bound",
        "path": "/v1/chat/completions",
        "stream": False,
        "tools": False,
        "choice": "single_stop_assistant",
        "usage_metric_limits": USAGE_METRIC_LIMITS,
        "usage_metric_numbers": "finite_int_or_float_excluding_bool",
        "cache_usage": "integer_within_prompt_and_hit_plus_miss_equals_prompt_if_both",
        "usage_details": {
            "prompt": sorted(PROMPT_DETAIL_FIELDS),
            "completion": sorted(COMPLETION_DETAIL_FIELDS),
            "reasoning": "nonnegative_integer_within_completion",
        },
        "empty_extensions": {
            level: {
                key: ([t.__name__ for t in kind] if isinstance(kind, tuple) else kind.__name__)
                for key, kind in fields.items()
            }
            for level, fields in (
                ("root", ROOT_EMPTY_FIELDS),
                ("choice", CHOICE_EMPTY_FIELDS),
                ("message", MESSAGE_EMPTY_FIELDS),
                ("usage", USAGE_OPTIONAL_FIELDS),
            )
        },
    }
)


class CucChatProbeCodecRegistration(DomainModel):
    expected_implementation_digest: ClassVar[str] = CUC_PROBE_CODEC_DIGEST
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
            or self.implementation_digest != self.expected_implementation_digest
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
    registration_type = CucChatProbeCodecRegistration
    request_text = CUC_PROBE_TEXT

    def __init__(self, registration: CucChatProbeCodecRegistration, *, clock=monotonic):
        self.registration = self.registration_type.model_validate(
            registration.model_dump(mode="python")
        )
        self.clock = clock
        self.response_model = None
        self.diagnostic_code = "response_shape_mismatch"
        self.shape_observations = ()
        self.usage_key_observations = ()
        self.usage_keys_truncated = False
        self.metric_issues = ()
        self.content_classification = None

    def _check(self, started):
        if self.clock() - started >= self.registration.limits.timeout_seconds:
            raise AgentProviderCodecTimedOut("CUC probe codec timed out")

    def _binding(self, model_registration):
        if (
            model_registration.provider_codec_id != self.registration.codec_id
            or model_registration.provider_id != self.registration.provider_id
            or model_registration.model != self.registration.request_model
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
            or fragments[0]["text"] != self.request_text
            or envelope.max_output_tokens > model_registration.max_output_tokens
        ):
            raise AgentProviderCodecRejected("CUC codec only accepts the fixed tool-free probe")
        payload = {
            "model": self.registration.request_model,
            "messages": [{"role": "user", "content": self.request_text}],
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
        self.diagnostic_code = "response_shape_mismatch"
        self.shape_observations = ()
        self.usage_key_observations = ()
        self.usage_keys_truncated = False
        self.metric_issues = ()
        self.content_classification = None
        self._binding(model_registration)

        def require(condition, code):
            if not condition:
                self.diagnostic_code = code
                raise AgentProviderCodecRejected("CUC probe structural check rejected")

        require(
            len(raw) <= self.registration.limits.max_structured_output_bytes, "response_over_budget"
        )
        self.diagnostic_code = "response_json_invalid"
        payload = _strict_json(raw, "CUC probe response")
        self.shape_observations = _observe_shape(payload)
        if isinstance(payload, dict) and isinstance(payload.get("usage"), dict):
            usage = payload["usage"]
            self.metric_issues = tuple(
                MetricIssue(field=name, reason=reason)
                for name, maximum in USAGE_METRIC_LIMITS.items()
                if name in usage and (reason := _metric_issue(usage[name], maximum)) is not None
            )
        if isinstance(payload, dict):
            self.usage_key_observations, self.usage_keys_truncated = observe_usage_keys(
                payload.get("usage"),
                {"prompt_tokens", "completion_tokens", "total_tokens"} | set(USAGE_OPTIONAL_FIELDS),
            )
        required = {"id", "object", "created", "model", "choices", "usage"}
        allowed = required | {"system_fingerprint", "service_tier"} | set(ROOT_EMPTY_FIELDS)
        require(isinstance(payload, dict), "response_root_type")
        require(required <= set(payload), "response_root_missing_fields")
        require(set(payload) <= allowed, "response_root_extra_fields")
        require(_empty_extensions(payload, ROOT_EMPTY_FIELDS), "response_root_extension_nonempty")
        require(
            all(
                payload.get(k) is None or isinstance(payload[k], str)
                for k in ("service_tier", "system_fingerprint")
            ),
            "response_root_metadata",
        )
        require(
            payload["object"] == "chat.completion"
            and isinstance(payload["id"], str)
            and type(payload["created"]) is int
            and payload["created"] >= 0,
            "response_root_metadata",
        )
        require(
            payload["model"] in self.registration.accepted_response_models,
            "response_identity_mismatch",
        )
        choices = payload["choices"]
        require(isinstance(choices, list), "response_choices_type")
        require(len(choices) == 1, "response_choices_count")
        choice = choices[0]
        require(isinstance(choice, dict), "response_choice_type")
        require(
            {"index", "message", "finish_reason"} <= set(choice), "response_choice_missing_fields"
        )
        require(
            set(choice)
            <= {"index", "message", "finish_reason", "logprobs"} | set(CHOICE_EMPTY_FIELDS),
            "response_choice_extra_fields",
        )
        require(
            _empty_extensions(choice, CHOICE_EMPTY_FIELDS), "response_choice_extension_nonempty"
        )
        require(type(choice["index"]) is int and choice["index"] == 0, "response_choice_index")
        require(choice["finish_reason"] == "stop", "response_choice_finish_reason")
        require(choice.get("logprobs") is None, "response_choice_logprobs")
        message = choice["message"]
        require(isinstance(message, dict), "response_message_type")
        require({"role", "content"} <= set(message), "response_message_missing_fields")
        require(
            set(message)
            <= {"role", "content", "refusal", "reasoning_content"} | set(MESSAGE_EMPTY_FIELDS),
            "response_message_extra_fields",
        )
        require(
            _empty_extensions(message, MESSAGE_EMPTY_FIELDS), "response_message_extension_nonempty"
        )
        require(message["role"] == "assistant", "response_message_role")
        require(message.get("refusal") is None, "response_message_refusal")
        require(
            message.get("reasoning_content") is None
            or isinstance(message["reasoning_content"], str),
            "response_message_reasoning_type",
        )
        self.content_classification = self._classify_content(message["content"])
        require(
            self.content_classification
            in {
                "response_content_exact",
                "response_content_trimmed_match",
                "response_content_punctuation_match",
            },
            self.content_classification,
        )
        usage = payload["usage"]
        usage_error = _usage_error(usage, model_registration.max_output_tokens)
        require(usage_error is None, usage_error)
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

    def _classify_content(self, content):
        return classify_pong_content(content)


class CucStructuredProbeResponse(DomainModel):
    """Synthetic schema acceptance only; never an Agent decision or tool instruction."""

    status: Literal["ok"]
    count: int = Field(strict=True, ge=3, le=3)


CUC_STRUCTURED_CODEC_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.cuc-chat-structured-probe",
        "version": 1,
        "wire_contract": CUC_PROBE_CODEC_DIGEST,
        "request_text": CUC_STRUCTURED_PROBE_TEXT,
        "response_schema": CucStructuredProbeResponse.model_json_schema(),
        "duplicate_keys": "reject",
        "tools": False,
    }
)


class CucChatStructuredProbeCodecRegistration(CucChatProbeCodecRegistration):
    expected_implementation_digest: ClassVar[str] = CUC_STRUCTURED_CODEC_DIGEST
    protocol: Literal["cuc-chat-structured-probe-v1"] = "cuc-chat-structured-probe-v1"
    implementation_digest: Digest = CUC_STRUCTURED_CODEC_DIGEST


class CucChatStructuredProbeCodec(CucChatProbeCodec):
    """Fixed JSON compatibility test, without arbitrary prompts or tool dispatch."""

    registration_type = CucChatStructuredProbeCodecRegistration
    request_text = CUC_STRUCTURED_PROBE_TEXT

    def _classify_content(self, content):
        if not isinstance(content, str):
            return "response_content_type"
        try:
            CucStructuredProbeResponse.model_validate(_strict_json(content, "structured probe"))
        except (AgentProviderCodecRejected, ValidationError):
            return "response_content_other"
        return "response_content_exact"


def _observe_shape(payload):
    """Only fixed, reviewed identifiers and nullness; never arbitrary keys or values."""
    if not isinstance(payload, dict):
        return ()
    observed = []

    def observe(level, value, fields, core):
        for field in sorted(fields):
            if field in value:
                observed.append(
                    level + "_" + field + ("_null" if value[field] is None else "_non_null")
                )
        if set(value) - (set(fields) | core):
            observed.append(level + "_other_fields")

    observe(
        "root",
        payload,
        ROOT_EMPTY_FIELDS,
        {
            "id",
            "object",
            "created",
            "model",
            "choices",
            "usage",
            "system_fingerprint",
            "service_tier",
        },
    )
    choices = payload.get("choices")
    if isinstance(choices, list) and len(choices) == 1 and isinstance(choices[0], dict):
        choice = choices[0]
        observe(
            "choice", choice, CHOICE_EMPTY_FIELDS, {"index", "message", "finish_reason", "logprobs"}
        )
        message = choice.get("message")
        if isinstance(message, dict):
            observe(
                "message",
                message,
                MESSAGE_EMPTY_FIELDS,
                {"role", "content", "refusal", "reasoning_content"},
            )
    usage = payload.get("usage")
    if isinstance(usage, dict):
        observe(
            "usage",
            usage,
            {**USAGE_OPTIONAL_FIELDS, "cached_tokens": int},
            {"prompt_tokens", "completion_tokens", "total_tokens"},
        )
        for name, prefix, fields, interesting in (
            ("prompt_tokens_details", "prompt_details", PROMPT_DETAIL_FIELDS, "cached_tokens"),
            (
                "completion_tokens_details",
                "completion_details",
                COMPLETION_DETAIL_FIELDS,
                "reasoning_tokens",
            ),
        ):
            detail = usage.get(name)
            if isinstance(detail, dict):
                if interesting in detail:
                    observed.append(prefix + "_" + interesting)
                if set(detail) - fields:
                    observed.append(prefix + "_other_fields")
    return tuple(observed)
