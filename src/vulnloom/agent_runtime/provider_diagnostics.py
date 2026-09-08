"""Closed, body-free observations; never authority to accept a provider response."""

from hashlib import sha256
from typing import Literal, Self, get_args

from pydantic import Field, model_serializer, model_validator

from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

ContentClassification = Literal[
    "response_content_type",
    "response_content_exact",
    "response_content_trimmed_match",
    "response_content_casefold_match",
    "response_content_punctuation_match",
    "response_content_empty",
    "response_content_other",
]

ContentShapeObservation = Literal[
    "recommendation_json_invalid",
    "recommendation_root_type",
    "recommendation_missing_fields",
    "recommendation_extra_fields",
    "recommendation_projection_id_type",
    "recommendation_projection_id_mismatch",
    "recommendation_priority_type",
    "recommendation_priority_value",
    "recommendation_rationale_type",
    "recommendation_rationale_empty",
    "recommendation_rationale_over_budget",
    "recommendation_rationale_untrimmed",
    "recommendation_rationale_unsafe",
    "recommendation_questions_type",
    "recommendation_questions_count",
    "recommendation_question_item_type",
    "recommendation_question_unsafe",
    "recommendation_indexes_type",
    "recommendation_indexes_count",
    "recommendation_index_item_type",
    "recommendation_indexes_order_or_duplicate",
    "recommendation_index_out_of_range",
]


ResponseShapeCode = Literal[
    "response_root_extension_nonempty",
    "response_choice_extension_nonempty",
    "response_message_extension_nonempty",
    "response_json_invalid",
    "response_over_budget",
    "response_root_type",
    "response_root_missing_fields",
    "response_root_extra_fields",
    "response_root_metadata",
    "response_choices_type",
    "response_choices_count",
    "response_choice_type",
    "response_choice_missing_fields",
    "response_choice_extra_fields",
    "response_choice_index",
    "response_choice_finish_reason",
    "response_choice_logprobs",
    "response_message_type",
    "response_message_missing_fields",
    "response_message_extra_fields",
    "response_message_null_tool_calls",
    "response_message_null_function_call",
    "response_message_null_call_fields",
    "response_message_role",
    "response_message_refusal",
    "response_message_reasoning_type",
]


ShapeObservation = Literal[
    "root_prompt_logprobs_null",
    "root_prompt_logprobs_non_null",
    "root_kv_transfer_params_null",
    "root_kv_transfer_params_non_null",
    "root_prompt_token_ids_null",
    "root_prompt_token_ids_non_null",
    "root_prompt_text_null",
    "root_prompt_text_non_null",
    "root_ec_transfer_params_null",
    "root_ec_transfer_params_non_null",
    "root_metrics_null",
    "root_metrics_non_null",
    "root_other_fields",
    "message_tool_calls_null",
    "message_tool_calls_non_null",
    "message_function_call_null",
    "message_function_call_non_null",
    "message_annotations_null",
    "message_annotations_non_null",
    "message_audio_null",
    "message_audio_non_null",
    "message_reasoning_null",
    "message_reasoning_non_null",
    "message_other_fields",
    "choice_stop_reason_null",
    "choice_stop_reason_non_null",
    "choice_token_ids_null",
    "choice_token_ids_non_null",
    "choice_routed_experts_null",
    "choice_routed_experts_non_null",
    "choice_other_fields",
    "usage_prompt_tokens_details_null",
    "usage_prompt_tokens_details_non_null",
    "usage_prompt_cache_hit_tokens_null",
    "usage_prompt_cache_hit_tokens_non_null",
    "usage_prompt_cache_miss_tokens_null",
    "usage_prompt_cache_miss_tokens_non_null",
    "usage_time_per_output_token_ms_null",
    "usage_time_per_output_token_ms_non_null",
    "usage_time_to_first_token_ms_null",
    "usage_time_to_first_token_ms_non_null",
    "usage_tokens_per_second_null",
    "usage_tokens_per_second_non_null",
    "usage_other_fields",
    "usage_completion_tokens_details_null",
    "usage_completion_tokens_details_non_null",
    "usage_reasoning_tokens_null",
    "usage_reasoning_tokens_non_null",
    "usage_cached_tokens_null",
    "usage_cached_tokens_non_null",
    "prompt_details_cached_tokens",
    "completion_details_reasoning_tokens",
    "prompt_details_other_fields",
    "completion_details_other_fields",
]


UsageCandidateField = Literal[
    "num_cached_tokens",
    "cached_prompt_tokens",
    "prompt_tokens_cached",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
    "input_tokens_details",
    "output_tokens_details",
    "total_tokens_details",
]


class UsageKeyObservation(DomainModel):
    candidate: UsageCandidateField | None = None
    name_sha256: Digest | None = None
    value_type: Literal["null", "int", "dict", "other"]

    @model_validator(mode="after")
    def exclusive_identity(self) -> Self:
        if (self.candidate is None) == (self.name_sha256 is None):
            raise ValueError("usage observation needs exactly one closed identity")
        return self


def observe_usage_keys(usage, allowed):
    if not isinstance(usage, dict):
        return (), False
    unknown = sorted(set(usage) - set(allowed))
    observations = []
    candidates = get_args(UsageCandidateField)
    for name in unknown[:32]:
        value = usage[name]
        kind = (
            "null"
            if value is None
            else "int"
            if type(value) is int
            else "dict"
            if type(value) is dict
            else "other"
        )
        observations.append(
            UsageKeyObservation(
                candidate=name if name in candidates else None,
                name_sha256=None
                if name in candidates
                else sha256(name.encode("utf-8")).hexdigest(),
                value_type=kind,
            )
        )
    return tuple(observations), len(unknown) > 32


class MetricIssue(DomainModel):
    field: Literal["time_per_output_token_ms", "time_to_first_token_ms", "tokens_per_second"]
    reason: Literal["type", "non_finite", "negative", "above_limit"]


class ProviderDiagnostic(DomainModel):
    metric_issues: tuple[MetricIssue, ...] = Field(default=(), max_length=3)
    usage_key_observations: tuple[UsageKeyObservation, ...] = Field(default=(), max_length=32)
    usage_keys_truncated: bool = Field(default=False, strict=True)
    content_classification: ContentClassification | None = None
    content_shape_observations: tuple[ContentShapeObservation, ...] = Field(
        default=(), max_length=32
    )
    shape_observations: tuple[ShapeObservation, ...] = Field(default=(), max_length=32)

    @model_serializer(mode="wrap")
    def omit_absent_observations(self, handler):
        result = handler(self)
        if not self.metric_issues:
            result.pop("metric_issues", None)
        if not self.usage_key_observations:
            result.pop("usage_key_observations", None)
        if not self.usage_keys_truncated:
            result.pop("usage_keys_truncated", None)
        if self.content_classification is None:
            result.pop("content_classification", None)
        if not self.content_shape_observations:
            result.pop("content_shape_observations", None)
        if not self.shape_observations:
            result.pop("shape_observations", None)  # Preserve existing result digests.
        return result

    failure_stage: Literal["transport_process", "http_status", "response_codec"] | None
    error_code: (
        Literal[
            "transport_rejected",
            "tls_failed",
            "connect_failed",
            "http_non_200",
            "response_headers_rejected",
            "response_empty",
            "response_size_exceeded",
            "transport_timeout",
            "response_identity_mismatch",
            "response_shape_mismatch",
            "response_content_mismatch",
            "usage_mismatch",
            "codec_timeout",
        ]
        | ContentClassification
        | Literal[
            "usage_total_mismatch",
            "usage_unknown_fields",
            "usage_details_mismatch",
            "usage_cache_mismatch",
            "usage_metrics_mismatch",
        ]
        | ResponseShapeCode
        | None
    )
    http_status: int | None = Field(default=None, strict=True, ge=100, le=599)
    # None means no trustworthy observation, e.g. a parent-enforced process timeout.
    network_opened: bool | None = Field(default=None, strict=True)
    captured_response_bytes: int = Field(default=0, strict=True, ge=0, le=2_097_153)
    tls_version: Literal["TLSv1.2", "TLSv1.3"] | None = None

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (self.failure_stage is None) != (self.error_code is None):
            raise ValueError("diagnostic failure fields must agree")
        if self.tls_version is not None and self.network_opened is not True:
            raise ValueError("TLS observation requires a network connection")
        if self.http_status is not None and self.tls_version is None:
            raise ValueError("HTTPS status requires TLS observation")
        if self.failure_stage == "http_status" and (
            self.error_code != "http_non_200" or self.http_status in (None, 200)
        ):
            raise ValueError("HTTP rejection requires non-200 status")
        if self.failure_stage == "response_codec" and self.http_status != 200:
            raise ValueError("response decoding requires HTTP 200")
        return self


def safe_shape_observations(codec):
    observations = getattr(codec, "shape_observations", ())
    if (
        not isinstance(observations, tuple)
        or len(observations) > 32
        or any(item not in get_args(ShapeObservation) for item in observations)
    ):
        return ()
    return observations


def safe_content_classification(codec):
    code = getattr(codec, "content_classification", None)
    return code if code in get_args(ContentClassification) else None


def safe_content_shape_observations(codec):
    observations = getattr(codec, "content_shape_observations", ())
    if (
        not isinstance(observations, tuple)
        or len(observations) > 32
        or any(item not in get_args(ContentShapeObservation) for item in observations)
    ):
        return ()
    return observations


def safe_usage_key_observations(codec):
    items = getattr(codec, "usage_key_observations", ())
    truncated = getattr(codec, "usage_keys_truncated", False)
    if not isinstance(items, tuple) or len(items) > 32 or type(truncated) is not bool:
        return {"usage_key_observations": (), "usage_keys_truncated": False}
    try:
        safe = tuple(UsageKeyObservation.model_validate(x.model_dump()) for x in items)
    except (ValueError, AttributeError, TypeError):
        return {"usage_key_observations": (), "usage_keys_truncated": False}
    return {"usage_key_observations": safe, "usage_keys_truncated": truncated}


def safe_metric_issues(codec):
    items = getattr(codec, "metric_issues", ())
    if not isinstance(items, tuple) or len(items) > 3:
        return ()
    try:
        return tuple(MetricIssue.model_validate(x.model_dump()) for x in items)
    except (ValueError, AttributeError, TypeError):
        return ()
