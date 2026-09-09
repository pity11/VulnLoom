"""Content-addressed compatibility baselines for provider adapter migrations."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .provider_probe_cuc import (
    CUC_PROBE_CODEC_DIGEST,
    CUC_STRUCTURED_CODEC_DIGEST,
    CucChatProbeCodecRegistration,
    CucChatStructuredProbeCodecRegistration,
)
from .provider_probe_fixture import (
    CUC_PROBE_TEXT,
    CUC_RESPONSE_MODELS,
    CUC_STRUCTURED_PROBE_TEXT,
    PROBE_SUMMARY,
)


class CucChatCompatibilityDrift(ValueError):
    pass


_CUC_CHAT_COMPATIBILITY_V1 = {
    "baseline_version": "cuc-chat-compatibility-v1",
    "pong_codec_id": "edce425c81cfe65b7fc0c67d427af69755cc6bd698ecb1b349e8a50309f4be23",
    "structured_codec_id": "fe9343d9be615c3621eb52114785ead61e6974b714f8cfdfdde8a6a4423dc2a8",
    "pong_implementation_digest": (
        "7887368111e432b619bd83bba0647de22cff84ad9de1254b39fdfcb3c44238cc"
    ),
    "structured_implementation_digest": (
        "70613f46628afb7b2f5446a24bcc2d0082d3e2b18b6832bf2736cbde1b34da20"
    ),
    "pong_request_digest": "343e369cdc9d14ba0f7f3f02e0439c4e0c2935f680cdca80ba68c93c0fa62809",
    "structured_request_digest": (
        "f9377af3bcd5d0e18e5c91f6675fa779d8c6f4e57d5a547a04dcbfc816d14d60"
    ),
    "pong_completion_summary_digest": (
        "90c876c59a9aed601edfb3e1f2ee771bd3d8c17c79a302b24f13b8e7c75cc736"
    ),
    "request_model": "cuc/deepseek",
    "accepted_response_models": CUC_RESPONSE_MODELS,
    "accepted_pong_classifications": (
        "response_content_exact",
        "response_content_punctuation_match",
        "response_content_trimmed_match",
    ),
    "failure_semantics": (
        "closed_diagnostics",
        "no_reply",
        "no_receipt",
        "single_terminal_attempt",
        "verified_cleanup_required",
    ),
}


class CucChatCompatibilityBaseline(DomainModel):
    """Frozen evidence contract for preserving the admitted CUC probe path."""

    baseline_id: Digest
    baseline_version: Literal["cuc-chat-compatibility-v1"]
    pong_codec_id: Digest
    structured_codec_id: Digest
    pong_implementation_digest: Digest
    structured_implementation_digest: Digest
    pong_request_digest: Digest
    structured_request_digest: Digest
    pong_completion_summary_digest: Digest
    request_model: Literal["cuc/deepseek"]
    accepted_response_models: tuple[str, str]
    accepted_pong_classifications: tuple[str, str, str]
    failure_semantics: tuple[str, str, str, str, str]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        values = self.model_dump(mode="python", exclude={"baseline_id"})
        if values != _CUC_CHAT_COMPATIBILITY_V1:
            raise ValueError("CUC Chat compatibility baseline content drifted")
        if self.baseline_id != canonical_digest(values):
            raise ValueError("CUC Chat compatibility baseline digest mismatch")
        return self

    @classmethod
    def create(cls) -> CucChatCompatibilityBaseline:
        return cls(
            baseline_id=canonical_digest(_CUC_CHAT_COMPATIBILITY_V1),
            **_CUC_CHAT_COMPATIBILITY_V1,
        )

    def assert_current(self) -> None:
        """Fail closed if the legacy path changed without a reviewed new baseline."""
        current = {
            "pong_codec_id": CucChatProbeCodecRegistration.create().codec_id,
            "structured_codec_id": CucChatStructuredProbeCodecRegistration.create().codec_id,
            "pong_implementation_digest": CUC_PROBE_CODEC_DIGEST,
            "structured_implementation_digest": CUC_STRUCTURED_CODEC_DIGEST,
            "pong_request_digest": canonical_digest(CUC_PROBE_TEXT),
            "structured_request_digest": canonical_digest(CUC_STRUCTURED_PROBE_TEXT),
            "pong_completion_summary_digest": PROBE_SUMMARY,
            "request_model": CucChatProbeCodecRegistration.create().request_model,
            "accepted_response_models": CUC_RESPONSE_MODELS,
        }
        expected = {
            name: getattr(self, name)
            for name in current
        }
        if current != expected:
            raise CucChatCompatibilityDrift(
                "admitted CUC Chat probe path drifted from its compatibility baseline"
            )
