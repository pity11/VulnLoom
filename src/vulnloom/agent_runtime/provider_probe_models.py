"""Fixed-content, tool-free provider connectivity probe contracts."""

from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.adapters.model_credentials import ModelCredentialReference
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import WorkerRole
from vulnloom.runners.models import Digest

from .models import AgentAdapterKind, AgentModelRegistration
from .provider_codec import AgentProviderCodecRegistration
from .provider_diagnostics import ProviderDiagnostic
from .provider_probe_cuc import (
    CucChatProbeCodecRegistration,
    CucChatStructuredProbeCodecRegistration,
)
from .provider_probe_fixture import (
    CUC_PROBE_DIGEST,
    CUC_STRUCTURED_PROBE_DIGEST,
    PROBE_DIGEST,
    PROBE_SUMMARY,
    PROBE_TEXT,
)
from .provider_process import SUBPROCESS_HTTPS_ADAPTER_DIGEST
from .transport import AgentProviderTransportAdmission, AgentProviderTransportMode

__all__ = [
    "PROBE_DIGEST",
    "PROBE_SUMMARY",
    "PROBE_TEXT",
    "ProviderProbeConfig",
    "ProviderProbePlan",
    "ProviderProbeResult",
]


class ProviderProbeConfig(DomainModel):
    registration: AgentModelRegistration
    admission: AgentProviderTransportAdmission
    credential_reference: ModelCredentialReference
    codec: (
        AgentProviderCodecRegistration
        | CucChatStructuredProbeCodecRegistration
        | CucChatProbeCodecRegistration
    )

    @model_validator(mode="after")
    def bounded_live_binding(self) -> Self:
        r, a = self.registration, self.admission
        if (
            r.adapter_kind is not AgentAdapterKind.SUBPROCESS_HTTPS_PROVIDER
            or a.mode is not AgentProviderTransportMode.LIVE_HTTPS
            or r.adapter_digest != SUBPROCESS_HTTPS_ADAPTER_DIGEST
            or a.adapter_digest != SUBPROCESS_HTTPS_ADAPTER_DIGEST
            or r.transport_admission_id != a.admission_id
            or r.credential_reference_id != self.credential_reference.reference_id
            or a.credential_reference_id != self.credential_reference.reference_id
            or r.provider_id != a.provider_id
            or r.provider_id != self.codec.provider_id
            or r.provider_codec_id != self.codec.codec_id
            or a.request_path != self.codec.request_path
            or r.supported_roles != (WorkerRole.REPORTER,)
            or r.max_output_tokens > 512
            or a.limits.max_request_bytes > 32768
            or a.limits.max_response_bytes > 32768
            or self.codec.limits.timeout_seconds > 2
            or a.limits.timeout_seconds > 20
            or a.limits.max_requests_per_minute != 1
        ):
            raise ValueError("provider probe config is not a bounded live binding")
        if isinstance(self.codec, CucChatProbeCodecRegistration) and (
            r.model != "cuc/deepseek"
            or a.hostname != "openai.cuc.edu.cn"
            or self.credential_reference.environment_variable != "CUC_DEEPSEEK_API_KEY"
        ):
            raise ValueError("CUC probe endpoint, model or credential reference drifted")
        return self


class ProviderProbePlan(DomainModel):
    plan_id: Digest
    config_digest: Digest
    grant_id: Digest
    fixture_digest: Literal[
        PROBE_DIGEST, CUC_PROBE_DIGEST, CUC_STRUCTURED_PROBE_DIGEST
    ] = PROBE_DIGEST
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not 0 < (self.deadline - self.created_at).total_seconds() <= 300:
            raise ValueError("provider probe window invalid")
        if "\x00" in self.idempotency_key or self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("provider probe plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault("fixture_digest", PROBE_DIGEST)
        return cls(plan_id=canonical_digest(values), **values)


class ProviderProbeResult(DomainModel):
    result_id: Digest
    plan_id: Digest
    status: Literal["passed", "rejected", "timed_out"]
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0, le=512)
    process_started: bool
    cleanup_verified: bool
    attempt_digest: Digest | None
    receipt_digest: Digest | None
    completed_at: AwareDatetime
    diagnostic: ProviderDiagnostic | None = None
    response_model: Literal["deepseek-v4-flash", "deepseek-v4-flash-0731"] | None = None

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.status == "passed" and not (
            self.process_started
            and self.cleanup_verified
            and self.attempt_digest
            and self.receipt_digest
        ):
            raise ValueError("successful probe requires transport and cleanup proof")
        values = self.model_dump(mode="python", exclude={"result_id"})
        if self.diagnostic is not None and self.status == 'passed' and (
            self.diagnostic.error_code is not None or self.diagnostic.http_status != 200
        ):
            raise ValueError('passed probe cannot contain failure diagnostic')
        if self.diagnostic is None:
            values.pop('diagnostic')  # Preserve legacy result identities.
        if self.response_model is None:
            values.pop("response_model")  # Preserve M9.15 result identities.
        if self.result_id != canonical_digest(values):
            raise ValueError("provider probe result digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        if isinstance(values.get("diagnostic"), ProviderDiagnostic):
            values["diagnostic"] = values["diagnostic"].model_dump(mode="python")
        if values.get("diagnostic") is None:
            values.pop("diagnostic", None)
        if values.get("response_model") is None:
            values.pop("response_model", None)
        return cls(result_id=canonical_digest(values), **values)
