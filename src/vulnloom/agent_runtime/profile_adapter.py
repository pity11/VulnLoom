"""Trusted two-stage assembly for an OpenAI-compatible Provider Profile."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from time import monotonic
from typing import Protocol, Self

from pydantic import AwareDatetime, model_validator

from vulnloom.adapters import (
    ModelCredentialProvider,
    ModelCredentialReference,
    ModelEndpointProvider,
    ModelEndpointReference,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.model_routing import (
    CapabilityManifest,
    CapabilityStatus,
    FlowModelSnapshot,
    ModelAgentRole,
    ModelCapability,
    ModelEngine,
    ProviderLifecycleState,
    ProviderProfile,
    ProviderProtocol,
)
from vulnloom.domain.models import DomainModel, utc_now
from vulnloom.domain.protocol import WorkerRole
from vulnloom.runners.models import Digest

from .live_provider import (
    ProviderProcessRunner,
    ProviderResolver,
    SubprocessHttpsProviderAdapter,
)
from .models import AgentModelRegistration
from .openai_chat import (
    OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST,
    OpenAIChatCompletionsCodecRegistration,
    OpenAIChatCompletionsFeatureGate,
    OpenAIChatCompletionsV1Codec,
)
from .provider_admission import (
    AgentProviderEgressGrant,
    AgentProviderEgressPurpose,
    AgentProviderEgressStore,
)
from .provider_codec import AgentProviderCodecLimits
from .provider_process import SUBPROCESS_HTTPS_ADAPTER_DIGEST
from .transport import (
    AgentProviderTransportAdmission,
    AgentProviderTransportLimits,
)

OPENAI_CHAT_PROFILE_ADAPTER_ID = "openai-chat-completions-v1"

_WORKER_ROLE_BY_MODEL_ROLE = {
    ModelAgentRole.PLANNER: WorkerRole.SCOPE_INTERPRETER,
    ModelAgentRole.RECON: WorkerRole.HYPOTHESIS,
    ModelAgentRole.EXTRACTOR: WorkerRole.SOURCE_MAPPER,
    ModelAgentRole.SOURCE: WorkerRole.ANALYZER,
    ModelAgentRole.WEB: WorkerRole.HYPOTHESIS,
    ModelAgentRole.VALIDATOR: WorkerRole.VALIDATOR,
    ModelAgentRole.CRITIC: WorkerRole.CRITIC,
    ModelAgentRole.REPORTER: WorkerRole.REPORTER,
}


class OpenAIChatProfileAssemblyRejected(ValueError):
    pass


class ProviderEgressVerifier(Protocol):
    def require_active(
        self,
        grant_id: str,
        *,
        admission: AgentProviderTransportAdmission,
        now: datetime,
    ) -> AgentProviderEgressGrant: ...


class OpenAIChatTaskCodecRegistration(Protocol):
    codec_id: str
    provider_id: str
    request_path: str
    request_model: str
    limits: AgentProviderCodecLimits


class OpenAIChatProfilePreparation(DomainModel):
    preparation_id: Digest
    flow_snapshot_digest: Digest
    provider_profile_digest: Digest
    provider_lifecycle_digest: Digest
    capability_manifest_digest: Digest
    endpoint_reference_id: Digest
    credential_reference_id: Digest
    engine: ModelEngine
    agent_role: ModelAgentRole
    worker_role: WorkerRole
    transport_admission: AgentProviderTransportAdmission
    codec_registration: OpenAIChatCompletionsCodecRegistration
    max_output_tokens: int
    prepared_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.transport_admission.provider_id != self.codec_registration.provider_id
            or self.transport_admission.request_path != self.codec_registration.request_path
            or self.transport_admission.credential_reference_id
            != self.credential_reference_id
            or self.max_output_tokens <= 0
            or self.max_output_tokens > 65_536
        ):
            raise ValueError("OpenAI Chat Profile preparation binding mismatch")
        if self.preparation_id != canonical_digest(
            self.model_dump(mode="python", exclude={"preparation_id"})
        ):
            raise ValueError("OpenAI Chat Profile preparation digest mismatch")
        return self


@dataclass(frozen=True)
class OpenAIChatRuntimeBinding:
    preparation: OpenAIChatProfilePreparation
    model_registration: AgentModelRegistration
    codec: OpenAIChatCompletionsV1Codec


def prepare_openai_chat_profile(
    *,
    profile: ProviderProfile,
    manifest: CapabilityManifest,
    flow_snapshot: FlowModelSnapshot,
    engine: ModelEngine,
    agent_role: ModelAgentRole,
    worker_role: WorkerRole,
    endpoint_reference: ModelEndpointReference,
    credential_reference: ModelCredentialReference,
    endpoint_provider: ModelEndpointProvider,
    transport_limits: AgentProviderTransportLimits,
    codec_limits: AgentProviderCodecLimits,
    accepted_response_models: tuple[str, ...] | None = None,
    allowed_empty_root_fields: tuple[str, ...] = (),
    allowed_empty_choice_fields: tuple[str, ...] = (),
    allowed_empty_message_fields: tuple[str, ...] = (),
    reviewed_usage_extensions_allowed: bool = False,
    now: datetime,
    deadline: datetime,
) -> OpenAIChatProfilePreparation:
    if now >= deadline:
        raise OpenAIChatProfileAssemblyRejected("Profile preparation deadline expired")
    if _WORKER_ROLE_BY_MODEL_ROLE[agent_role] is not worker_role:
        raise OpenAIChatProfileAssemblyRejected("model role and Worker role mismatch")
    _assert_profile_binding(
        profile=profile,
        manifest=manifest,
        flow_snapshot=flow_snapshot,
        engine=engine,
        agent_role=agent_role,
        endpoint_reference=endpoint_reference,
        credential_reference=credential_reference,
    )
    endpoint = endpoint_provider.resolve(endpoint_reference)
    request_path = "/v1/chat/completions"
    if not endpoint.admits(request_path):
        raise OpenAIChatProfileAssemblyRejected(
            "model endpoint base path does not admit the codec request path"
        )
    binding = _binding(flow_snapshot, engine, agent_role)
    if (
        codec_limits.timeout_seconds > transport_limits.timeout_seconds
        or codec_limits.max_structured_output_bytes
        > transport_limits.max_response_bytes
        or transport_limits.timeout_seconds > binding.budget.timeout_seconds_per_attempt
    ):
        raise OpenAIChatProfileAssemblyRejected(
            "codec or transport limits exceed the routed model budget"
        )
    codec_registration = OpenAIChatCompletionsCodecRegistration.create(
        provider_id=profile.provider_id,
        request_model=manifest.provider_model_id,
        accepted_response_models=accepted_response_models,
        limits=codec_limits,
        allowed_empty_root_fields=allowed_empty_root_fields,
        allowed_empty_choice_fields=allowed_empty_choice_fields,
        allowed_empty_message_fields=allowed_empty_message_fields,
        reviewed_usage_extensions_allowed=reviewed_usage_extensions_allowed,
    )
    admission = AgentProviderTransportAdmission.create_live_https(
        provider_id=profile.provider_id,
        hostname=endpoint.hostname,
        request_path=request_path,
        credential_reference_id=credential_reference.reference_id,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        limits=transport_limits,
    )
    max_output_tokens = min(
        manifest.max_output_tokens or 65_536,
        binding.budget.max_output_tokens_per_turn,
        65_536,
    )
    values = {
        "flow_snapshot_digest": flow_snapshot.snapshot_digest,
        "provider_profile_digest": profile.profile_digest,
        "provider_lifecycle_digest": profile.lifecycle_digest,
        "capability_manifest_digest": manifest.manifest_digest,
        "endpoint_reference_id": endpoint_reference.reference_id,
        "credential_reference_id": credential_reference.reference_id,
        "engine": engine,
        "agent_role": agent_role,
        "worker_role": worker_role,
        "transport_admission": admission,
        "codec_registration": codec_registration,
        "max_output_tokens": max_output_tokens,
        "prepared_at": now,
    }
    digest_values = {
        **values,
        "transport_admission": admission.model_dump(mode="python"),
        "codec_registration": codec_registration.model_dump(mode="python"),
    }
    return OpenAIChatProfilePreparation(
        preparation_id=canonical_digest(digest_values), **values
    )


def bind_openai_chat_profile(
    preparation: OpenAIChatProfilePreparation,
    *,
    current_profile: ProviderProfile,
    current_flow_snapshot: FlowModelSnapshot,
    grant_id: str,
    egress_verifier: ProviderEgressVerifier,
    feature_gate: OpenAIChatCompletionsFeatureGate,
    now: datetime,
    deadline: datetime,
) -> OpenAIChatRuntimeBinding:
    registration = bind_openai_chat_task_registration(
        preparation,
        task_codec_registration=preparation.codec_registration,
        current_profile=current_profile,
        current_flow_snapshot=current_flow_snapshot,
        grant_id=grant_id,
        egress_verifier=egress_verifier,
        worker_role=preparation.worker_role,
        max_output_tokens=preparation.max_output_tokens,
        now=now,
        deadline=deadline,
    )
    return OpenAIChatRuntimeBinding(
        preparation=preparation,
        model_registration=registration,
        codec=OpenAIChatCompletionsV1Codec(
            preparation.codec_registration,
            feature_gate=feature_gate,
        ),
    )


def bind_openai_chat_task_registration(
    preparation: OpenAIChatProfilePreparation,
    *,
    task_codec_registration: OpenAIChatTaskCodecRegistration,
    current_profile: ProviderProfile,
    current_flow_snapshot: FlowModelSnapshot,
    grant_id: str,
    egress_verifier: ProviderEgressVerifier,
    worker_role: WorkerRole,
    max_output_tokens: int,
    now: datetime,
    deadline: datetime,
) -> AgentModelRegistration:
    if now >= deadline:
        raise OpenAIChatProfileAssemblyRejected("Profile binding deadline expired")
    if (
        task_codec_registration.provider_id
        != preparation.codec_registration.provider_id
        or task_codec_registration.request_model
        != preparation.codec_registration.request_model
        or task_codec_registration.request_path
        != preparation.transport_admission.request_path
        or task_codec_registration.limits.timeout_seconds
        > preparation.transport_admission.limits.timeout_seconds
        or task_codec_registration.limits.max_structured_output_bytes
        > preparation.transport_admission.limits.max_response_bytes
        or worker_role is not preparation.worker_role
        or not 0 < max_output_tokens <= preparation.max_output_tokens
    ):
        raise OpenAIChatProfileAssemblyRejected("task codec Profile binding rejected")
    current_binding = _binding(
        current_flow_snapshot, preparation.engine, preparation.agent_role
    )
    if (
        current_profile.state is not ProviderLifecycleState.ROLE_ADMITTED
        or current_profile.profile_digest != preparation.provider_profile_digest
        or current_profile.lifecycle_digest != preparation.provider_lifecycle_digest
        or current_flow_snapshot.snapshot_digest != preparation.flow_snapshot_digest
        or current_binding.provider_lifecycle_digest
        != preparation.provider_lifecycle_digest
        or current_binding.selected_model.capability_manifest_digest
        != preparation.capability_manifest_digest
    ):
        raise OpenAIChatProfileAssemblyRejected(
            "current Provider Profile or Flow binding drifted"
        )
    grant = egress_verifier.require_active(
        grant_id,
        admission=preparation.transport_admission,
        now=now,
    )
    if grant.purpose is not AgentProviderEgressPurpose.MODEL_INFERENCE:
        raise OpenAIChatProfileAssemblyRejected("egress grant purpose is not model inference")
    registration = AgentModelRegistration.create_subprocess_https(
        provider_id=task_codec_registration.provider_id,
        model=task_codec_registration.request_model,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        credential_reference_id=preparation.credential_reference_id,
        transport_admission_id=preparation.transport_admission.admission_id,
        egress_grant_id=grant.grant_id,
        provider_codec_id=task_codec_registration.codec_id,
        supported_roles=(worker_role,),
        max_output_tokens=max_output_tokens,
    )
    return registration


def create_openai_chat_provider_adapter(
    binding: OpenAIChatRuntimeBinding,
    *,
    credential_reference: ModelCredentialReference,
    credential_provider: ModelCredentialProvider,
    egress_store: AgentProviderEgressStore,
    resolver: ProviderResolver,
    process_runner: ProviderProcessRunner,
    clock: Callable[[], float] = monotonic,
    now: Callable[[], datetime] = utc_now,
) -> SubprocessHttpsProviderAdapter:
    if credential_reference.reference_id != binding.preparation.credential_reference_id:
        raise OpenAIChatProfileAssemblyRejected(
            "runtime credential reference does not match the Profile preparation"
        )
    return SubprocessHttpsProviderAdapter(
        registration=binding.model_registration,
        admission=binding.preparation.transport_admission,
        credential_reference=credential_reference,
        credential_provider=credential_provider,
        egress_store=egress_store,
        provider_codec=binding.codec,
        resolver=resolver,
        process_runner=process_runner,
        clock=clock,
        now=now,
    )


def _assert_profile_binding(
    *,
    profile: ProviderProfile,
    manifest: CapabilityManifest,
    flow_snapshot: FlowModelSnapshot,
    engine: ModelEngine,
    agent_role: ModelAgentRole,
    endpoint_reference: ModelEndpointReference,
    credential_reference: ModelCredentialReference,
) -> None:
    if (
        profile.state is not ProviderLifecycleState.ROLE_ADMITTED
        or profile.protocol not in {
            ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
            ProviderProtocol.LOCAL_OPENAI_COMPATIBLE,
        }
        or profile.protocol_adapter_id != OPENAI_CHAT_PROFILE_ADAPTER_ID
        or profile.endpoint_reference_id != endpoint_reference.reference_id
        or profile.credential_reference_id != credential_reference.reference_id
    ):
        raise OpenAIChatProfileAssemblyRejected("Provider Profile binding rejected")
    if (
        manifest.provider_profile_digest != profile.profile_digest
        or manifest.protocol_adapter_digest
        != OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST
        or manifest.max_output_tokens is None
    ):
        raise OpenAIChatProfileAssemblyRejected("Capability Manifest binding rejected")
    probed = {
        item.capability
        for item in manifest.assessments
        if item.status is CapabilityStatus.PROBED
    }
    if not {
        ModelCapability.CHAT,
        ModelCapability.STRICT_STRUCTURED_OUTPUT,
        ModelCapability.USAGE_ACCOUNTING,
    } <= probed:
        raise OpenAIChatProfileAssemblyRejected(
            "OpenAI Chat Profile lacks required probed capabilities"
        )
    binding = _binding(flow_snapshot, engine, agent_role)
    if (
        binding.selected_model.provider_profile_digest != profile.profile_digest
        or binding.selected_model.capability_manifest_digest != manifest.manifest_digest
        or binding.selected_model.provider_model_id != manifest.provider_model_id
        or binding.provider_lifecycle_digest != profile.lifecycle_digest
        or binding.protocol_adapter_digest != manifest.protocol_adapter_digest
    ):
        raise OpenAIChatProfileAssemblyRejected("Flow model binding rejected")


def _binding(
    snapshot: FlowModelSnapshot, engine: ModelEngine, role: ModelAgentRole
):
    matches = tuple(
        item
        for item in snapshot.bindings
        if item.engine is engine and item.agent_role is role
    )
    if len(matches) != 1:
        raise OpenAIChatProfileAssemblyRejected("Flow model binding is unavailable")
    return matches[0]
