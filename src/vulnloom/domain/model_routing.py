"""Pure multi-provider lifecycle, routing, and Flow snapshot contracts.

These models contain only content digests and non-secret metadata. Provider
endpoints and credentials remain Control Plane concerns and never cross this
domain boundary as raw values.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .digests import canonical_digest
from .models import DomainModel

ContentDigest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ProviderId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
ProviderModelId = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
]


class ProviderProtocol(StrEnum):
    OPENAI_RESPONSES = "openai_responses"
    OPENAI_CHAT_COMPLETIONS = "openai_chat_completions"
    ANTHROPIC_MESSAGES = "anthropic_messages"
    GEMINI_GENERATE_CONTENT = "gemini_generate_content"
    LOCAL_OPENAI_COMPATIBLE = "local_openai_compatible"


class ProviderLifecycleState(StrEnum):
    DRAFT = "draft"
    SECRET_BOUND = "secret_bound"
    CONNECTIVITY_VERIFIED = "connectivity_verified"
    CATALOG_DISCOVERED = "catalog_discovered"
    CAPABILITIES_PROBED = "capabilities_probed"
    ROLE_ADMITTED = "role_admitted"
    DEGRADED = "degraded"
    DISABLED = "disabled"
    REVOKED = "revoked"


class ModelCapability(StrEnum):
    CHAT = "chat"
    STRICT_STRUCTURED_OUTPUT = "strict_structured_output"
    TOOL_PROPOSAL = "tool_proposal"
    STREAMING = "streaming"
    REASONING = "reasoning"
    IMAGE_INPUT = "image_input"
    USAGE_ACCOUNTING = "usage_accounting"
    CANCELLATION = "cancellation"


class CapabilityStatus(StrEnum):
    UNKNOWN = "unknown"
    DECLARED = "declared"
    PROBED = "probed"
    FAILED = "failed"


class ContextDataClass(StrEnum):
    SYNTHETIC = "synthetic"
    PUBLIC_TARGET_METADATA = "public_target_metadata"
    SOURCE_CODE = "source_code"
    REDACTED_EVIDENCE = "redacted_evidence"


class ModelEngine(StrEnum):
    SOURCE_HUNT = "source_hunt"
    AUTHORIZED_RED_TEAM = "authorized_red_team"
    HYBRID = "hybrid"


class ModelAgentRole(StrEnum):
    PLANNER = "planner"
    RECON = "recon"
    EXTRACTOR = "extractor"
    SOURCE = "source"
    WEB = "web"
    VALIDATOR = "validator"
    CRITIC = "critic"
    REPORTER = "reporter"


class FallbackTrigger(StrEnum):
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    EMPTY_RESPONSE = "empty_response"


def _sorted_unique[T: StrEnum](values: Iterable[T], *, name: str) -> tuple[T, ...]:
    result = tuple(sorted(set(values), key=lambda item: item.value))
    if not result:
        raise ValueError(f"{name} must be non-empty")
    return result


def _digest_projection(value: object) -> object:
    if isinstance(value, DomainModel):
        return _digest_projection(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _digest_projection(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_digest_projection(item) for item in value]
    return value


def _domain_digest(value: object) -> str:
    return canonical_digest(_digest_projection(value))


class ProviderProfile(DomainModel):
    profile_digest: ContentDigest
    lifecycle_digest: ContentDigest
    provider_id: ProviderId
    revision: int = Field(ge=1)
    lifecycle_sequence: int = Field(ge=1)
    lifecycle_evidence_digest: ContentDigest | None = None
    display_name: str = Field(min_length=1, max_length=128)
    protocol: ProviderProtocol
    protocol_adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    endpoint_reference_id: ContentDigest
    credential_reference_id: ContentDigest
    data_policy_id: ContentDigest
    allowed_context_data_classes: Annotated[tuple[ContextDataClass, ...], Field(min_length=1)]
    state: ProviderLifecycleState = ProviderLifecycleState.DRAFT

    @model_validator(mode="after")
    def sealed_and_normalized(self) -> Self:
        expected_classes = _sorted_unique(
            self.allowed_context_data_classes, name="provider data classes"
        )
        if self.allowed_context_data_classes != expected_classes:
            raise ValueError("provider data classes must be unique and sorted")
        if self.profile_digest != provider_profile_digest(self):
            raise ValueError("Provider Profile content digest mismatch")
        if self.lifecycle_sequence == 1:
            if (
                self.state is not ProviderLifecycleState.DRAFT
                or self.lifecycle_evidence_digest is not None
            ):
                raise ValueError("initial Provider lifecycle must be an unevidenced draft")
        elif self.lifecycle_evidence_digest is None:
            raise ValueError("Provider lifecycle transition requires evidence")
        if self.lifecycle_digest != provider_lifecycle_digest(self):
            raise ValueError("Provider lifecycle content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        display_name: str,
        protocol: ProviderProtocol,
        protocol_adapter_id: str,
        endpoint_reference_id: str,
        credential_reference_id: str,
        data_policy_id: str,
        allowed_context_data_classes: tuple[ContextDataClass, ...],
    ) -> ProviderProfile:
        values = {
            "provider_id": provider_id,
            "revision": 1,
            "lifecycle_sequence": 1,
            "lifecycle_evidence_digest": None,
            "display_name": display_name,
            "protocol": protocol,
            "protocol_adapter_id": protocol_adapter_id,
            "endpoint_reference_id": endpoint_reference_id,
            "credential_reference_id": credential_reference_id,
            "data_policy_id": data_policy_id,
            "allowed_context_data_classes": _sorted_unique(
                allowed_context_data_classes, name="provider data classes"
            ),
            "state": ProviderLifecycleState.DRAFT,
        }
        profile_digest = canonical_digest(
            {
                key: value
                for key, value in values.items()
                if key
                not in {"lifecycle_sequence", "lifecycle_evidence_digest", "state"}
            }
        )
        lifecycle_digest = canonical_digest(
            {
                "profile_digest": profile_digest,
                "state": ProviderLifecycleState.DRAFT,
                "lifecycle_sequence": 1,
                "lifecycle_evidence_digest": None,
            }
        )
        return cls(
            profile_digest=profile_digest,
            lifecycle_digest=lifecycle_digest,
            **values,
        )


def provider_profile_digest(profile: ProviderProfile) -> str:
    return canonical_digest(
        profile.model_dump(
            mode="python",
            exclude={
                "profile_digest",
                "lifecycle_digest",
                "lifecycle_sequence",
                "lifecycle_evidence_digest",
                "state",
            },
        )
    )


def provider_lifecycle_digest(profile: ProviderProfile) -> str:
    return canonical_digest(
        {
            "profile_digest": profile.profile_digest,
            "state": profile.state,
            "lifecycle_sequence": profile.lifecycle_sequence,
            "lifecycle_evidence_digest": profile.lifecycle_evidence_digest,
        }
    )


class ProviderTransitionRejected(ValueError):
    """A Provider Profile lifecycle transition violated the closed state graph."""


_PROVIDER_TRANSITIONS: dict[ProviderLifecycleState, frozenset[ProviderLifecycleState]] = {
    ProviderLifecycleState.DRAFT: frozenset(
        {ProviderLifecycleState.SECRET_BOUND, ProviderLifecycleState.DISABLED}
    ),
    ProviderLifecycleState.SECRET_BOUND: frozenset(
        {
            ProviderLifecycleState.CONNECTIVITY_VERIFIED,
            ProviderLifecycleState.DISABLED,
            ProviderLifecycleState.REVOKED,
        }
    ),
    ProviderLifecycleState.CONNECTIVITY_VERIFIED: frozenset(
        {
            ProviderLifecycleState.CATALOG_DISCOVERED,
            ProviderLifecycleState.DEGRADED,
            ProviderLifecycleState.DISABLED,
            ProviderLifecycleState.REVOKED,
        }
    ),
    ProviderLifecycleState.CATALOG_DISCOVERED: frozenset(
        {
            ProviderLifecycleState.CAPABILITIES_PROBED,
            ProviderLifecycleState.DEGRADED,
            ProviderLifecycleState.DISABLED,
            ProviderLifecycleState.REVOKED,
        }
    ),
    ProviderLifecycleState.CAPABILITIES_PROBED: frozenset(
        {
            ProviderLifecycleState.ROLE_ADMITTED,
            ProviderLifecycleState.DEGRADED,
            ProviderLifecycleState.DISABLED,
            ProviderLifecycleState.REVOKED,
        }
    ),
    ProviderLifecycleState.ROLE_ADMITTED: frozenset(
        {
            ProviderLifecycleState.DEGRADED,
            ProviderLifecycleState.DISABLED,
            ProviderLifecycleState.REVOKED,
        }
    ),
    ProviderLifecycleState.DEGRADED: frozenset(
        {
            ProviderLifecycleState.CONNECTIVITY_VERIFIED,
            ProviderLifecycleState.DISABLED,
            ProviderLifecycleState.REVOKED,
        }
    ),
    ProviderLifecycleState.DISABLED: frozenset(
        {ProviderLifecycleState.DRAFT, ProviderLifecycleState.REVOKED}
    ),
}


def transition_provider_profile(
    profile: ProviderProfile,
    target: ProviderLifecycleState,
    *,
    evidence_digest: str,
) -> ProviderProfile:
    if target not in _PROVIDER_TRANSITIONS.get(profile.state, frozenset()):
        raise ProviderTransitionRejected(
            f"illegal Provider Profile transition: {profile.state} -> {target}"
        )
    if len(evidence_digest) != 64 or any(
        character not in "0123456789abcdef" for character in evidence_digest
    ):
        raise ProviderTransitionRejected("Provider lifecycle evidence must be a content digest")
    values = profile.model_dump(
        mode="python", exclude={"profile_digest", "lifecycle_digest"}
    )
    values.update(
        {
            "lifecycle_sequence": profile.lifecycle_sequence + 1,
            "lifecycle_evidence_digest": evidence_digest,
            "state": target,
        }
    )
    lifecycle_digest = canonical_digest(
        {
            "profile_digest": profile.profile_digest,
            "state": target,
            "lifecycle_sequence": values["lifecycle_sequence"],
            "lifecycle_evidence_digest": evidence_digest,
        }
    )
    return ProviderProfile(
        profile_digest=profile.profile_digest,
        lifecycle_digest=lifecycle_digest,
        **values,
    )


class ModelCapabilityAssessment(DomainModel):
    capability: ModelCapability
    status: CapabilityStatus
    probe_result_digest: ContentDigest | None = None

    @model_validator(mode="after")
    def evidence_matches_status(self) -> Self:
        if self.status in {CapabilityStatus.PROBED, CapabilityStatus.FAILED}:
            if self.probe_result_digest is None:
                raise ValueError("probed or failed capability requires a probe result")
        elif self.probe_result_digest is not None:
            raise ValueError("unprobed capability cannot bind a probe result")
        return self


class CapabilityManifest(DomainModel):
    manifest_digest: ContentDigest
    provider_profile_digest: ContentDigest
    provider_model_id: ProviderModelId
    protocol_adapter_digest: ContentDigest
    assessments: Annotated[tuple[ModelCapabilityAssessment, ...], Field(min_length=1)]
    max_context_tokens: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    observed_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def sealed_and_normalized(self) -> Self:
        expected = tuple(sorted(self.assessments, key=lambda item: item.capability.value))
        capabilities = tuple(item.capability for item in expected)
        if self.assessments != expected or len(set(capabilities)) != len(capabilities):
            raise ValueError("capability assessments must be unique and sorted")
        was_probed = any(
            item.status in {CapabilityStatus.PROBED, CapabilityStatus.FAILED}
            for item in self.assessments
        )
        if was_probed != (self.observed_at is not None):
            raise ValueError("capability probe timestamp does not match assessment status")
        if self.manifest_digest != capability_manifest_digest(self):
            raise ValueError("Capability Manifest content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        provider_profile_digest: str,
        provider_model_id: str,
        protocol_adapter_digest: str,
        assessments: tuple[ModelCapabilityAssessment, ...],
        max_context_tokens: int | None = None,
        max_output_tokens: int | None = None,
        observed_at: datetime | None = None,
    ) -> CapabilityManifest:
        ordered = tuple(sorted(assessments, key=lambda item: item.capability.value))
        values = {
            "provider_profile_digest": provider_profile_digest,
            "provider_model_id": provider_model_id,
            "protocol_adapter_digest": protocol_adapter_digest,
            "assessments": ordered,
            "max_context_tokens": max_context_tokens,
            "max_output_tokens": max_output_tokens,
            "observed_at": observed_at,
        }
        return cls(manifest_digest=_domain_digest(values), **values)


def capability_manifest_digest(manifest: CapabilityManifest) -> str:
    return canonical_digest(manifest.model_dump(mode="python", exclude={"manifest_digest"}))


class ModelReference(DomainModel):
    provider_profile_digest: ContentDigest
    capability_manifest_digest: ContentDigest
    provider_model_id: ProviderModelId


class ModelBudgetProfile(DomainModel):
    max_total_tokens: int = Field(gt=0)
    max_output_tokens_per_turn: int = Field(gt=0)
    max_provider_attempts: int = Field(default=1, ge=1, le=8)
    timeout_seconds_per_attempt: float = Field(gt=0, le=600)
    max_cost_microunits: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def output_fits_total(self) -> Self:
        if self.max_output_tokens_per_turn > self.max_total_tokens:
            raise ValueError("per-turn output tokens exceed the total model budget")
        return self


class FallbackPolicy(DomainModel):
    policy_digest: ContentDigest
    ordered_models: Annotated[tuple[ModelReference, ...], Field(max_length=4)] = ()
    triggers: Annotated[tuple[FallbackTrigger, ...], Field(max_length=4)] = ()
    max_fallback_attempts: int = Field(default=0, ge=0, le=4)
    allow_cross_provider: bool = False
    require_operator_approval: bool = False
    only_before_effect_commit: Literal[True] = True

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        trigger_order = tuple(sorted(set(self.triggers), key=lambda item: item.value))
        if self.triggers != trigger_order:
            raise ValueError("fallback triggers must be unique and sorted")
        if len(set(self.ordered_models)) != len(self.ordered_models):
            raise ValueError("fallback models must be unique")
        if self.max_fallback_attempts > len(self.ordered_models):
            raise ValueError("fallback attempts exceed the ordered model list")
        if bool(self.ordered_models) != bool(self.triggers):
            raise ValueError("fallback models and triggers must be configured together")
        if bool(self.ordered_models) != (self.max_fallback_attempts > 0):
            raise ValueError("fallback attempt budget does not match configured models")
        if self.policy_digest != fallback_policy_digest(self):
            raise ValueError("Fallback Policy content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        ordered_models: tuple[ModelReference, ...] = (),
        triggers: tuple[FallbackTrigger, ...] = (),
        max_fallback_attempts: int = 0,
        allow_cross_provider: bool = False,
        require_operator_approval: bool = False,
    ) -> FallbackPolicy:
        values = {
            "ordered_models": ordered_models,
            "triggers": tuple(sorted(set(triggers), key=lambda item: item.value)),
            "max_fallback_attempts": max_fallback_attempts,
            "allow_cross_provider": allow_cross_provider,
            "require_operator_approval": require_operator_approval,
            "only_before_effect_commit": True,
        }
        return cls(policy_digest=_domain_digest(values), **values)


def fallback_policy_digest(policy: FallbackPolicy) -> str:
    return canonical_digest(policy.model_dump(mode="python", exclude={"policy_digest"}))


class ModelRoute(DomainModel):
    route_digest: ContentDigest
    engine: ModelEngine
    agent_role: ModelAgentRole
    primary_model: ModelReference
    fallback_policy_digest: ContentDigest
    required_capabilities: Annotated[tuple[ModelCapability, ...], Field(min_length=1)]
    required_context_data_classes: Annotated[
        tuple[ContextDataClass, ...], Field(min_length=1)
    ]
    budget: ModelBudgetProfile

    @model_validator(mode="after")
    def sealed_and_normalized(self) -> Self:
        expected_capabilities = _sorted_unique(
            self.required_capabilities, name="route capabilities"
        )
        expected_data_classes = _sorted_unique(
            self.required_context_data_classes, name="route data classes"
        )
        if self.required_capabilities != expected_capabilities:
            raise ValueError("route capabilities must be unique and sorted")
        if self.required_context_data_classes != expected_data_classes:
            raise ValueError("route data classes must be unique and sorted")
        if self.route_digest != model_route_digest(self):
            raise ValueError("Model Route content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        engine: ModelEngine,
        agent_role: ModelAgentRole,
        primary_model: ModelReference,
        fallback_policy: FallbackPolicy,
        required_capabilities: tuple[ModelCapability, ...],
        required_context_data_classes: tuple[ContextDataClass, ...],
        budget: ModelBudgetProfile,
    ) -> ModelRoute:
        values = {
            "engine": engine,
            "agent_role": agent_role,
            "primary_model": primary_model,
            "fallback_policy_digest": fallback_policy.policy_digest,
            "required_capabilities": _sorted_unique(
                required_capabilities, name="route capabilities"
            ),
            "required_context_data_classes": _sorted_unique(
                required_context_data_classes, name="route data classes"
            ),
            "budget": budget,
        }
        return cls(route_digest=_domain_digest(values), **values)


def model_route_digest(route: ModelRoute) -> str:
    return canonical_digest(route.model_dump(mode="python", exclude={"route_digest"}))


class FlowRoleModelBinding(DomainModel):
    engine: ModelEngine
    agent_role: ModelAgentRole
    route_digest: ContentDigest
    selected_model: ModelReference
    fallback_policy_digest: ContentDigest
    provider_lifecycle_digest: ContentDigest
    provider_data_policy_id: ContentDigest
    protocol_adapter_digest: ContentDigest
    budget: ModelBudgetProfile


class FlowModelSnapshot(DomainModel):
    snapshot_digest: ContentDigest
    flow_id: UUID
    routing_policy_digest: ContentDigest
    prompt_contract_digest: ContentDigest
    tool_schema_digest: ContentDigest
    bindings: Annotated[tuple[FlowRoleModelBinding, ...], Field(min_length=1)]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_and_normalized(self) -> Self:
        expected = tuple(
            sorted(self.bindings, key=lambda item: (item.engine.value, item.agent_role.value))
        )
        keys = tuple((item.engine, item.agent_role) for item in expected)
        if self.bindings != expected or len(set(keys)) != len(keys):
            raise ValueError("Flow model bindings must be unique and sorted")
        if self.snapshot_digest != flow_model_snapshot_digest(self):
            raise ValueError("Flow Model Snapshot content digest mismatch")
        return self


def flow_model_snapshot_digest(snapshot: FlowModelSnapshot) -> str:
    return canonical_digest(snapshot.model_dump(mode="python", exclude={"snapshot_digest"}))


class ModelRouteRejected(ValueError):
    """A route cannot be admitted against the exact Provider capability state."""


def build_flow_model_snapshot(
    *,
    flow_id: UUID,
    routes: tuple[ModelRoute, ...],
    profiles: Mapping[str, ProviderProfile],
    manifests: Mapping[str, CapabilityManifest],
    fallback_policies: Mapping[str, FallbackPolicy],
    routing_policy_digest: str,
    prompt_contract_digest: str,
    tool_schema_digest: str,
    created_at: datetime,
) -> FlowModelSnapshot:
    if not routes:
        raise ModelRouteRejected("Flow requires at least one model route")
    ordered_routes = tuple(
        sorted(routes, key=lambda item: (item.engine.value, item.agent_role.value))
    )
    route_keys = tuple((item.engine, item.agent_role) for item in ordered_routes)
    if len(set(route_keys)) != len(route_keys):
        raise ModelRouteRejected("Flow model routes must be unique per Engine and role")

    bindings = tuple(
        _admit_route(
            route,
            profiles=profiles,
            manifests=manifests,
            fallback_policies=fallback_policies,
        )
        for route in ordered_routes
    )
    values = {
        "flow_id": flow_id,
        "routing_policy_digest": routing_policy_digest,
        "prompt_contract_digest": prompt_contract_digest,
        "tool_schema_digest": tool_schema_digest,
        "bindings": bindings,
        "created_at": created_at,
    }
    return FlowModelSnapshot(snapshot_digest=_domain_digest(values), **values)


def _admit_route(
    route: ModelRoute,
    *,
    profiles: Mapping[str, ProviderProfile],
    manifests: Mapping[str, CapabilityManifest],
    fallback_policies: Mapping[str, FallbackPolicy],
) -> FlowRoleModelBinding:
    policy = fallback_policies.get(route.fallback_policy_digest)
    if policy is None or fallback_policy_digest(policy) != route.fallback_policy_digest:
        raise ModelRouteRejected("route Fallback Policy is missing or invalid")
    primary_profile, primary_manifest = _admit_model_reference(
        route.primary_model,
        required_capabilities=route.required_capabilities,
        required_data_classes=route.required_context_data_classes,
        profiles=profiles,
        manifests=manifests,
    )
    if route.primary_model in policy.ordered_models:
        raise ModelRouteRejected("primary model cannot also be a fallback")
    if route.budget.max_provider_attempts < 1 + policy.max_fallback_attempts:
        raise ModelRouteRejected("route attempt budget cannot cover its Fallback Policy")

    for fallback in policy.ordered_models:
        fallback_profile, _ = _admit_model_reference(
            fallback,
            required_capabilities=route.required_capabilities,
            required_data_classes=route.required_context_data_classes,
            profiles=profiles,
            manifests=manifests,
        )
        if (
            not policy.allow_cross_provider
            and fallback_profile.provider_id != primary_profile.provider_id
        ):
            raise ModelRouteRejected("Fallback Policy forbids cross-provider routing")

    return FlowRoleModelBinding(
        engine=route.engine,
        agent_role=route.agent_role,
        route_digest=route.route_digest,
        selected_model=route.primary_model,
        fallback_policy_digest=policy.policy_digest,
        provider_lifecycle_digest=primary_profile.lifecycle_digest,
        provider_data_policy_id=primary_profile.data_policy_id,
        protocol_adapter_digest=primary_manifest.protocol_adapter_digest,
        budget=route.budget,
    )


def _admit_model_reference(
    reference: ModelReference,
    *,
    required_capabilities: tuple[ModelCapability, ...],
    required_data_classes: tuple[ContextDataClass, ...],
    profiles: Mapping[str, ProviderProfile],
    manifests: Mapping[str, CapabilityManifest],
) -> tuple[ProviderProfile, CapabilityManifest]:
    profile = profiles.get(reference.provider_profile_digest)
    if profile is None or provider_profile_digest(profile) != reference.provider_profile_digest:
        raise ModelRouteRejected("model Provider Profile is missing or invalid")
    if profile.state is not ProviderLifecycleState.ROLE_ADMITTED:
        raise ModelRouteRejected("model Provider Profile is not role-admitted")
    if not set(required_data_classes) <= set(profile.allowed_context_data_classes):
        raise ModelRouteRejected("model Provider Profile rejects required context data")

    manifest = manifests.get(reference.capability_manifest_digest)
    if (
        manifest is None
        or capability_manifest_digest(manifest) != reference.capability_manifest_digest
    ):
        raise ModelRouteRejected("model Capability Manifest is missing or invalid")
    if (
        manifest.provider_profile_digest != profile.profile_digest
        or manifest.provider_model_id != reference.provider_model_id
    ):
        raise ModelRouteRejected("model reference does not match its capability manifest")
    probed = {
        item.capability
        for item in manifest.assessments
        if item.status is CapabilityStatus.PROBED
    }
    missing = set(required_capabilities) - probed
    if missing:
        names = ", ".join(sorted(item.value for item in missing))
        raise ModelRouteRejected(f"model lacks probed capabilities: {names}")
    return profile, manifest
