from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.model_routing import (
    CapabilityManifest,
    CapabilityStatus,
    ContextDataClass,
    FallbackPolicy,
    FallbackTrigger,
    FlowModelSnapshot,
    ModelAgentRole,
    ModelBudgetProfile,
    ModelCapability,
    ModelCapabilityAssessment,
    ModelEngine,
    ModelReference,
    ModelRoute,
    ModelRouteRejected,
    ProviderLifecycleState,
    ProviderProfile,
    ProviderProtocol,
    ProviderTransitionRejected,
    build_flow_model_snapshot,
    transition_provider_profile,
)


def _digest(label: str) -> str:
    return canonical_digest({"fixture": label})


def _profile(
    provider_id: str = "cuc",
    *,
    data_classes: tuple[ContextDataClass, ...] = (
        ContextDataClass.SYNTHETIC,
        ContextDataClass.SOURCE_CODE,
        ContextDataClass.REDACTED_EVIDENCE,
    ),
) -> ProviderProfile:
    profile = ProviderProfile.create(
        provider_id=provider_id,
        display_name=provider_id.upper(),
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        protocol_adapter_id="openai-chat-v1",
        endpoint_reference_id=_digest(f"{provider_id}:endpoint-ref"),
        credential_reference_id=_digest(f"{provider_id}:credential-ref"),
        data_policy_id=_digest(f"{provider_id}:data-policy"),
        allowed_context_data_classes=data_classes,
    )
    for state in (
        ProviderLifecycleState.SECRET_BOUND,
        ProviderLifecycleState.CONNECTIVITY_VERIFIED,
        ProviderLifecycleState.CATALOG_DISCOVERED,
        ProviderLifecycleState.CAPABILITIES_PROBED,
        ProviderLifecycleState.ROLE_ADMITTED,
    ):
        profile = transition_provider_profile(
            profile, state, evidence_digest=_digest(f"{provider_id}:{state.value}")
        )
    return profile


def _manifest(profile: ProviderProfile, model: str = "research-model") -> CapabilityManifest:
    now = datetime(2026, 9, 8, tzinfo=UTC)
    return CapabilityManifest.create(
        provider_profile_digest=profile.profile_digest,
        provider_model_id=model,
        protocol_adapter_digest=_digest("openai-chat-adapter-v1"),
        assessments=(
            ModelCapabilityAssessment(
                capability=ModelCapability.STRICT_STRUCTURED_OUTPUT,
                status=CapabilityStatus.PROBED,
                probe_result_digest=_digest(f"{profile.provider_id}:json-probe"),
            ),
            ModelCapabilityAssessment(
                capability=ModelCapability.CHAT,
                status=CapabilityStatus.PROBED,
                probe_result_digest=_digest(f"{profile.provider_id}:chat-probe"),
            ),
            ModelCapabilityAssessment(
                capability=ModelCapability.TOOL_PROPOSAL,
                status=CapabilityStatus.DECLARED,
            ),
        ),
        max_context_tokens=64_000,
        max_output_tokens=8_192,
        observed_at=now,
    )


def _reference(profile: ProviderProfile, manifest: CapabilityManifest) -> ModelReference:
    return ModelReference(
        provider_profile_digest=profile.profile_digest,
        capability_manifest_digest=manifest.manifest_digest,
        provider_model_id=manifest.provider_model_id,
    )


def _route(
    reference: ModelReference,
    fallback_policy: FallbackPolicy,
    *,
    data_classes: tuple[ContextDataClass, ...] = (ContextDataClass.SOURCE_CODE,),
) -> ModelRoute:
    return ModelRoute.create(
        engine=ModelEngine.SOURCE_HUNT,
        agent_role=ModelAgentRole.SOURCE,
        primary_model=reference,
        fallback_policy=fallback_policy,
        required_capabilities=(
            ModelCapability.STRICT_STRUCTURED_OUTPUT,
            ModelCapability.CHAT,
        ),
        required_context_data_classes=data_classes,
        budget=ModelBudgetProfile(
            max_total_tokens=20_000,
            max_output_tokens_per_turn=4_096,
            max_provider_attempts=2,
            timeout_seconds_per_attempt=60,
            max_cost_microunits=5_000_000,
        ),
    )


def _snapshot(
    *,
    routes: tuple[ModelRoute, ...],
    profiles: tuple[ProviderProfile, ...],
    manifests: tuple[CapabilityManifest, ...],
    policies: tuple[FallbackPolicy, ...],
) -> FlowModelSnapshot:
    return build_flow_model_snapshot(
        flow_id=uuid4(),
        routes=routes,
        profiles={item.profile_digest: item for item in profiles},
        manifests={item.manifest_digest: item for item in manifests},
        fallback_policies={item.policy_digest: item for item in policies},
        routing_policy_digest=_digest("routing-policy"),
        prompt_contract_digest=_digest("prompt-contract"),
        tool_schema_digest=_digest("tool-schema"),
        created_at=datetime(2026, 9, 8, 12, tzinfo=UTC),
    )


def test_provider_lifecycle_keeps_config_identity_and_seals_each_state():
    draft = ProviderProfile.create(
        provider_id="cuc",
        display_name="CUC",
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        protocol_adapter_id="openai-chat-v1",
        endpoint_reference_id=_digest("endpoint"),
        credential_reference_id=_digest("credential"),
        data_policy_id=_digest("policy"),
        allowed_context_data_classes=(
            ContextDataClass.SOURCE_CODE,
            ContextDataClass.SYNTHETIC,
        ),
    )
    bound = transition_provider_profile(
        draft,
        ProviderLifecycleState.SECRET_BOUND,
        evidence_digest=_digest("secret-bound"),
    )

    assert draft.allowed_context_data_classes == (
        ContextDataClass.SOURCE_CODE,
        ContextDataClass.SYNTHETIC,
    )
    assert bound.profile_digest == draft.profile_digest
    assert bound.lifecycle_digest != draft.lifecycle_digest
    assert bound.lifecycle_sequence == draft.lifecycle_sequence + 1
    assert bound.revision == draft.revision

    with pytest.raises(ProviderTransitionRejected, match="illegal Provider Profile"):
        transition_provider_profile(
            draft,
            ProviderLifecycleState.ROLE_ADMITTED,
            evidence_digest=_digest("invalid-jump"),
        )
    with pytest.raises(ProviderTransitionRejected, match="evidence must be"):
        transition_provider_profile(
            draft, ProviderLifecycleState.SECRET_BOUND, evidence_digest="invalid"
        )
    with pytest.raises(ValidationError, match="lifecycle content digest mismatch"):
        ProviderProfile.model_validate(
            {**bound.model_dump(mode="python"), "lifecycle_digest": "0" * 64}
        )


def test_profile_contains_references_but_no_endpoint_or_credential_value():
    profile = _profile()
    serialized = profile.model_dump_json()

    assert "https://" not in serialized
    assert "secret-value" not in serialized
    assert "base_url" not in ProviderProfile.model_fields
    assert "api_key" not in ProviderProfile.model_fields


def test_capability_manifest_requires_probe_evidence_and_rejects_duplicates():
    with pytest.raises(ValidationError, match="requires a probe result"):
        ModelCapabilityAssessment(
            capability=ModelCapability.CHAT,
            status=CapabilityStatus.PROBED,
        )
    with pytest.raises(ValidationError, match="cannot bind a probe result"):
        ModelCapabilityAssessment(
            capability=ModelCapability.CHAT,
            status=CapabilityStatus.DECLARED,
            probe_result_digest=_digest("unexpected"),
        )

    profile = _profile()
    item = ModelCapabilityAssessment(
        capability=ModelCapability.CHAT,
        status=CapabilityStatus.PROBED,
        probe_result_digest=_digest("chat"),
    )
    with pytest.raises(ValidationError, match="unique and sorted"):
        CapabilityManifest.create(
            provider_profile_digest=profile.profile_digest,
            provider_model_id="duplicate-model",
            protocol_adapter_digest=_digest("adapter"),
            assessments=(item, item),
            observed_at=datetime(2026, 9, 8, tzinfo=UTC),
        )


def test_route_admission_builds_a_digest_pinned_flow_snapshot():
    profile = _profile()
    manifest = _manifest(profile)
    reference = _reference(profile, manifest)
    policy = FallbackPolicy.create()
    route = _route(reference, policy)

    snapshot = _snapshot(
        routes=(route,),
        profiles=(profile,),
        manifests=(manifest,),
        policies=(policy,),
    )

    binding = snapshot.bindings[0]
    assert binding.route_digest == route.route_digest
    assert binding.selected_model == reference
    assert binding.provider_lifecycle_digest == profile.lifecycle_digest
    assert binding.provider_data_policy_id == profile.data_policy_id
    assert binding.protocol_adapter_digest == manifest.protocol_adapter_digest
    assert "credential_reference_id" not in binding.model_dump_json()
    with pytest.raises(ValidationError, match="Snapshot content digest mismatch"):
        FlowModelSnapshot.model_validate(
            {**snapshot.model_dump(mode="python"), "snapshot_digest": "0" * 64}
        )


def test_route_fails_closed_without_probed_capability():
    profile = _profile()
    manifest = _manifest(profile)
    reference = _reference(profile, manifest)
    policy = FallbackPolicy.create()
    route = ModelRoute.create(
        engine=ModelEngine.AUTHORIZED_RED_TEAM,
        agent_role=ModelAgentRole.WEB,
        primary_model=reference,
        fallback_policy=policy,
        required_capabilities=(ModelCapability.TOOL_PROPOSAL,),
        required_context_data_classes=(ContextDataClass.REDACTED_EVIDENCE,),
        budget=ModelBudgetProfile(
            max_total_tokens=1_000,
            max_output_tokens_per_turn=500,
            timeout_seconds_per_attempt=30,
        ),
    )

    with pytest.raises(ModelRouteRejected, match="lacks probed capabilities"):
        _snapshot(
            routes=(route,),
            profiles=(profile,),
            manifests=(manifest,),
            policies=(policy,),
        )


def test_route_fails_closed_for_disallowed_context_data():
    profile = _profile(data_classes=(ContextDataClass.SYNTHETIC,))
    manifest = _manifest(profile)
    reference = _reference(profile, manifest)
    policy = FallbackPolicy.create()
    route = _route(reference, policy)

    with pytest.raises(ModelRouteRejected, match="rejects required context data"):
        _snapshot(
            routes=(route,),
            profiles=(profile,),
            manifests=(manifest,),
            policies=(policy,),
        )


def test_route_fails_closed_for_provider_that_is_not_role_admitted():
    draft = ProviderProfile.create(
        provider_id="draft",
        display_name="Draft",
        protocol=ProviderProtocol.OPENAI_RESPONSES,
        protocol_adapter_id="responses-v1",
        endpoint_reference_id=_digest("draft-endpoint"),
        credential_reference_id=_digest("draft-credential"),
        data_policy_id=_digest("draft-policy"),
        allowed_context_data_classes=(ContextDataClass.SOURCE_CODE,),
    )
    manifest = _manifest(draft)
    reference = _reference(draft, manifest)
    policy = FallbackPolicy.create()

    with pytest.raises(ModelRouteRejected, match="not role-admitted"):
        _snapshot(
            routes=(_route(reference, policy),),
            profiles=(draft,),
            manifests=(manifest,),
            policies=(policy,),
        )


def test_fallback_cannot_cross_provider_without_explicit_policy():
    primary_profile = _profile("cuc")
    primary_manifest = _manifest(primary_profile, "primary")
    primary = _reference(primary_profile, primary_manifest)
    fallback_profile = _profile("second")
    fallback_manifest = _manifest(fallback_profile, "fallback")
    fallback = _reference(fallback_profile, fallback_manifest)
    policy = FallbackPolicy.create(
        ordered_models=(fallback,),
        triggers=(FallbackTrigger.TIMEOUT,),
        max_fallback_attempts=1,
    )

    with pytest.raises(ModelRouteRejected, match="forbids cross-provider"):
        _snapshot(
            routes=(_route(primary, policy),),
            profiles=(primary_profile, fallback_profile),
            manifests=(primary_manifest, fallback_manifest),
            policies=(policy,),
        )


def test_explicit_cross_provider_fallback_is_pinned_in_snapshot():
    primary_profile = _profile("cuc")
    primary_manifest = _manifest(primary_profile, "primary")
    primary = _reference(primary_profile, primary_manifest)
    fallback_profile = _profile("second")
    fallback_manifest = _manifest(fallback_profile, "fallback")
    fallback = _reference(fallback_profile, fallback_manifest)
    policy = FallbackPolicy.create(
        ordered_models=(fallback,),
        triggers=(FallbackTrigger.PROVIDER_UNAVAILABLE,),
        max_fallback_attempts=1,
        allow_cross_provider=True,
    )

    snapshot = _snapshot(
        routes=(_route(primary, policy),),
        profiles=(primary_profile, fallback_profile),
        manifests=(primary_manifest, fallback_manifest),
        policies=(policy,),
    )

    assert snapshot.bindings[0].fallback_policy_digest == policy.policy_digest
    assert policy.only_before_effect_commit


def test_fallback_is_bounded_and_always_before_effect_commit():
    with pytest.raises(ValidationError, match="attempts exceed"):
        FallbackPolicy.create(
            ordered_models=(),
            triggers=(FallbackTrigger.TIMEOUT,),
            max_fallback_attempts=1,
        )
    policy = FallbackPolicy.create()
    with pytest.raises(ValidationError):
        FallbackPolicy.model_validate(
            {**policy.model_dump(mode="python"), "only_before_effect_commit": False}
        )


def test_route_attempt_budget_must_cover_fallback_policy():
    profile = _profile()
    manifest = _manifest(profile)
    primary = _reference(profile, manifest)
    fallback_manifest = _manifest(profile, "fallback-model")
    fallback = _reference(profile, fallback_manifest)
    policy = FallbackPolicy.create(
        ordered_models=(fallback,),
        triggers=(FallbackTrigger.TIMEOUT,),
        max_fallback_attempts=1,
    )
    route = ModelRoute.create(
        engine=ModelEngine.SOURCE_HUNT,
        agent_role=ModelAgentRole.SOURCE,
        primary_model=primary,
        fallback_policy=policy,
        required_capabilities=(ModelCapability.CHAT,),
        required_context_data_classes=(ContextDataClass.SOURCE_CODE,),
        budget=ModelBudgetProfile(
            max_total_tokens=1_000,
            max_output_tokens_per_turn=500,
            max_provider_attempts=1,
            timeout_seconds_per_attempt=30,
        ),
    )

    with pytest.raises(ModelRouteRejected, match="attempt budget"):
        _snapshot(
            routes=(route,),
            profiles=(profile,),
            manifests=(manifest, fallback_manifest),
            policies=(policy,),
        )


def test_flow_rejects_duplicate_engine_role_routes():
    profile = _profile()
    manifest = _manifest(profile)
    reference = _reference(profile, manifest)
    policy = FallbackPolicy.create()
    route = _route(reference, policy)

    with pytest.raises(ModelRouteRejected, match="unique per Engine and role"):
        _snapshot(
            routes=(route, route),
            profiles=(profile,),
            manifests=(manifest,),
            policies=(policy,),
        )


def test_revoked_provider_lifecycle_is_terminal():
    profile = _profile()
    revoked = transition_provider_profile(
        profile,
        ProviderLifecycleState.REVOKED,
        evidence_digest=_digest("provider-revoked"),
    )

    with pytest.raises(ProviderTransitionRejected, match="illegal Provider Profile"):
        transition_provider_profile(
            revoked,
            ProviderLifecycleState.DRAFT,
            evidence_digest=_digest("cannot-reopen"),
        )
