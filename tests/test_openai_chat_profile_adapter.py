from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.adapters import (
    EnvironmentModelCredentialProvider,
    EnvironmentModelEndpointProvider,
    ModelCredentialReference,
    ModelEndpointReference,
    ModelEndpointUnavailable,
)
from vulnloom.agent_runtime import (
    OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST,
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextSource,
    AgentContextSourceKind,
    AgentMessageRenderer,
    AgentProviderCodecLimits,
    AgentProviderEgressAuthority,
    AgentProviderEgressGrant,
    AgentProviderEgressIssuerPolicy,
    AgentProviderEgressPurpose,
    AgentProviderEgressRejected,
    AgentProviderEgressStore,
    AgentProviderTransportLimits,
    AgentProviderTransportMode,
    AgentProviderTransportRejected,
    AgentProviderTransportStatus,
    AgentProviderTransportTimedOut,
    AgentRunLimits,
    AgentRunPlan,
    AgentStepRequest,
    OpenAIChatCompletionsCodecRegistration,
    OpenAIChatCompletionsFeatureDisabled,
    OpenAIChatCompletionsFeatureGate,
    ProviderProcessExecutionError,
    ProviderProcessResult,
    create_openai_chat_provider_adapter,
)
from vulnloom.agent_runtime.profile_adapter import (
    OPENAI_CHAT_PROFILE_ADAPTER_ID,
    OpenAIChatProfileAssemblyRejected,
    OpenAIChatProfilePreparation,
    bind_openai_chat_profile,
    bind_openai_chat_task_registration,
    prepare_openai_chat_profile,
)
from vulnloom.agent_runtime.provider_diagnostics import ProviderDiagnostic
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.model_routing import (
    CapabilityManifest,
    CapabilityStatus,
    ContextDataClass,
    FallbackPolicy,
    ModelAgentRole,
    ModelBudgetProfile,
    ModelCapability,
    ModelCapabilityAssessment,
    ModelEngine,
    ModelReference,
    ModelRoute,
    ProviderLifecycleState,
    ProviderProfile,
    ProviderProtocol,
    build_flow_model_snapshot,
    transition_provider_profile,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _digest(label: str) -> str:
    return canonical_digest({"fixture": label})


def _case(
    provider_id: str,
    model: str,
    *,
    engine: ModelEngine = ModelEngine.SOURCE_HUNT,
    agent_role: ModelAgentRole = ModelAgentRole.SOURCE,
):
    endpoint_ref = ModelEndpointReference.create(
        configuration_key=f"{provider_id.upper()}_MODEL_ENDPOINT"
    )
    credential_ref = ModelCredentialReference.create(
        environment_variable=f"{provider_id.upper()}_MODEL_KEY"
    )
    profile = ProviderProfile.create(
        provider_id=provider_id,
        display_name=provider_id,
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        protocol_adapter_id=OPENAI_CHAT_PROFILE_ADAPTER_ID,
        endpoint_reference_id=endpoint_ref.reference_id,
        credential_reference_id=credential_ref.reference_id,
        data_policy_id=_digest(provider_id + ":policy"),
        allowed_context_data_classes=(ContextDataClass.SOURCE_CODE,),
    )
    for state in (
        ProviderLifecycleState.SECRET_BOUND,
        ProviderLifecycleState.CONNECTIVITY_VERIFIED,
        ProviderLifecycleState.CATALOG_DISCOVERED,
        ProviderLifecycleState.CAPABILITIES_PROBED,
        ProviderLifecycleState.ROLE_ADMITTED,
    ):
        profile = transition_provider_profile(
            profile, state, evidence_digest=_digest(provider_id + ":" + state.value)
        )
    assessments = tuple(
        ModelCapabilityAssessment(
            capability=capability,
            status=CapabilityStatus.PROBED,
            probe_result_digest=_digest(provider_id + ":" + capability.value),
        )
        for capability in (
            ModelCapability.CHAT,
            ModelCapability.STRICT_STRUCTURED_OUTPUT,
            ModelCapability.USAGE_ACCOUNTING,
        )
    )
    manifest = CapabilityManifest.create(
        provider_profile_digest=profile.profile_digest,
        provider_model_id=model,
        protocol_adapter_digest=OPENAI_CHAT_COMPLETIONS_V1_IMPLEMENTATION_DIGEST,
        assessments=assessments,
        max_context_tokens=32_000,
        max_output_tokens=2_048,
        observed_at=NOW,
    )
    reference = ModelReference(
        provider_profile_digest=profile.profile_digest,
        capability_manifest_digest=manifest.manifest_digest,
        provider_model_id=model,
    )
    policy = FallbackPolicy.create()
    route = ModelRoute.create(
        engine=engine,
        agent_role=agent_role,
        primary_model=reference,
        fallback_policy=policy,
        required_capabilities=(
            ModelCapability.CHAT,
            ModelCapability.STRICT_STRUCTURED_OUTPUT,
            ModelCapability.USAGE_ACCOUNTING,
        ),
        required_context_data_classes=(ContextDataClass.SOURCE_CODE,),
        budget=ModelBudgetProfile(
            max_total_tokens=8_192,
            max_output_tokens_per_turn=1_024,
            max_provider_attempts=1,
            timeout_seconds_per_attempt=30,
        ),
    )
    snapshot = build_flow_model_snapshot(
        flow_id=uuid4(),
        routes=(route,),
        profiles={profile.profile_digest: profile},
        manifests={manifest.manifest_digest: manifest},
        fallback_policies={policy.policy_digest: policy},
        routing_policy_digest=_digest("routing"),
        prompt_contract_digest=_digest("prompt"),
        tool_schema_digest=_digest("tools"),
        created_at=NOW,
    )
    return profile, manifest, snapshot, endpoint_ref, credential_ref


def _prepare(
    provider_id: str = "alpha",
    model: str = "model-a",
    *,
    engine: ModelEngine = ModelEngine.SOURCE_HUNT,
    agent_role: ModelAgentRole = ModelAgentRole.SOURCE,
    worker_role: WorkerRole = WorkerRole.ANALYZER,
):
    profile, manifest, snapshot, endpoint_ref, credential_ref = _case(
        provider_id, model, engine=engine, agent_role=agent_role
    )
    endpoint_provider = EnvironmentModelEndpointProvider(
        {endpoint_ref.configuration_key: f"https://{provider_id}.example/v1"},
        allowed_references=(endpoint_ref,),
    )
    preparation = prepare_openai_chat_profile(
        profile=profile,
        manifest=manifest,
        flow_snapshot=snapshot,
        engine=engine,
        agent_role=agent_role,
        worker_role=worker_role,
        endpoint_reference=endpoint_ref,
        credential_reference=credential_ref,
        endpoint_provider=endpoint_provider,
        transport_limits=AgentProviderTransportLimits(timeout_seconds=30),
        codec_limits=AgentProviderCodecLimits(timeout_seconds=10),
        now=NOW,
        deadline=NOW + timedelta(minutes=1),
    )
    return preparation, profile, manifest, snapshot, endpoint_ref, credential_ref


def _grant(preparation: OpenAIChatProfilePreparation, *, purpose=None):
    values = {
        "admission_id": preparation.transport_admission.admission_id,
        "provider_id": preparation.codec_registration.provider_id,
        "mode": AgentProviderTransportMode.LIVE_HTTPS,
        "credential_reference_id": preparation.credential_reference_id,
        "adapter_digest": preparation.transport_admission.adapter_digest,
        "issuer_policy_id": _digest("issuer-policy"),
        "issuer_id": "operator",
        "purpose": purpose or AgentProviderEgressPurpose.MODEL_INFERENCE,
        "issued_at": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(minutes=1),
        "idempotency_key": "profile-adapter:test",
    }
    return AgentProviderEgressGrant(grant_id=canonical_digest(values), **values)


def test_task_codec_binding_is_profile_routed_and_fail_closed():
    preparation, profile, _, snapshot, _, _ = _prepare()
    grant = _grant(preparation)
    task_codec = OpenAIChatCompletionsCodecRegistration.create(
        provider_id="alpha",
        request_model="model-a",
        allowed_empty_root_fields=("vendor_extension",),
    )

    registration = bind_openai_chat_task_registration(
        preparation,
        task_codec_registration=task_codec,
        current_profile=profile,
        current_flow_snapshot=snapshot,
        grant_id=grant.grant_id,
        egress_verifier=_Verifier(grant),
        worker_role=WorkerRole.ANALYZER,
        max_output_tokens=512,
        now=NOW,
        deadline=NOW + timedelta(seconds=10),
    )

    assert registration.provider_codec_id == task_codec.codec_id
    assert registration.provider_id == "alpha"
    assert registration.model == "model-a"

    mismatched_codec = OpenAIChatCompletionsCodecRegistration.create(
        provider_id="beta",
        request_model="model-a",
    )
    for codec, role, output_tokens in (
        (mismatched_codec, WorkerRole.ANALYZER, 512),
        (task_codec, WorkerRole.REPORTER, 512),
        (task_codec, WorkerRole.ANALYZER, preparation.max_output_tokens + 1),
    ):
        with pytest.raises(OpenAIChatProfileAssemblyRejected, match="task codec"):
            bind_openai_chat_task_registration(
                preparation,
                task_codec_registration=codec,
                current_profile=profile,
                current_flow_snapshot=snapshot,
                grant_id=grant.grant_id,
                egress_verifier=_Verifier(grant),
                worker_role=role,
                max_output_tokens=output_tokens,
                now=NOW,
                deadline=NOW + timedelta(seconds=10),
            )


class _Verifier:
    def __init__(self, grant, *, error: Exception | None = None):
        self.grant = grant
        self.error = error

    def require_active(self, grant_id, *, admission, now):
        if self.error:
            raise self.error
        assert grant_id == self.grant.grant_id
        assert admission.admission_id == self.grant.admission_id
        assert now == NOW
        return self.grant


class _Resolver:
    def resolve(self, host):
        assert host.endswith(".example")
        return ("8.8.8.8",)


class _ProcessRunner:
    def __init__(self, *, provider_id, model, secret, failure=None):
        self.provider_id = provider_id
        self.model = model
        self.secret_digest = hashlib.sha256(secret.encode()).hexdigest()
        self.failure = failure
        self.request_body = None

    def exchange(self, **values):
        assert hashlib.sha256(values["credential"]).hexdigest() == self.secret_digest
        self.request_body = bytes(values["request_body"])
        if self.failure == "timeout":
            raise ProviderProcessExecutionError("provider_timeout", timed_out=True)
        if self.failure in {"401", "429"}:
            raise ProviderProcessExecutionError(
                "provider_https_rejected",
                diagnostic=ProviderDiagnostic(
                    failure_stage="http_status",
                    error_code="http_non_200",
                    http_status=int(self.failure),
                    network_opened=True,
                    captured_response_bytes=0,
                    tls_version="TLSv1.3",
                ),
            )
        response = b"not-json" if self.failure == "malformed" else _response(self.model)
        return ProviderProcessResult(
            response_body=bytearray(response),
            latency_seconds=0.1,
            peer_ip="8.8.8.8",
            tls_version="TLSv1.3",
        )


def _response(model):
    decision = {
        "kind": "complete",
        "summary_digest": "f" * 64,
        "supporting_ref_digests": [],
        "tool_call": None,
    }
    payload = {
        "choices": [
            {
                "finish_reason": "stop",
                "index": 0,
                "message": {
                    "content": json.dumps(decision, separators=(",", ":")),
                    "role": "assistant",
                },
            }
        ],
        "created": 1,
        "id": "chatcmpl-local",
        "model": model,
        "object": "chat.completion",
        "usage": {"completion_tokens": 2, "prompt_tokens": 3, "total_tokens": 5},
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def _e2e_case(tmp_path, *, provider_id, model, failure=None):
    preparation, profile, _, flow_snapshot, _, credential_reference = _prepare(
        provider_id, model
    )
    policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="operator",
        allowed_provider_ids=(provider_id,),
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=120,
    )
    store = AgentProviderEgressStore(tmp_path / (provider_id + "-egress"))
    grant = AgentProviderEgressAuthority(
        store=store, issuer_policies=(policy,)
    ).issue(
        admission=preparation.transport_admission,
        issuer_policy_id=policy.policy_id,
        purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
        now=NOW,
        expires_at=NOW + timedelta(seconds=60),
        deadline=NOW + timedelta(seconds=10),
        idempotency_key=provider_id + ":e2e-grant",
    )
    binding = bind_openai_chat_profile(
        preparation,
        current_profile=profile,
        current_flow_snapshot=flow_snapshot,
        grant_id=grant.grant_id,
        egress_verifier=store,
        feature_gate=OpenAIChatCompletionsFeatureGate.create(enabled=True),
        now=NOW,
        deadline=NOW + timedelta(seconds=10),
    )
    source_ref = "observation:" + "e" * 64
    task = TaskEnvelope(
        engagement_id=uuid4(),
        target_id=uuid4(),
        target_version="a" * 40,
        scope_id=uuid4(),
        worker_role=WorkerRole.ANALYZER,
        scope_version=1,
        policy_digest="a" * 64,
        sandbox_profile_digest="b" * 64,
        tool_registry_digest="c" * 64,
        input_refs=(source_ref,),
        allowed_tools=frozenset(),
        budget=TaskBudget(wall_seconds=30, model_tokens=100, tool_calls=0),
        deadline=NOW + timedelta(minutes=2),
        idempotency_key=provider_id + ":e2e-task",
    )
    context = AgentContextAssembler().assemble(
        task=task,
        sources=(
            AgentContextSource(
                source_ref=source_ref,
                kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                text="Synthetic profile adapter context.",
            ),
        ),
        limits=AgentContextLimits(),
        now=NOW,
        deadline=NOW + timedelta(seconds=10),
    )
    plan = AgentRunPlan.create(
        task=task,
        registration=binding.model_registration,
        limits=AgentRunLimits(
            max_steps=1,
            max_output_tokens_per_step=64,
            timeout_seconds=10,
        ),
        created_at=NOW,
        deadline=NOW + timedelta(seconds=20),
        idempotency_key=provider_id + ":e2e-plan",
        context_snapshot=context,
    )
    initial = AgentStepRequest.create(plan=plan, step=1, remaining_model_tokens=100)
    envelope = AgentMessageRenderer().render(
        plan=plan, snapshot=context, request=initial
    )
    request = AgentStepRequest.create(
        plan=plan,
        step=1,
        remaining_model_tokens=100,
        message_envelope_id=envelope.envelope_id,
    )
    secret = provider_id + "-local-secret"
    runner = _ProcessRunner(
        provider_id=provider_id,
        model=model,
        secret=secret,
        failure=failure,
    )
    adapter = create_openai_chat_provider_adapter(
        binding,
        credential_reference=credential_reference,
        credential_provider=EnvironmentModelCredentialProvider(
            {
                credential_reference.environment_variable: secret,
                "UNRELATED_PROVIDER_SECRET": "must-not-cross-boundary",
            },
            allowed_references=(credential_reference,),
        ),
        egress_store=store,
        resolver=_Resolver(),
        process_runner=runner,
        now=lambda: NOW + timedelta(seconds=1),
    )
    return adapter, runner, request, envelope, store


def test_environment_endpoint_provider_is_allowlisted_and_strict():
    reference = ModelEndpointReference.create(configuration_key="MODEL_ENDPOINT")
    provider = EnvironmentModelEndpointProvider(
        {"MODEL_ENDPOINT": "https://models.example/v1"},
        allowed_references=(reference,),
    )

    resolved = provider.resolve(reference)
    assert (resolved.hostname, resolved.port, resolved.base_path) == (
        "models.example",
        443,
        "/v1",
    )
    assert resolved.admits("/v1/chat/completions")

    other = ModelEndpointReference.create(configuration_key="OTHER_ENDPOINT")
    with pytest.raises(ModelEndpointUnavailable, match="not allowed"):
        provider.resolve(other)
    for value in (
        "http://models.example/v1",
        "https://user:pass@models.example/v1",
        "https://models.example/v1?debug=1",
        "https://models.example:8443/v1",
    ):
        invalid = EnvironmentModelEndpointProvider(
            {"MODEL_ENDPOINT": value}, allowed_references=(reference,)
        )
        with pytest.raises(ModelEndpointUnavailable, match="invalid"):
            invalid.resolve(reference)


def test_preparation_and_binding_switch_between_two_fake_provider_configs():
    first_case = _prepare("alpha", "model-a")
    second_case = _prepare("beta", "model-b")
    first = first_case[0]
    second = second_case[0]

    bound = []
    for preparation, profile, snapshot in (
        (first, first_case[1], first_case[3]),
        (second, second_case[1], second_case[3]),
    ):
        grant = _grant(preparation)
        bound.append(
            bind_openai_chat_profile(
                preparation,
                current_profile=profile,
                current_flow_snapshot=snapshot,
                grant_id=grant.grant_id,
                egress_verifier=_Verifier(grant),
                feature_gate=OpenAIChatCompletionsFeatureGate.create(enabled=True),
                now=NOW,
                deadline=NOW + timedelta(minutes=1),
            )
        )

    assert [item.model_registration.provider_id for item in bound] == ["alpha", "beta"]
    assert [item.model_registration.model for item in bound] == ["model-a", "model-b"]
    assert (
        bound[0].model_registration.registration_id
        != bound[1].model_registration.registration_id
    )
    assert bound[0].codec.registration.codec_id != bound[1].codec.registration.codec_id
    assert first.max_output_tokens == 1_024


def test_preparation_rejects_profile_manifest_flow_and_endpoint_drift():
    preparation, profile, manifest, snapshot, endpoint_ref, credential_ref = _prepare()
    endpoint_provider = EnvironmentModelEndpointProvider(
        {endpoint_ref.configuration_key: "https://alpha.example/other"},
        allowed_references=(endpoint_ref,),
    )
    with pytest.raises(OpenAIChatProfileAssemblyRejected, match="base path"):
        prepare_openai_chat_profile(
            profile=profile,
            manifest=manifest,
            flow_snapshot=snapshot,
            engine=preparation.engine,
            agent_role=preparation.agent_role,
            worker_role=preparation.worker_role,
            endpoint_reference=endpoint_ref,
            credential_reference=credential_ref,
            endpoint_provider=endpoint_provider,
            transport_limits=preparation.transport_admission.limits,
            codec_limits=preparation.codec_registration.limits,
            now=NOW,
            deadline=NOW + timedelta(minutes=1),
        )
    wrong_credential = ModelCredentialReference.create(
        environment_variable="WRONG_MODEL_KEY"
    )
    with pytest.raises(OpenAIChatProfileAssemblyRejected, match="Profile binding"):
        prepare_openai_chat_profile(
            profile=profile,
            manifest=manifest,
            flow_snapshot=snapshot,
            engine=preparation.engine,
            agent_role=preparation.agent_role,
            worker_role=preparation.worker_role,
            endpoint_reference=endpoint_ref,
            credential_reference=wrong_credential,
            endpoint_provider=endpoint_provider,
            transport_limits=preparation.transport_admission.limits,
            codec_limits=preparation.codec_registration.limits,
            now=NOW,
            deadline=NOW + timedelta(minutes=1),
        )


def test_binding_requires_live_grant_feature_gate_and_deadline():
    preparation, profile, _, snapshot, *_ = _prepare()
    grant = _grant(preparation)
    with pytest.raises(OpenAIChatCompletionsFeatureDisabled):
        bind_openai_chat_profile(
            preparation,
            current_profile=profile,
            current_flow_snapshot=snapshot,
            grant_id=grant.grant_id,
            egress_verifier=_Verifier(grant),
            feature_gate=OpenAIChatCompletionsFeatureGate.create(),
            now=NOW,
            deadline=NOW + timedelta(minutes=1),
        )
    with pytest.raises(OpenAIChatProfileAssemblyRejected, match="deadline"):
        bind_openai_chat_profile(
            preparation,
            current_profile=profile,
            current_flow_snapshot=snapshot,
            grant_id=grant.grant_id,
            egress_verifier=_Verifier(grant),
            feature_gate=OpenAIChatCompletionsFeatureGate.create(enabled=True),
            now=NOW,
            deadline=NOW,
        )
    with pytest.raises(RuntimeError, match="inactive"):
        bind_openai_chat_profile(
            preparation,
            current_profile=profile,
            current_flow_snapshot=snapshot,
            grant_id=grant.grant_id,
            egress_verifier=_Verifier(grant, error=RuntimeError("inactive grant")),
            feature_gate=OpenAIChatCompletionsFeatureGate.create(enabled=True),
            now=NOW,
            deadline=NOW + timedelta(minutes=1),
        )

    disabled = transition_provider_profile(
        profile,
        ProviderLifecycleState.DISABLED,
        evidence_digest=_digest("disabled"),
    )
    with pytest.raises(OpenAIChatProfileAssemblyRejected, match="drifted"):
        bind_openai_chat_profile(
            preparation,
            current_profile=disabled,
            current_flow_snapshot=snapshot,
            grant_id=grant.grant_id,
            egress_verifier=_Verifier(grant),
            feature_gate=OpenAIChatCompletionsFeatureGate.create(enabled=True),
            now=NOW,
            deadline=NOW + timedelta(minutes=1),
        )


def test_preparation_is_content_addressed_and_contains_no_secret():
    preparation, *_ = _prepare()
    serialized = preparation.model_dump_json()

    assert "MODEL_KEY" not in serialized
    assert "secret" not in serialized
    with pytest.raises(ValidationError, match="preparation digest mismatch"):
        OpenAIChatProfilePreparation.model_validate(
            {**preparation.model_dump(mode="python"), "preparation_id": "f" * 64}
        )


def test_preparation_rejects_role_budget_and_expired_deadline():
    preparation, profile, manifest, snapshot, endpoint_ref, credential_ref = _prepare()
    endpoint_provider = EnvironmentModelEndpointProvider(
        {endpoint_ref.configuration_key: "https://alpha.example/v1"},
        allowed_references=(endpoint_ref,),
    )
    common = {
        "profile": profile,
        "manifest": manifest,
        "flow_snapshot": snapshot,
        "engine": preparation.engine,
        "agent_role": preparation.agent_role,
        "endpoint_reference": endpoint_ref,
        "credential_reference": credential_ref,
        "endpoint_provider": endpoint_provider,
        "codec_limits": preparation.codec_registration.limits,
        "now": NOW,
    }
    with pytest.raises(OpenAIChatProfileAssemblyRejected, match="Worker role"):
        prepare_openai_chat_profile(
            **common,
            worker_role=WorkerRole.HYPOTHESIS,
            transport_limits=preparation.transport_admission.limits,
            deadline=NOW + timedelta(seconds=1),
        )
    with pytest.raises(OpenAIChatProfileAssemblyRejected, match="budget"):
        prepare_openai_chat_profile(
            **common,
            worker_role=WorkerRole.ANALYZER,
            transport_limits=AgentProviderTransportLimits(timeout_seconds=31),
            deadline=NOW + timedelta(seconds=1),
        )
    with pytest.raises(OpenAIChatProfileAssemblyRejected, match="deadline"):
        prepare_openai_chat_profile(
            **common,
            worker_role=WorkerRole.ANALYZER,
            transport_limits=preparation.transport_admission.limits,
            deadline=NOW,
        )


def test_binding_consumes_the_authoritative_grant_lifecycle(tmp_path):
    preparation, profile, _, snapshot, *_ = _prepare()
    policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="operator",
        allowed_provider_ids=(profile.provider_id,),
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=120,
    )
    with AgentProviderEgressStore(tmp_path / "egress") as store:
        authority = AgentProviderEgressAuthority(
            store=store,
            issuer_policies=(policy,),
        )
        grant = authority.issue(
            admission=preparation.transport_admission,
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=NOW,
            expires_at=NOW + timedelta(seconds=60),
            deadline=NOW + timedelta(seconds=10),
            idempotency_key="profile-adapter:authoritative",
        )
        result = bind_openai_chat_profile(
            preparation,
            current_profile=profile,
            current_flow_snapshot=snapshot,
            grant_id=grant.grant_id,
            egress_verifier=store,
            feature_gate=OpenAIChatCompletionsFeatureGate.create(enabled=True),
            now=NOW,
            deadline=NOW + timedelta(seconds=10),
        )
        assert result.model_registration.egress_grant_id == grant.grant_id

        authority.revoke(
            grant_id=grant.grant_id,
            issuer_policy_id=policy.policy_id,
            reason_digest=_digest("operator-revoked"),
            now=NOW + timedelta(seconds=1),
            deadline=NOW + timedelta(seconds=10),
            idempotency_key="profile-adapter:revoke",
        )
        with pytest.raises(AgentProviderEgressRejected, match="revoked"):
            bind_openai_chat_profile(
                preparation,
                current_profile=profile,
                current_flow_snapshot=snapshot,
                grant_id=grant.grant_id,
                egress_verifier=store,
                feature_gate=OpenAIChatCompletionsFeatureGate.create(enabled=True),
                now=NOW + timedelta(seconds=2),
                deadline=NOW + timedelta(seconds=10),
            )


@pytest.mark.parametrize(
    "provider_id,model",
    (("alpha", "model-a"), ("beta", "model-b")),
)
def test_profile_assembly_drives_a_complete_fake_provider_agent_turn(
    tmp_path, provider_id, model
):
    adapter, runner, request, envelope, store = _e2e_case(
        tmp_path, provider_id=provider_id, model=model
    )
    try:
        reply = adapter.complete(request, message_envelope=envelope)
    finally:
        store.close()

    wire_request = json.loads(runner.request_body)
    assert reply.provider_id == provider_id and reply.model == model
    assert reply.structured_output["kind"] == "complete"
    assert wire_request["model"] == model
    assert wire_request["stream"] is False
    assert "tools" not in wire_request
    assert adapter.attempts[0].status is AgentProviderTransportStatus.COMPLETED
    assert adapter.released_leases[0].zeroed
    assert not any(adapter.released_request_bodies[0])
    assert not any(adapter.discarded_response_bodies[0])


@pytest.mark.parametrize("failure", ("401", "429", "timeout", "malformed"))
def test_assembled_profile_failures_are_closed_and_cleaned(tmp_path, failure):
    adapter, _, request, envelope, store = _e2e_case(
        tmp_path,
        provider_id="alpha",
        model="model-a",
        failure=failure,
    )
    expected = (
        AgentProviderTransportTimedOut
        if failure == "timeout"
        else AgentProviderTransportRejected
    )
    try:
        with pytest.raises(expected):
            adapter.complete(request, message_envelope=envelope)
    finally:
        store.close()

    assert adapter.attempts[0].status in {
        AgentProviderTransportStatus.REJECTED,
        AgentProviderTransportStatus.TIMED_OUT,
    }
    assert adapter.released_leases[0].zeroed
    assert not any(adapter.released_request_bodies[0])
    if failure == "malformed":
        assert not any(adapter.discarded_response_bodies[0])
    assert not adapter.receipts
