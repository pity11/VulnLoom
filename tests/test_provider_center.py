from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from vulnloom.adapters import (
    ModelCredentialReference,
    ModelEndpointReference,
    ResolvedModelEndpoint,
)
from vulnloom.agent_runtime.provider_probe import create_cuc_probe_config
from vulnloom.agent_runtime.provider_probe_fixture import (
    CUC_PROBE_DIGEST,
    CUC_STRUCTURED_PROBE_DIGEST,
)
from vulnloom.agent_runtime.provider_probe_models import (
    ProviderProbePlan,
)
from vulnloom.agent_runtime.provider_probe_models import (
    ProviderProbeResult as SourceProviderProbeResult,
)
from vulnloom.agent_runtime.provider_probe_store import (
    ProviderProbeRecoveryRequired,
    ProviderProbeStore,
)
from vulnloom.cli import main
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.model_routing import (
    ContextDataClass,
    FallbackPolicy,
    ModelAgentRole,
    ModelBudgetProfile,
    ModelCapability,
    ModelEngine,
    ModelReference,
    ModelRoute,
    ProviderLifecycleState,
    ProviderProfile,
    ProviderProtocol,
    revise_provider_profile,
)
from vulnloom.provider_center import (
    BindProviderProbeCommand,
    CapabilityProbeObservation,
    CapabilityProbeRequest,
    CapabilityProbeStatus,
    DisableProviderCommand,
    EnableProviderCommand,
    FixtureCapabilityProbeAdapter,
    ProviderCenterConflict,
    ProviderCenterRecoveryRequired,
    ProviderCenterService,
    ProviderCenterStore,
    ProviderReferenceBundle,
    RegisterProviderCommand,
    SetDefaultRouteCommand,
    StoredProviderProbeEvidenceReader,
    UpdateProviderCommand,
)

NOW = datetime(2026, 9, 9, 12, tzinfo=UTC)


def _digest(label: str) -> str:
    return canonical_digest({"fixture": label})


def _projection(value):
    if hasattr(value, "model_dump"):
        return _projection(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {key: _projection(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_projection(item) for item in value]
    return value


def _sealed(model, identity: str, **values):
    return model(**{identity: canonical_digest(_projection(values)), **values})


def _profile(provider_id: str):
    endpoint = ModelEndpointReference.create(configuration_key=f"{provider_id.upper()}_ENDPOINT")
    credential = ModelCredentialReference.create(
        environment_variable=(
            "CUC_DEEPSEEK_API_KEY" if provider_id == "cuc" else f"{provider_id.upper()}_KEY"
        )
    )
    profile = ProviderProfile.create(
        provider_id=provider_id,
        display_name=provider_id.upper(),
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        protocol_adapter_id="openai-chat-completions-v1",
        endpoint_reference_id=endpoint.reference_id,
        credential_reference_id=credential.reference_id,
        data_policy_id=_digest(f"{provider_id}:policy"),
        allowed_context_data_classes=(ContextDataClass.SYNTHETIC,),
    )
    return profile, ProviderReferenceBundle(endpoint=endpoint, credential=credential)


def _register(service, provider_id="cuc", key="register-1"):
    profile, references = _profile(provider_id)
    command = RegisterProviderCommand.create(
        idempotency_key=key,
        profile=profile,
        references=references,
        actor_ref=_digest("operator"),
        issued_at=NOW,
    )
    return service.register(command), command


def _probe_request(profile, provider_id="cuc", key="probe-1"):
    values = {
        "idempotency_key": key,
        "provider_profile_digest": profile.profile_digest,
        "provider_model_id": "cuc/deepseek" if provider_id == "cuc" else "model-v2",
        "protocol_adapter_digest": _digest("openai-chat-codec"),
        "capabilities": (
            ModelCapability.CHAT,
            ModelCapability.STRICT_STRUCTURED_OUTPUT,
            ModelCapability.USAGE_ACCOUNTING,
        ),
        "max_context_tokens": 32_768,
        "max_output_tokens": 2_048,
        "synthetic_only": True,
        "actor_ref": _digest("operator"),
        "created_at": NOW,
        "deadline": NOW + timedelta(seconds=10),
    }
    return _sealed(CapabilityProbeRequest, "request_id", **values)


def _passed_observation():
    return CapabilityProbeObservation(
        status=CapabilityProbeStatus.PASSED,
        passed_capabilities=(
            ModelCapability.CHAT,
            ModelCapability.STRICT_STRUCTURED_OUTPUT,
            ModelCapability.USAGE_ACCOUNTING,
        ),
        cleanup_verified=True,
        diagnostic_code="fixture_passed",
        observed_at=NOW + timedelta(seconds=1),
    )


def _route(profile, manifest, *, role=ModelAgentRole.PLANNER):
    fallback = FallbackPolicy.create()
    route = ModelRoute.create(
        engine=ModelEngine.SOURCE_HUNT,
        agent_role=role,
        primary_model=ModelReference(
            provider_profile_digest=profile.profile_digest,
            capability_manifest_digest=manifest.manifest_digest,
            provider_model_id=manifest.provider_model_id,
        ),
        fallback_policy=fallback,
        required_capabilities=(
            ModelCapability.CHAT,
            ModelCapability.STRICT_STRUCTURED_OUTPUT,
        ),
        required_context_data_classes=(ContextDataClass.SYNTHETIC,),
        budget=ModelBudgetProfile(
            max_total_tokens=4096,
            max_output_tokens_per_turn=1024,
            timeout_seconds_per_attempt=10,
        ),
    )
    return route, fallback


def _enable(service, profile, manifest, key="enable-1"):
    route, fallback = _route(profile, manifest)
    values = {
        "idempotency_key": key,
        "provider_id": profile.provider_id,
        "expected_profile_digest": profile.profile_digest,
        "route": route,
        "fallback_policy": fallback,
        "actor_ref": _digest("operator"),
        "issued_at": NOW + timedelta(seconds=2),
    }
    command = _sealed(EnableProviderCommand, "command_id", **values)
    return service.enable(command), command


class _CucEndpointProvider:
    def resolve(self, reference):
        return ResolvedModelEndpoint(hostname="openai.cuc.edu.cn", port=443, base_path="")


def _source_probe(tmp_path, *, status="passed", cleanup=True, key="source-probe", structured=True):
    config = create_cuc_probe_config(grant_id=_digest(f"{key}:grant"), structured=structured)
    plan = ProviderProbePlan.create(
        config_digest=canonical_digest(config.model_dump(mode="python")),
        grant_id=config.registration.egress_grant_id,
        fixture_digest=CUC_STRUCTURED_PROBE_DIGEST if structured else CUC_PROBE_DIGEST,
        created_at=NOW,
        deadline=NOW + timedelta(seconds=10),
        idempotency_key=key,
    )
    result = SourceProviderProbeResult.create(
        plan_id=plan.plan_id,
        status=status,
        input_tokens=34 if status == "passed" else 0,
        output_tokens=10 if status == "passed" else 0,
        process_started=status != "timed_out",
        cleanup_verified=cleanup,
        attempt_digest=_digest(f"{key}:attempt") if status != "timed_out" else None,
        receipt_digest=_digest(f"{key}:receipt") if status == "passed" else None,
        completed_at=NOW + timedelta(seconds=1),
        response_model="deepseek-v4-flash-0731" if status == "passed" else None,
    )
    store = ProviderProbeStore(tmp_path / f"{key}.db")
    assert store.claim(plan) is None
    store.complete(result)
    return config, plan, result, store


def _bind_command(profile, config, plan, *, key="bind-source-probe", expected_capabilities=None):
    values = {
        "idempotency_key": key,
        "provider_id": profile.provider_id,
        "expected_profile_digest": profile.profile_digest,
        "probe_plan_id": plan.plan_id,
        "probe_config_digest": canonical_digest(config.model_dump(mode="python")),
        "expected_capabilities": expected_capabilities
        or (
            ModelCapability.CHAT,
            ModelCapability.STRICT_STRUCTURED_OUTPUT,
            ModelCapability.USAGE_ACCOUNTING,
        ),
        "actor_ref": _digest("operator"),
        "issued_at": NOW + timedelta(seconds=2),
    }
    return _sealed(BindProviderProbeCommand, "command_id", **values)


def test_provider_center_success_idempotency_route_and_redacted_audit(tmp_path):
    db = tmp_path / "provider-center.db"
    with ProviderCenterStore(db) as store:
        service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=2))
        registered, register_command = _register(service)
        assert registered.profile.state is ProviderLifecycleState.SECRET_BOUND
        replay = service.register(register_command)
        assert replay.applied is False

        request = _probe_request(registered.profile)
        probe = service.probe(request, FixtureCapabilityProbeAdapter(_passed_observation()))
        assert probe.status is CapabilityProbeStatus.PASSED
        assert probe.cleanup_verified is True
        assert probe.manifest is not None
        assert store.current_profile("cuc").state is ProviderLifecycleState.CAPABILITIES_PROBED

        enabled, enable_command = _enable(service, registered.profile, probe.manifest)
        assert enabled.profile.state is ProviderLifecycleState.ROLE_ADMITTED
        assert service.enable(enable_command).applied is False
        view = store.view()
        assert view.default_routes == (enabled.route,)
        assert view.health[0].status.value == "healthy"
        assert view.health[0].cleanup_verified is True
        assert [item.action.value for item in reversed(view.recent_audit)] == [
            "register",
            "probe",
            "enable",
        ]

    contents = db.read_bytes()
    assert b"raw-secret-value" not in contents
    assert b"https://private-gateway.example" not in contents
    assert b"Authorization" not in contents


def test_enable_rejects_missing_capability_without_changing_profile(tmp_path):
    with ProviderCenterStore(tmp_path / "center.db") as store:
        service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=2))
        registered, _ = _register(service)
        request = _probe_request(registered.profile)
        probe = service.probe(request, FixtureCapabilityProbeAdapter(_passed_observation()))
        route, fallback = _route(registered.profile, probe.manifest)
        route = ModelRoute.create(
            engine=route.engine,
            agent_role=route.agent_role,
            primary_model=route.primary_model,
            fallback_policy=fallback,
            required_capabilities=(ModelCapability.TOOL_PROPOSAL,),
            required_context_data_classes=route.required_context_data_classes,
            budget=route.budget,
        )
        values = {
            "idempotency_key": "bad-enable",
            "provider_id": "cuc",
            "expected_profile_digest": registered.profile.profile_digest,
            "route": route,
            "fallback_policy": fallback,
            "actor_ref": _digest("operator"),
            "issued_at": NOW + timedelta(seconds=2),
        }
        command = _sealed(EnableProviderCommand, "command_id", **values)

        with pytest.raises(ValueError, match="lacks probed capabilities"):
            service.enable(command)
        assert store.current_profile("cuc").state is ProviderLifecycleState.CAPABILITIES_PROBED
        assert len(store.view().recent_audit) == 2


def test_probe_timeout_is_closed_cleaned_and_audited(tmp_path):
    with ProviderCenterStore(tmp_path / "center.db") as store:
        service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=11))
        registered, _ = _register(service)
        request = _probe_request(registered.profile)

        class MustNotRun:
            def probe(self, request):
                raise AssertionError("expired probe invoked its adapter")

        result = service.probe(request, MustNotRun())

        assert result.status is CapabilityProbeStatus.TIMED_OUT
        assert result.manifest is None
        assert result.cleanup_verified is True
        assert store.current_profile("cuc").state is ProviderLifecycleState.SECRET_BOUND
        assert result.diagnostic_code == "probe_deadline_expired"
        assert store.view().recent_audit[0].outcome.value == "timed_out"


def test_probe_cannot_admit_capabilities_without_cleanup_proof(tmp_path):
    with ProviderCenterStore(tmp_path / "center.db") as store:
        service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=2))
        registered, _ = _register(service)
        unsafe = _passed_observation().model_copy(update={"cleanup_verified": False})

        result = service.probe(
            _probe_request(registered.profile), FixtureCapabilityProbeAdapter(unsafe)
        )

        assert result.status is CapabilityProbeStatus.FAILED
        assert result.diagnostic_code == "cleanup_unverified"
        assert result.manifest is None
        assert store.current_profile("cuc").state is ProviderLifecycleState.SECRET_BOUND
        assert store.view().health[0].status.value == "failed"


def test_interrupted_probe_requires_explicit_recovery(tmp_path, monkeypatch):
    with ProviderCenterStore(tmp_path / "center.db") as store:
        service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=2))
        registered, _ = _register(service)
        request = _probe_request(registered.profile)
        monkeypatch.setattr(store, "complete_probe", lambda *args: (_ for _ in ()).throw(OSError()))
        with pytest.raises(OSError):
            service.probe(request, FixtureCapabilityProbeAdapter(_passed_observation()))
        with pytest.raises(ProviderCenterRecoveryRequired):
            store.claim_probe(request)


def test_update_resets_trust_and_disable_is_fail_closed(tmp_path):
    with ProviderCenterStore(tmp_path / "center.db") as store:
        service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=2))
        registered, _ = _register(service)
        request = _probe_request(registered.profile)
        probe = service.probe(request, FixtureCapabilityProbeAdapter(_passed_observation()))
        enabled, _ = _enable(service, registered.profile, probe.manifest)
        disable_values = {
            "idempotency_key": "disable-1",
            "provider_id": "cuc",
            "expected_profile_digest": enabled.profile.profile_digest,
            "reason_digest": _digest("operator-disabled"),
            "actor_ref": _digest("operator"),
            "issued_at": NOW + timedelta(seconds=3),
        }
        disable_command = _sealed(DisableProviderCommand, "command_id", **disable_values)
        disabled = service.disable(disable_command)
        assert disabled.profile.state is ProviderLifecycleState.DISABLED
        assert service.disable(disable_command).applied is False

        endpoint = ModelEndpointReference.create(configuration_key="CUC_ENDPOINT_V2")
        credential = ModelCredentialReference.create(environment_variable="CUC_DEEPSEEK_API_KEY")
        replacement = revise_provider_profile(
            disabled.profile,
            display_name="CUC revised",
            protocol=disabled.profile.protocol,
            protocol_adapter_id=disabled.profile.protocol_adapter_id,
            endpoint_reference_id=endpoint.reference_id,
            credential_reference_id=credential.reference_id,
            data_policy_id=disabled.profile.data_policy_id,
            allowed_context_data_classes=disabled.profile.allowed_context_data_classes,
        )
        update_values = {
            "idempotency_key": "update-1",
            "expected_profile_digest": disabled.profile.profile_digest,
            "replacement": replacement,
            "references": ProviderReferenceBundle(endpoint=endpoint, credential=credential),
            "actor_ref": _digest("operator"),
            "issued_at": NOW + timedelta(seconds=4),
        }
        update_command = _sealed(UpdateProviderCommand, "command_id", **update_values)
        updated = service.update(update_command)
        assert updated.profile.revision == 2
        assert updated.profile.state is ProviderLifecycleState.SECRET_BOUND
        assert service.update(update_command).applied is False


def test_route_switch_uses_same_application_service(tmp_path):
    with ProviderCenterStore(tmp_path / "center.db") as store:
        service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=2))
        first, _ = _register(service, "cuc", "register-cuc")
        first_probe = service.probe(
            _probe_request(first.profile, "cuc", "probe-cuc"),
            FixtureCapabilityProbeAdapter(_passed_observation()),
        )
        _enable(service, first.profile, first_probe.manifest, "enable-cuc")
        second, _ = _register(service, "second", "register-second")
        second_probe = service.probe(
            _probe_request(second.profile, "second", "probe-second"),
            FixtureCapabilityProbeAdapter(_passed_observation()),
        )
        second_enabled, _ = _enable(service, second.profile, second_probe.manifest, "enable-second")
        assert (
            second_enabled.route.primary_model.provider_profile_digest
            == second.profile.profile_digest
        )

        first_profile = store.current_profile("cuc")
        first_route, fallback = _route(first_profile, first_probe.manifest)
        values = {
            "idempotency_key": "switch-back-to-cuc",
            "route": first_route,
            "fallback_policy": fallback,
            "actor_ref": _digest("operator"),
            "issued_at": NOW + timedelta(seconds=4),
        }
        switched = service.set_default_route(
            _sealed(SetDefaultRouteCommand, "command_id", **values)
        )
        assert switched.route.primary_model.provider_profile_digest == first_profile.profile_digest
        assert store.route("source_hunt", "planner") == first_route


def test_cli_lists_and_probes_without_accepting_secret_fields(tmp_path, capsys):
    profile, references = _profile("cuc")
    command = RegisterProviderCommand.create(
        idempotency_key="cli-register",
        profile=profile,
        references=references,
        actor_ref=_digest("operator"),
        issued_at=NOW,
    )
    command_file = tmp_path / "register.json"
    command_file.write_text(command.model_dump_json(), encoding="utf-8")
    db = tmp_path / "center.db"
    assert (
        main(
            [
                "provider",
                "--provider-db",
                str(db),
                "add",
                "--command-file",
                str(command_file),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["profile"]["provider_id"] == "cuc"
    assert main(["provider", "--provider-db", str(db), "list"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["profiles"][0]["credential_reference_id"] == references.credential.reference_id
    serialized = command.model_dump(mode="json")
    serialized["api_key"] = "raw-secret-value"
    with pytest.raises(ValidationError):
        RegisterProviderCommand.model_validate(serialized)
    command_file.write_text(json.dumps(serialized), encoding="utf-8")
    assert (
        main(
            [
                "provider",
                "--provider-db",
                str(db),
                "add",
                "--command-file",
                str(command_file),
            ]
        )
        == 1
    )
    rejected_output = capsys.readouterr().out
    assert json.loads(rejected_output) == {"status": "provider_center_rejected"}
    assert "raw-secret-value" not in rejected_output


def test_provider_center_rejects_conflicting_idempotency_key(tmp_path):
    with ProviderCenterStore(tmp_path / "center.db") as store:
        service = ProviderCenterService(store)
        _register(service, "cuc", "same-key")
        with pytest.raises(ProviderCenterConflict, match="identity conflict"):
            _register(service, "second", "same-key")


def test_bind_authoritative_structured_probe_promotes_exact_capabilities(tmp_path):
    config, plan, source, probe_store = _source_probe(tmp_path)
    center_db = tmp_path / "center.db"
    try:
        with ProviderCenterStore(center_db) as store:
            service = ProviderCenterService(store, now=lambda: NOW + timedelta(seconds=2))
            registered, _ = _register(service)
            command = _bind_command(registered.profile, config, plan)

            record = service.bind_provider_probe(
                command,
                evidence_reader=StoredProviderProbeEvidenceReader(config=config, store=probe_store),
                endpoint_provider=_CucEndpointProvider(),
            )

            assert record.status is CapabilityProbeStatus.PASSED
            assert record.source_result_id == source.result_id
            assert record.capabilities == command.expected_capabilities
            assert record.manifest is not None
            assert record.manifest.protocol_adapter_digest != config.codec.codec_id
            assert store.current_profile("cuc").state is ProviderLifecycleState.CAPABILITIES_PROBED
            assert store.view().probe_bindings == (record,)
            assert store.view().health[0].status.value == "healthy"
            assert (
                service.bind_provider_probe(
                    command,
                    evidence_reader=StoredProviderProbeEvidenceReader(
                        config=config, store=probe_store
                    ),
                    endpoint_provider=_CucEndpointProvider(),
                )
                == record
            )
    finally:
        probe_store.close()

    center_bytes = center_db.read_bytes()
    assert b"openai.cuc.edu.cn" not in center_bytes
    assert b"Authorization" not in center_bytes


def test_pong_probe_cannot_claim_structured_output_capability(tmp_path):
    config, plan, _, probe_store = _source_probe(tmp_path, key="pong-source", structured=False)
    try:
        with ProviderCenterStore(tmp_path / "center.db") as store:
            service = ProviderCenterService(store)
            registered, _ = _register(service)
            capabilities = (
                ModelCapability.CHAT,
                ModelCapability.USAGE_ACCOUNTING,
            )
            record = service.bind_provider_probe(
                _bind_command(
                    registered.profile,
                    config,
                    plan,
                    key="bind-pong",
                    expected_capabilities=capabilities,
                ),
                evidence_reader=StoredProviderProbeEvidenceReader(config=config, store=probe_store),
                endpoint_provider=_CucEndpointProvider(),
            )
            assert record.capabilities == capabilities
            assert ModelCapability.STRICT_STRUCTURED_OUTPUT not in record.capabilities
    finally:
        probe_store.close()


@pytest.mark.parametrize(
    ("status", "cleanup", "expected"),
    [("rejected", False, "failed"), ("timed_out", True, "timed_out")],
)
def test_unsuccessful_authoritative_probe_is_audited_without_capability_uplift(
    tmp_path, status, cleanup, expected
):
    config, plan, _, probe_store = _source_probe(
        tmp_path, status=status, cleanup=cleanup, key=f"source-{status}"
    )
    try:
        with ProviderCenterStore(tmp_path / "center.db") as store:
            service = ProviderCenterService(store)
            registered, _ = _register(service)
            record = service.bind_provider_probe(
                _bind_command(registered.profile, config, plan, key=f"bind-{status}"),
                evidence_reader=StoredProviderProbeEvidenceReader(config=config, store=probe_store),
                endpoint_provider=_CucEndpointProvider(),
            )

            assert record.status.value == expected
            assert record.manifest is None and record.capabilities == ()
            assert record.cleanup_verified is cleanup
            assert store.current_profile("cuc").state is ProviderLifecycleState.SECRET_BOUND
            assert store.view().health[0].status.value == expected
            assert store.view().recent_audit[0].outcome.value in {"rejected", "timed_out"}
    finally:
        probe_store.close()


def test_probe_binding_rejects_capability_or_endpoint_overclaim(tmp_path):
    config, plan, _, probe_store = _source_probe(tmp_path)
    try:
        with ProviderCenterStore(tmp_path / "center.db") as store:
            service = ProviderCenterService(store)
            registered, _ = _register(service)
            command = _bind_command(registered.profile, config, plan)
            values = command.model_dump(mode="python", exclude={"command_id"})
            values["expected_capabilities"] = tuple(
                sorted(
                    (*command.expected_capabilities, ModelCapability.TOOL_PROPOSAL),
                    key=lambda item: item.value,
                )
            )
            overclaim = _sealed(BindProviderProbeCommand, "command_id", **values)
            with pytest.raises(ProviderCenterConflict, match="claim is not exact"):
                service.bind_provider_probe(
                    overclaim,
                    evidence_reader=StoredProviderProbeEvidenceReader(
                        config=config, store=probe_store
                    ),
                    endpoint_provider=_CucEndpointProvider(),
                )

            class WrongEndpoint:
                def resolve(self, reference):
                    return ResolvedModelEndpoint(
                        hostname="different.example", port=443, base_path=""
                    )

            with pytest.raises(ProviderCenterConflict, match="endpoint reference"):
                service.bind_provider_probe(
                    command,
                    evidence_reader=StoredProviderProbeEvidenceReader(
                        config=config, store=probe_store
                    ),
                    endpoint_provider=WrongEndpoint(),
                )
            assert store.current_profile("cuc").state is ProviderLifecycleState.SECRET_BOUND
            assert store.view().probe_bindings == ()
    finally:
        probe_store.close()


def test_probe_binding_write_failure_rolls_back_and_can_retry(tmp_path):
    config, plan, _, probe_store = _source_probe(tmp_path)
    try:
        with ProviderCenterStore(tmp_path / "center.db") as store:
            service = ProviderCenterService(store)
            registered, _ = _register(service)
            command = _bind_command(registered.profile, config, plan)
            reader = StoredProviderProbeEvidenceReader(config=config, store=probe_store)
            store.connection.execute(
                "CREATE TRIGGER fail_probe_binding BEFORE INSERT ON provider_center_audit "
                "WHEN NEW.event_json LIKE '%probe_bind%' BEGIN SELECT RAISE(ABORT, 'fail'); END"
            )
            with pytest.raises(ProviderCenterConflict):
                service.bind_provider_probe(
                    command,
                    evidence_reader=reader,
                    endpoint_provider=_CucEndpointProvider(),
                )
            assert store.current_profile("cuc").state is ProviderLifecycleState.SECRET_BOUND
            assert store.view().probe_bindings == ()
            store.connection.execute("DROP TRIGGER fail_probe_binding")
            record = service.bind_provider_probe(
                command,
                evidence_reader=reader,
                endpoint_provider=_CucEndpointProvider(),
            )
            assert record.status is CapabilityProbeStatus.PASSED
    finally:
        probe_store.close()


def test_probe_evidence_reader_rejects_started_ledger(tmp_path):
    config = create_cuc_probe_config(grant_id=_digest("grant"), structured=True)
    plan = ProviderProbePlan.create(
        config_digest=canonical_digest(config.model_dump(mode="python")),
        grant_id=config.registration.egress_grant_id,
        fixture_digest=CUC_STRUCTURED_PROBE_DIGEST,
        created_at=NOW,
        deadline=NOW + timedelta(seconds=10),
        idempotency_key="unfinished-source",
    )
    with ProviderProbeStore(tmp_path / "probe.db") as probe_store:
        assert probe_store.claim(plan) is None
        reader = StoredProviderProbeEvidenceReader(config=config, store=probe_store)
        with pytest.raises(ProviderProbeRecoveryRequired, match="unavailable"):
            reader.load_completed(plan.plan_id)


def test_probe_evidence_reader_rejects_tampered_completed_ledger(tmp_path):
    config, plan, _, probe_store = _source_probe(tmp_path, key="tampered-source")
    try:
        probe_store.connection.execute(
            "UPDATE provider_probes SET result_json='{}' WHERE plan_id=?",
            (plan.plan_id,),
        )
        probe_store.connection.commit()
        reader = StoredProviderProbeEvidenceReader(config=config, store=probe_store)

        with pytest.raises(ProviderProbeRecoveryRequired, match="invalid"):
            reader.load_completed(plan.plan_id)
    finally:
        probe_store.close()


def test_probe_binding_rejects_plan_grant_drift(tmp_path):
    config, _, _, probe_store = _source_probe(tmp_path, key="unused-source")
    probe_store.close()
    plan = ProviderProbePlan.create(
        config_digest=canonical_digest(config.model_dump(mode="python")),
        grant_id=_digest("different-grant"),
        fixture_digest=CUC_STRUCTURED_PROBE_DIGEST,
        created_at=NOW,
        deadline=NOW + timedelta(seconds=10),
        idempotency_key="grant-drift-source",
    )
    result = SourceProviderProbeResult.create(
        plan_id=plan.plan_id,
        status="passed",
        input_tokens=34,
        output_tokens=10,
        process_started=True,
        cleanup_verified=True,
        attempt_digest=_digest("grant-drift:attempt"),
        receipt_digest=_digest("grant-drift:receipt"),
        completed_at=NOW + timedelta(seconds=1),
        response_model="deepseek-v4-flash-0731",
    )
    with ProviderProbeStore(tmp_path / "grant-drift.db") as drifted_store:
        assert drifted_store.claim(plan) is None
        drifted_store.complete(result)
        with ProviderCenterStore(tmp_path / "center.db") as store:
            service = ProviderCenterService(store)
            registered, _ = _register(service)
            with pytest.raises(ProviderCenterConflict, match="identity binding"):
                service.bind_provider_probe(
                    _bind_command(registered.profile, config, plan),
                    evidence_reader=StoredProviderProbeEvidenceReader(
                        config=config, store=drifted_store
                    ),
                    endpoint_provider=_CucEndpointProvider(),
                )


def test_read_only_probe_ledger_does_not_create_a_missing_database(tmp_path):
    missing = tmp_path / "missing-probe.db"
    with pytest.raises(sqlite3.OperationalError):
        ProviderProbeStore(missing, read_only=True)
    assert not missing.exists()


def test_cli_binds_existing_probe_without_network_or_endpoint_output(tmp_path, monkeypatch, capsys):
    config, plan, _, probe_store = _source_probe(tmp_path, key="cli-source")
    probe_db = tmp_path / "cli-source.db"
    probe_store.close()
    center_db = tmp_path / "center.db"
    with ProviderCenterStore(center_db) as store:
        service = ProviderCenterService(store)
        registered, _ = _register(service)
    command = _bind_command(registered.profile, config, plan, key="cli-bind")
    command_file = tmp_path / "bind.json"
    config_file = tmp_path / "probe-config.json"
    command_file.write_text(command.model_dump_json(), encoding="utf-8")
    config_file.write_text(config.model_dump_json(), encoding="utf-8")
    monkeypatch.setenv("CUC_ENDPOINT", "https://openai.cuc.edu.cn")

    assert (
        main(
            [
                "provider",
                "--provider-db",
                str(center_db),
                "bind-probe",
                "--command-file",
                str(command_file),
                "--probe-config-file",
                str(config_file),
                "--probe-db",
                str(probe_db),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    parsed = json.loads(output)
    assert parsed["status"] == "passed"
    assert "openai.cuc.edu.cn" not in output
    assert "CUC_ENDPOINT" not in output
    assert "CUC_DEEPSEEK_API_KEY" not in output
