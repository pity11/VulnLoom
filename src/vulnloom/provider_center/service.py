"""Trusted Provider Center application service shared by CLI and future APIs."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol
from uuid import UUID

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.model_routing import (
    CapabilityManifest,
    CapabilityStatus,
    ModelCapabilityAssessment,
    ProviderLifecycleState,
    build_flow_model_snapshot,
    revise_provider_profile,
    transition_provider_profile,
)
from vulnloom.domain.models import utc_now

from .models import (
    CapabilityProbeObservation,
    CapabilityProbeRequest,
    CapabilityProbeResult,
    CapabilityProbeStatus,
    DisableProviderCommand,
    EnableProviderCommand,
    ProviderAuditEvent,
    ProviderCenterAction,
    ProviderCenterOutcome,
    ProviderMutationResult,
    RegisterProviderCommand,
    SetDefaultRouteCommand,
    UpdateProviderCommand,
)
from .store import ProviderCenterConflict, ProviderCenterStore


class CapabilityProbeAdapter(Protocol):
    """Adapter sees only a fixed synthetic request and returns a redacted observation."""

    def probe(self, request: CapabilityProbeRequest) -> CapabilityProbeObservation: ...


class FixtureCapabilityProbeAdapter:
    """Offline adapter used by the local CLI and contract tests; never opens a socket."""

    def __init__(self, observation: CapabilityProbeObservation):
        self.observation = observation

    def probe(self, request: CapabilityProbeRequest) -> CapabilityProbeObservation:
        return self.observation


def _audit(
    *,
    action: ProviderCenterAction,
    outcome: ProviderCenterOutcome,
    provider_id: str,
    profile_digest: str,
    actor_ref: str,
    diagnostic_code: str,
    occurred_at: datetime,
) -> ProviderAuditEvent:
    values = {
        "action": action,
        "outcome": outcome,
        "provider_id": provider_id,
        "profile_digest": profile_digest,
        "actor_ref": actor_ref,
        "diagnostic_code": diagnostic_code,
        "occurred_at": occurred_at,
    }
    return ProviderAuditEvent(event_id=canonical_digest(values), **values)


class ProviderCenterService:
    def __init__(
        self,
        store: ProviderCenterStore,
        *,
        now: Callable[[], datetime] = utc_now,
    ):
        self.store = store
        self.now = now

    def register(self, command: RegisterProviderCommand) -> ProviderMutationResult:
        replay = self.store.mutation_replay(command)
        if replay is not None:
            return replay
        evidence = canonical_digest(command.references.model_dump(mode="python"))
        profile = transition_provider_profile(
            command.profile,
            ProviderLifecycleState.SECRET_BOUND,
            evidence_digest=evidence,
        )
        result = ProviderMutationResult(
            command_id=command.command_id, applied=True, profile=profile
        )
        event = _audit(
            action=ProviderCenterAction.REGISTER,
            outcome=ProviderCenterOutcome.APPLIED,
            provider_id=profile.provider_id,
            profile_digest=profile.profile_digest,
            actor_ref=command.actor_ref,
            diagnostic_code="references_bound",
            occurred_at=command.issued_at,
        )

        def mutation(db):
            if db.execute(
                "SELECT 1 FROM provider_center_profiles WHERE provider_id=?",
                (profile.provider_id,),
            ).fetchone():
                raise ProviderCenterConflict("Provider already exists")
            db.execute(
                "INSERT INTO provider_center_profiles VALUES (?,?,?,?,?,?)",
                (
                    profile.profile_digest,
                    profile.provider_id,
                    profile.revision,
                    1,
                    profile.model_dump_json(),
                    command.references.model_dump_json(),
                ),
            )

        return self.store.apply_mutation(command, result, event, mutation)

    def update(self, command: UpdateProviderCommand) -> ProviderMutationResult:
        replay = self.store.mutation_replay(command)
        if replay is not None:
            return replay
        current = self.store.current_profile(command.replacement.provider_id)
        if current.profile_digest != command.expected_profile_digest:
            raise ProviderCenterConflict("current Provider Profile changed")
        expected = revise_provider_profile(
            current,
            display_name=command.replacement.display_name,
            protocol=command.replacement.protocol,
            protocol_adapter_id=command.replacement.protocol_adapter_id,
            endpoint_reference_id=command.replacement.endpoint_reference_id,
            credential_reference_id=command.replacement.credential_reference_id,
            data_policy_id=command.replacement.data_policy_id,
            allowed_context_data_classes=command.replacement.allowed_context_data_classes,
        )
        if command.replacement != expected:
            raise ProviderCenterConflict("replacement Provider revision is not canonical")
        evidence = canonical_digest(command.references.model_dump(mode="python"))
        replacement = transition_provider_profile(
            command.replacement,
            ProviderLifecycleState.SECRET_BOUND,
            evidence_digest=evidence,
        )
        result = ProviderMutationResult(
            command_id=command.command_id, applied=True, profile=replacement
        )
        event = _audit(
            action=ProviderCenterAction.UPDATE,
            outcome=ProviderCenterOutcome.APPLIED,
            provider_id=replacement.provider_id,
            profile_digest=replacement.profile_digest,
            actor_ref=command.actor_ref,
            diagnostic_code="new_revision_bound",
            occurred_at=command.issued_at,
        )

        def mutation(db):
            row = db.execute(
                "SELECT profile_json FROM provider_center_profiles "
                "WHERE provider_id=? AND is_current=1",
                (replacement.provider_id,),
            ).fetchone()
            if row is None or row[0] != current.model_dump_json():
                raise ProviderCenterConflict("current Provider Profile changed")
            db.execute(
                "UPDATE provider_center_profiles SET is_current=0 WHERE provider_id=?",
                (replacement.provider_id,),
            )
            db.execute(
                "INSERT INTO provider_center_profiles VALUES (?,?,?,?,?,?)",
                (
                    replacement.profile_digest,
                    replacement.provider_id,
                    replacement.revision,
                    1,
                    replacement.model_dump_json(),
                    command.references.model_dump_json(),
                ),
            )

        return self.store.apply_mutation(command, result, event, mutation)

    def probe(
        self,
        request: CapabilityProbeRequest,
        adapter: CapabilityProbeAdapter,
    ) -> CapabilityProbeResult:
        replay = self.store.probe_replay(request)
        if replay is not None:
            return replay
        profile = self._current_profile_for_digest(request.provider_profile_digest)
        if profile.state is not ProviderLifecycleState.SECRET_BOUND:
            raise ProviderCenterConflict("Provider is not ready for an initial capability probe")
        self.store.claim_probe(request)
        started_at = self.now()
        if started_at >= request.deadline:
            observed = CapabilityProbeObservation(
                status=CapabilityProbeStatus.TIMED_OUT,
                cleanup_verified=True,
                diagnostic_code="probe_deadline_expired",
                observed_at=started_at,
            )
        else:
            observed = adapter.probe(request)
        now = self.now()
        if observed.observed_at < request.created_at or observed.observed_at > now:
            raise ProviderCenterConflict("capability probe observation time is invalid")
        status = observed.status
        diagnostic_code = observed.diagnostic_code
        if now >= request.deadline or observed.observed_at >= request.deadline:
            status = CapabilityProbeStatus.TIMED_OUT
            diagnostic_code = "probe_deadline_expired"
        elif status is CapabilityProbeStatus.PASSED and not observed.cleanup_verified:
            status = CapabilityProbeStatus.FAILED
            diagnostic_code = "cleanup_unverified"
        elif status is CapabilityProbeStatus.PASSED and set(observed.passed_capabilities) != set(
            request.capabilities
        ):
            status = CapabilityProbeStatus.FAILED
            diagnostic_code = "capability_set_mismatch"
        manifest = None
        if status is CapabilityProbeStatus.PASSED:
            probe_digest = canonical_digest(observed.model_dump(mode="python"))
            manifest = CapabilityManifest.create(
                provider_profile_digest=profile.profile_digest,
                provider_model_id=request.provider_model_id,
                protocol_adapter_digest=request.protocol_adapter_digest,
                assessments=tuple(
                    ModelCapabilityAssessment(
                        capability=capability,
                        status=CapabilityStatus.PROBED,
                        probe_result_digest=probe_digest,
                    )
                    for capability in request.capabilities
                ),
                max_context_tokens=request.max_context_tokens,
                max_output_tokens=request.max_output_tokens,
                observed_at=observed.observed_at,
            )
        values = {
            "request_id": request.request_id,
            "provider_profile_digest": profile.profile_digest,
            "status": status,
            "manifest": manifest,
            "cleanup_verified": observed.cleanup_verified,
            "diagnostic_code": diagnostic_code,
            "completed_at": now,
        }
        digest_values = {
            **values,
            "manifest": None if manifest is None else manifest.model_dump(mode="python"),
        }
        result = CapabilityProbeResult(result_id=canonical_digest(digest_values), **values)
        updated = profile
        if status is CapabilityProbeStatus.PASSED:
            for target in (
                ProviderLifecycleState.CONNECTIVITY_VERIFIED,
                ProviderLifecycleState.CATALOG_DISCOVERED,
                ProviderLifecycleState.CAPABILITIES_PROBED,
            ):
                updated = transition_provider_profile(
                    updated, target, evidence_digest=result.result_id
                )
        outcome = {
            CapabilityProbeStatus.PASSED: ProviderCenterOutcome.APPLIED,
            CapabilityProbeStatus.FAILED: ProviderCenterOutcome.REJECTED,
            CapabilityProbeStatus.TIMED_OUT: ProviderCenterOutcome.TIMED_OUT,
        }[status]
        event = _audit(
            action=ProviderCenterAction.PROBE,
            outcome=outcome,
            provider_id=profile.provider_id,
            profile_digest=profile.profile_digest,
            actor_ref=request.actor_ref,
            diagnostic_code=diagnostic_code,
            occurred_at=now,
        )
        self.store.complete_probe(result, profile, updated, event)
        return result

    def enable(self, command: EnableProviderCommand) -> ProviderMutationResult:
        replay = self.store.mutation_replay(command)
        if replay is not None:
            return replay
        profile = self._current_profile_for_digest(command.expected_profile_digest)
        if profile.provider_id != command.provider_id:
            raise ProviderCenterConflict("Provider identity mismatch")
        references = self.store.references(profile.profile_digest)
        if (
            references.endpoint.reference_id != profile.endpoint_reference_id
            or references.credential.reference_id != profile.credential_reference_id
        ):
            raise ProviderCenterConflict("Provider references are incomplete")
        enabled = transition_provider_profile(
            profile,
            ProviderLifecycleState.ROLE_ADMITTED,
            evidence_digest=command.command_id,
        )
        manifests = self.store.manifests_for(profile.profile_digest)
        self._validate_route(command.route, command.fallback_policy, override=enabled)
        result = ProviderMutationResult(
            command_id=command.command_id,
            applied=True,
            profile=enabled,
            route=command.route,
        )
        event = _audit(
            action=ProviderCenterAction.ENABLE,
            outcome=ProviderCenterOutcome.APPLIED,
            provider_id=profile.provider_id,
            profile_digest=profile.profile_digest,
            actor_ref=command.actor_ref,
            diagnostic_code=f"role_admitted_{len(manifests)}_manifest",
            occurred_at=command.issued_at,
        )

        def mutation(db):
            row = db.execute(
                "SELECT profile_json FROM provider_center_profiles "
                "WHERE profile_digest=? AND is_current=1",
                (profile.profile_digest,),
            ).fetchone()
            if row is None or row[0] != profile.model_dump_json():
                raise ProviderCenterConflict("Provider lifecycle changed during enable")
            changed = db.execute(
                "UPDATE provider_center_profiles SET profile_json=? "
                "WHERE profile_digest=? AND is_current=1",
                (enabled.model_dump_json(), enabled.profile_digest),
            ).rowcount
            if changed != 1:
                raise ProviderCenterConflict("Provider enable update failed")
            db.execute(
                "INSERT INTO provider_center_routes VALUES (?,?,?,?) "
                "ON CONFLICT(engine,agent_role) DO UPDATE SET "
                "route_json=excluded.route_json,fallback_json=excluded.fallback_json",
                (
                    command.route.engine.value,
                    command.route.agent_role.value,
                    command.route.model_dump_json(),
                    command.fallback_policy.model_dump_json(),
                ),
            )

        return self.store.apply_mutation(command, result, event, mutation)

    def disable(self, command: DisableProviderCommand) -> ProviderMutationResult:
        replay = self.store.mutation_replay(command)
        if replay is not None:
            return replay
        profile = self._current_profile_for_digest(command.expected_profile_digest)
        if profile.provider_id != command.provider_id:
            raise ProviderCenterConflict("Provider identity mismatch")
        disabled = transition_provider_profile(
            profile,
            ProviderLifecycleState.DISABLED,
            evidence_digest=command.reason_digest,
        )
        result = ProviderMutationResult(
            command_id=command.command_id, applied=True, profile=disabled
        )
        event = _audit(
            action=ProviderCenterAction.DISABLE,
            outcome=ProviderCenterOutcome.APPLIED,
            provider_id=profile.provider_id,
            profile_digest=profile.profile_digest,
            actor_ref=command.actor_ref,
            diagnostic_code="provider_disabled",
            occurred_at=command.issued_at,
        )

        def mutation(db):
            row = db.execute(
                "SELECT profile_json FROM provider_center_profiles "
                "WHERE profile_digest=? AND is_current=1",
                (profile.profile_digest,),
            ).fetchone()
            if row is None or row[0] != profile.model_dump_json():
                raise ProviderCenterConflict("Provider lifecycle changed during disable")
            changed = db.execute(
                "UPDATE provider_center_profiles SET profile_json=? "
                "WHERE profile_digest=? AND is_current=1",
                (disabled.model_dump_json(), disabled.profile_digest),
            ).rowcount
            if changed != 1:
                raise ProviderCenterConflict("Provider disable update failed")

        return self.store.apply_mutation(command, result, event, mutation)

    def set_default_route(self, command: SetDefaultRouteCommand) -> ProviderMutationResult:
        replay = self.store.mutation_replay(command)
        if replay is not None:
            return replay
        profile = self._validate_route(command.route, command.fallback_policy)
        result = ProviderMutationResult(
            command_id=command.command_id,
            applied=True,
            profile=profile,
            route=command.route,
        )
        event = _audit(
            action=ProviderCenterAction.ROUTE_SET,
            outcome=ProviderCenterOutcome.APPLIED,
            provider_id=profile.provider_id,
            profile_digest=profile.profile_digest,
            actor_ref=command.actor_ref,
            diagnostic_code="default_route_updated",
            occurred_at=command.issued_at,
        )

        def mutation(db):
            row = db.execute(
                "SELECT profile_json FROM provider_center_profiles "
                "WHERE profile_digest=? AND is_current=1",
                (profile.profile_digest,),
            ).fetchone()
            if row is None or row[0] != profile.model_dump_json():
                raise ProviderCenterConflict("Provider lifecycle changed during route update")
            db.execute(
                "INSERT INTO provider_center_routes VALUES (?,?,?,?) "
                "ON CONFLICT(engine,agent_role) DO UPDATE SET "
                "route_json=excluded.route_json,fallback_json=excluded.fallback_json",
                (
                    command.route.engine.value,
                    command.route.agent_role.value,
                    command.route.model_dump_json(),
                    command.fallback_policy.model_dump_json(),
                ),
            )

        return self.store.apply_mutation(command, result, event, mutation)

    def _current_profile_for_digest(self, profile_digest: str):
        profiles = self.store.view(audit_limit=0).profiles
        matches = tuple(item for item in profiles if item.profile_digest == profile_digest)
        if len(matches) != 1:
            raise ProviderCenterConflict("current Provider Profile is unavailable")
        return matches[0]

    def _validate_route(self, route, fallback_policy, *, override=None):
        view = self.store.view(audit_limit=0)
        profiles = {item.profile_digest: item for item in view.profiles}
        if override is not None:
            profiles[override.profile_digest] = override
        manifests = {item.manifest_digest: item for item in view.capability_manifests}
        build_flow_model_snapshot(
            flow_id=UUID(int=0),
            routes=(route,),
            profiles=profiles,
            manifests=manifests,
            fallback_policies={fallback_policy.policy_digest: fallback_policy},
            routing_policy_digest=canonical_digest({"provider_center": "route_validation"}),
            prompt_contract_digest=canonical_digest({"provider_center": "prompt_contract"}),
            tool_schema_digest=canonical_digest({"provider_center": "tool_schema"}),
            created_at=self.now(),
        )
        return profiles[route.primary_model.provider_profile_digest]
