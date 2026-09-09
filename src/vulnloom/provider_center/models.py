"""Typed, secret-free Provider Center commands and query results."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.adapters import ModelCredentialReference, ModelEndpointReference
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.model_routing import (
    CapabilityManifest,
    FallbackPolicy,
    ModelCapability,
    ModelRoute,
    ProviderProfile,
)
from vulnloom.domain.models import DomainModel

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
IdempotencyKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]


class ProviderCenterAction(StrEnum):
    REGISTER = "register"
    UPDATE = "update"
    PROBE = "probe"
    ENABLE = "enable"
    DISABLE = "disable"
    ROUTE_SET = "route_set"


class ProviderCenterOutcome(StrEnum):
    APPLIED = "applied"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


class CapabilityProbeStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ProviderHealthStatus(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    DISABLED = "disabled"


class ProviderReferenceBundle(DomainModel):
    endpoint: ModelEndpointReference
    credential: ModelCredentialReference


class RegisterProviderCommand(DomainModel):
    command_id: Digest
    idempotency_key: IdempotencyKey
    profile: ProviderProfile
    references: ProviderReferenceBundle
    actor_ref: Digest
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.profile.revision != 1 or self.profile.state.value != "draft":
            raise ValueError("registered Provider Profile must be an initial draft")
        if (
            self.profile.endpoint_reference_id != self.references.endpoint.reference_id
            or self.profile.credential_reference_id != self.references.credential.reference_id
        ):
            raise ValueError("Provider Profile references are incomplete")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"command_id"}))
        if self.command_id != expected:
            raise ValueError("register Provider command digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        idempotency_key: str,
        profile: ProviderProfile,
        references: ProviderReferenceBundle,
        actor_ref: str,
        issued_at: datetime,
    ) -> RegisterProviderCommand:
        values = {
            "idempotency_key": idempotency_key,
            "profile": profile,
            "references": references,
            "actor_ref": actor_ref,
            "issued_at": issued_at,
        }
        digest_values = {
            **values,
            "profile": profile.model_dump(mode="python"),
            "references": references.model_dump(mode="python"),
        }
        return cls(command_id=canonical_digest(digest_values), **values)


class UpdateProviderCommand(DomainModel):
    command_id: Digest
    idempotency_key: IdempotencyKey
    expected_profile_digest: Digest
    replacement: ProviderProfile
    references: ProviderReferenceBundle
    actor_ref: Digest
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.replacement.state.value != "draft":
            raise ValueError("replacement Provider Profile must be a draft")
        if (
            self.replacement.endpoint_reference_id != self.references.endpoint.reference_id
            or self.replacement.credential_reference_id != self.references.credential.reference_id
        ):
            raise ValueError("replacement Provider Profile references are incomplete")
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("update Provider command digest mismatch")
        return self


class CapabilityProbeRequest(DomainModel):
    request_id: Digest
    idempotency_key: IdempotencyKey
    provider_profile_digest: Digest
    provider_model_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
    protocol_adapter_digest: Digest
    capabilities: Annotated[tuple[ModelCapability, ...], Field(min_length=1)]
    max_context_tokens: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    synthetic_only: Literal[True] = True
    actor_ref: Digest
    created_at: AwareDatetime
    deadline: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        ordered = tuple(sorted(set(self.capabilities), key=lambda item: item.value))
        if self.capabilities != ordered:
            raise ValueError("probe capabilities must be unique and sorted")
        if self.created_at >= self.deadline:
            raise ValueError("capability probe deadline must be in the future")
        if self.request_id != canonical_digest(
            self.model_dump(mode="python", exclude={"request_id"})
        ):
            raise ValueError("capability probe request digest mismatch")
        return self


class CapabilityProbeObservation(DomainModel):
    status: CapabilityProbeStatus
    passed_capabilities: tuple[ModelCapability, ...] = ()
    failed_capabilities: tuple[ModelCapability, ...] = ()
    cleanup_verified: bool
    diagnostic_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def consistent(self) -> Self:
        passed = tuple(sorted(set(self.passed_capabilities), key=lambda item: item.value))
        failed = tuple(sorted(set(self.failed_capabilities), key=lambda item: item.value))
        if self.passed_capabilities != passed or self.failed_capabilities != failed:
            raise ValueError("probe capability outcomes must be unique and sorted")
        if set(passed) & set(failed):
            raise ValueError("probe capability cannot both pass and fail")
        if self.status is CapabilityProbeStatus.PASSED and (failed or not passed):
            raise ValueError("passed probe must contain only passed capabilities")
        if self.status is CapabilityProbeStatus.TIMED_OUT and (passed or failed):
            raise ValueError("timed out probe cannot claim capability results")
        return self


class CapabilityProbeResult(DomainModel):
    result_id: Digest
    request_id: Digest
    provider_profile_digest: Digest
    status: CapabilityProbeStatus
    manifest: CapabilityManifest | None = None
    cleanup_verified: bool
    diagnostic_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (self.status is CapabilityProbeStatus.PASSED) != (self.manifest is not None):
            raise ValueError("only a passed probe may publish a Capability Manifest")
        if self.result_id != canonical_digest(
            self.model_dump(mode="python", exclude={"result_id"})
        ):
            raise ValueError("capability probe result digest mismatch")
        return self


class EnableProviderCommand(DomainModel):
    command_id: Digest
    idempotency_key: IdempotencyKey
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    expected_profile_digest: Digest
    route: ModelRoute
    fallback_policy: FallbackPolicy
    actor_ref: Digest
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("enable Provider command digest mismatch")
        return self


class DisableProviderCommand(DomainModel):
    command_id: Digest
    idempotency_key: IdempotencyKey
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    expected_profile_digest: Digest
    reason_digest: Digest
    actor_ref: Digest
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("disable Provider command digest mismatch")
        return self


class SetDefaultRouteCommand(DomainModel):
    command_id: Digest
    idempotency_key: IdempotencyKey
    route: ModelRoute
    fallback_policy: FallbackPolicy
    actor_ref: Digest
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("set default route command digest mismatch")
        return self


class ProviderMutationResult(DomainModel):
    command_id: Digest
    applied: bool
    profile: ProviderProfile
    route: ModelRoute | None = None


class ProviderAuditEvent(DomainModel):
    event_id: Digest
    action: ProviderCenterAction
    outcome: ProviderCenterOutcome
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    profile_digest: Digest
    actor_ref: Digest
    diagnostic_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.event_id != canonical_digest(self.model_dump(mode="python", exclude={"event_id"})):
            raise ValueError("Provider audit event digest mismatch")
        return self


class ProviderHealthView(DomainModel):
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    provider_profile_digest: Digest
    status: ProviderHealthStatus
    last_probe_at: AwareDatetime | None = None
    cleanup_verified: bool | None = None
    diagnostic_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")


class ProviderCenterView(DomainModel):
    profiles: tuple[ProviderProfile, ...]
    health: tuple[ProviderHealthView, ...]
    capability_manifests: tuple[CapabilityManifest, ...]
    default_routes: tuple[ModelRoute, ...]
    recent_audit: tuple[ProviderAuditEvent, ...]


class CapabilityProbeFixture(DomainModel):
    observation: CapabilityProbeObservation
