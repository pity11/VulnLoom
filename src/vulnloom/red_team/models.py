"""Typed contracts for an authorized, bounded Red Team flow."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.workflows import (
    AutonomyLevel,
    ExecutionProfile,
    Visibility,
    WorkflowKind,
    WorkflowMode,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ReasonCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]


class RedTeamPhase(StrEnum):
    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    VALIDATION = "validation"
    POST_EXPLOITATION = "post_exploitation"


class ImpactClass(StrEnum):
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    REAL_CREDENTIAL = "real_credential"
    EXTERNAL_CALLBACK = "external_callback"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"


class RedTeamActionKind(StrEnum):
    DNS_LOOKUP = "dns_lookup"
    TLS_INSPECT = "tls_inspect"
    HTTP_HEAD = "http_head"


class RedTeamFlowStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    KILLED = "killed"


class ReconOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class ServiceTlsVersion(StrEnum):
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"


class AttackSurfaceSnapshot(DomainModel):
    """Redacted, content-addressed facts produced by one trusted Recon action."""

    snapshot_id: Digest
    plan_id: Digest
    action_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    requested_url_digest: Digest
    final_url_digest: Digest
    status_code: int = Field(ge=100, le=599)
    peer_ip: str = Field(min_length=1, max_length=64)
    redirect_count: int = Field(ge=0, le=5)
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=6)]
    policy_record_digests: Annotated[
        tuple[Digest, ...], Field(min_length=1, max_length=6)
    ]
    captured_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.snapshot_id != canonical_digest(
            self.model_dump(mode="python", exclude={"snapshot_id"})
        ):
            raise ValueError("Attack Surface Snapshot content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackSurfaceSnapshot:
        expanded = cls.model_construct(snapshot_id="0" * 64, **values).model_dump(
            mode="python", exclude={"snapshot_id"}
        )
        return cls(snapshot_id=canonical_digest(expanded), **expanded)


class ServiceIdentitySnapshot(DomainModel):
    """Redacted identity facts from one CA- and hostname-verified TLS session."""

    snapshot_id: Digest
    plan_id: Digest
    action_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    endpoint_url_digest: Digest
    peer_ip: str = Field(min_length=1, max_length=64)
    tls_version: ServiceTlsVersion
    cipher_suite: str = Field(pattern=r"^[A-Z0-9_-]{1,128}$")
    cipher_bits: int = Field(ge=112, le=1024)
    leaf_certificate_sha256: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=1)]
    policy_record_digests: Annotated[
        tuple[Digest, ...], Field(min_length=1, max_length=1)
    ]
    captured_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.snapshot_id != canonical_digest(
            self.model_dump(mode="python", exclude={"snapshot_id"})
        ):
            raise ValueError("Service Identity Snapshot content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> ServiceIdentitySnapshot:
        expanded = cls.model_construct(snapshot_id="0" * 64, **values).model_dump(
            mode="python", exclude={"snapshot_id"}
        )
        return cls(snapshot_id=canonical_digest(expanded), **expanded)


class AuthorizedWebTarget(DomainModel):
    target_id: UUID = Field(default_factory=uuid4)
    url: str = Field(min_length=1, max_length=2_048)

    @field_validator("url")
    @classmethod
    def normalized_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Red Team target must be an uncredentialed HTTP(S) base URL")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Red Team target port is invalid") from exc
        default = 443 if parsed.scheme.lower() == "https" else 80
        host = parsed.hostname.lower()
        rendered_host = f"[{host}]" if ":" in host else host
        netloc = (
            f"{rendered_host}:{port}"
            if port is not None and port != default
            else rendered_host
        )
        path = parsed.path or "/"
        normalized = urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
        if (
            not value.isascii()
            or any(ord(character) <= 32 for character in value)
            or normalized != value
        ):
            raise ValueError("Red Team target URL must already be canonical")
        return value


class RedTeamStopConditions(DomainModel):
    stop_at: AwareDatetime
    max_actions: int = Field(ge=1, le=10_000)
    max_consecutive_failures: int = Field(default=3, ge=1, le=20)


class RulesOfEngagement(DomainModel):
    roe_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    phases: Annotated[tuple[RedTeamPhase, ...], Field(min_length=1)]
    allowed_test_classes: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    allowed_impacts: Annotated[tuple[ImpactClass, ...], Field(min_length=1)]
    approval_required_impacts: tuple[ImpactClass, ...]
    prohibited_impacts: tuple[ImpactClass, ...]
    stop_conditions: RedTeamStopConditions
    emergency_contact_ref: str = Field(
        pattern=r"^contact:[a-zA-Z0-9._-]{1,200}$"
    )

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if len(set(self.phases)) != len(self.phases):
            raise ValueError("Rules of Engagement phases must be unique")
        if tuple(sorted(set(self.allowed_test_classes))) != self.allowed_test_classes:
            raise ValueError("Rules of Engagement test classes must be sorted and unique")
        impact_groups = (
            set(self.allowed_impacts),
            set(self.approval_required_impacts),
            set(self.prohibited_impacts),
        )
        if any(
            left & right
            for index, left in enumerate(impact_groups)
            for right in impact_groups[index + 1 :]
        ):
            raise ValueError("Rules of Engagement impact classes overlap")
        if self.roe_id != canonical_digest(
            self.model_dump(mode="python", exclude={"roe_id"})
        ):
            raise ValueError("Rules of Engagement content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RulesOfEngagement:
        digest_values = dict(values)
        digest_values["stop_conditions"] = values["stop_conditions"].model_dump(  # type: ignore[union-attr]
            mode="python"
        )
        return cls(roe_id=canonical_digest(digest_values), **values)


class RedTeamFlowPlan(DomainModel):
    plan_id: Digest
    mode: WorkflowMode
    target: AuthorizedWebTarget
    rules: RulesOfEngagement
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.mode.workflow is not WorkflowKind.AUTHORIZED_RED_TEAM
            or self.mode.execution_profile is not ExecutionProfile.RED_TEAM
            or self.mode.visibility not in {Visibility.BLACK_BOX, Visibility.GREY_BOX}
            or self.mode.autonomy is not AutonomyLevel.BOUNDED_EXECUTION
        ):
            raise ValueError("Red Team V1 requires bounded black/grey-box mode")
        if self.target.target_id != self.rules.target_id:
            raise ValueError("Red Team target and Rules of Engagement do not match")
        if not self.created_at < self.deadline <= self.rules.stop_conditions.stop_at:
            raise ValueError("Red Team deadline exceeds its stop conditions")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("Red Team plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamFlowPlan:
        digest_values = dict(values)
        for key in ("mode", "target", "rules"):
            digest_values[key] = values[key].model_dump(mode="python")  # type: ignore[union-attr]
        return cls(plan_id=canonical_digest(digest_values), **values)


class RedTeamCheckpoint(DomainModel):
    checkpoint_id: Digest
    plan_id: Digest
    revision: int = Field(ge=0)
    status: RedTeamFlowStatus
    actions_used: int = Field(ge=0)
    consecutive_failures: int = Field(ge=0)
    observation_ids: tuple[Digest, ...]
    stop_reason: ReasonCode | None = None
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        terminal = self.status in {
            RedTeamFlowStatus.COMPLETED,
            RedTeamFlowStatus.CANCELLED,
            RedTeamFlowStatus.TIMED_OUT,
            RedTeamFlowStatus.FAILED,
            RedTeamFlowStatus.KILLED,
        }
        if terminal != (self.stop_reason is not None):
            raise ValueError("Red Team terminal status and stop reason are inconsistent")
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ValueError("Red Team observation references must be unique")
        if self.checkpoint_id != canonical_digest(
            self.model_dump(mode="python", exclude={"checkpoint_id"})
        ):
            raise ValueError("Red Team checkpoint content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **expanded)


class RedTeamReconAction(DomainModel):
    action_id: Digest
    plan_id: Digest
    expected_checkpoint_id: Digest
    kind: RedTeamActionKind
    target_url: str = Field(min_length=1, max_length=2_048)
    test_class: str = Field(min_length=1, max_length=128)
    impact: ImpactClass = ImpactClass.READ_ONLY
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.impact is not ImpactClass.READ_ONLY:
            raise ValueError("Red Team V1 Recon action must be read-only")
        if self.deadline <= self.created_at:
            raise ValueError("Red Team Recon deadline must be after creation")
        if self.action_id != canonical_digest(
            self.model_dump(mode="python", exclude={"action_id"})
        ):
            raise ValueError("Red Team Recon action content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamReconAction:
        expanded = cls.model_construct(action_id="0" * 64, **values).model_dump(
            mode="python", exclude={"action_id"}
        )
        return cls(action_id=canonical_digest(expanded), **expanded)


class RedTeamReconCommand(DomainModel):
    command_id: Digest
    action: RedTeamReconAction
    attempt: int = Field(default=1, ge=1, le=3)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("Red Team Recon command content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamReconCommand:
        expanded = cls.model_construct(command_id="0" * 64, **values).model_dump(
            mode="python", exclude={"command_id"}
        )
        return cls(command_id=canonical_digest(expanded), **expanded)


class RedTeamReconObservation(DomainModel):
    observation_id: Digest
    action_id: Digest
    outcome: ReconOutcome
    status_code: int | None = Field(default=None, ge=100, le=599)
    reason_code: ReasonCode
    cleanup_complete: bool
    sensitive_data_redacted: bool = True
    attack_surface: AttackSurfaceSnapshot | None = None
    service_identity: ServiceIdentitySnapshot | None = None
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.outcome is ReconOutcome.SUCCEEDED and not self.cleanup_complete:
            raise ValueError("Successful Recon requires cleanup proof")
        if not self.sensitive_data_redacted:
            raise ValueError("Recon observation must be redacted")
        if self.attack_surface is not None and (
            self.outcome is not ReconOutcome.SUCCEEDED
            or self.status_code != self.attack_surface.status_code
            or self.action_id != self.attack_surface.action_id
        ):
            raise ValueError("Recon Attack Surface binding is invalid")
        if self.service_identity is not None and (
            self.outcome is not ReconOutcome.SUCCEEDED
            or self.status_code is not None
            or self.action_id != self.service_identity.action_id
        ):
            raise ValueError("Recon Service Identity binding is invalid")
        if self.attack_surface is not None and self.service_identity is not None:
            raise ValueError("Recon observation cannot contain multiple snapshot kinds")
        if self.observation_id != canonical_digest(
            self.model_dump(mode="python", exclude={"observation_id"})
        ):
            raise ValueError("Red Team observation content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamReconObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)
