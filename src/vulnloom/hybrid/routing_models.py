"""Typed contracts for routing one Source Candidate to exact live Validation."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class LiveEndpointReference(DomainModel):
    """Opaque pointer to trusted local endpoint configuration."""

    reference_id: Digest
    configuration_key: str = Field(pattern=r"^HYBRID_ENDPOINT_[A-Z0-9_]{1,111}$")

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reference_id != canonical_digest(
            {"configuration_key": self.configuration_key}
        ):
            raise ValueError("Live Endpoint Reference content digest mismatch")
        return self

    @classmethod
    def create(cls, *, configuration_key: str) -> LiveEndpointReference:
        return cls(
            reference_id=canonical_digest({"configuration_key": configuration_key}),
            configuration_key=configuration_key,
        )


class HybridRoutePolicy(DomainModel):
    policy_id: Digest
    validation_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_registry_digest: Digest
    runner_wall_seconds: int = Field(default=60, ge=1, le=600)
    connect_seconds: float = Field(default=3.0, gt=0, le=30)
    read_seconds: float = Field(default=10.0, gt=0, le=60)
    total_seconds: float = Field(default=15.0, gt=0, le=120)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1, le=20 * 1024 * 1024)
    materialization_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.total_seconds < max(self.connect_seconds, self.read_seconds):
            raise ValueError("Hybrid Route HTTP total timeout is too small")
        if self.policy_id != canonical_digest(
            self.model_dump(mode="python", exclude={"policy_id"})
        ):
            raise ValueError("Hybrid Route Policy content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> HybridRoutePolicy:
        expanded = cls.model_construct(policy_id="0" * 64, **values).model_dump(
            mode="python", exclude={"policy_id"}
        )
        return cls(policy_id=canonical_digest(expanded), **expanded)


class HybridRouteRequest(DomainModel):
    route_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_target_id: UUID
    source_target_version: str = Field(min_length=1, max_length=256)
    source_manifest_digest: Digest
    live_target_id: UUID
    deployment_proof_id: Digest
    deployment_proof_digest: Digest
    endpoint_reference: LiveEndpointReference
    endpoint_url_digest: Digest
    expected_status_code: int = Field(ge=100, le=599)
    expected_body_sha256: Digest
    test_class: str = Field(min_length=1, max_length=128)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    route_policy_id: Digest
    selected_by: str = Field(pattern=r"^operator:[a-zA-Z0-9._-]{1,200}$")
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Hybrid Route window is invalid")
        if self.route_id != canonical_digest(
            self.model_dump(mode="python", exclude={"route_id"})
        ):
            raise ValueError("Hybrid Route Request content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> HybridRouteRequest:
        expanded = cls.model_construct(route_id="0" * 64, **values).model_dump(
            mode="python", exclude={"route_id"}
        )
        return cls(route_id=canonical_digest(expanded), **expanded)


class HybridRouteState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class HybridRouteOutcome(DomainModel):
    route_id: Digest
    state: HybridRouteState
    attempt: int = Field(ge=1, le=3)
    validation_plan_id: Digest | None = None
    validation_plan_digest: Digest | None = None
    endpoint_reference_id: Digest
    endpoint_url_digest: Digest
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        if self.state is HybridRouteState.STARTED:
            raise ValueError("Hybrid Route outcome must be terminal")
        has_plan = self.validation_plan_id is not None
        if (
            has_plan != (self.validation_plan_digest is not None)
            or has_plan != (self.state is HybridRouteState.COMPLETED)
            or not self.cleanup_complete
        ):
            raise ValueError("Hybrid Route outcome bindings are inconsistent")
        return self
