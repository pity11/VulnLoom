"""Typed contracts for deterministic, offline Attack Surface reduction."""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest


class AttackSurfaceReductionState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class AttackSurfaceReductionLimits(DomainModel):
    max_observations: int = Field(default=1_000, ge=1, le=10_000)
    max_endpoints: int = Field(default=1_000, ge=1, le=10_000)
    max_evidence_refs: int = Field(default=6_000, ge=1, le=60_000)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_attempts: int = Field(default=3, ge=1, le=3)


class AttackSurfaceReductionPlan(DomainModel):
    reduction_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=10_000)]
    snapshot_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=10_000)]
    limits: AttackSurfaceReductionLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Attack Surface reduction deadline must follow creation")
        if (
            self.observation_ids != tuple(sorted(set(self.observation_ids)))
            or self.snapshot_ids != tuple(sorted(set(self.snapshot_ids)))
            or len(self.observation_ids) != len(self.snapshot_ids)
            or len(self.observation_ids) > self.limits.max_observations
        ):
            raise ValueError("Attack Surface reduction inputs must be bounded, unique, and sorted")
        if self.reduction_id != canonical_digest(
            self.model_dump(mode="python", exclude={"reduction_id"})
        ):
            raise ValueError("Attack Surface reduction plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackSurfaceReductionPlan:
        expanded = cls.model_construct(reduction_id="0" * 64, **values).model_dump(
            mode="python", exclude={"reduction_id"}
        )
        return cls(reduction_id=canonical_digest(expanded), **expanded)


class AttackSurfaceEndpoint(DomainModel):
    endpoint_id: Digest
    requested_url_digest: Digest
    final_url_digest: Digest
    peer_ip: str = Field(min_length=1, max_length=64)
    status_codes: Annotated[tuple[int, ...], Field(min_length=1, max_length=100)]
    redirect_counts: Annotated[tuple[int, ...], Field(min_length=1, max_length=6)]
    observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=10_000)]
    snapshot_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=10_000)]
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=60_000)]
    first_observed_at: AwareDatetime
    last_observed_at: AwareDatetime

    @field_validator("peer_ip")
    @classmethod
    def normalized_peer(cls, value: str) -> str:
        normalized = str(ipaddress.ip_address(value))
        if normalized != value:
            raise ValueError("Attack Surface peer IP must be normalized")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.status_codes != tuple(sorted(set(self.status_codes)))
            or any(item < 100 or item > 599 for item in self.status_codes)
            or self.redirect_counts != tuple(sorted(set(self.redirect_counts)))
            or any(item < 0 or item > 5 for item in self.redirect_counts)
            or self.observation_ids != tuple(sorted(set(self.observation_ids)))
            or self.snapshot_ids != tuple(sorted(set(self.snapshot_ids)))
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or len(self.observation_ids) != len(self.snapshot_ids)
            or self.first_observed_at > self.last_observed_at
        ):
            raise ValueError("Attack Surface endpoint facts are not canonical")
        identity = {
            "requested_url_digest": self.requested_url_digest,
            "final_url_digest": self.final_url_digest,
            "peer_ip": self.peer_ip,
        }
        if self.endpoint_id != canonical_digest(identity):
            raise ValueError("Attack Surface endpoint identity mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackSurfaceEndpoint:
        identity = {
            "requested_url_digest": values["requested_url_digest"],
            "final_url_digest": values["final_url_digest"],
            "peer_ip": values["peer_ip"],
        }
        return cls(endpoint_id=canonical_digest(identity), **values)


class AttackSurfaceInventory(DomainModel):
    inventory_id: Digest
    reduction_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=10_000)]
    snapshot_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=10_000)]
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=60_000)]
    endpoints: Annotated[tuple[AttackSurfaceEndpoint, ...], Field(min_length=1, max_length=10_000)]
    reduced_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        endpoint_ids = tuple(item.endpoint_id for item in self.endpoints)
        if (
            self.observation_ids != tuple(sorted(set(self.observation_ids)))
            or self.snapshot_ids != tuple(sorted(set(self.snapshot_ids)))
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or endpoint_ids != tuple(sorted(set(endpoint_ids)))
            or len(self.observation_ids) != len(self.snapshot_ids)
            or set(self.observation_ids)
            != {item for endpoint in self.endpoints for item in endpoint.observation_ids}
            or set(self.snapshot_ids)
            != {item for endpoint in self.endpoints for item in endpoint.snapshot_ids}
            or set(self.evidence_refs)
            != {item for endpoint in self.endpoints for item in endpoint.evidence_refs}
        ):
            raise ValueError("Attack Surface inventory facts are not canonical")
        if self.inventory_id != canonical_digest(
            self.model_dump(mode="python", exclude={"inventory_id"})
        ):
            raise ValueError("Attack Surface inventory content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackSurfaceInventory:
        expanded = cls.model_construct(inventory_id="0" * 64, **values).model_dump(
            mode="python", exclude={"inventory_id"}
        )
        return cls(inventory_id=canonical_digest(expanded), **expanded)


class AttackSurfaceReductionOutcome(DomainModel):
    reduction_id: Digest
    inventory: AttackSurfaceInventory
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: bool = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.inventory.reduction_id != self.reduction_id or not self.cleanup_complete:
            raise ValueError("Attack Surface reduction outcome is invalid")
        return self
