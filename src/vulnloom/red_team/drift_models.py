"""Typed contracts for deterministic Attack Surface drift comparison."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest


class AttackSurfaceDriftState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class AttackSurfaceChangeKind(StrEnum):
    ENDPOINT_ADDED = "endpoint_added"
    ENDPOINT_REMOVED = "endpoint_removed"
    PEER_SET_CHANGED = "peer_set_changed"
    FINAL_DESTINATION_CHANGED = "final_destination_changed"
    HTTP_STATUS_CHANGED = "http_status_changed"
    REDIRECT_BEHAVIOR_CHANGED = "redirect_behavior_changed"
    TLS_IDENTITY_ADDED = "tls_identity_added"
    TLS_IDENTITY_REMOVED = "tls_identity_removed"
    TLS_VERSION_CHANGED = "tls_version_changed"
    CIPHER_CHANGED = "cipher_changed"
    CERTIFICATE_CHANGED = "certificate_changed"


class AttackSurfaceDriftLimits(DomainModel):
    max_surfaces: int = Field(default=10_000, ge=1, le=20_000)
    max_evidence_refs: int = Field(default=60_000, ge=1, le=120_000)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_attempts: int = Field(default=3, ge=1, le=3)


class AttackSurfaceDriftPlan(DomainModel):
    comparison_id: Digest
    baseline_reduction_id: Digest
    baseline_inventory_id: Digest
    current_reduction_id: Digest
    current_inventory_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    limits: AttackSurfaceDriftLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.baseline_reduction_id == self.current_reduction_id
            or self.baseline_inventory_id == self.current_inventory_id
            or self.deadline <= self.created_at
        ):
            raise ValueError("Attack Surface drift plan requires ordered distinct inputs")
        if self.comparison_id != canonical_digest(
            self.model_dump(mode="python", exclude={"comparison_id"})
        ):
            raise ValueError("Attack Surface drift plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackSurfaceDriftPlan:
        expanded = cls.model_construct(comparison_id="0" * 64, **values).model_dump(
            mode="python", exclude={"comparison_id"}
        )
        return cls(comparison_id=canonical_digest(expanded), **expanded)


class AttackSurfaceChange(DomainModel):
    surface_key: Digest
    change_kinds: Annotated[
        tuple[AttackSurfaceChangeKind, ...], Field(min_length=1, max_length=11)
    ]
    baseline_endpoint_ids: Annotated[tuple[Digest, ...], Field(max_length=10_000)] = ()
    current_endpoint_ids: Annotated[tuple[Digest, ...], Field(max_length=10_000)] = ()
    baseline_identity_ids: Annotated[tuple[Digest, ...], Field(max_length=10_000)] = ()
    current_identity_ids: Annotated[tuple[Digest, ...], Field(max_length=10_000)] = ()
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=120_000)] = ()

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if (
            self.change_kinds
            != tuple(sorted(set(self.change_kinds), key=lambda item: item.value))
            or self.baseline_endpoint_ids
            != tuple(sorted(set(self.baseline_endpoint_ids)))
            or self.current_endpoint_ids != tuple(sorted(set(self.current_endpoint_ids)))
            or self.baseline_identity_ids
            != tuple(sorted(set(self.baseline_identity_ids)))
            or self.current_identity_ids != tuple(sorted(set(self.current_identity_ids)))
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
        ):
            raise ValueError("Attack Surface change facts must be canonical")
        return self


class AttackSurfaceDriftReport(DomainModel):
    report_id: Digest
    comparison_id: Digest
    baseline_inventory_id: Digest
    current_inventory_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    compared_surface_count: int = Field(ge=0, le=20_000)
    unchanged_surface_count: int = Field(ge=0, le=20_000)
    changes: Annotated[tuple[AttackSurfaceChange, ...], Field(max_length=20_000)] = ()
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=120_000)] = ()
    compared_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        keys = tuple(item.surface_key for item in self.changes)
        if (
            keys != tuple(sorted(set(keys)))
            or self.compared_surface_count
            != self.unchanged_surface_count + len(self.changes)
            or self.evidence_refs
            != tuple(
                sorted(
                    {
                        ref
                        for change in self.changes
                        for ref in change.evidence_refs
                    }
                )
            )
        ):
            raise ValueError("Attack Surface drift report facts are not canonical")
        if self.report_id != canonical_digest(
            self.model_dump(mode="python", exclude={"report_id"})
        ):
            raise ValueError("Attack Surface drift report content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackSurfaceDriftReport:
        expanded = cls.model_construct(report_id="0" * 64, **values).model_dump(
            mode="python", exclude={"report_id"}
        )
        return cls(report_id=canonical_digest(expanded), **expanded)


class AttackSurfaceDriftOutcome(DomainModel):
    comparison_id: Digest
    report: AttackSurfaceDriftReport
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: bool = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.report.comparison_id != self.comparison_id or not self.cleanup_complete:
            raise ValueError("Attack Surface drift outcome is invalid")
        return self
