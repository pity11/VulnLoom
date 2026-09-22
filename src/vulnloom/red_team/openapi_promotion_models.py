"""Typed contracts for reviewed OpenAPI discovery promotion."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest
from .seed_models import EndpointSeed


class OpenApiDiscoveryPromotionState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class OpenApiDiscoveryPromotionLimits(DomainModel):
    max_selections: int = Field(default=100, ge=1, le=1_000)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class OpenApiDiscoverySelection(DomainModel):
    selection_id: Digest
    discovery_id: Digest
    concrete_path: str = Field(min_length=1, max_length=1_024)
    concrete_path_digest: Digest

    @model_validator(mode="after")
    def sealed(self) -> Self:
        seed = EndpointSeed.create(path=self.concrete_path)
        identity = {
            "discovery_id": self.discovery_id,
            "concrete_path_digest": seed.path_digest,
        }
        if (
            self.concrete_path_digest != seed.path_digest
            or self.selection_id != canonical_digest(identity)
        ):
            raise ValueError("OpenAPI discovery selection binding is invalid")
        return self

    @classmethod
    def create(
        cls, *, discovery_id: str, concrete_path: str
    ) -> OpenApiDiscoverySelection:
        seed = EndpointSeed.create(path=concrete_path)
        identity = {
            "discovery_id": discovery_id,
            "concrete_path_digest": seed.path_digest,
        }
        return cls(
            selection_id=canonical_digest(identity),
            discovery_id=discovery_id,
            concrete_path=seed.path,
            concrete_path_digest=seed.path_digest,
        )


class OpenApiDiscoveryPromotionPlan(DomainModel):
    promotion_plan_id: Digest
    openapi_observation_plan_id: Digest
    openapi_observation_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    operator_ref: str = Field(pattern=r"^operator:[a-zA-Z0-9._-]{1,200}$")
    selections: Annotated[
        tuple[OpenApiDiscoverySelection, ...], Field(min_length=1, max_length=1_000)
    ]
    limits: OpenApiDiscoveryPromotionLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    seed_set_expires_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        selection_ids = tuple(item.selection_id for item in self.selections)
        discovery_ids = tuple(item.discovery_id for item in self.selections)
        concrete_paths = tuple(item.concrete_path for item in self.selections)
        if (
            selection_ids != tuple(sorted(set(selection_ids)))
            or len(discovery_ids) != len(set(discovery_ids))
            or len(concrete_paths) != len(set(concrete_paths))
            or len(self.selections) > self.limits.max_selections
            or not self.created_at < self.deadline <= self.seed_set_expires_at
            or self.promotion_plan_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"promotion_plan_id"})
            )
        ):
            raise ValueError("OpenAPI discovery promotion plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> OpenApiDiscoveryPromotionPlan:
        expanded = cls.model_construct(
            promotion_plan_id="0" * 64, **values
        ).model_dump(mode="python", exclude={"promotion_plan_id"})
        return cls(
            promotion_plan_id=canonical_digest(expanded),
            **expanded,
        )


class OpenApiDiscoveryPromotionOutcome(DomainModel):
    outcome_id: Digest
    promotion_plan_id: Digest
    openapi_observation_id: Digest
    seed_set_id: Digest
    selection_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=1_000)]
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.selection_ids != tuple(sorted(set(self.selection_ids)))
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("OpenAPI discovery promotion outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> OpenApiDiscoveryPromotionOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
