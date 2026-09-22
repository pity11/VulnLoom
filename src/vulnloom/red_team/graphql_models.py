"""Typed contracts for bounded, offline GraphQL SDL observation."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest


class GraphQlSchemaObservationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class GraphQlSchemaObservationLimits(DomainModel):
    max_document_bytes: int = Field(default=64 * 1024, ge=1, le=64 * 1024)
    max_tokens: int = Field(default=20_000, ge=1, le=100_000)
    max_types: int = Field(default=512, ge=1, le=2_000)
    max_query_fields: int = Field(default=1_024, ge=1, le=10_000)
    max_depth: int = Field(default=32, ge=1, le=64)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class GraphQlSchemaObservationPlan(DomainModel):
    plan_id: Digest
    endpoint_recon_plan_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    source_observation_id: Digest
    web_response_snapshot_id: Digest
    evidence_ref: Digest
    response_body_sha256: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    limits: GraphQlSchemaObservationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at or self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("GraphQL schema observation plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> GraphQlSchemaObservationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


_GRAPHQL_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,127}$")


class GraphQlQueryFieldDiscovery(DomainModel):
    discovery_id: Digest
    field_name: str = Field(min_length=1, max_length=128)
    field_name_digest: Digest
    return_named_type: str = Field(min_length=1, max_length=128)
    return_type_digest: Digest
    execution_authorized: Literal[False] = False
    arguments_disclosed: Literal[False] = False

    @field_validator("field_name", "return_named_type")
    @classmethod
    def graphql_name(cls, value: str) -> str:
        if not _GRAPHQL_NAME.fullmatch(value):
            raise ValueError("GraphQL discovery name is invalid")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        field_digest = canonical_digest(self.field_name)
        return_digest = canonical_digest(self.return_named_type)
        identity = {
            "field_name_digest": field_digest,
            "return_type_digest": return_digest,
        }
        if (
            self.field_name_digest != field_digest
            or self.return_type_digest != return_digest
            or self.execution_authorized
            or self.arguments_disclosed
            or self.discovery_id != canonical_digest(identity)
        ):
            raise ValueError("GraphQL query field discovery binding is invalid")
        return self

    @classmethod
    def create(
        cls, *, field_name: str, return_named_type: str
    ) -> GraphQlQueryFieldDiscovery:
        field_digest = canonical_digest(field_name)
        return_digest = canonical_digest(return_named_type)
        return cls(
            discovery_id=canonical_digest(
                {
                    "field_name_digest": field_digest,
                    "return_type_digest": return_digest,
                }
            ),
            field_name=field_name,
            field_name_digest=field_digest,
            return_named_type=return_named_type,
            return_type_digest=return_digest,
        )


class GraphQlSchemaObservation(DomainModel):
    observation_id: Digest
    plan_id: Digest
    endpoint_recon_plan_id: Digest
    source_observation_id: Digest
    web_response_snapshot_id: Digest
    evidence_ref: Digest
    response_body_sha256: Digest
    query_root_type: str = Field(min_length=1, max_length=128)
    query_fields: Annotated[
        tuple[GraphQlQueryFieldDiscovery, ...], Field(min_length=1, max_length=10_000)
    ]
    type_count: int = Field(ge=1, le=2_000)
    mutation_fields_ignored: int = Field(ge=0, le=10_000)
    subscription_fields_ignored: int = Field(ge=0, le=10_000)
    directive_uses_ignored: int = Field(ge=0, le=100_000)
    operation_execution_authorized: Literal[False] = False
    target_expansion_authorized: Literal[False] = False
    observed_at: AwareDatetime

    @field_validator("query_root_type")
    @classmethod
    def query_root_name(cls, value: str) -> str:
        if not _GRAPHQL_NAME.fullmatch(value):
            raise ValueError("GraphQL query root name is invalid")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        discovery_ids = tuple(item.discovery_id for item in self.query_fields)
        field_names = tuple(item.field_name for item in self.query_fields)
        if (
            discovery_ids != tuple(sorted(set(discovery_ids)))
            or len(field_names) != len(set(field_names))
            or self.operation_execution_authorized
            or self.target_expansion_authorized
            or self.observation_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"observation_id"})
            )
        ):
            raise ValueError("GraphQL schema observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> GraphQlSchemaObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class GraphQlSchemaObservationOutcome(DomainModel):
    plan_id: Digest
    observation: GraphQlSchemaObservation
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.observation.plan_id != self.plan_id:
            raise ValueError("GraphQL schema observation outcome binding is invalid")
        return self
