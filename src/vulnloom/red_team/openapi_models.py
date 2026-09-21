"""Typed contracts for bounded, offline OpenAPI document observation."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest


class OpenApiObservationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class OpenApiHttpMethod(StrEnum):
    DELETE = "DELETE"
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    POST = "POST"
    PUT = "PUT"


class OpenApiObservationLimits(DomainModel):
    max_document_bytes: int = Field(default=64 * 1024, ge=1, le=64 * 1024)
    max_paths: int = Field(default=256, ge=1, le=1_000)
    max_operations: int = Field(default=1_024, ge=1, le=10_000)
    max_nodes: int = Field(default=20_000, ge=1, le=100_000)
    max_depth: int = Field(default=32, ge=1, le=64)
    max_servers: int = Field(default=100, ge=0, le=1_000)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class OpenApiDocumentObservationPlan(DomainModel):
    plan_id: Digest
    endpoint_recon_plan_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    source_observation_id: Digest
    web_response_snapshot_id: Digest
    evidence_ref: Digest
    document_body_sha256: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    limits: OpenApiObservationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at or self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("OpenAPI observation plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> OpenApiDocumentObservationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


_PATH_TEMPLATE = re.compile(
    r"^/(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|\{[A-Za-z0-9._-]{1,128}\}|/)*$"
)


class OpenApiPathDiscovery(DomainModel):
    discovery_id: Digest
    path_template: str = Field(min_length=1, max_length=1_024)
    path_digest: Digest
    methods: Annotated[tuple[OpenApiHttpMethod, ...], Field(min_length=1, max_length=7)]
    execution_authorized: Literal[False] = False

    @field_validator("path_template")
    @classmethod
    def canonical_template(cls, value: str) -> str:
        segments = value.split("/")
        if (
            not value.isascii()
            or not _PATH_TEMPLATE.fullmatch(value)
            or "//" in value
            or "%" in value
            or "\\" in value
            or any(segment in {".", ".."} for segment in segments)
        ):
            raise ValueError("OpenAPI path template is not canonical")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        methods = tuple(sorted(set(self.methods), key=str))
        path_digest = canonical_digest(self.path_template)
        identity = {"path_digest": path_digest, "methods": methods}
        if (
            methods != self.methods
            or self.path_digest != path_digest
            or self.execution_authorized
            or self.discovery_id != canonical_digest(identity)
        ):
            raise ValueError("OpenAPI path discovery binding is invalid")
        return self

    @classmethod
    def create(
        cls, *, path_template: str, methods: tuple[OpenApiHttpMethod, ...]
    ) -> OpenApiPathDiscovery:
        ordered = tuple(sorted(set(methods), key=str))
        path_digest = canonical_digest(path_template)
        return cls(
            discovery_id=canonical_digest(
                {"path_digest": path_digest, "methods": ordered}
            ),
            path_template=path_template,
            path_digest=path_digest,
            methods=ordered,
        )


class OpenApiDocumentObservation(DomainModel):
    observation_id: Digest
    plan_id: Digest
    endpoint_recon_plan_id: Digest
    source_observation_id: Digest
    web_response_snapshot_id: Digest
    evidence_ref: Digest
    document_body_sha256: Digest
    openapi_version: str = Field(pattern=r"^3\.(?:0|1)\.[0-9]+$")
    paths: Annotated[tuple[OpenApiPathDiscovery, ...], Field(min_length=1, max_length=1_000)]
    operation_count: int = Field(ge=1, le=10_000)
    server_entries_ignored: int = Field(ge=0, le=1_000)
    reference_entries_ignored: int = Field(ge=0, le=100_000)
    target_expansion_authorized: Literal[False] = False
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        discovery_ids = tuple(item.discovery_id for item in self.paths)
        if (
            discovery_ids != tuple(sorted(set(discovery_ids)))
            or self.operation_count != sum(len(item.methods) for item in self.paths)
            or self.target_expansion_authorized
            or self.observation_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"observation_id"})
            )
        ):
            raise ValueError("OpenAPI document observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> OpenApiDocumentObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class OpenApiDocumentObservationOutcome(DomainModel):
    plan_id: Digest
    observation: OpenApiDocumentObservation
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.observation.plan_id != self.plan_id:
            raise ValueError("OpenAPI observation outcome binding is invalid")
        return self
