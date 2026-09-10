"""Operator-sealed endpoint seeds and bounded Recon plan contracts."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest, ReasonCode


class EndpointReconRunState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class EndpointReconOutcomeKind(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class EndpointSeed(DomainModel):
    seed_id: Digest
    path: str = Field(min_length=1, max_length=1_024)
    path_digest: Digest

    @field_validator("path")
    @classmethod
    def canonical_absolute_path(cls, value: str) -> str:
        parsed = urlsplit(value)
        segments = value.split("/")
        if (
            not value.isascii()
            or not value.startswith("/")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or "%" in value
            or "\\" in value
            or "//" in value
            or any(ord(character) <= 32 or ord(character) == 127 for character in value)
            or any(segment in {".", ".."} for segment in segments)
        ):
            raise ValueError("Endpoint seed must be a canonical query-free absolute path")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_path = canonical_digest(self.path)
        expected_seed = canonical_digest({"path_digest": expected_path})
        if self.path_digest != expected_path or self.seed_id != expected_seed:
            raise ValueError("Endpoint seed content digest mismatch")
        return self

    @classmethod
    def create(cls, *, path: str) -> EndpointSeed:
        path_digest = canonical_digest(path)
        return cls(
            seed_id=canonical_digest({"path_digest": path_digest}),
            path=path,
            path_digest=path_digest,
        )


class EndpointSeedSet(DomainModel):
    seed_set_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    operator_ref: str = Field(pattern=r"^operator:[a-zA-Z0-9._-]{1,200}$")
    seeds: Annotated[tuple[EndpointSeed, ...], Field(min_length=1, max_length=1_000)]
    sealed_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        paths = tuple(item.path for item in self.seeds)
        if paths != tuple(sorted(set(paths))) or self.expires_at <= self.sealed_at:
            raise ValueError("Endpoint Seed Set must be ordered, unique, and active")
        if self.seed_set_id != canonical_digest(
            self.model_dump(mode="python", exclude={"seed_set_id"})
        ):
            raise ValueError("Endpoint Seed Set content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> EndpointSeedSet:
        expanded = cls.model_construct(seed_set_id="0" * 64, **values).model_dump(
            mode="python", exclude={"seed_set_id"}
        )
        return cls(seed_set_id=canonical_digest(expanded), **values)


class EndpointReconLimits(DomainModel):
    max_steps: int = Field(default=100, ge=1, le=1_000)
    max_requests: int = Field(default=100, ge=1, le=1_000)
    per_request_seconds: float = Field(default=5.0, gt=0, le=30)
    total_seconds: float = Field(default=60.0, gt=0, le=300)
    max_attempts: int = Field(default=3, ge=1, le=3)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.total_seconds < self.per_request_seconds:
            raise ValueError("Endpoint Recon total budget must cover one request")
        return self


class EndpointReconStep(DomainModel):
    step_id: Digest
    seed_id: Digest
    ordinal: int = Field(ge=1, le=1_000)
    target_url: str = Field(min_length=1, max_length=2_048)
    target_url_digest: Digest
    method: Literal["HEAD"] = "HEAD"
    follow_redirects: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_url = hashlib.sha256(self.target_url.encode()).hexdigest()
        identity = {
            "seed_id": self.seed_id,
            "ordinal": self.ordinal,
            "target_url_digest": expected_url,
            "method": self.method,
            "follow_redirects": self.follow_redirects,
        }
        if self.target_url_digest != expected_url or self.step_id != canonical_digest(identity):
            raise ValueError("Endpoint Recon step content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> EndpointReconStep:
        target_url_digest = hashlib.sha256(str(values["target_url"]).encode()).hexdigest()
        identity = {
            "seed_id": values["seed_id"],
            "ordinal": values["ordinal"],
            "target_url_digest": target_url_digest,
            "method": "HEAD",
            "follow_redirects": False,
        }
        return cls(
            step_id=canonical_digest(identity),
            target_url_digest=target_url_digest,
            **values,
        )


class EndpointReconPlan(DomainModel):
    endpoint_recon_plan_id: Digest
    seed_set_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    test_class: ReasonCode
    steps: Annotated[tuple[EndpointReconStep, ...], Field(min_length=1, max_length=1_000)]
    limits: EndpointReconLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        ordinals = tuple(item.ordinal for item in self.steps)
        seed_ids = tuple(item.seed_id for item in self.steps)
        if (
            ordinals != tuple(range(1, len(self.steps) + 1))
            or len(seed_ids) != len(set(seed_ids))
            or len(self.steps) > min(self.limits.max_steps, self.limits.max_requests)
            or self.deadline <= self.created_at
        ):
            raise ValueError("Endpoint Recon plan steps or budget are invalid")
        if self.endpoint_recon_plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"endpoint_recon_plan_id"})
        ):
            raise ValueError("Endpoint Recon plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> EndpointReconPlan:
        expanded = cls.model_construct(endpoint_recon_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"endpoint_recon_plan_id"}
        )
        return cls(endpoint_recon_plan_id=canonical_digest(expanded), **values)


class EndpointReconStepResult(DomainModel):
    step_id: Digest
    target_url_digest: Digest
    outcome: EndpointReconOutcomeKind
    status_code: int | None = Field(default=None, ge=100, le=599)
    reason_code: ReasonCode
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=1)] = ()
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.outcome is EndpointReconOutcomeKind.SUCCEEDED and (
            self.status_code is None or not self.cleanup_complete
        ):
            raise ValueError("Successful Endpoint Recon requires status and cleanup proof")
        if self.outcome is not EndpointReconOutcomeKind.SUCCEEDED and self.status_code:
            raise ValueError("Unsuccessful Endpoint Recon cannot include an HTTP status")
        return self


class EndpointReconOutcome(DomainModel):
    endpoint_recon_plan_id: Digest
    seed_set_id: Digest
    outcome: EndpointReconOutcomeKind
    results: Annotated[tuple[EndpointReconStepResult, ...], Field(min_length=1, max_length=1_000)]
    requests_used: int = Field(ge=1, le=1_000)
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def coherent(self) -> Self:
        step_ids = tuple(item.step_id for item in self.results)
        if len(step_ids) != len(set(step_ids)) or self.requests_used != len(self.results):
            raise ValueError("Endpoint Recon outcome results are invalid")
        expected = self.results[-1].outcome
        if self.outcome is not expected:
            raise ValueError("Endpoint Recon terminal outcome is inconsistent")
        if self.cleanup_complete != all(item.cleanup_complete for item in self.results):
            raise ValueError("Endpoint Recon cleanup summary is inconsistent")
        return self
