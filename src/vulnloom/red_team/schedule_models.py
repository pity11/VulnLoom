"""Typed contracts for recurring, exact Endpoint security checks."""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.workflows import Visibility

from .models import AuthorizedWebTarget, Digest, ReasonCode
from .seed_models import EndpointReconLimits, EndpointSeed


class EndpointScheduleState(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class EndpointScheduleRunState(StrEnum):
    STARTED = "started"
    MATERIALIZED = "materialized"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class EndpointCheckSchedule(DomainModel):
    schedule_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_url: str = Field(min_length=1, max_length=2_048)
    visibility: Visibility
    test_class: ReasonCode
    operator_ref: str = Field(pattern=r"^operator:[a-zA-Z0-9._-]{1,200}$")
    emergency_contact_ref: str = Field(pattern=r"^contact:[a-zA-Z0-9._-]{1,200}$")
    paths: Annotated[tuple[str, ...], Field(min_length=1, max_length=100)]
    interval_seconds: int = Field(ge=60, le=2_592_000)
    run_ttl_seconds: int = Field(ge=1, le=300)
    max_consecutive_failures: int = Field(default=2, ge=1, le=3)
    recon_limits: EndpointReconLimits
    active_from: AwareDatetime
    active_until: AwareDatetime
    created_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @field_validator("target_url")
    @classmethod
    def canonical_target(cls, value: str) -> str:
        return AuthorizedWebTarget(url=value).url

    @field_validator("paths")
    @classmethod
    def canonical_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            EndpointSeed.create(path=path)
        if value != tuple(sorted(set(value))):
            raise ValueError("Endpoint Check Schedule paths must be ordered and unique")
        return value

    @field_validator("active_from", "active_until", "created_at")
    @classmethod
    def utc_schedule_time(cls, value):
        if value.utcoffset() != timedelta(0):
            raise ValueError("Endpoint Check Schedule times must use UTC")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.visibility not in {Visibility.BLACK_BOX, Visibility.GREY_BOX}
            or self.test_class != "read_only"
            or self.created_at > self.active_from
            or self.active_until <= self.active_from
            or len(self.paths)
            > min(self.recon_limits.max_steps, self.recon_limits.max_requests)
            or self.recon_limits.total_seconds > self.run_ttl_seconds
        ):
            raise ValueError("Endpoint Check Schedule window or budget is invalid")
        if self.schedule_id != canonical_digest(
            self.model_dump(mode="python", exclude={"schedule_id"})
        ):
            raise ValueError("Endpoint Check Schedule content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> EndpointCheckSchedule:
        expanded = cls.model_construct(schedule_id="0" * 64, **values).model_dump(
            mode="python", exclude={"schedule_id"}
        )
        return cls(schedule_id=canonical_digest(expanded), **values)


class EndpointScheduleCheckpoint(DomainModel):
    checkpoint_id: Digest
    schedule_id: Digest
    revision: int = Field(ge=0)
    state: EndpointScheduleState
    next_due_at: AwareDatetime
    active_run_id: Digest | None = None
    last_run_id: Digest | None = None
    reason_code: ReasonCode | None = None
    updated_at: AwareDatetime

    @field_validator("next_due_at", "updated_at")
    @classmethod
    def utc_checkpoint_time(cls, value):
        if value.utcoffset() != timedelta(0):
            raise ValueError("Endpoint Schedule checkpoint times must use UTC")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            (self.state is EndpointScheduleState.ACTIVE) != (self.reason_code is None)
            or (
                self.active_run_id is not None
                and self.state is not EndpointScheduleState.ACTIVE
            )
        ):
            raise ValueError("Endpoint Schedule checkpoint state is inconsistent")
        if self.checkpoint_id != canonical_digest(
            self.model_dump(mode="python", exclude={"checkpoint_id"})
        ):
            raise ValueError("Endpoint Schedule checkpoint content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> EndpointScheduleCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **values)


class EndpointScheduleRun(DomainModel):
    schedule_run_id: Digest
    schedule_id: Digest
    scheduled_for: AwareDatetime
    state: EndpointScheduleRunState
    attempt: int = Field(ge=1, le=3)
    started_at: AwareDatetime
    deadline: AwareDatetime
    flow_plan_id: Digest | None = None
    seed_set_id: Digest | None = None
    endpoint_recon_plan_id: Digest | None = None
    cleanup_complete: bool | None = None
    terminal_reason: ReasonCode | None = None
    completed_at: AwareDatetime | None = None

    @field_validator("scheduled_for", "started_at", "deadline", "completed_at")
    @classmethod
    def utc_run_time(cls, value):
        if value is not None and value.utcoffset() != timedelta(0):
            raise ValueError("Endpoint Schedule Run times must use UTC")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        ids = (self.flow_plan_id, self.seed_set_id, self.endpoint_recon_plan_id)
        terminal = self.state is not EndpointScheduleRunState.STARTED
        if (
            self.deadline <= self.started_at
            or self.scheduled_for > self.started_at
            or terminal != (self.completed_at is not None)
            or terminal != (self.terminal_reason is not None)
            or terminal != (self.cleanup_complete is not None)
            or (
                self.state is EndpointScheduleRunState.MATERIALIZED
                and (any(item is None for item in ids) or not self.cleanup_complete)
            )
            or (
                self.state is EndpointScheduleRunState.STARTED
                and any(item is not None for item in ids)
            )
            or (
                self.completed_at is not None
                and self.completed_at < self.started_at
            )
            or (
                self.state is EndpointScheduleRunState.TIMED_OUT
                and self.completed_at < self.deadline
            )
            or (
                self.state is EndpointScheduleRunState.FAILED
                and self.attempt != 3
            )
        ):
            raise ValueError("Endpoint Schedule Run state is inconsistent")
        expected = canonical_digest(
            {"schedule_id": self.schedule_id, "scheduled_for": self.scheduled_for}
        )
        if self.schedule_run_id != expected:
            raise ValueError("Endpoint Schedule Run identity mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> EndpointScheduleRun:
        schedule_run_id = canonical_digest(
            {
                "schedule_id": values["schedule_id"],
                "scheduled_for": values["scheduled_for"],
            }
        )
        return cls(schedule_run_id=schedule_run_id, **values)
