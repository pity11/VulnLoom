"""Content-bound S1.2 resource-pressure admission contracts.

The trusted harness runs only bounded local canaries.  This module contains no
process or container execution: it binds terminal observations to exact runs and
reduces them into a fail-closed admission decision.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import (
    Digest,
    ImageDigest,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    invocation_digest,
    sandbox_profile_digest,
)


class ResourcePressureProbeKind(StrEnum):
    PID_LIMIT = "pid_limit"
    OPEN_FILES_LIMIT = "open_files_limit"
    OUTPUT_LIMIT = "output_limit"
    TEMP_STORAGE_LIMIT = "temporary_storage_limit"
    MEMORY_LIMIT = "memory_limit"
    TIMEOUT_PROCESS_GROUP = "timeout_process_group"


REQUIRED_RESOURCE_PRESSURE_PROBES = frozenset(ResourcePressureProbeKind)
RESOURCE_PRESSURE_PROBE_CONTRACT_DIGEST = canonical_digest(
    {
        "contract": "vulnloom-resource-pressure-s1.2-v1",
        "probes": tuple(sorted(item.value for item in REQUIRED_RESOURCE_PRESSURE_PROBES)),
        "payloads": "bounded-local-canaries-only",
        "network": "none",
        "cleanup": "container-absence-required",
    }
)

_TERMINAL_CONTRACT = {
    ResourcePressureProbeKind.PID_LIMIT: (SandboxRunStatus.COMPLETED, ()),
    ResourcePressureProbeKind.OPEN_FILES_LIMIT: (SandboxRunStatus.COMPLETED, ()),
    ResourcePressureProbeKind.OUTPUT_LIMIT: (
        SandboxRunStatus.FAILED,
        ("output_capture_failed",),
    ),
    ResourcePressureProbeKind.TEMP_STORAGE_LIMIT: (SandboxRunStatus.COMPLETED, ()),
    ResourcePressureProbeKind.MEMORY_LIMIT: (
        SandboxRunStatus.FAILED,
        ("memory_limit_exceeded",),
    ),
    ResourcePressureProbeKind.TIMEOUT_PROCESS_GROUP: (
        SandboxRunStatus.TIMED_OUT,
        ("wall_time_budget_exceeded",),
    ),
}


class ResourcePressureProbeExpectation(DomainModel):
    kind: ResourcePressureProbeKind
    probe_contract_digest: Digest = RESOURCE_PRESSURE_PROBE_CONTRACT_DIGEST
    run_id: UUID
    task_id: UUID
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    expected_status: SandboxRunStatus
    expected_error_codes: Annotated[tuple[str, ...], Field(max_length=2)] = ()

    @model_validator(mode="after")
    def fixed_probe_semantics(self) -> Self:
        if self.probe_contract_digest != RESOURCE_PRESSURE_PROBE_CONTRACT_DIGEST:
            raise ValueError("resource-pressure probe contract is not admitted")
        if (self.expected_status, self.expected_error_codes) != _TERMINAL_CONTRACT[
            self.kind
        ]:
            raise ValueError("resource-pressure probe terminal semantics cannot be changed")
        return self

    @classmethod
    def from_request(
        cls, *, kind: ResourcePressureProbeKind, request: SandboxRunRequest
    ) -> ResourcePressureProbeExpectation:
        status, error_codes = _TERMINAL_CONTRACT[kind]
        return cls(
            kind=kind,
            run_id=request.run_id,
            task_id=request.task.task_id,
            sandbox_profile_digest=sandbox_profile_digest(request.profile),
            invocation_digest=invocation_digest(request.invocation),
            expected_status=status,
            expected_error_codes=error_codes,
        )


class ResourcePressureQualificationPlan(DomainModel):
    plan_id: Digest
    image_digest: ImageDigest
    created_at: AwareDatetime
    expires_at: AwareDatetime
    probes: Annotated[
        tuple[ResourcePressureProbeExpectation, ...], Field(min_length=6, max_length=6)
    ]

    @model_validator(mode="after")
    def content_addressed_and_complete(self) -> Self:
        kinds = [probe.kind for probe in self.probes]
        if len(set(kinds)) != len(kinds) or set(kinds) != REQUIRED_RESOURCE_PRESSURE_PROBES:
            raise ValueError("resource-pressure qualification requires every probe exactly once")
        if self.expires_at <= self.created_at:
            raise ValueError("resource-pressure qualification plan must have a future expiry")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        if self.plan_id != expected:
            raise ValueError("resource-pressure qualification plan id does not match its content")
        return self

    @classmethod
    def create(
        cls,
        *,
        image_digest: str,
        created_at: datetime,
        expires_at: datetime,
        probes: tuple[ResourcePressureProbeExpectation, ...],
    ) -> ResourcePressureQualificationPlan:
        values = {
            "image_digest": image_digest,
            "created_at": created_at,
            "expires_at": expires_at,
            "probes": probes,
        }
        digest_values = {
            **values,
            "probes": tuple(probe.model_dump(mode="python") for probe in probes),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


class ResourcePressureProbeObservation(DomainModel):
    kind: ResourcePressureProbeKind
    run_id: UUID
    task_id: UUID
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    status: SandboxRunStatus
    error_codes: Annotated[tuple[str, ...], Field(max_length=8)] = ()
    boundary_observed: bool
    cleanup_verified: bool
    container_absent: bool

    @model_validator(mode="after")
    def terminal_observation_only(self) -> Self:
        if self.status is SandboxRunStatus.CHECKPOINTED:
            raise ValueError("resource-pressure probe observation must be terminal")
        if any(not code or len(code) > 128 for code in self.error_codes):
            raise ValueError("resource-pressure probe error codes must be bounded")
        return self

    @classmethod
    def from_result(
        cls,
        *,
        kind: ResourcePressureProbeKind,
        result: SandboxRunResult,
        boundary_observed: bool,
        container_absent: bool,
    ) -> ResourcePressureProbeObservation:
        return cls(
            kind=kind,
            run_id=result.run_id,
            task_id=result.task_id,
            sandbox_profile_digest=result.sandbox_profile_digest,
            invocation_digest=result.invocation_digest,
            status=result.status,
            error_codes=result.error_codes,
            boundary_observed=boundary_observed,
            cleanup_verified=result.cleanup.complete,
            container_absent=container_absent,
        )

    @classmethod
    def cleanup_unproven(
        cls, expectation: ResourcePressureProbeExpectation
    ) -> ResourcePressureProbeObservation:
        return cls(
            kind=expectation.kind,
            run_id=expectation.run_id,
            task_id=expectation.task_id,
            sandbox_profile_digest=expectation.sandbox_profile_digest,
            invocation_digest=expectation.invocation_digest,
            status=SandboxRunStatus.FAILED,
            error_codes=("cleanup_unproven",),
            boundary_observed=False,
            cleanup_verified=False,
            container_absent=False,
        )


class ResourcePressureQualificationStatus(StrEnum):
    ADMITTED = "admitted"
    DENIED = "denied"


class ResourcePressureQualificationOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    status: ResourcePressureQualificationStatus
    observations: Annotated[
        tuple[ResourcePressureProbeObservation, ...], Field(max_length=6)
    ]
    denial_codes: Annotated[tuple[str, ...], Field(max_length=32)] = ()

    @model_validator(mode="after")
    def content_addressed_terminal_outcome(self) -> Self:
        if len({item.kind for item in self.observations}) != len(self.observations):
            raise ValueError("resource-pressure probe observations must be unique")
        if (self.status is ResourcePressureQualificationStatus.ADMITTED) == bool(
            self.denial_codes
        ):
            raise ValueError("admitted outcome must be clean and denied outcome must explain why")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        if self.outcome_id != expected:
            raise ValueError(
                "resource-pressure qualification outcome id does not match its content"
            )
        return self


def qualify_resource_pressure(
    plan: ResourcePressureQualificationPlan,
    observations: tuple[ResourcePressureProbeObservation, ...],
    *,
    now: datetime,
) -> ResourcePressureQualificationOutcome:
    """Reduce trusted, bounded probe observations into an admission decision."""

    expected = {probe.kind: probe for probe in plan.probes}
    actual: dict[ResourcePressureProbeKind, ResourcePressureProbeObservation] = {}
    denial_codes: list[str] = []
    if now >= plan.expires_at:
        denial_codes.append("plan_expired")
    for observation in observations:
        if observation.kind in actual:
            denial_codes.append(f"duplicate_probe:{observation.kind.value}")
            continue
        actual[observation.kind] = observation
    for kind in sorted(REQUIRED_RESOURCE_PRESSURE_PROBES, key=lambda item: item.value):
        expectation = expected[kind]
        observation = actual.get(kind)
        if observation is None:
            denial_codes.append(f"missing_probe:{kind.value}")
            continue
        if (
            observation.run_id != expectation.run_id
            or observation.task_id != expectation.task_id
            or observation.sandbox_profile_digest != expectation.sandbox_profile_digest
            or observation.invocation_digest != expectation.invocation_digest
        ):
            denial_codes.append(f"binding_mismatch:{kind.value}")
        if (
            observation.status is not expectation.expected_status
            or observation.error_codes != expectation.expected_error_codes
        ):
            denial_codes.append(f"terminal_mismatch:{kind.value}")
        if not observation.boundary_observed:
            denial_codes.append(f"boundary_unproven:{kind.value}")
        if not observation.cleanup_verified or not observation.container_absent:
            denial_codes.append(f"cleanup_unproven:{kind.value}")
    status = (
        ResourcePressureQualificationStatus.DENIED
        if denial_codes
        else ResourcePressureQualificationStatus.ADMITTED
    )
    values = {
        "plan_id": plan.plan_id,
        "status": status,
        "observations": tuple(actual[kind] for kind in sorted(actual, key=lambda item: item.value)),
        "denial_codes": tuple(dict.fromkeys(denial_codes)),
    }
    digest_values = {
        **values,
        "observations": tuple(
            item.model_dump(mode="python") for item in values["observations"]
        ),
    }
    return ResourcePressureQualificationOutcome(
        outcome_id=canonical_digest(digest_values), **values
    )
