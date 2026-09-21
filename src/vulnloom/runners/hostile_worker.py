"""Content-bound S1.1 hostile Worker admission contracts.

The probe harness is trusted Control Plane code.  Probe payloads are deliberately
boring local canaries: this module only reduces their typed terminal observations
and cannot start a process, open a socket, or grant a Worker new capabilities.
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


class HostileWorkerProbeKind(StrEnum):
    SECRET_BOUNDARY = "secret_boundary"
    NETWORK_BOUNDARY = "network_boundary"
    HOST_RESOURCE_BOUNDARY = "host_resource_boundary"
    AUTHORITY_READ_ONLY = "authority_read_only"
    EPHEMERAL_WRITABLE_LAYER = "ephemeral_writable_layer"
    CRASH_CLEANUP = "crash_cleanup"
    TIMEOUT_CLEANUP = "timeout_cleanup"


REQUIRED_HOSTILE_WORKER_PROBES = frozenset(HostileWorkerProbeKind)
HOSTILE_WORKER_PROBE_CONTRACT_DIGEST = canonical_digest(
    {
        "contract": "vulnloom-hostile-worker-s1.1-v1",
        "probes": tuple(sorted(item.value for item in REQUIRED_HOSTILE_WORKER_PROBES)),
        "network": "none",
        "secrets": "synthetic-canaries-only",
        "payloads": "non-exploitative-local-checks",
    }
)


class HostileWorkerProbeExpectation(DomainModel):
    kind: HostileWorkerProbeKind
    probe_contract_digest: Digest = HOSTILE_WORKER_PROBE_CONTRACT_DIGEST
    run_id: UUID
    task_id: UUID
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    expected_status: SandboxRunStatus

    @model_validator(mode="after")
    def terminal_expectation_only(self) -> Self:
        if self.probe_contract_digest != HOSTILE_WORKER_PROBE_CONTRACT_DIGEST:
            raise ValueError("hostile Worker probe contract is not admitted")
        if self.expected_status not in {
            SandboxRunStatus.COMPLETED,
            SandboxRunStatus.FAILED,
            SandboxRunStatus.TIMED_OUT,
        }:
            raise ValueError("hostile Worker probes require a fixed terminal status")
        if (
            self.kind is HostileWorkerProbeKind.CRASH_CLEANUP
            and self.expected_status is not SandboxRunStatus.FAILED
        ):
            raise ValueError("crash cleanup probe must expect a failed Worker")
        if (
            self.kind is HostileWorkerProbeKind.TIMEOUT_CLEANUP
            and self.expected_status is not SandboxRunStatus.TIMED_OUT
        ):
            raise ValueError("timeout cleanup probe must expect a timed-out Worker")
        return self

    @classmethod
    def from_request(
        cls,
        *,
        kind: HostileWorkerProbeKind,
        request: SandboxRunRequest,
        expected_status: SandboxRunStatus,
    ) -> HostileWorkerProbeExpectation:
        return cls(
            kind=kind,
            run_id=request.run_id,
            task_id=request.task.task_id,
            sandbox_profile_digest=sandbox_profile_digest(request.profile),
            invocation_digest=invocation_digest(request.invocation),
            expected_status=expected_status,
        )


class HostileWorkerQualificationPlan(DomainModel):
    plan_id: Digest
    image_digest: ImageDigest
    created_at: AwareDatetime
    expires_at: AwareDatetime
    probes: Annotated[tuple[HostileWorkerProbeExpectation, ...], Field(min_length=7, max_length=7)]

    @model_validator(mode="after")
    def content_addressed_and_complete(self) -> Self:
        kinds = [probe.kind for probe in self.probes]
        if len(set(kinds)) != len(kinds) or set(kinds) != REQUIRED_HOSTILE_WORKER_PROBES:
            raise ValueError("hostile Worker qualification requires every probe exactly once")
        if self.expires_at <= self.created_at:
            raise ValueError("hostile Worker qualification plan must have a future expiry")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        if self.plan_id != expected:
            raise ValueError("hostile Worker qualification plan id does not match its content")
        return self

    @classmethod
    def create(
        cls,
        *,
        image_digest: str,
        created_at: datetime,
        expires_at: datetime,
        probes: tuple[HostileWorkerProbeExpectation, ...],
    ) -> HostileWorkerQualificationPlan:
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


class HostileWorkerProbeObservation(DomainModel):
    kind: HostileWorkerProbeKind
    run_id: UUID
    task_id: UUID
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    status: SandboxRunStatus
    cleanup_verified: bool
    container_absent: bool
    error_codes: Annotated[tuple[str, ...], Field(max_length=8)] = ()

    @model_validator(mode="after")
    def terminal_observation_only(self) -> Self:
        if self.status is SandboxRunStatus.CHECKPOINTED:
            raise ValueError("hostile Worker probe observation must be terminal")
        if any(not code or len(code) > 128 for code in self.error_codes):
            raise ValueError("hostile Worker probe error codes must be bounded")
        return self

    @classmethod
    def from_result(
        cls,
        *,
        kind: HostileWorkerProbeKind,
        result: SandboxRunResult,
        container_absent: bool,
    ) -> HostileWorkerProbeObservation:
        return cls(
            kind=kind,
            run_id=result.run_id,
            task_id=result.task_id,
            sandbox_profile_digest=result.sandbox_profile_digest,
            invocation_digest=result.invocation_digest,
            status=result.status,
            cleanup_verified=result.cleanup.complete,
            container_absent=container_absent,
            error_codes=result.error_codes,
        )

    @classmethod
    def cleanup_unproven(
        cls, expectation: HostileWorkerProbeExpectation
    ) -> HostileWorkerProbeObservation:
        return cls(
            kind=expectation.kind,
            run_id=expectation.run_id,
            task_id=expectation.task_id,
            sandbox_profile_digest=expectation.sandbox_profile_digest,
            invocation_digest=expectation.invocation_digest,
            status=SandboxRunStatus.FAILED,
            cleanup_verified=False,
            container_absent=False,
            error_codes=("cleanup_unproven",),
        )


class HostileWorkerQualificationStatus(StrEnum):
    ADMITTED = "admitted"
    DENIED = "denied"


class HostileWorkerQualificationOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    status: HostileWorkerQualificationStatus
    observations: Annotated[
        tuple[HostileWorkerProbeObservation, ...], Field(max_length=7)
    ]
    denial_codes: Annotated[tuple[str, ...], Field(max_length=32)] = ()

    @model_validator(mode="after")
    def content_addressed_terminal_outcome(self) -> Self:
        if len({item.kind for item in self.observations}) != len(self.observations):
            raise ValueError("hostile Worker probe observations must be unique")
        if (self.status is HostileWorkerQualificationStatus.ADMITTED) == bool(
            self.denial_codes
        ):
            raise ValueError("admitted outcome must be clean and denied outcome must explain why")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        if self.outcome_id != expected:
            raise ValueError("hostile Worker qualification outcome id does not match its content")
        return self


def qualify_hostile_worker(
    plan: HostileWorkerQualificationPlan,
    observations: tuple[HostileWorkerProbeObservation, ...],
    *,
    now: datetime,
) -> HostileWorkerQualificationOutcome:
    """Reduce trusted probe observations into a fail-closed admission decision."""

    expected = {probe.kind: probe for probe in plan.probes}
    actual: dict[HostileWorkerProbeKind, HostileWorkerProbeObservation] = {}
    denial_codes: list[str] = []
    if now >= plan.expires_at:
        denial_codes.append("plan_expired")
    for observation in observations:
        if observation.kind in actual:
            denial_codes.append(f"duplicate_probe:{observation.kind.value}")
            continue
        actual[observation.kind] = observation
    for kind in sorted(REQUIRED_HOSTILE_WORKER_PROBES, key=lambda item: item.value):
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
        if observation.status is not expectation.expected_status:
            denial_codes.append(f"terminal_status_mismatch:{kind.value}")
        if not observation.cleanup_verified or not observation.container_absent:
            denial_codes.append(f"cleanup_unproven:{kind.value}")
    unexpected = set(actual) - REQUIRED_HOSTILE_WORKER_PROBES
    denial_codes.extend(f"unexpected_probe:{kind.value}" for kind in sorted(unexpected))
    status = (
        HostileWorkerQualificationStatus.DENIED
        if denial_codes
        else HostileWorkerQualificationStatus.ADMITTED
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
    return HostileWorkerQualificationOutcome(
        outcome_id=canonical_digest(digest_values), **values
    )
