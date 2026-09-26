"""Sealed B5.2 contracts for isolated A3 runtime qualification."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.hostile_worker import HOSTILE_WORKER_PROBE_CONTRACT_DIGEST
from vulnloom.runners.models import Digest, ImageDigest, SandboxRunStatus
from vulnloom.runners.resource_pressure import RESOURCE_PRESSURE_PROBE_CONTRACT_DIGEST
from vulnloom.runners.seccomp import WORKER_SECCOMP_CONTRACT
from vulnloom.workflows import AutonomyLevel


class RuntimeAssuranceLevel(StrEnum):
    LOCAL_DOCKER = "local_docker"
    ROOTLESS_PRODUCTION = "rootless_production"


class AdaptiveRuntimeProbeKind(StrEnum):
    BOUNDARY = "boundary"
    TIMEOUT_CLEANUP = "timeout_cleanup"


REQUIRED_ADAPTIVE_RUNTIME_PROBES = frozenset(AdaptiveRuntimeProbeKind)
ADAPTIVE_RUNTIME_PROBE_CONTRACT_DIGEST = canonical_digest(
    {
        "contract": "vulnloom-adaptive-runtime-b5.2-v1",
        "probes": tuple(sorted(item.value for item in REQUIRED_ADAPTIVE_RUNTIME_PROBES)),
        "network": "none",
        "content": "coverage-ledger-id-only",
        "payloads": "bounded-local-canaries-only",
    }
)


class AdaptiveRuntimeQualificationLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class AdaptiveRuntimeQualificationPlan(DomainModel):
    plan_id: Digest
    adaptive_plan_id: Digest
    adaptive_outcome_id: Digest
    adaptive_outcome_digest: Digest
    flow_plan_id: Digest
    coverage_ledger_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    image_digest: ImageDigest
    sandbox_profile_digest: Digest
    hostile_worker_plan_id: Digest
    hostile_worker_outcome_id: Digest
    hostile_worker_outcome_digest: Digest
    hostile_worker_contract_digest: Literal[
        HOSTILE_WORKER_PROBE_CONTRACT_DIGEST
    ] = HOSTILE_WORKER_PROBE_CONTRACT_DIGEST
    resource_pressure_plan_id: Digest
    resource_pressure_outcome_id: Digest
    resource_pressure_outcome_digest: Digest
    resource_pressure_contract_digest: Literal[
        RESOURCE_PRESSURE_PROBE_CONTRACT_DIGEST
    ] = RESOURCE_PRESSURE_PROBE_CONTRACT_DIGEST
    seccomp_contract_digest: Literal[
        WORKER_SECCOMP_CONTRACT.contract_id
    ] = WORKER_SECCOMP_CONTRACT.contract_id
    runtime_probe_contract_digest: Literal[
        ADAPTIVE_RUNTIME_PROBE_CONTRACT_DIGEST
    ] = ADAPTIVE_RUNTIME_PROBE_CONTRACT_DIGEST
    required_probes: tuple[AdaptiveRuntimeProbeKind, ...] = tuple(
        sorted(REQUIRED_ADAPTIVE_RUNTIME_PROBES, key=str)
    )
    limits: AdaptiveRuntimeQualificationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    requested_autonomy: Literal[AutonomyLevel.ADAPTIVE_FLOW] = AutonomyLevel.ADAPTIVE_FLOW
    execution_authority_requested: Literal[False] = False
    campaign_qualification_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.required_probes
            != tuple(sorted(REQUIRED_ADAPTIVE_RUNTIME_PROBES, key=str))
            or not self.created_at < self.deadline
            or self.execution_authority_requested
            or self.campaign_qualification_requested
            or self.plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Adaptive Runtime Qualification Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AdaptiveRuntimeQualificationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class AdaptiveRuntimeProbeObservation(DomainModel):
    observation_id: Digest
    plan_id: Digest
    adaptive_outcome_id: Digest
    coverage_ledger_id: Digest
    kind: AdaptiveRuntimeProbeKind
    run_id: UUID
    task_id: UUID
    image_digest: ImageDigest
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    runner_result_digest: Digest
    status: SandboxRunStatus
    error_codes: Annotated[tuple[str, ...], Field(max_length=4)] = ()
    assurance_level: RuntimeAssuranceLevel
    actual_container_observed: Literal[True] = True
    network_disabled: Literal[True] = True
    non_root: Literal[True] = True
    read_only_root: Literal[True] = True
    capabilities_dropped: Literal[True] = True
    no_new_privileges: Literal[True] = True
    seccomp_enforced: Literal[True] = True
    resource_limits_enforced: Literal[True] = True
    environment_allowlisted: Literal[True] = True
    content_mount_read_only: Literal[True] = True
    docker_socket_absent: Literal[True] = True
    cleanup_verified: Literal[True] = True
    container_absent: Literal[True] = True
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = {
            AdaptiveRuntimeProbeKind.BOUNDARY: (SandboxRunStatus.COMPLETED, ()),
            AdaptiveRuntimeProbeKind.TIMEOUT_CLEANUP: (
                SandboxRunStatus.TIMED_OUT,
                ("wall_time_budget_exceeded",),
            ),
        }[self.kind]
        if (
            (self.status, self.error_codes) != expected
            or not all(
                (
                    self.actual_container_observed,
                    self.network_disabled,
                    self.non_root,
                    self.read_only_root,
                    self.capabilities_dropped,
                    self.no_new_privileges,
                    self.seccomp_enforced,
                    self.resource_limits_enforced,
                    self.environment_allowlisted,
                    self.content_mount_read_only,
                    self.docker_socket_absent,
                    self.cleanup_verified,
                    self.container_absent,
                )
            )
            or self.observation_id
            != canonical_digest(self.model_dump(mode="python", exclude={"observation_id"}))
        ):
            raise ValueError("Adaptive Runtime Probe Observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AdaptiveRuntimeProbeObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class AdaptiveRuntimeQualificationOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    adaptive_outcome_id: Digest
    flow_plan_id: Digest
    coverage_ledger_id: Digest
    probe_observation_ids: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=2)]
    assurance_level: RuntimeAssuranceLevel
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    qualified_autonomy: Literal[AutonomyLevel.ADAPTIVE_FLOW] = AutonomyLevel.ADAPTIVE_FLOW
    isolated_lab_qualified: Literal[True] = True
    production_runner_admitted: bool
    execution_authority_granted: Literal[False] = False
    campaign_qualified: Literal[False] = False
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            len(set(self.probe_observation_ids)) != 2
            or self.production_runner_admitted
            != (self.assurance_level is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION)
            or not self.isolated_lab_qualified
            or self.execution_authority_granted
            or self.campaign_qualified
            or self.candidate_created
            or self.finding_created
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Adaptive Runtime Qualification Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AdaptiveRuntimeQualificationOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
