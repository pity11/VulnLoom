"""Sealed B5.4 contracts for isolated A4 Campaign runtime qualification."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, DomainModel
from vulnloom.runners.hostile_worker import HOSTILE_WORKER_PROBE_CONTRACT_DIGEST
from vulnloom.runners.models import Digest, ImageDigest, SandboxRunStatus
from vulnloom.runners.resource_pressure import RESOURCE_PRESSURE_PROBE_CONTRACT_DIGEST
from vulnloom.runners.seccomp import WORKER_SECCOMP_CONTRACT
from vulnloom.workflows import AutonomyLevel

from .adaptive_runtime_models import RuntimeAssuranceLevel
from .campaign_models import CampaignPhaseKind


class CampaignRuntimeStopProbeKind(StrEnum):
    BUDGET_STOP = "budget_stop"
    TIMEOUT_CLEANUP = "timeout_cleanup"


REQUIRED_CAMPAIGN_RUNTIME_STOP_PROBES = frozenset(CampaignRuntimeStopProbeKind)
CAMPAIGN_RUNTIME_PROBE_CONTRACT_DIGEST = canonical_digest(
    {
        "contract": "vulnloom-campaign-runtime-b5.4-v1",
        "phases": tuple(item.value for item in CampaignPhaseKind),
        "stop_probes": tuple(
            sorted(item.value for item in REQUIRED_CAMPAIGN_RUNTIME_STOP_PROBES)
        ),
        "network": "none",
        "model_tokens": 0,
        "content": "campaign-qualification-id-only",
        "actions": "none",
    }
)


class CampaignRuntimeQualificationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CampaignRuntimeQualificationLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class CampaignRuntimeQualificationPlan(DomainModel):
    runtime_plan_id: Digest
    campaign_plan_id: Digest
    campaign_plan_digest: Digest
    campaign_outcome_id: Digest
    campaign_outcome_digest: Digest
    goal_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_set_digest: Digest
    phase_graph_digest: Digest
    required_phase_ids: Annotated[tuple[Digest, ...], Field(min_length=6, max_length=6)]
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
        CAMPAIGN_RUNTIME_PROBE_CONTRACT_DIGEST
    ] = CAMPAIGN_RUNTIME_PROBE_CONTRACT_DIGEST
    required_stop_probes: tuple[CampaignRuntimeStopProbeKind, ...] = tuple(
        sorted(REQUIRED_CAMPAIGN_RUNTIME_STOP_PROBES, key=str)
    )
    limits: CampaignRuntimeQualificationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    requested_autonomy: Literal[
        AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    ] = AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    campaign_execution_requested: Literal[False] = False
    action_execution_requested: Literal[False] = False
    dynamic_target_expansion_requested: Literal[False] = False
    credential_access_requested: Literal[False] = False
    submission_requested: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            len(set(self.required_phase_ids)) != 6
            or self.required_stop_probes
            != tuple(sorted(REQUIRED_CAMPAIGN_RUNTIME_STOP_PROBES, key=str))
            or not self.created_at < self.deadline
            or self.campaign_execution_requested
            or self.action_execution_requested
            or self.dynamic_target_expansion_requested
            or self.credential_access_requested
            or self.submission_requested
            or self.runtime_plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"runtime_plan_id"}))
        ):
            raise ValueError("Campaign Runtime Qualification Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignRuntimeQualificationPlan:
        expanded = cls.model_construct(runtime_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"runtime_plan_id"}
        )
        return cls(runtime_plan_id=canonical_digest(expanded), **expanded)


class CampaignPhaseRuntimeObservation(DomainModel):
    observation_id: Digest
    runtime_plan_id: Digest
    campaign_plan_id: Digest
    campaign_outcome_id: Digest
    phase_id: Digest
    phase_kind: CampaignPhaseKind
    ordinal: int = Field(ge=1, le=6)
    prerequisite_phase_ids: Annotated[tuple[Digest, ...], Field(max_length=8)]
    approval_id: UUID
    approval_action: Literal[
        ApprovalAction.ADVANCE_CAMPAIGN_PHASE
    ] = ApprovalAction.ADVANCE_CAMPAIGN_PHASE
    approval_digest: Digest
    run_id: UUID
    task_id: UUID
    image_digest: ImageDigest
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    runner_result_digest: Digest
    status: Literal[SandboxRunStatus.COMPLETED] = SandboxRunStatus.COMPLETED
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
    target_set_unchanged: Literal[True] = True
    no_action_executed: Literal[True] = True
    cleanup_verified: Literal[True] = True
    container_absent: Literal[True] = True
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.approval_action is not ApprovalAction.ADVANCE_CAMPAIGN_PHASE
            or self.approval_digest != self.phase_id
            or self.status is not SandboxRunStatus.COMPLETED
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
                    self.target_set_unchanged,
                    self.no_action_executed,
                    self.cleanup_verified,
                    self.container_absent,
                )
            )
            or self.observation_id
            != canonical_digest(self.model_dump(mode="python", exclude={"observation_id"}))
        ):
            raise ValueError("Campaign Phase Runtime Observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignPhaseRuntimeObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class CampaignStopRuntimeObservation(DomainModel):
    observation_id: Digest
    runtime_plan_id: Digest
    campaign_plan_id: Digest
    campaign_outcome_id: Digest
    kind: CampaignRuntimeStopProbeKind
    run_id: UUID
    task_id: UUID
    image_digest: ImageDigest
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    runner_result_digest: Digest
    status: SandboxRunStatus
    error_codes: Annotated[tuple[str, ...], Field(max_length=2)] = ()
    worker_exit_code: int | None = Field(default=None, ge=0, le=255)
    assurance_level: RuntimeAssuranceLevel
    stop_enforced: Literal[True] = True
    no_extra_phase_started: Literal[True] = True
    target_set_unchanged: Literal[True] = True
    no_action_executed: Literal[True] = True
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
            CampaignRuntimeStopProbeKind.BUDGET_STOP: (
                SandboxRunStatus.COMPLETED,
                (),
                42,
            ),
            CampaignRuntimeStopProbeKind.TIMEOUT_CLEANUP: (
                SandboxRunStatus.TIMED_OUT,
                ("wall_time_budget_exceeded",),
                None,
            ),
        }[self.kind]
        if (
            (self.status, self.error_codes, self.worker_exit_code) != expected
            or not all(
                (
                    self.stop_enforced,
                    self.no_extra_phase_started,
                    self.target_set_unchanged,
                    self.no_action_executed,
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
            raise ValueError("Campaign Stop Runtime Observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignStopRuntimeObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class CampaignRuntimeQualificationOutcome(DomainModel):
    outcome_id: Digest
    runtime_plan_id: Digest
    campaign_plan_id: Digest
    campaign_outcome_id: Digest
    phase_observation_ids: Annotated[tuple[Digest, ...], Field(min_length=6, max_length=6)]
    stop_observation_ids: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=2)]
    assurance_level: RuntimeAssuranceLevel
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    qualified_autonomy: Literal[
        AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    ] = AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    isolated_runtime_qualified: Literal[True] = True
    production_campaign_runtime_admitted: bool
    campaign_started: Literal[False] = False
    action_execution_authority_granted: Literal[False] = False
    dynamic_target_expansion_granted: Literal[False] = False
    credential_access_granted: Literal[False] = False
    submission_granted: Literal[False] = False
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            len(set(self.phase_observation_ids)) != 6
            or len(set(self.stop_observation_ids)) != 2
            or self.production_campaign_runtime_admitted
            != (self.assurance_level is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION)
            or not self.isolated_runtime_qualified
            or self.campaign_started
            or self.action_execution_authority_granted
            or self.dynamic_target_expansion_granted
            or self.credential_access_granted
            or self.submission_granted
            or self.candidate_created
            or self.finding_created
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Campaign Runtime Qualification Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CampaignRuntimeQualificationOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
