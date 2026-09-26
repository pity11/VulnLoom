"""Trusted Docker projections for B5.4 Campaign runtime evidence."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest
from vulnloom.runners.environment import build_worker_environment
from vulnloom.runners.models import (
    MountKind,
    NetworkMode,
    SandboxProfileKind,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    invocation_digest,
    sandbox_profile_digest,
)
from vulnloom.runners.seccomp import WORKER_SECCOMP_CONTRACT

from .adaptive_runtime_models import RuntimeAssuranceLevel
from .campaign_models import CampaignPhase, GoalDrivenCampaignPlan
from .campaign_runtime_models import (
    CampaignPhaseRuntimeObservation,
    CampaignRuntimeQualificationPlan,
    CampaignRuntimeStopProbeKind,
    CampaignStopRuntimeObservation,
)


class CampaignRuntimeDockerEvidenceRejected(ValueError):
    pass


def observe_docker_campaign_phase(
    *,
    plan: CampaignRuntimeQualificationPlan,
    campaign_plan: GoalDrivenCampaignPlan,
    phase: CampaignPhase,
    approval: ApprovalRequest,
    request: SandboxRunRequest,
    result: SandboxRunResult,
    inspection: Mapping[str, Any],
    terminal_inspection: Mapping[str, Any],
    engine_info: Mapping[str, Any],
    container_absent: bool,
    now: datetime,
) -> CampaignPhaseRuntimeObservation:
    """Project one exact admitted phase canary after verifying real isolation."""

    boundaries, assurance = _boundaries(
        plan=plan,
        campaign_plan=campaign_plan,
        request=request,
        result=result,
        inspection=inspection,
        engine_info=engine_info,
        container_absent=container_absent,
    )
    if (
        phase not in campaign_plan.phases
        or request.invocation.arguments
        != (phase.phase_id, phase.kind.value, str(phase.ordinal))
        or result.status is not SandboxRunStatus.COMPLETED
        or result.error_codes
        or terminal_inspection.get("State", {}).get("ExitCode") != 0
        or approval.engagement_id != request.task.engagement_id
        or approval.target_id is not None
        or approval.decided_at is None
        or approval.decided_at > now
        or not approval.is_valid_for(
            action=ApprovalAction.ADVANCE_CAMPAIGN_PHASE,
            digest=phase.phase_id,
            now=now,
        )
    ):
        raise CampaignRuntimeDockerEvidenceRejected(
            "actual Docker phase run did not prove its sealed admission and terminal"
        )
    return CampaignPhaseRuntimeObservation.create(
        runtime_plan_id=plan.runtime_plan_id,
        campaign_plan_id=plan.campaign_plan_id,
        campaign_outcome_id=plan.campaign_outcome_id,
        phase_id=phase.phase_id,
        phase_kind=phase.kind,
        ordinal=phase.ordinal,
        prerequisite_phase_ids=phase.prerequisite_phase_ids,
        approval_id=approval.approval_id,
        approval_digest=approval.action_digest,
        run_id=result.run_id,
        task_id=result.task_id,
        image_digest=request.profile.image_digest,
        sandbox_profile_digest=result.sandbox_profile_digest,
        invocation_digest=result.invocation_digest,
        runner_result_digest=canonical_digest(result.model_dump(mode="python")),
        status=result.status,
        assurance_level=assurance,
        observed_at=now,
        **boundaries,
    )


def observe_docker_campaign_stop(
    *,
    plan: CampaignRuntimeQualificationPlan,
    campaign_plan: GoalDrivenCampaignPlan,
    kind: CampaignRuntimeStopProbeKind,
    request: SandboxRunRequest,
    result: SandboxRunResult,
    inspection: Mapping[str, Any],
    terminal_inspection: Mapping[str, Any] | None,
    engine_info: Mapping[str, Any],
    container_absent: bool,
    now: datetime,
) -> CampaignStopRuntimeObservation:
    """Project an actual budget-stop or timeout-cleanup canary."""

    boundaries, assurance = _boundaries(
        plan=plan,
        campaign_plan=campaign_plan,
        request=request,
        result=result,
        inspection=inspection,
        engine_info=engine_info,
        container_absent=container_absent,
    )
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
    }[kind]
    terminal_code = (
        terminal_inspection.get("State", {}).get("ExitCode")
        if terminal_inspection is not None
        else None
    )
    worker_exit_code = terminal_code if kind is CampaignRuntimeStopProbeKind.BUDGET_STOP else None
    if (
        request.invocation.arguments != (kind.value,)
        or (result.status, result.error_codes, worker_exit_code) != expected
    ):
        raise CampaignRuntimeDockerEvidenceRejected(
            "actual Docker stop run did not prove its sealed stop terminal"
        )
    return CampaignStopRuntimeObservation.create(
        runtime_plan_id=plan.runtime_plan_id,
        campaign_plan_id=plan.campaign_plan_id,
        campaign_outcome_id=plan.campaign_outcome_id,
        kind=kind,
        run_id=result.run_id,
        task_id=result.task_id,
        image_digest=request.profile.image_digest,
        sandbox_profile_digest=result.sandbox_profile_digest,
        invocation_digest=result.invocation_digest,
        runner_result_digest=canonical_digest(result.model_dump(mode="python")),
        status=result.status,
        error_codes=result.error_codes,
        worker_exit_code=worker_exit_code,
        assurance_level=assurance,
        observed_at=now,
        **boundaries,
    )


def _boundaries(
    *,
    plan: CampaignRuntimeQualificationPlan,
    campaign_plan: GoalDrivenCampaignPlan,
    request: SandboxRunRequest,
    result: SandboxRunResult,
    inspection: Mapping[str, Any],
    engine_info: Mapping[str, Any],
    container_absent: bool,
) -> tuple[dict[str, bool], RuntimeAssuranceLevel]:
    profile = request.profile
    config = inspection.get("Config", {})
    host = inspection.get("HostConfig", {})
    mounts = inspection.get("Mounts") or ()
    security = {str(item).lower() for item in engine_info.get("SecurityOptions", ())}
    expected_environment = build_worker_environment(request.environment)
    expected_environment["PATH"] = (
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    actual_environment = dict(
        item.split("=", 1) for item in config.get("Env", ()) if "=" in item
    )
    evidence_mount = next(
        (item for item in profile.mounts if item.kind is MountKind.EVIDENCE), None
    )
    inspected_evidence = next(
        (item for item in mounts if item.get("Destination") == "/workspace/evidence"),
        None,
    )
    nofile = next(
        (item for item in host.get("Ulimits") or () if item.get("Name") == "nofile"),
        None,
    )
    values = {
        "network_disabled": host.get("NetworkMode") == "none"
        and not config.get("ExposedPorts"),
        "non_root": config.get("User") == f"{profile.run_as_uid}:{profile.run_as_gid}",
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "capabilities_dropped": set(host.get("CapDrop") or ()) == {"ALL"},
        "no_new_privileges": any(
            "no-new-privileges" in str(item).lower()
            for item in host.get("SecurityOpt") or ()
        ),
        "seccomp_enforced": any("seccomp" in item for item in security)
        and not (
            {str(item).lower() for item in host.get("SecurityOpt") or ()}
            & WORKER_SECCOMP_CONTRACT.forbidden_container_security_options
        ),
        "resource_limits_enforced": str(engine_info.get("CgroupVersion")) == "2"
        and all(
            engine_info.get(field) is True
            for field in ("MemoryLimit", "CpuCfsQuota", "PidsLimit")
        )
        and host.get("PidsLimit") == profile.limits.pids
        and host.get("Memory") == profile.limits.memory_bytes
        and host.get("MemorySwap") == profile.limits.memory_bytes
        and nofile is not None
        and nofile.get("Soft") == profile.limits.open_files
        and nofile.get("Hard") == profile.limits.open_files,
        "environment_allowlisted": actual_environment == expected_environment,
        "content_mount_read_only": evidence_mount is not None
        and evidence_mount.object_id == plan.campaign_outcome_id
        and evidence_mount.read_only
        and inspected_evidence is not None
        and inspected_evidence.get("RW") is False,
        "docker_socket_absent": not host.get("Binds")
        and not host.get("Devices")
        and all(
            item.get("Destination")
            not in {"/var/run/docker.sock", "/run/docker.sock"}
            for item in mounts
        ),
        "target_set_unchanged": canonical_digest(campaign_plan.target_ids)
        == plan.target_set_digest,
        "no_action_executed": request.task.budget.model_tokens == 0
        and request.task.budget.tool_calls == 1
        and request.task.allowed_tools == frozenset({"red_team.evidence_read"})
        and request.invocation.tool_id == "red_team.evidence_read"
        and not result.outputs
        and not result.evidence_refs,
        "cleanup_verified": result.cleanup.complete,
        "container_absent": container_absent,
    }
    binding_valid = (
        profile.kind is SandboxProfileKind.POST_EXPLOITATION
        and profile.network_mode is NetworkMode.NONE
        and not profile.execute_target_code
        and profile.image_digest == plan.image_digest
        and sandbox_profile_digest(profile) == plan.sandbox_profile_digest
        and result.run_id == request.run_id
        and result.task_id == request.task.task_id
        and result.sandbox_profile_digest == plan.sandbox_profile_digest
        and result.invocation_digest == invocation_digest(request.invocation)
        and request.task.sandbox_profile_digest == plan.sandbox_profile_digest
        and request.task.scope_id == plan.scope_id
        and request.task.scope_version == plan.scope_version
        and request.task.target_id in campaign_plan.target_ids
        and request.task.target_version == plan.campaign_plan_id
        and result.cleanup.complete
        and container_absent
    )
    if not binding_valid or not all(values.values()):
        raise CampaignRuntimeDockerEvidenceRejected(
            "actual Docker Campaign runtime did not prove every sealed boundary"
        )
    rootless = any("rootless" in item for item in security)
    production = (
        rootless
        and str(engine_info.get("ServerVersion"))
        in WORKER_SECCOMP_CONTRACT.engine_versions
        and WORKER_SECCOMP_CONTRACT.required_engine_security_option in security
    )
    return values, (
        RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
        if production
        else RuntimeAssuranceLevel.LOCAL_DOCKER
    )
