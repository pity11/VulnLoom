"""Trusted projection of an actual Docker run into B5.2 isolation evidence."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from vulnloom.domain.digests import canonical_digest
from vulnloom.runners.environment import build_worker_environment
from vulnloom.runners.models import (
    MountKind,
    NetworkMode,
    SandboxProfileKind,
    SandboxRunRequest,
    SandboxRunResult,
    invocation_digest,
    sandbox_profile_digest,
)
from vulnloom.runners.seccomp import WORKER_SECCOMP_CONTRACT

from .adaptive_runtime_models import (
    AdaptiveRuntimeProbeKind,
    AdaptiveRuntimeProbeObservation,
    AdaptiveRuntimeQualificationPlan,
    RuntimeAssuranceLevel,
)


class AdaptiveRuntimeDockerEvidenceRejected(ValueError):
    pass


def observe_docker_adaptive_runtime(
    *,
    plan: AdaptiveRuntimeQualificationPlan,
    request: SandboxRunRequest,
    result: SandboxRunResult,
    inspection: Mapping[str, Any],
    engine_info: Mapping[str, Any],
    container_absent: bool,
    kind: AdaptiveRuntimeProbeKind,
    now: datetime,
) -> AdaptiveRuntimeProbeObservation:
    """Fail closed unless the exact B5.2 run crossed a real hardened container boundary."""

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
        (
            item
            for item in profile.mounts
            if item.kind is MountKind.EVIDENCE
        ),
        None,
    )
    inspected_evidence = next(
        (
            item
            for item in mounts
            if item.get("Destination") == "/workspace/evidence"
        ),
        None,
    )
    nofile = next(
        (item for item in host.get("Ulimits") or () if item.get("Name") == "nofile"),
        None,
    )
    network_disabled = host.get("NetworkMode") == "none" and not config.get(
        "ExposedPorts"
    )
    non_root = config.get("User") == f"{profile.run_as_uid}:{profile.run_as_gid}"
    read_only_root = host.get("ReadonlyRootfs") is True
    capabilities_dropped = set(host.get("CapDrop") or ()) == {"ALL"}
    no_new_privileges = any(
        "no-new-privileges" in str(item).lower()
        for item in host.get("SecurityOpt") or ()
    )
    seccomp_enforced = (
        any("seccomp" in item for item in security)
        and not (
            {str(item).lower() for item in host.get("SecurityOpt") or ()}
            & WORKER_SECCOMP_CONTRACT.forbidden_container_security_options
        )
    )
    resource_limits_enforced = (
        str(engine_info.get("CgroupVersion")) == "2"
        and all(
            engine_info.get(field) is True
            for field in ("MemoryLimit", "CpuCfsQuota", "PidsLimit")
        )
        and host.get("PidsLimit") == profile.limits.pids
        and host.get("Memory") == profile.limits.memory_bytes
        and host.get("MemorySwap") == profile.limits.memory_bytes
        and nofile is not None
        and nofile.get("Soft") == profile.limits.open_files
        and nofile.get("Hard") == profile.limits.open_files
    )
    content_mount_read_only = (
        evidence_mount is not None
        and evidence_mount.object_id == plan.coverage_ledger_id
        and evidence_mount.read_only
        and inspected_evidence is not None
        and inspected_evidence.get("RW") is False
    )
    docker_socket_absent = (
        not host.get("Binds")
        and not host.get("Devices")
        and all(
            item.get("Destination")
            not in {"/var/run/docker.sock", "/run/docker.sock"}
            for item in mounts
        )
    )
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
        and request.task.budget.model_tokens == 0
        and result.cleanup.complete
        and container_absent
    )
    boundaries = (
        network_disabled,
        non_root,
        read_only_root,
        capabilities_dropped,
        no_new_privileges,
        seccomp_enforced,
        resource_limits_enforced,
        actual_environment == expected_environment,
        content_mount_read_only,
        docker_socket_absent,
    )
    if not binding_valid or not all(boundaries):
        raise AdaptiveRuntimeDockerEvidenceRejected(
            "actual Docker runtime did not prove every sealed isolation boundary"
        )

    rootless = any("rootless" in item for item in security)
    production = (
        rootless
        and str(engine_info.get("ServerVersion"))
        in WORKER_SECCOMP_CONTRACT.engine_versions
        and WORKER_SECCOMP_CONTRACT.required_engine_security_option in security
    )
    return AdaptiveRuntimeProbeObservation.create(
        plan_id=plan.plan_id,
        adaptive_outcome_id=plan.adaptive_outcome_id,
        coverage_ledger_id=plan.coverage_ledger_id,
        kind=kind,
        run_id=result.run_id,
        task_id=result.task_id,
        image_digest=profile.image_digest,
        sandbox_profile_digest=result.sandbox_profile_digest,
        invocation_digest=result.invocation_digest,
        runner_result_digest=canonical_digest(result.model_dump(mode="python")),
        status=result.status,
        error_codes=result.error_codes,
        assurance_level=(
            RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            if production
            else RuntimeAssuranceLevel.LOCAL_DOCKER
        ),
        network_disabled=network_disabled,
        non_root=non_root,
        read_only_root=read_only_root,
        capabilities_dropped=capabilities_dropped,
        no_new_privileges=no_new_privileges,
        seccomp_enforced=seccomp_enforced,
        resource_limits_enforced=resource_limits_enforced,
        environment_allowlisted=actual_environment == expected_environment,
        content_mount_read_only=content_mount_read_only,
        docker_socket_absent=docker_socket_absent,
        cleanup_verified=result.cleanup.complete,
        container_absent=container_absent,
        observed_at=now,
    )
