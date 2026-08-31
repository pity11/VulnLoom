"""Shared fail-closed preflight for offline and Docker analyzer execution."""

from __future__ import annotations

from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, ScopeState, TargetSnapshot
from vulnloom.domain.protocol import WorkerRole
from vulnloom.ingestion import IngestionError, IngestionService
from vulnloom.policy import PolicyEngine
from vulnloom.runners import MountKind, NetworkMode, SandboxProfileKind
from vulnloom.runners.models import sandbox_profile_digest

from .analyzer_execution_models import AnalyzerExecutionPlan, AnalyzerToolRegistration
from .analyzer_execution_registry import AnalyzerToolRegistry


class AnalyzerExecutionRejected(ValueError):
    """The sealed source-only execution request failed trusted preflight."""


def validate_analyzer_execution(
    *,
    scope: Scope,
    registry: AnalyzerToolRegistry,
    target: TargetSnapshot,
    plan: AnalyzerExecutionPlan,
    now: datetime,
) -> AnalyzerToolRegistration:
    try:
        target = TargetSnapshot.model_validate(target.model_dump(mode="python"))
        plan = AnalyzerExecutionPlan.model_validate(plan.model_dump(mode="python"))
    except ValueError as exc:
        raise AnalyzerExecutionRejected("analyzer execution boundary validation failed") from exc
    if scope.state is not ScopeState.APPROVED or not scope.valid_from <= now < scope.valid_until:
        raise AnalyzerExecutionRejected("Scope is not approved and active")
    try:
        IngestionService.require_snapshot_scope(target, scope, now)
    except IngestionError as exc:
        raise AnalyzerExecutionRejected("Target Snapshot is outside active Scope") from exc
    if now < plan.created_at or now >= plan.deadline or plan.deadline > scope.valid_until:
        raise AnalyzerExecutionRejected("analyzer execution plan is not active")
    if (
        target.target.engagement_id != scope.engagement_id
        or target.artifact.engagement_id != scope.engagement_id
        or target.manifest.target_id != target.target.target_id
        or target.manifest.target_version != target.target.version
        or plan.target_id != target.target.target_id
        or plan.target_version != target.target.version
        or plan.target_snapshot_digest != canonical_digest(target.model_dump(mode="python"))
        or plan.manifest_id != target.manifest.manifest_id
        or plan.scope_id != scope.scope_id
        or plan.scope_version != scope.version
    ):
        raise AnalyzerExecutionRejected("analyzer execution Target or Scope binding mismatch")
    request = plan.runner_request
    task = request.task
    if (
        task.engagement_id != scope.engagement_id
        or task.target_id != target.target.target_id
        or task.target_version != target.target.version
        or task.scope_id != scope.scope_id
        or task.scope_version != scope.version
        or task.worker_role is not WorkerRole.ANALYZER
        or task.policy_digest != PolicyEngine(scope).policy_digest
        or task.deadline > plan.deadline
        or task.tool_registry_digest != registry.digest
        or plan.registry_digest != registry.digest
    ):
        raise AnalyzerExecutionRejected("analyzer task provenance or policy binding mismatch")
    try:
        registration = registry.get(request.invocation.tool_id)
    except ValueError as exc:
        raise AnalyzerExecutionRejected(str(exc)) from exc
    if (
        plan.registration_id != registration.registration_id
        or plan.registration_digest != canonical_digest(registration.model_dump(mode="python"))
        or request.profile.kind is not SandboxProfileKind.STATIC
        or request.profile.network_mode is not NetworkMode.NONE
        or request.profile.execute_target_code
        or request.profile.image_digest != registration.image_digest
        or request.profile.allowed_tools != {registration.tool_id}
        or request.task.allowed_tools != {registration.tool_id}
        or request.task.sandbox_profile_digest != sandbox_profile_digest(request.profile)
        or request.invocation.arguments
        or request.invocation.working_directory.value != "source"
        or request.environment != registration.environment
    ):
        raise AnalyzerExecutionRejected("analyzer registration or sandbox binding mismatch")
    expected_refs = [f"snapshot:{target.manifest.manifest_id}"]
    expected_data_id = None
    if registration.trivy_database is not None:
        expected_data_id = registration.trivy_database.snapshot_id
        expected_refs.append(f"analyzer-data:{expected_data_id}")
    elif registration.codeql_snapshot is not None:
        expected_data_id = registration.codeql_snapshot.snapshot_id
        expected_refs.append(f"analyzer-data:{expected_data_id}")
    data_mounts = tuple(
        mount for mount in request.profile.mounts if mount.kind is MountKind.ANALYZER_DATA
    )
    if (
        task.input_refs != tuple(expected_refs)
        or (expected_data_id is None and data_mounts)
        or (
            expected_data_id is not None
            and (
                len(data_mounts) != 1
                or data_mounts[0].object_id != expected_data_id
                or not data_mounts[0].read_only
            )
        )
    ):
        raise AnalyzerExecutionRejected("analyzer data provenance or mount binding mismatch")
    return registration
