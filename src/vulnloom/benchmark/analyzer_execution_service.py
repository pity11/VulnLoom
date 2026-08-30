"""Offline-only analyzer execution orchestration for M6.4a."""

from __future__ import annotations

from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, ScopeState, TargetSnapshot
from vulnloom.domain.protocol import WorkerRole
from vulnloom.ingestion import IngestionError, IngestionService
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkMode, OfflineSandboxRunner, SandboxProfileKind
from vulnloom.runners.models import SandboxRunStatus, sandbox_profile_digest

from .analyzer_execution_models import (
    AnalyzerExecutionPlan,
    OfflineAnalyzerExecutionOutcome,
    OfflineAnalyzerExecutionStatus,
)
from .analyzer_execution_registry import AnalyzerToolRegistry
from .analyzer_execution_store import AnalyzerExecutionStore


class AnalyzerExecutionRejected(ValueError):
    """The sealed source-only execution request failed trusted preflight."""


class OfflineAnalyzerExecutionService:
    """Exercise the full control-plane contract without running an analyzer."""

    def __init__(
        self,
        *,
        scope: Scope,
        registry: AnalyzerToolRegistry,
        runner: OfflineSandboxRunner,
        store: AnalyzerExecutionStore,
    ):
        if type(runner) is not OfflineSandboxRunner:
            raise TypeError("offline analyzer execution requires the exact OfflineSandboxRunner")
        self.scope = scope
        self.registry = registry
        self.runner = runner
        self.store = store

    def execute(
        self,
        target: TargetSnapshot,
        plan: AnalyzerExecutionPlan,
        *,
        now: datetime,
    ) -> OfflineAnalyzerExecutionOutcome:
        registration = self._preflight(target, plan, now)
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed analyzer execution checkpoint has no outcome")
            return claim.outcome
        result = self.runner.execute(plan.runner_request, now=now)
        status = {
            SandboxRunStatus.COMPLETED: OfflineAnalyzerExecutionStatus.PROTOCOL_COMPLETED,
            SandboxRunStatus.FAILED: OfflineAnalyzerExecutionStatus.FAILED,
            SandboxRunStatus.TIMED_OUT: OfflineAnalyzerExecutionStatus.TIMED_OUT,
            SandboxRunStatus.CANCELLED: OfflineAnalyzerExecutionStatus.CANCELLED,
            SandboxRunStatus.CHECKPOINTED: OfflineAnalyzerExecutionStatus.FAILED,
        }[result.status]
        outcome = OfflineAnalyzerExecutionOutcome(
            plan_id=plan.plan_id,
            registration_id=registration.registration_id,
            target_id=target.target.target_id,
            target_version=target.target.version,
            status=status,
            runner_result=result,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome

    def _preflight(self, target: TargetSnapshot, plan: AnalyzerExecutionPlan, now: datetime):
        try:
            target = TargetSnapshot.model_validate(target.model_dump(mode="python"))
            plan = AnalyzerExecutionPlan.model_validate(plan.model_dump(mode="python"))
        except ValueError as exc:
            raise AnalyzerExecutionRejected(
                "analyzer execution boundary validation failed"
            ) from exc
        if self.scope.state is not ScopeState.APPROVED or not (
            self.scope.valid_from <= now < self.scope.valid_until
        ):
            raise AnalyzerExecutionRejected("Scope is not approved and active")
        try:
            IngestionService.require_snapshot_scope(target, self.scope, now)
        except IngestionError as exc:
            raise AnalyzerExecutionRejected("Target Snapshot is outside active Scope") from exc
        if now < plan.created_at or now >= plan.deadline or plan.deadline > self.scope.valid_until:
            raise AnalyzerExecutionRejected("analyzer execution plan is not active")
        if (
            target.target.engagement_id != self.scope.engagement_id
            or target.artifact.engagement_id != self.scope.engagement_id
            or target.manifest.target_id != target.target.target_id
            or target.manifest.target_version != target.target.version
            or plan.target_id != target.target.target_id
            or plan.target_version != target.target.version
            or plan.target_snapshot_digest != canonical_digest(target.model_dump(mode="python"))
            or plan.manifest_id != target.manifest.manifest_id
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
        ):
            raise AnalyzerExecutionRejected("analyzer execution Target or Scope binding mismatch")
        request = plan.runner_request
        task = request.task
        if (
            task.engagement_id != self.scope.engagement_id
            or task.target_id != target.target.target_id
            or task.target_version != target.target.version
            or task.scope_id != self.scope.scope_id
            or task.scope_version != self.scope.version
            or task.worker_role is not WorkerRole.ANALYZER
            or task.policy_digest != PolicyEngine(self.scope).policy_digest
            or task.deadline > plan.deadline
            or task.tool_registry_digest != self.registry.digest
            or plan.registry_digest != self.registry.digest
            or task.input_refs != (f"snapshot:{target.manifest.manifest_id}",)
        ):
            raise AnalyzerExecutionRejected("analyzer task provenance or policy binding mismatch")
        try:
            registration = self.registry.get(request.invocation.tool_id)
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
        return registration
