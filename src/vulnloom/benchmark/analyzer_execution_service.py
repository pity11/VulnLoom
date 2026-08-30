"""Offline-only analyzer execution orchestration for M6.4a."""

from __future__ import annotations

from datetime import datetime

from vulnloom.domain.models import Scope, TargetSnapshot
from vulnloom.runners import OfflineSandboxRunner
from vulnloom.runners.models import SandboxRunStatus

from .analyzer_execution_models import (
    AnalyzerExecutionPlan,
    OfflineAnalyzerExecutionOutcome,
    OfflineAnalyzerExecutionStatus,
)
from .analyzer_execution_preflight import (
    AnalyzerExecutionRejected,
    validate_analyzer_execution,
)
from .analyzer_execution_registry import AnalyzerToolRegistry
from .analyzer_execution_store import AnalyzerExecutionStore


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
        registration = validate_analyzer_execution(
            scope=self.scope,
            registry=self.registry,
            target=target,
            plan=plan,
            now=now,
        )
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


__all__ = ["AnalyzerExecutionRejected", "OfflineAnalyzerExecutionService"]
