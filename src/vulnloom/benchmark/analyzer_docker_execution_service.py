"""Real network-disabled Checkov/Kubesec execution followed by M6.3a import."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vulnloom.domain.models import Scope, TargetSnapshot
from vulnloom.runners import DockerSandboxRunner, RunnerOutputStore, SandboxRunStatus

from .analyzer_docker_execution_store import AnalyzerDockerExecutionStore
from .analyzer_execution_adapters import validate_admitted_registration
from .analyzer_execution_models import (
    AnalyzerExecutionPlan,
    DockerAnalyzerExecutionOutcome,
    DockerAnalyzerExecutionStatus,
)
from .analyzer_execution_preflight import (
    AnalyzerExecutionRejected,
    validate_analyzer_execution,
)
from .analyzer_execution_registry import AnalyzerToolRegistry
from .analyzer_io import (
    AnalyzerDeadline,
    AnalyzerImportRejected,
    create_analyzer_snapshot,
    inspect_result_file,
)
from .analyzer_models import AnalyzerImportPlan
from .analyzer_service import AnalyzerImportService


class DockerAnalyzerExecutionService:
    def __init__(
        self,
        *,
        scope: Scope,
        registry: AnalyzerToolRegistry,
        runner: DockerSandboxRunner,
        output_store: RunnerOutputStore,
        execution_store: AnalyzerDockerExecutionStore,
        import_service: AnalyzerImportService,
    ):
        if type(runner) is not DockerSandboxRunner:
            raise TypeError("real analyzer execution requires the exact DockerSandboxRunner")
        if runner.output_store is not output_store:
            raise ValueError("Docker Runner and analyzer service must share one output store")
        self.scope = scope
        self.registry = registry
        self.runner = runner
        self.output_store = output_store
        self.execution_store = execution_store
        self.import_service = import_service

    def execute(
        self,
        target: TargetSnapshot,
        plan: AnalyzerExecutionPlan,
        *,
        cwe_map_path: Path,
        now: datetime,
    ) -> DockerAnalyzerExecutionOutcome:
        registration = validate_analyzer_execution(
            scope=self.scope,
            registry=self.registry,
            target=target,
            plan=plan,
            now=now,
        )
        try:
            validate_admitted_registration(target, registration)
        except ValueError as exc:
            raise AnalyzerExecutionRejected(str(exc)) from exc
        if (
            registration.tool_id not in self.runner.captured_output_tools
            or self.import_service.adapter.kind is not registration.analyzer
            or self.import_service.adapter.adapter_id != registration.adapter_id
            or self.import_service.adapter.adapter_digest != registration.adapter_digest
            or registration.cwe_map is None
        ):
            raise AnalyzerExecutionRejected("Docker output or Observation adapter binding mismatch")
        cwe_map = inspect_result_file(
            cwe_map_path,
            logical_name="cwe-map.json",
            max_bytes=plan.import_limits.max_cwe_map_bytes,
            deadline=AnalyzerDeadline(
                min(
                    plan.import_limits.timeout_seconds,
                    max(0.001, (plan.deadline - now).total_seconds()),
                )
            ),
        )
        if cwe_map != registration.cwe_map:
            raise AnalyzerExecutionRejected("analyzer CWE map does not match its registration")

        claim = self.execution_store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed analyzer Docker checkpoint has no outcome")
            return claim.outcome
        result = self.runner.execute(plan.runner_request, now=now)
        if result.status is not SandboxRunStatus.COMPLETED:
            outcome = DockerAnalyzerExecutionOutcome(
                plan_id=plan.plan_id,
                registration_id=registration.registration_id,
                target_id=target.target.target_id,
                target_version=target.target.version,
                status=_execution_status(result.status),
                runner_result=result,
                completed_at=now,
            )
            self.execution_store.complete(outcome)
            return outcome
        if len(result.outputs) != 1:
            raise AnalyzerExecutionRejected("completed analyzer run did not publish one output")
        output_path = self.output_store.path(result.outputs[0])
        snapshot = create_analyzer_snapshot(
            output_path,
            analyzer=registration.analyzer,
            target_id=target.target.target_id,
            target_version=target.target.version,
            tool_version=registration.tool_version,
            rules_digest=registration.rules_digest,
            cwe_map_path=cwe_map_path,
            limits=plan.import_limits,
        )
        if (
            snapshot.output.sha256 != result.outputs[0].sha256
            or snapshot.output.size != result.outputs[0].size
            or snapshot.cwe_map != registration.cwe_map
        ):
            raise AnalyzerImportRejected("captured analyzer output binding mismatch")
        import_plan = AnalyzerImportPlan.create(
            snapshot=snapshot,
            adapter_id=registration.adapter_id,
            adapter_digest=registration.adapter_digest,
            limits=plan.import_limits,
            created_at=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.import_idempotency_key,
        )
        imported = self.import_service.import_result(
            output_path,
            snapshot,
            import_plan,
            now=now,
            cwe_map_path=cwe_map_path,
        )
        outcome = DockerAnalyzerExecutionOutcome(
            plan_id=plan.plan_id,
            registration_id=registration.registration_id,
            target_id=target.target.target_id,
            target_version=target.target.version,
            status=DockerAnalyzerExecutionStatus.COMPLETED,
            runner_result=result,
            analyzer_result_snapshot=snapshot,
            import_outcome=imported,
            completed_at=now,
        )
        self.execution_store.complete(outcome)
        return outcome


def _execution_status(status: SandboxRunStatus) -> DockerAnalyzerExecutionStatus:
    return {
        SandboxRunStatus.FAILED: DockerAnalyzerExecutionStatus.FAILED,
        SandboxRunStatus.TIMED_OUT: DockerAnalyzerExecutionStatus.TIMED_OUT,
        SandboxRunStatus.CANCELLED: DockerAnalyzerExecutionStatus.CANCELLED,
        SandboxRunStatus.CHECKPOINTED: DockerAnalyzerExecutionStatus.FAILED,
    }[status]
