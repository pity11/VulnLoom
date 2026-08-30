"""A deterministic runner that proves orchestration semantics without executing code."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskBudget

from .models import (
    CleanupReport,
    Digest,
    RunnerCheckpoint,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    SandboxUsage,
    checkpoint_digest,
    invocation_digest,
    run_request_digest,
    sandbox_profile_digest,
)
from .preflight import RunnerIdempotencyConflict, validate_run_request


class OfflineOutcome(StrEnum):
    COMPLETED = "completed"
    CHECKPOINTED = "checkpointed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class OfflineScenario(DomainModel):
    outcome: OfflineOutcome = OfflineOutcome.COMPLETED
    wall_seconds: float = Field(default=0.01, ge=0)
    cpu_millis: int = Field(default=1, ge=0)
    peak_memory_bytes: int = Field(default=1024, ge=0)
    pids_peak: int = Field(default=1, ge=0)
    open_files_peak: int = Field(default=3, ge=0)
    output_bytes: int = Field(default=0, ge=0)
    temporary_bytes: int = Field(default=0, ge=0)
    evidence_refs: tuple[Digest, ...] = ()


class OfflineSandboxRunner:
    """Records lifecycle results but never spawns a process or opens a network socket."""

    def __init__(self, registered_tools: frozenset[str]):
        self.registered_tools = registered_tools
        self._results: dict[str, tuple[str, SandboxRunResult]] = {}

    def execute(
        self,
        request: SandboxRunRequest,
        *,
        now: datetime,
        scenario: OfflineScenario | None = None,
    ) -> SandboxRunResult:
        request = validate_run_request(request, self.registered_tools)
        digest = run_request_digest(request)
        existing = self._results.get(request.idempotency_key)
        if existing is not None:
            if existing[0] != digest:
                raise RunnerIdempotencyConflict(
                    "run idempotency key was reused with a different request"
                )
            return existing[1]

        selected = scenario or OfflineScenario()
        profile_digest = sandbox_profile_digest(request.profile)
        invocation_id = invocation_digest(request.invocation)
        status = SandboxRunStatus.COMPLETED
        errors: tuple[str, ...] = ()
        checkpoint = None
        wall_limit = min(request.task.budget.wall_seconds, request.profile.limits.wall_seconds)
        if now >= request.task.deadline or selected.wall_seconds > wall_limit:
            status = SandboxRunStatus.TIMED_OUT
            errors = ("wall_time_budget_exceeded",)
        elif (
            selected.cpu_millis > request.profile.limits.cpu_millis
            or selected.peak_memory_bytes > request.profile.limits.memory_bytes
            or selected.pids_peak > request.profile.limits.pids
            or selected.open_files_peak > request.profile.limits.open_files
            or selected.output_bytes > request.profile.limits.file_bytes
            or selected.temporary_bytes > request.profile.limits.tmp_bytes
        ):
            status = SandboxRunStatus.FAILED
            errors = ("sandbox_resource_limit_exceeded",)
        elif selected.outcome is OfflineOutcome.CANCELLED:
            status = SandboxRunStatus.CANCELLED
            errors = ("cancelled_by_control_plane",)
        elif selected.outcome is OfflineOutcome.FAILED:
            status = SandboxRunStatus.FAILED
            errors = ("offline_scenario_failed",)
        elif selected.outcome is OfflineOutcome.CHECKPOINTED:
            if request.attempt >= request.profile.max_attempts:
                status = SandboxRunStatus.FAILED
                errors = ("retry_limit_exhausted",)
            else:
                status = SandboxRunStatus.CHECKPOINTED
                partial = RunnerCheckpoint(
                    checkpoint_id="0" * 64,
                    task_id=request.task.task_id,
                    target_id=request.task.target_id,
                    target_version=request.task.target_version,
                    scope_id=request.task.scope_id,
                    scope_version=request.task.scope_version,
                    policy_digest=request.task.policy_digest,
                    sandbox_profile_digest=profile_digest,
                    invocation_digest=invocation_id,
                    attempt=request.attempt,
                )
                checkpoint = partial.model_copy(
                    update={"checkpoint_id": checkpoint_digest(partial)}
                )

        cleanup = CleanupReport(
            processes_terminated=True,
            network_released=True,
            writable_layer_removed=True,
            temporary_mounts_removed=True,
        )
        result = SandboxRunResult(
            run_id=request.run_id,
            task_id=request.task.task_id,
            status=status,
            sandbox_profile_digest=profile_digest,
            invocation_digest=invocation_id,
            budget_used=TaskBudget(
                wall_seconds=max(1, min(int(selected.wall_seconds), wall_limit)),
                model_tokens=0,
                tool_calls=0 if status is SandboxRunStatus.TIMED_OUT else 1,
            ),
            usage=SandboxUsage(
                wall_seconds=selected.wall_seconds,
                cpu_millis=selected.cpu_millis,
                peak_memory_bytes=selected.peak_memory_bytes,
                pids_peak=selected.pids_peak,
                open_files_peak=selected.open_files_peak,
                output_bytes=selected.output_bytes,
                temporary_bytes=selected.temporary_bytes,
            ),
            evidence_refs=selected.evidence_refs if status is SandboxRunStatus.COMPLETED else (),
            checkpoint=checkpoint,
            error_codes=errors,
            cleanup=cleanup,
        )
        self._results[request.idempotency_key] = (digest, result)
        return result
