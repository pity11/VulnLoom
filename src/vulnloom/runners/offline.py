"""A deterministic runner that proves orchestration semantics without executing code."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field, ValidationError

from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskBudget, WorkerRole

from .environment import build_worker_environment
from .models import (
    CleanupReport,
    Digest,
    MountKind,
    RunnerCheckpoint,
    SandboxProfileKind,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    SandboxUsage,
    checkpoint_digest,
    invocation_digest,
    run_request_digest,
    sandbox_profile_digest,
)


class RunnerRejected(ValueError):
    """The request failed preflight before any sandbox resource was created."""


class RunnerIdempotencyConflict(ValueError):
    """A run idempotency key was reused for a different request."""


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


_ROLE_PROFILES = {
    WorkerRole.SCOPE_INTERPRETER: SandboxProfileKind.STATIC,
    WorkerRole.SOURCE_MAPPER: SandboxProfileKind.STATIC,
    WorkerRole.HYPOTHESIS: SandboxProfileKind.STATIC,
    WorkerRole.VALIDATOR: SandboxProfileKind.VALIDATION,
    WorkerRole.CRITIC: SandboxProfileKind.REPORT,
    WorkerRole.REPORTER: SandboxProfileKind.REPORT,
}


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
        try:
            request = SandboxRunRequest.model_validate(request.model_dump(mode="python"))
        except ValidationError as exc:
            raise RunnerRejected("sandbox run request failed boundary validation") from exc
        self._preflight(request)
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

    def _preflight(self, request: SandboxRunRequest) -> None:
        profile_digest = sandbox_profile_digest(request.profile)
        if request.task.sandbox_profile_digest != profile_digest:
            raise RunnerRejected("TaskEnvelope is bound to another SandboxProfile")
        if _ROLE_PROFILES[request.task.worker_role] is not request.profile.kind:
            raise RunnerRejected("Worker role cannot use this SandboxProfile kind")
        tool_id = request.invocation.tool_id
        if (
            tool_id not in self.registered_tools
            or tool_id not in request.task.allowed_tools
            or tool_id not in request.profile.allowed_tools
        ):
            raise RunnerRejected("tool is not registered and allowed by both task and profile")
        if request.task.budget.tool_calls < 1:
            raise RunnerRejected("TaskEnvelope has no tool-call budget")
        build_worker_environment(request.environment)
        mount_kinds = {mount.kind for mount in request.profile.mounts}
        required_mount = {
            "source": MountKind.SNAPSHOT,
            "output": MountKind.OUTPUT,
            "temp": MountKind.TEMP,
        }[request.invocation.working_directory.value]
        if required_mount not in mount_kinds:
            raise RunnerRejected("working directory is unavailable in the SandboxProfile")
        if request.attempt > request.profile.max_attempts:
            raise RunnerRejected("run attempt exceeds the SandboxProfile retry limit")
        if request.resume_from is None:
            if request.attempt != 1:
                raise RunnerRejected("non-initial attempt requires a checkpoint")
            return
        checkpoint = request.resume_from
        if checkpoint_digest(checkpoint) != checkpoint.checkpoint_id:
            raise RunnerRejected("checkpoint content digest mismatch")
        expected = (
            checkpoint.task_id == request.task.task_id
            and checkpoint.target_id == request.task.target_id
            and checkpoint.target_version == request.task.target_version
            and checkpoint.scope_id == request.task.scope_id
            and checkpoint.scope_version == request.task.scope_version
            and checkpoint.policy_digest == request.task.policy_digest
            and checkpoint.sandbox_profile_digest == profile_digest
            and checkpoint.invocation_digest == invocation_digest(request.invocation)
            and request.attempt == checkpoint.attempt + 1
        )
        if not expected:
            raise RunnerRejected("checkpoint does not match the run request")
