"""Shared fail-closed validation for every sandbox runner implementation."""

from __future__ import annotations

from pydantic import ValidationError

from vulnloom.domain.protocol import WorkerRole

from .environment import build_worker_environment
from .models import (
    MountKind,
    SandboxProfileKind,
    SandboxRunRequest,
    checkpoint_digest,
    invocation_digest,
    sandbox_profile_digest,
)


class RunnerRejected(ValueError):
    """The request failed preflight before any sandbox resource was created."""


class RunnerIdempotencyConflict(ValueError):
    """A run idempotency key was reused for a different request."""


_ROLE_PROFILES = {
    WorkerRole.SCOPE_INTERPRETER: SandboxProfileKind.STATIC,
    WorkerRole.SOURCE_MAPPER: SandboxProfileKind.STATIC,
    WorkerRole.HYPOTHESIS: SandboxProfileKind.STATIC,
    WorkerRole.ANALYZER: SandboxProfileKind.STATIC,
    WorkerRole.VALIDATOR: SandboxProfileKind.VALIDATION,
    WorkerRole.CRITIC: SandboxProfileKind.REPORT,
    WorkerRole.REPORTER: SandboxProfileKind.REPORT,
}


def validate_run_request(
    request: SandboxRunRequest, registered_tools: frozenset[str]
) -> SandboxRunRequest:
    """Reparse and authorize a request before a runner allocates resources."""
    try:
        request = SandboxRunRequest.model_validate(request.model_dump(mode="python"))
    except ValidationError as exc:
        raise RunnerRejected("sandbox run request failed boundary validation") from exc

    profile_digest = sandbox_profile_digest(request.profile)
    if request.task.sandbox_profile_digest != profile_digest:
        raise RunnerRejected("TaskEnvelope is bound to another SandboxProfile")
    if _ROLE_PROFILES[request.task.worker_role] is not request.profile.kind:
        raise RunnerRejected("Worker role cannot use this SandboxProfile kind")
    tool_id = request.invocation.tool_id
    if (
        tool_id not in registered_tools
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
        return request

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
    return request
