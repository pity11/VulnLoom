"""Typed contracts for the Control Plane / sandbox runner boundary."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope

from .environment import build_worker_environment

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ImageDigest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
ToolId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]


class SandboxProfileKind(StrEnum):
    STATIC = "static"
    VALIDATION = "validation"
    REPORT = "report"


class NetworkMode(StrEnum):
    NONE = "none"
    TARGET_ONLY = "target_only"


class MountKind(StrEnum):
    SNAPSHOT = "snapshot"
    EVIDENCE = "evidence"
    OUTPUT = "output"
    TEMP = "temp"


_MOUNT_DESTINATIONS = {
    MountKind.SNAPSHOT: "/workspace/source",
    MountKind.EVIDENCE: "/workspace/evidence",
    MountKind.OUTPUT: "/workspace/output",
    MountKind.TEMP: "/tmp",
}


class SandboxMount(DomainModel):
    kind: MountKind
    destination: str
    object_id: Digest | None = None
    read_only: bool

    @model_validator(mode="after")
    def enforce_fixed_slot(self) -> Self:
        if self.destination != _MOUNT_DESTINATIONS[self.kind]:
            raise ValueError("sandbox mount destination is not a registered slot")
        content_mount = self.kind in {MountKind.SNAPSHOT, MountKind.EVIDENCE}
        if content_mount and (self.object_id is None or not self.read_only):
            raise ValueError("content mounts require an immutable object id and read-only mode")
        if not content_mount and (self.object_id is not None or self.read_only):
            raise ValueError("scratch mounts must be anonymous and writable")
        return self


class NetworkGrant(DomainModel):
    host: str = Field(min_length=1, max_length=253)
    ports: Annotated[frozenset[Annotated[int, Field(ge=1, le=65535)]], Field(min_length=1)]
    schemes: frozenset[str]

    @field_validator("host")
    @classmethod
    def normalized_host(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized != value.lower() or any(item in normalized for item in "/@?#"):
            raise ValueError("network grant host must be a normalized hostname or IP literal")
        return normalized

    @field_validator("schemes")
    @classmethod
    def supported_schemes(cls, value: frozenset[str]) -> frozenset[str]:
        normalized = frozenset(item.lower() for item in value)
        if not normalized or not normalized <= {"http", "https"}:
            raise ValueError("network grant schemes must be http and/or https")
        return normalized


class SandboxLimits(DomainModel):
    wall_seconds: int = Field(gt=0, le=3600)
    cpu_millis: int = Field(gt=0, le=16 * 3_600_000)
    memory_bytes: int = Field(ge=16 * 1024 * 1024, le=16 * 1024 * 1024 * 1024)
    pids: int = Field(gt=0, le=4096)
    open_files: int = Field(gt=0, le=65_536)
    file_bytes: int = Field(gt=0, le=10 * 1024 * 1024 * 1024)
    tmp_bytes: int = Field(gt=0, le=10 * 1024 * 1024 * 1024)


class SandboxProfile(DomainModel):
    kind: SandboxProfileKind
    image_digest: ImageDigest
    run_as_uid: int = Field(gt=0, le=2**31 - 1)
    run_as_gid: int = Field(gt=0, le=2**31 - 1)
    read_only_root: bool = True
    no_new_privileges: bool = True
    capabilities: frozenset[str] = frozenset()
    network_mode: NetworkMode = NetworkMode.NONE
    network_grants: tuple[NetworkGrant, ...] = ()
    mounts: tuple[SandboxMount, ...]
    writable_paths: frozenset[str] = frozenset({"/tmp", "/workspace/output"})
    allowed_tools: frozenset[ToolId]
    execute_target_code: bool = False
    max_attempts: int = Field(default=2, ge=1, le=3)
    limits: SandboxLimits

    @model_validator(mode="after")
    def enforce_security_invariants(self) -> Self:
        if not self.read_only_root or not self.no_new_privileges or self.capabilities:
            raise ValueError("sandbox hardening flags cannot be weakened")
        if self.writable_paths != {"/tmp", "/workspace/output"}:
            raise ValueError("sandbox writable paths must match the registered scratch mounts")
        if len({mount.kind for mount in self.mounts}) != len(self.mounts):
            raise ValueError("sandbox mount kinds must be unique")
        kinds = {mount.kind for mount in self.mounts}
        if not {MountKind.OUTPUT, MountKind.TEMP} <= kinds:
            raise ValueError("sandbox requires bounded output and temporary mounts")
        if self.network_mode is NetworkMode.NONE and self.network_grants:
            raise ValueError("network-disabled profile cannot contain grants")
        if self.network_mode is NetworkMode.TARGET_ONLY and not self.network_grants:
            raise ValueError("target-only network requires an explicit grant")
        if self.kind in {
            SandboxProfileKind.STATIC,
            SandboxProfileKind.REPORT,
        } and (self.network_mode is not NetworkMode.NONE or self.execute_target_code):
            raise ValueError("static and report profiles cannot execute targets or use network")
        source_kinds = {MountKind.SNAPSHOT, MountKind.OUTPUT, MountKind.TEMP}
        report_kinds = {MountKind.EVIDENCE, MountKind.OUTPUT, MountKind.TEMP}
        if self.kind is SandboxProfileKind.STATIC and kinds != source_kinds:
            raise ValueError("static profile requires only source and scratch mounts")
        if self.kind is SandboxProfileKind.VALIDATION and (
            kinds != source_kinds or not self.execute_target_code
        ):
            raise ValueError("validation profile requires only source and scratch mounts")
        if self.kind is SandboxProfileKind.REPORT and kinds != report_kinds:
            raise ValueError("report profile requires only evidence and scratch mounts")
        return self


def sandbox_profile_digest(profile: SandboxProfile) -> str:
    return canonical_digest(profile.model_dump(mode="python"))


class WorkingDirectory(StrEnum):
    SOURCE = "source"
    OUTPUT = "output"
    TEMP = "temp"


class ToolInvocation(DomainModel):
    tool_id: ToolId
    arguments: Annotated[tuple[str, ...], Field(max_length=128)] = ()
    working_directory: WorkingDirectory

    @field_validator("arguments")
    @classmethod
    def safe_argument_size(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in item or len(item.encode()) > 16_384 for item in value):
            raise ValueError("tool argument contains NUL or exceeds the size limit")
        return value


class RunnerCheckpoint(DomainModel):
    checkpoint_id: Digest
    task_id: UUID
    target_id: UUID
    target_version: str = Field(min_length=1)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    policy_digest: Digest
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    attempt: int = Field(ge=1, le=3)


def checkpoint_digest(checkpoint: RunnerCheckpoint) -> str:
    payload = checkpoint.model_dump(mode="python", exclude={"checkpoint_id"})
    return canonical_digest(payload)


class SandboxRunRequest(DomainModel):
    run_id: UUID = Field(default_factory=uuid4)
    task: TaskEnvelope
    profile: SandboxProfile
    invocation: ToolInvocation
    environment: dict[str, str] = Field(default_factory=dict)
    attempt: int = Field(default=1, ge=1, le=3)
    resume_from: RunnerCheckpoint | None = None
    idempotency_key: str = Field(min_length=1, max_length=256)

    @field_validator("environment")
    @classmethod
    def environment_is_explicit_and_safe(cls, value: dict[str, str]) -> dict[str, str]:
        build_worker_environment(value)
        return value


def invocation_digest(invocation: ToolInvocation) -> str:
    return canonical_digest(invocation.model_dump(mode="python"))


def run_request_digest(request: SandboxRunRequest) -> str:
    return canonical_digest(request.model_dump(mode="python", exclude={"run_id"}))


class SandboxRunStatus(StrEnum):
    COMPLETED = "completed"
    CHECKPOINTED = "checkpointed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class SandboxUsage(DomainModel):
    wall_seconds: float = Field(ge=0)
    cpu_millis: int = Field(ge=0)
    peak_memory_bytes: int = Field(ge=0)
    pids_peak: int = Field(ge=0)
    open_files_peak: int = Field(ge=0)
    output_bytes: int = Field(ge=0)
    temporary_bytes: int = Field(ge=0)


class CleanupReport(DomainModel):
    processes_terminated: bool
    network_released: bool
    writable_layer_removed: bool
    temporary_mounts_removed: bool

    @property
    def complete(self) -> bool:
        return all(
            (
                self.processes_terminated,
                self.network_released,
                self.writable_layer_removed,
                self.temporary_mounts_removed,
            )
        )


class SandboxRunResult(DomainModel):
    run_id: UUID
    task_id: UUID
    status: SandboxRunStatus
    sandbox_profile_digest: Digest
    invocation_digest: Digest
    budget_used: TaskBudget
    usage: SandboxUsage
    evidence_refs: tuple[Digest, ...] = ()
    checkpoint: RunnerCheckpoint | None = None
    error_codes: tuple[str, ...] = ()
    cleanup: CleanupReport

    @model_validator(mode="after")
    def terminal_result_is_clean(self) -> Self:
        if not self.cleanup.complete:
            raise ValueError("sandbox result requires complete cleanup")
        if self.status is SandboxRunStatus.CHECKPOINTED and self.checkpoint is None:
            raise ValueError("checkpointed result requires a checkpoint")
        if self.status is not SandboxRunStatus.CHECKPOINTED and self.checkpoint is not None:
            raise ValueError("only checkpointed results may include a checkpoint")
        return self
