"""Sealed contracts for source-only analyzer execution orchestration."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.benchmark.analyzer_models import (
    AnalyzerImportLimits,
    AnalyzerImportOutcome,
    AnalyzerKind,
    AnalyzerResultFile,
    AnalyzerResultSnapshot,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, TargetSnapshot
from vulnloom.runners import SandboxRunRequest, SandboxRunResult, SandboxRunStatus
from vulnloom.runners.environment import build_worker_environment
from vulnloom.runners.models import Digest, ImageDigest, ToolId

from .trivy_database import TrivyDatabaseSnapshot


class AnalyzerExecutionMode(StrEnum):
    SOURCE_ONLY = "source_only"


class AnalyzerOutputMode(StrEnum):
    FILE = "file"
    STDOUT = "stdout"


class AnalyzerToolRegistration(DomainModel):
    registration_id: Digest
    tool_id: ToolId
    analyzer: AnalyzerKind
    tool_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
    image_digest: ImageDigest
    rules_digest: Digest
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    adapter_digest: Digest
    argv: Annotated[tuple[str, ...], Field(min_length=2, max_length=128)]
    input_paths: Annotated[tuple[str, ...], Field(max_length=4096)] = ()
    environment: dict[str, str] = Field(default_factory=dict)
    output_mode: AnalyzerOutputMode = AnalyzerOutputMode.FILE
    output_path: str | None = "/workspace/output/output.json"
    cwe_map: AnalyzerResultFile | None = None
    trivy_database: TrivyDatabaseSnapshot | None = None
    mode: AnalyzerExecutionMode = AnalyzerExecutionMode.SOURCE_ONLY

    @field_validator("argv")
    @classmethod
    def exact_safe_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value[0].startswith("/"):
            raise ValueError("analyzer executable must be an absolute in-image path")
        if PurePosixPath(value[0]).name.lower() in {
            "bash",
            "cmd.exe",
            "dash",
            "fish",
            "powershell",
            "pwsh",
            "sh",
            "zsh",
        }:
            raise ValueError("analyzer executable cannot be a shell interpreter")
        if any(
            not item
            or "\x00" in item
            or "\n" in item
            or "\r" in item
            or "{" in item
            or "}" in item
            or len(item.encode()) > 16_384
            for item in value
        ):
            raise ValueError("analyzer argv must be fixed, non-empty, and placeholder-free")
        return value

    @field_validator("environment")
    @classmethod
    def explicit_environment(cls, value: dict[str, str]) -> dict[str, str]:
        build_worker_environment(value)
        return value

    @field_validator("input_paths")
    @classmethod
    def safe_input_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            path = PurePosixPath(item)
            if (
                not item
                or "\\" in item
                or path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise ValueError("analyzer input path must be normalized and relative")
        if value != tuple(sorted(set(value))):
            raise ValueError("analyzer input paths must be unique and sorted")
        return value

    @model_validator(mode="after")
    def sealed_source_only_registration(self) -> Self:
        if not self.tool_id.startswith("analyzer."):
            raise ValueError("analyzer tool id must use the analyzer namespace")
        if self.output_mode is AnalyzerOutputMode.FILE:
            if self.output_path != "/workspace/output/output.json":
                raise ValueError("file-mode analyzer output path is fixed")
            if self.argv.count(self.output_path) != 1:
                raise ValueError("file-mode analyzer must write exactly one sealed output.json")
        elif self.output_path is not None:
            raise ValueError("stdout-mode analyzer cannot declare a filesystem output")
        if any("://" in item for item in self.argv):
            raise ValueError("analyzer argv cannot contain a network location")
        if self.trivy_database is not None and (
            self.analyzer is not AnalyzerKind.TRIVY
            or self.trivy_database.tool_version != self.tool_version
            or self.rules_digest != self.trivy_database.snapshot_id
            or self.cwe_map is not None
        ):
            raise ValueError("Trivy registration database or rules binding mismatch")
        if self.registration_id != analyzer_tool_registration_digest(self):
            raise ValueError("analyzer tool registration content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        tool_id: str,
        analyzer: AnalyzerKind,
        tool_version: str,
        image_digest: str,
        rules_digest: str,
        adapter_id: str,
        adapter_digest: str,
        argv: tuple[str, ...],
        input_paths: tuple[str, ...] = (),
        environment: dict[str, str] | None = None,
        output_mode: AnalyzerOutputMode = AnalyzerOutputMode.FILE,
        cwe_map: AnalyzerResultFile | None = None,
        trivy_database: TrivyDatabaseSnapshot | None = None,
    ) -> AnalyzerToolRegistration:
        values = {
            "tool_id": tool_id,
            "analyzer": analyzer,
            "tool_version": tool_version,
            "image_digest": image_digest,
            "rules_digest": rules_digest,
            "adapter_id": adapter_id,
            "adapter_digest": adapter_digest,
            "argv": argv,
            "input_paths": input_paths,
            "environment": environment or {},
            "output_mode": output_mode,
            "output_path": (
                "/workspace/output/output.json"
                if output_mode is AnalyzerOutputMode.FILE
                else None
            ),
            "cwe_map": cwe_map,
            "trivy_database": trivy_database,
            "mode": AnalyzerExecutionMode.SOURCE_ONLY,
        }
        digest_values = {
            **values,
            "cwe_map": cwe_map.model_dump(mode="python") if cwe_map is not None else None,
            "trivy_database": (
                trivy_database.model_dump(mode="python") if trivy_database is not None else None
            ),
        }
        return cls(registration_id=canonical_digest(digest_values), **values)


def analyzer_tool_registration_digest(registration: AnalyzerToolRegistration) -> str:
    return canonical_digest(registration.model_dump(mode="python", exclude={"registration_id"}))


class AnalyzerExecutionPlan(DomainModel):
    plan_id: Digest
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    target_snapshot_digest: Digest
    manifest_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    registration_id: Digest
    registration_digest: Digest
    registry_digest: Digest
    runner_request: SandboxRunRequest
    import_limits: AnalyzerImportLimits
    import_idempotency_key: str = Field(min_length=1, max_length=256)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("analyzer execution deadline must be after creation")
        if self.plan_id != analyzer_execution_plan_digest(self):
            raise ValueError("analyzer execution plan content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        target: TargetSnapshot,
        scope_id: UUID,
        scope_version: int,
        registration: AnalyzerToolRegistration,
        registry_digest: str,
        runner_request: SandboxRunRequest,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
        import_limits: AnalyzerImportLimits | None = None,
    ) -> AnalyzerExecutionPlan:
        values = {
            "target_id": target.target.target_id,
            "target_version": target.target.version,
            "target_snapshot_digest": canonical_digest(target.model_dump(mode="python")),
            "manifest_id": target.manifest.manifest_id,
            "scope_id": scope_id,
            "scope_version": scope_version,
            "registration_id": registration.registration_id,
            "registration_digest": canonical_digest(registration.model_dump(mode="python")),
            "registry_digest": registry_digest,
            "runner_request": runner_request,
            "import_limits": import_limits or AnalyzerImportLimits(),
            "import_idempotency_key": f"{idempotency_key}:observations",
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "runner_request": runner_request.model_dump(mode="python"),
            "import_limits": values["import_limits"].model_dump(mode="python"),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def analyzer_execution_plan_digest(plan: AnalyzerExecutionPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class OfflineAnalyzerExecutionStatus(StrEnum):
    PROTOCOL_COMPLETED = "protocol_completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class OfflineAnalyzerExecutionOutcome(DomainModel):
    plan_id: Digest
    registration_id: Digest
    target_id: UUID
    target_version: str
    status: OfflineAnalyzerExecutionStatus
    runner_result: SandboxRunResult
    analyzer_result_snapshot: None = None
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def does_not_claim_analyzer_output(self) -> Self:
        if not self.runner_result.cleanup.complete:
            raise ValueError("offline analyzer execution requires proven cleanup")
        return self


class DockerAnalyzerExecutionStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class DockerAnalyzerExecutionOutcome(DomainModel):
    plan_id: Digest
    registration_id: Digest
    target_id: UUID
    target_version: str
    status: DockerAnalyzerExecutionStatus
    runner_result: SandboxRunResult
    analyzer_result_snapshot: AnalyzerResultSnapshot | None = None
    import_outcome: AnalyzerImportOutcome | None = None
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def completed_execution_is_observation_bound(self) -> Self:
        if not self.runner_result.cleanup.complete:
            raise ValueError("Docker analyzer execution requires proven cleanup")
        expected_status = {
            SandboxRunStatus.COMPLETED: DockerAnalyzerExecutionStatus.COMPLETED,
            SandboxRunStatus.FAILED: DockerAnalyzerExecutionStatus.FAILED,
            SandboxRunStatus.TIMED_OUT: DockerAnalyzerExecutionStatus.TIMED_OUT,
            SandboxRunStatus.CANCELLED: DockerAnalyzerExecutionStatus.CANCELLED,
            SandboxRunStatus.CHECKPOINTED: DockerAnalyzerExecutionStatus.FAILED,
        }[self.runner_result.status]
        if self.status is not expected_status:
            raise ValueError("Docker analyzer status does not match its Runner result")
        completed = self.status is DockerAnalyzerExecutionStatus.COMPLETED
        if completed != (self.analyzer_result_snapshot is not None):
            raise ValueError("completed Docker analyzer execution requires a result snapshot")
        if completed != (self.import_outcome is not None):
            raise ValueError("completed Docker analyzer execution requires Observation import")
        if completed:
            assert self.analyzer_result_snapshot is not None
            assert self.import_outcome is not None
            if len(self.runner_result.outputs) != 1:
                raise ValueError("completed Docker analyzer execution requires one output")
            runner_output = self.runner_result.outputs[0]
            if (
                self.analyzer_result_snapshot.output.sha256 != runner_output.sha256
                or self.analyzer_result_snapshot.output.size
                != runner_output.size
                or self.import_outcome.snapshot_id
                != self.analyzer_result_snapshot.snapshot_id
                or self.import_outcome.observation_set.target_id != self.target_id
                or self.import_outcome.observation_set.target_version != self.target_version
                or self.import_outcome.observation_set.analyzer
                is not self.analyzer_result_snapshot.analyzer
            ):
                raise ValueError("Docker analyzer Observation import binding mismatch")
        return self
