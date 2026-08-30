"""Sealed contracts for source-only analyzer execution orchestration."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.benchmark.analyzer_models import AnalyzerKind
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, TargetSnapshot
from vulnloom.runners import SandboxRunRequest, SandboxRunResult
from vulnloom.runners.environment import build_worker_environment
from vulnloom.runners.models import Digest, ImageDigest, ToolId


class AnalyzerExecutionMode(StrEnum):
    SOURCE_ONLY = "source_only"


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
    environment: dict[str, str] = Field(default_factory=dict)
    output_path: str = "/workspace/output/output.json"
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

    @model_validator(mode="after")
    def sealed_source_only_registration(self) -> Self:
        if not self.tool_id.startswith("analyzer."):
            raise ValueError("analyzer tool id must use the analyzer namespace")
        if self.output_path != "/workspace/output/output.json":
            raise ValueError("analyzer output path is fixed")
        if self.argv.count(self.output_path) != 1:
            raise ValueError("analyzer argv must write exactly one sealed output.json")
        if any("://" in item for item in self.argv):
            raise ValueError("analyzer argv cannot contain a network location")
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
        environment: dict[str, str] | None = None,
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
            "environment": environment or {},
            "output_path": "/workspace/output/output.json",
            "mode": AnalyzerExecutionMode.SOURCE_ONLY,
        }
        return cls(registration_id=canonical_digest(values), **values)


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
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {**values, "runner_request": runner_request.model_dump(mode="python")}
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
