"""Typed, content-addressed contracts for trusted project build recipes."""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, DomainModel
from vulnloom.runners import DockerTool, SandboxRunRequest, SandboxRunResult
from vulnloom.runners.environment import build_worker_environment
from vulnloom.runners.models import ImageDigest, ToolId
from vulnloom.source_hunt.models import BuildSystem

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ProjectRecipePhase(StrEnum):
    BUILD = "build"
    TEST = "test"


class ProjectRecipeStep(DomainModel):
    """One exact, trusted in-image command. Runtime arguments are forbidden."""

    step_id: Digest
    phase: ProjectRecipePhase
    tool_id: ToolId
    argv: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    environment: dict[str, str] = Field(default_factory=dict)
    wall_seconds: int = Field(default=600, ge=1, le=600)

    @field_validator("argv")
    @classmethod
    def fixed_non_shell_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        shell_names = {"bash", "dash", "fish", "powershell", "pwsh", "sh", "zsh"}
        executable = PurePosixPath(value[0])
        if (
            not executable.is_absolute()
            or value[0].startswith("//")
            or executable.as_posix() != value[0]
            or any(part in {"", ".", ".."} for part in executable.parts[1:])
            or executable.name.lower() in shell_names
        ):
            raise ValueError("project recipe requires an absolute non-shell executable")
        if any(
            not item
            or "\x00" in item
            or "\n" in item
            or "\r" in item
            or "{" in item
            or "}" in item
            or "://" in item
            or len(item.encode("utf-8")) > 16_384
            for item in value
        ):
            raise ValueError("project recipe argv must be fixed, bounded, and network-free")
        if sum(len(item.encode("utf-8")) + 1 for item in value) > 65_536:
            raise ValueError("project recipe argv exceeds its aggregate size limit")
        return value

    @field_validator("environment")
    @classmethod
    def explicit_environment(cls, value: dict[str, str]) -> dict[str, str]:
        build_worker_environment(value)
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.step_id != canonical_digest(
            self.model_dump(mode="python", exclude={"step_id"})
        ):
            raise ValueError("project recipe step content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> ProjectRecipeStep:
        expanded = cls.model_construct(step_id="0" * 64, **values).model_dump(
            mode="python", exclude={"step_id"}
        )
        return cls(step_id=canonical_digest(expanded), **expanded)

    def docker_tool(self) -> DockerTool:
        return DockerTool(tool_id=self.tool_id, argv_prefix=self.argv)


class ProjectRecipe(DomainModel):
    """Versioned recipe selected only from the trusted registry."""

    recipe_id: Digest
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
    required_build_systems: Annotated[
        tuple[BuildSystem, ...], Field(min_length=1, max_length=8)
    ]
    image_digest: ImageDigest
    steps: Annotated[tuple[ProjectRecipeStep, ...], Field(min_length=2, max_length=16)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        systems = tuple(sorted(self.required_build_systems, key=lambda item: item.value))
        phases = tuple(step.phase for step in self.steps)
        ordered_phases = tuple(
            sorted(phases, key=lambda item: tuple(ProjectRecipePhase).index(item))
        )
        if systems != self.required_build_systems or len(set(systems)) != len(systems):
            raise ValueError("project recipe build systems must be sorted and unique")
        if (
            ProjectRecipePhase.BUILD not in phases
            or ProjectRecipePhase.TEST not in phases
            or phases != ordered_phases
        ):
            raise ValueError("project recipe requires ordered build and test phases")
        if len({step.step_id for step in self.steps}) != len(self.steps) or len(
            {step.tool_id for step in self.steps}
        ) != len(self.steps):
            raise ValueError("project recipe steps and tools must be unique")
        if self.recipe_id != canonical_digest(
            self.model_dump(mode="python", exclude={"recipe_id"})
        ):
            raise ValueError("project recipe content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> ProjectRecipe:
        digest_values = dict(values)
        digest_values["steps"] = tuple(
            item.model_dump(mode="python") for item in values["steps"]  # type: ignore[union-attr]
        )
        return cls(recipe_id=canonical_digest(digest_values), **values)


class ProjectRecipeRunStep(DomainModel):
    step_id: Digest
    phase: ProjectRecipePhase
    request: SandboxRunRequest


class ProjectRecipeRunPlan(DomainModel):
    plan_id: Digest
    registry_digest: Digest
    recipe_id: Digest
    index_id: Digest
    manifest_id: Digest
    target_version: str = Field(min_length=1)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    steps: Annotated[tuple[ProjectRecipeRunStep, ...], Field(min_length=2, max_length=16)]
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("project recipe run deadline must be after creation")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("project recipe run plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> ProjectRecipeRunPlan:
        digest_values = dict(values)
        digest_values["steps"] = tuple(
            item.model_dump(mode="python") for item in values["steps"]  # type: ignore[union-attr]
        )
        return cls(plan_id=canonical_digest(digest_values), **values)


def project_recipe_approval_digest(plan: ProjectRecipeRunPlan) -> str:
    return canonical_digest(
        {"action": ApprovalAction.RUN_UNTRUSTED_BUILD, "plan_id": plan.plan_id}
    )


class ProjectRecipeRunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class ProjectRecipeRunOutcome(DomainModel):
    plan_id: Digest
    status: ProjectRecipeRunStatus
    executed_step_ids: tuple[Digest, ...]
    runner_results: tuple[SandboxRunResult, ...]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if len(self.executed_step_ids) != len(self.runner_results):
            raise ValueError("project recipe result binding is incomplete")
        if len(set(self.executed_step_ids)) != len(self.executed_step_ids):
            raise ValueError("project recipe steps cannot execute twice")
        if self.status is ProjectRecipeRunStatus.COMPLETED and not self.runner_results:
            raise ValueError("completed project recipe requires runner results")
        return self
