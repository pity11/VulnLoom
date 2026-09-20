"""Sealed R9 contracts for native fuzzing, crash identity, and PoV qualification."""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.benchmark.models import BenchmarkGateStatus
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners import DockerTool
from vulnloom.runners.environment import build_worker_environment
from vulnloom.runners.models import ImageDigest, ToolId

from .execution_models import SourceExecutionStage, SourceSanitizer
from .models import Digest


class SourceDynamicToolchain(StrEnum):
    NATIVE_COVERAGE_ASAN = "native_coverage_asan"


class SourceCrashSignal(StrEnum):
    ABORT = "abort"
    BUS = "bus"
    FPE = "fpe"
    ILL = "ill"
    SEGV = "segv"


class SourceCrashFrame(DomainModel):
    module: str = Field(pattern=r"^[A-Za-z0-9_.+-]{1,128}$")
    symbol: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_:.<>~+-]{0,255}$")
    source_path: str = Field(min_length=1, max_length=512)
    source_line: int = Field(ge=1, le=100_000_000)

    @field_validator("source_path")
    @classmethod
    def normalized_source_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("Crash frame source path must be normalized and relative")
        return value


class SourceCrashSignature(DomainModel):
    fingerprint: Digest
    sanitizer: SourceSanitizer
    signal: SourceCrashSignal
    failure_class: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    frames: Annotated[tuple[SourceCrashFrame, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.fingerprint != source_crash_signature_digest(self):
            raise ValueError("Crash Signature content digest mismatch")
        if len(self.frames) != len(set(self.frames)):
            raise ValueError("Crash Signature frames must be unique")
        return self

    @classmethod
    def create(
        cls,
        *,
        sanitizer: SourceSanitizer,
        signal: SourceCrashSignal,
        failure_class: str,
        frames: tuple[SourceCrashFrame, ...],
    ) -> SourceCrashSignature:
        values = {
            "sanitizer": sanitizer,
            "signal": signal,
            "failure_class": failure_class,
            "frames": frames,
        }
        digest_values = {
            **values,
            "frames": tuple(item.model_dump(mode="python") for item in frames),
        }
        return cls(fingerprint=canonical_digest(digest_values), **values)


def source_crash_signature_digest(signature: SourceCrashSignature) -> str:
    return canonical_digest(signature.model_dump(mode="python", exclude={"fingerprint"}))


class SourceToolReport(DomainModel):
    protocol: str = Field(pattern=r"^vulnloom\.source-tool-report\.v1$")
    registration_id: Digest
    toolchain: SourceDynamicToolchain
    tool_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
    adapter_digest: Digest
    stage: SourceExecutionStage
    input_digest: Digest
    output_digest: Digest
    coverage_edges: int = Field(default=0, ge=0)
    crash_input_digest: Digest | None = None
    crash_signature: SourceCrashSignature | None = None
    pov_reproduced: bool = False

    @model_validator(mode="after")
    def proves_stage(self) -> Self:
        if self.output_digest != canonical_digest(
            {"stage": self.stage.value, "input_digest": self.input_digest}
        ):
            raise ValueError("source tool report output digest is not deterministic")
        has_crash = self.crash_signature is not None and self.crash_input_digest is not None
        if (self.crash_signature is None) != (self.crash_input_digest is None):
            raise ValueError("source tool crash identity is incomplete")
        if self.stage in {SourceExecutionStage.BUILD, SourceExecutionStage.HARNESS}:
            valid = self.coverage_edges == 0 and not has_crash and not self.pov_reproduced
        elif self.stage is SourceExecutionStage.FUZZ:
            valid = self.coverage_edges > 0 and has_crash and not self.pov_reproduced
        elif self.stage is SourceExecutionStage.SANITIZER:
            valid = self.coverage_edges == 0 and has_crash and not self.pov_reproduced
        else:
            valid = self.coverage_edges == 0 and has_crash and self.pov_reproduced
        if not valid:
            raise ValueError("source tool report does not prove its stage")
        return self


class SourceDynamicToolRegistration(DomainModel):
    registration_id: Digest
    stage: SourceExecutionStage
    tool_id: ToolId
    toolchain: SourceDynamicToolchain
    tool_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
    image_digest: ImageDigest
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    adapter_digest: Digest
    argv: Annotated[tuple[str, ...], Field(min_length=2, max_length=128)]
    environment: dict[str, str] = Field(default_factory=dict)
    max_report_bytes: int = Field(default=1_048_576, ge=1, le=1_048_576)

    @field_validator("argv")
    @classmethod
    def exact_safe_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        shells = {"bash", "dash", "fish", "powershell", "pwsh", "sh", "zsh"}
        if not value[0].startswith("/") or PurePosixPath(value[0]).name.lower() in shells:
            raise ValueError("source dynamic tool requires an absolute non-shell executable")
        if any(
            not item
            or "\x00" in item
            or "\n" in item
            or "\r" in item
            or "{" in item
            or "}" in item
            or "://" in item
            or len(item.encode()) > 16_384
            for item in value
        ):
            raise ValueError("source dynamic tool argv must be fixed and network-free")
        return value

    @field_validator("environment")
    @classmethod
    def explicit_environment(cls, value: dict[str, str]) -> dict[str, str]:
        build_worker_environment(value)
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.tool_id != f"source.{self.stage.value}":
            raise ValueError("source dynamic tool id does not match its stage")
        if self.registration_id != source_dynamic_tool_registration_digest(self):
            raise ValueError("source dynamic tool registration content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourceDynamicToolRegistration:
        expanded = cls.model_construct(registration_id="0" * 64, **values).model_dump(
            mode="python", exclude={"registration_id"}
        )
        return cls(registration_id=canonical_digest(expanded), **expanded)

    def docker_tool(self) -> DockerTool:
        return DockerTool(tool_id=self.tool_id, argv_prefix=self.argv)


def source_dynamic_tool_registration_digest(
    registration: SourceDynamicToolRegistration,
) -> str:
    return canonical_digest(registration.model_dump(mode="python", exclude={"registration_id"}))


class SourceCrashDisposition(StrEnum):
    NEW = "new"
    DUPLICATE = "duplicate"


class SourceCrashRecord(DomainModel):
    fingerprint: Digest
    signature: SourceCrashSignature
    canonical_input_digest: Digest
    first_plan_id: Digest
    last_plan_id: Digest
    observation_count: int = Field(ge=1)
    observed_plan_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=10_000)]
    first_observed_at: AwareDatetime
    last_observed_at: AwareDatetime

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (
            self.fingerprint != self.signature.fingerprint
            or self.first_plan_id != self.observed_plan_ids[0]
            or self.last_plan_id != self.observed_plan_ids[-1]
            or self.observation_count != len(self.observed_plan_ids)
            or len(self.observed_plan_ids) != len(set(self.observed_plan_ids))
            or self.last_observed_at < self.first_observed_at
        ):
            raise ValueError("Crash record identity or history is inconsistent")
        return self


class SourceCrashRegistration(DomainModel):
    disposition: SourceCrashDisposition
    record: SourceCrashRecord


class SourcePovArtifact(DomainModel):
    artifact_id: Digest
    candidate_digest: Digest
    crash_fingerprint: Digest
    input_digest: Digest
    source_execution_plan_id: Digest
    sanitizer: SourceSanitizer
    created_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.artifact_id != canonical_digest(
            self.model_dump(mode="python", exclude={"artifact_id"})
        ):
            raise ValueError("PoV artifact content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourcePovArtifact:
        expanded = cls.model_construct(artifact_id="0" * 64, **values).model_dump(
            mode="python", exclude={"artifact_id"}
        )
        return cls(artifact_id=canonical_digest(expanded), **expanded)


class SourcePovBenchmarkCase(DomainModel):
    case_id: Digest
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    target_version: str = Field(min_length=1, max_length=256)
    candidate_digest: Digest
    expected_crash_fingerprint: Digest
    expected_sanitizer: SourceSanitizer

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.case_id != canonical_digest(self.model_dump(mode="python", exclude={"case_id"})):
            raise ValueError("PoV Benchmark case content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourcePovBenchmarkCase:
        expanded = cls.model_construct(case_id="0" * 64, **values).model_dump(
            mode="python", exclude={"case_id"}
        )
        return cls(case_id=canonical_digest(expanded), **expanded)


class SourcePovBenchmarkResult(DomainModel):
    result_id: Digest
    case_id: Digest
    execution_plan_id: Digest
    execution_outcome_digest: Digest
    crash_record_fingerprint: Digest
    pov_artifact: SourcePovArtifact
    gate_status: BenchmarkGateStatus
    violation_codes: tuple[str, ...] = ()
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.result_id != canonical_digest(
            self.model_dump(mode="python", exclude={"result_id"})
        ):
            raise ValueError("PoV Benchmark result content digest mismatch")
        if (self.gate_status is BenchmarkGateStatus.PASSED) != (not self.violation_codes):
            raise ValueError("PoV Benchmark gate does not match violations")
        return self

    @classmethod
    def create(cls, **values: object) -> SourcePovBenchmarkResult:
        expanded = cls.model_construct(result_id="0" * 64, **values).model_dump(
            mode="python", exclude={"result_id"}
        )
        return cls(result_id=canonical_digest(expanded), **expanded)
