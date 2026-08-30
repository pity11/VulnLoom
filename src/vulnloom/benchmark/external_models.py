"""Sealed contracts for importing pre-obtained external benchmark snapshots."""

from __future__ import annotations

import unicodedata
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import BenchmarkSuite, Digest


class ExternalBenchmarkKind(StrEnum):
    BOUNTYBENCH = "bountybench"
    AUTOPENBENCH = "autopenbench"


class SnapshotFile(DomainModel):
    path: str = Field(min_length=1, max_length=1024)
    size: int = Field(ge=0)
    sha256: Digest

    @field_validator("path")
    @classmethod
    def normalized_relative_path(cls, value: str) -> str:
        if (
            "\\" in value
            or any(unicodedata.category(character).startswith("C") for character in value)
            or unicodedata.normalize("NFC", value) != value
        ):
            raise ValueError("snapshot path is not normalized")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("snapshot path must be normalized and relative")
        return path.as_posix()


class ExternalBenchmarkSnapshot(DomainModel):
    snapshot_id: Digest
    kind: ExternalBenchmarkKind
    upstream_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}|[0-9a-f]{64}$")]
    license_spdx: str = Field(min_length=1, max_length=64)
    files: Annotated[tuple[SnapshotFile, ...], Field(min_length=1, max_length=100_000)]

    @model_validator(mode="after")
    def sealed_and_licensed(self) -> Self:
        if self.snapshot_id != external_snapshot_digest(self):
            raise ValueError("external benchmark snapshot content digest mismatch")
        expected_license = {
            ExternalBenchmarkKind.BOUNTYBENCH: "Apache-2.0",
            ExternalBenchmarkKind.AUTOPENBENCH: "MIT",
        }[self.kind]
        if self.license_spdx != expected_license:
            raise ValueError("external benchmark snapshot license does not match adapter")
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("snapshot files must be unique and sorted by path")
        if "LICENSE" not in paths:
            raise ValueError("external benchmark snapshot is missing its license file")
        if self.kind is ExternalBenchmarkKind.AUTOPENBENCH and (
            "data/games.json" not in paths or "vulnloom-autopenbench-cwe.json" not in paths
        ):
            raise ValueError("AutoPenBench snapshot requires games metadata and a CWE sidecar")
        return self

    @classmethod
    def create(
        cls,
        *,
        kind: ExternalBenchmarkKind,
        upstream_revision: str,
        license_spdx: str,
        files: tuple[SnapshotFile, ...],
    ) -> ExternalBenchmarkSnapshot:
        values = {
            "kind": kind,
            "upstream_revision": upstream_revision,
            "license_spdx": license_spdx,
            "files": files,
        }
        digest_values = {
            **values,
            "files": tuple(item.model_dump(mode="python") for item in files),
        }
        return cls(snapshot_id=canonical_digest(digest_values), **values)


def external_snapshot_digest(snapshot: ExternalBenchmarkSnapshot) -> str:
    return canonical_digest(snapshot.model_dump(mode="python", exclude={"snapshot_id"}))


class ExternalImportLimits(DomainModel):
    max_files: int = Field(default=20_000, gt=0, le=100_000)
    max_single_file_bytes: int = Field(default=20 * 1024 * 1024, gt=0)
    max_total_bytes: int = Field(default=200 * 1024 * 1024, gt=0)
    max_cases: int = Field(default=10_000, gt=0)
    timeout_seconds: float = Field(default=60.0, gt=0, le=3600)


class ExternalCaseExclusion(DomainModel):
    source_case_ref: str = Field(
        min_length=1,
        max_length=1024,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/+@=-]*$",
    )
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")


class ExternalBenchmarkImportPlan(DomainModel):
    plan_id: Digest
    snapshot_id: Digest
    snapshot_digest: Digest
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    adapter_digest: Digest
    limits: ExternalImportLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.plan_id != external_import_plan_digest(self):
            raise ValueError("external benchmark import plan content digest mismatch")
        if self.deadline <= self.created_at:
            raise ValueError("external benchmark import deadline must be after creation")
        return self

    @classmethod
    def create(
        cls,
        *,
        snapshot: ExternalBenchmarkSnapshot,
        adapter_id: str,
        adapter_digest: str,
        limits: ExternalImportLimits,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> ExternalBenchmarkImportPlan:
        values = {
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_digest": canonical_digest(snapshot.model_dump(mode="python")),
            "adapter_id": adapter_id,
            "adapter_digest": adapter_digest,
            "limits": limits,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {**values, "limits": limits.model_dump(mode="python")}
        return cls(plan_id=canonical_digest(digest_values), **values)


def external_import_plan_digest(plan: ExternalBenchmarkImportPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class ExternalBenchmarkArtifact(DomainModel):
    suite_digest: Digest
    json_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/suite\.json$")

    @model_validator(mode="after")
    def reference_matches_identity(self) -> Self:
        if self.json_ref != f"objects/{self.suite_digest}/suite.json":
            raise ValueError("external Benchmark artifact reference mismatch")
        return self


class ExternalBenchmarkImportOutcome(DomainModel):
    plan_id: Digest
    snapshot_id: Digest
    suite: BenchmarkSuite
    exclusions: tuple[ExternalCaseExclusion, ...]
    artifact: ExternalBenchmarkArtifact
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def suite_and_artifact_are_bound(self) -> Self:
        if self.artifact.suite_digest != canonical_digest(self.suite.model_dump(mode="python")):
            raise ValueError("external Benchmark artifact does not match normalized suite")
        return self
