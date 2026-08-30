"""Sealed contracts for importing precomputed analyzer observations offline."""

from __future__ import annotations

import unicodedata
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Code, Digest


class AnalyzerKind(StrEnum):
    CODEQL = "codeql"
    TRIVY = "trivy"
    CHECKOV = "checkov"
    KUBESEC = "kubesec"


class AnalyzerSeverity(StrEnum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalyzerResultFile(DomainModel):
    logical_name: str = Field(pattern=r"^(output|cwe-map)\.json$")
    size: int = Field(ge=0)
    sha256: Digest


class AnalyzerResultSnapshot(DomainModel):
    snapshot_id: Digest
    analyzer: AnalyzerKind
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    tool_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
    rules_digest: Digest
    output: AnalyzerResultFile
    cwe_map: AnalyzerResultFile | None = None

    @model_validator(mode="after")
    def sealed_files(self) -> Self:
        if self.snapshot_id != analyzer_snapshot_digest(self):
            raise ValueError("analyzer result snapshot content digest mismatch")
        if self.output.logical_name != "output.json":
            raise ValueError("analyzer output must use the sealed logical name output.json")
        if self.cwe_map is not None and self.cwe_map.logical_name != "cwe-map.json":
            raise ValueError("analyzer CWE map must use the sealed logical name cwe-map.json")
        return self

    @classmethod
    def create(
        cls,
        *,
        analyzer: AnalyzerKind,
        target_id: UUID,
        target_version: str,
        tool_version: str,
        rules_digest: str,
        output: AnalyzerResultFile,
        cwe_map: AnalyzerResultFile | None = None,
    ) -> AnalyzerResultSnapshot:
        values = {
            "analyzer": analyzer,
            "target_id": target_id,
            "target_version": target_version,
            "tool_version": tool_version,
            "rules_digest": rules_digest,
            "output": output,
            "cwe_map": cwe_map,
        }
        digest_values = {
            **values,
            "output": output.model_dump(mode="python"),
            "cwe_map": cwe_map.model_dump(mode="python") if cwe_map is not None else None,
        }
        return cls(snapshot_id=canonical_digest(digest_values), **values)


def analyzer_snapshot_digest(snapshot: AnalyzerResultSnapshot) -> str:
    return canonical_digest(snapshot.model_dump(mode="python", exclude={"snapshot_id"}))


class AnalyzerImportLimits(DomainModel):
    max_output_bytes: int = Field(default=32 * 1024 * 1024, gt=0)
    max_cwe_map_bytes: int = Field(default=1024 * 1024, gt=0)
    max_observations: int = Field(default=100_000, gt=0, le=1_000_000)
    max_locations_per_observation: int = Field(default=32, gt=0, le=1024)
    timeout_seconds: float = Field(default=60.0, gt=0, le=3600)


class AnalyzerLocation(DomainModel):
    path: str = Field(min_length=1, max_length=1024)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    start_column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def normalized_relative_path(cls, value: str) -> str:
        if (
            "\\" in value
            or "%" in value
            or "://" in value
            or any(unicodedata.category(character).startswith("C") for character in value)
            or unicodedata.normalize("NFC", value) != value
        ):
            raise ValueError("analyzer location path is not a safe normalized path")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("analyzer location path must be normalized and relative")
        return path.as_posix()

    @model_validator(mode="after")
    def ordered_region(self) -> Self:
        if self.start_line is None and any(
            value is not None for value in (self.end_line, self.start_column, self.end_column)
        ):
            raise ValueError("analyzer location columns and end line require a start line")
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("analyzer location end line precedes start line")
        if (
            self.end_column is not None
            and self.start_column is not None
            and self.end_line in {None, self.start_line}
            and self.end_column < self.start_column
        ):
            raise ValueError("analyzer location end column precedes start column")
        return self


class AnalyzerObservation(DomainModel):
    observation_id: Digest
    analyzer: AnalyzerKind
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    rule_id_digest: Digest
    rule_fingerprint: Digest
    cwes: Annotated[tuple[str, ...], Field(min_length=1, max_length=64)]
    severity: AnalyzerSeverity
    message_digest: Digest
    locations: tuple[AnalyzerLocation, ...] = ()

    @model_validator(mode="after")
    def sealed_and_normalized(self) -> Self:
        if self.observation_id != analyzer_observation_digest(self):
            raise ValueError("analyzer Observation content digest mismatch")
        if self.cwes != tuple(sorted(set(self.cwes))):
            raise ValueError("analyzer Observation CWEs must be unique and sorted")
        if any(not _valid_cwe(item) for item in self.cwes):
            raise ValueError("analyzer Observation contains an invalid CWE")
        location_keys = tuple(
            canonical_digest(item.model_dump(mode="python")) for item in self.locations
        )
        if location_keys != tuple(sorted(location_keys)) or len(location_keys) != len(
            set(location_keys)
        ):
            raise ValueError("analyzer Observation locations must be unique and sorted")
        return self

    @classmethod
    def create(
        cls,
        *,
        analyzer: AnalyzerKind,
        target_id: UUID,
        target_version: str,
        rule_id: str,
        rule_fingerprint: str,
        cwes: tuple[str, ...],
        severity: AnalyzerSeverity,
        message_digest: str,
        locations: tuple[AnalyzerLocation, ...] = (),
    ) -> AnalyzerObservation:
        normalized_cwes = tuple(sorted(set(cwes)))
        normalized_locations = tuple(
            sorted(
                set(locations),
                key=lambda item: canonical_digest(item.model_dump(mode="python")),
            )
        )
        values = {
            "analyzer": analyzer,
            "target_id": target_id,
            "target_version": target_version,
            "rule_id_digest": canonical_digest(rule_id),
            "rule_fingerprint": rule_fingerprint,
            "cwes": normalized_cwes,
            "severity": severity,
            "message_digest": message_digest,
            "locations": normalized_locations,
        }
        digest_values = {
            **values,
            "locations": tuple(item.model_dump(mode="python") for item in normalized_locations),
        }
        return cls(observation_id=canonical_digest(digest_values), **values)


def analyzer_observation_digest(observation: AnalyzerObservation) -> str:
    return canonical_digest(observation.model_dump(mode="python", exclude={"observation_id"}))


class AnalyzerExclusion(DomainModel):
    source_ref_digest: Digest
    reason_code: Code


class AnalyzerObservationSet(DomainModel):
    observation_set_id: Digest
    snapshot_id: Digest
    snapshot_digest: Digest
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    adapter_digest: Digest
    analyzer: AnalyzerKind
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    observations: tuple[AnalyzerObservation, ...] = ()
    exclusions: tuple[AnalyzerExclusion, ...] = ()

    @model_validator(mode="after")
    def sealed_and_unique(self) -> Self:
        if self.observation_set_id != analyzer_observation_set_digest(self):
            raise ValueError("AnalyzerObservationSet content digest mismatch")
        identities = tuple(item.observation_id for item in self.observations)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise ValueError("analyzer observations must be unique and sorted")
        if any(
            item.analyzer is not self.analyzer
            or item.target_id != self.target_id
            or item.target_version != self.target_version
            for item in self.observations
        ):
            raise ValueError("analyzer Observation escaped the sealed target binding")
        exclusion_keys = tuple(
            (item.source_ref_digest, item.reason_code) for item in self.exclusions
        )
        if exclusion_keys != tuple(sorted(exclusion_keys)) or len(exclusion_keys) != len(
            set(exclusion_keys)
        ):
            raise ValueError("analyzer exclusions must be unique and sorted")
        return self

    @classmethod
    def create(
        cls,
        *,
        snapshot: AnalyzerResultSnapshot,
        adapter_id: str,
        adapter_digest: str,
        observations: tuple[AnalyzerObservation, ...],
        exclusions: tuple[AnalyzerExclusion, ...],
    ) -> AnalyzerObservationSet:
        ordered_observations = tuple(sorted(observations, key=lambda item: item.observation_id))
        ordered_exclusions = tuple(
            sorted(exclusions, key=lambda item: (item.source_ref_digest, item.reason_code))
        )
        values = {
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_digest": canonical_digest(snapshot.model_dump(mode="python")),
            "adapter_id": adapter_id,
            "adapter_digest": adapter_digest,
            "analyzer": snapshot.analyzer,
            "target_id": snapshot.target_id,
            "target_version": snapshot.target_version,
            "observations": ordered_observations,
            "exclusions": ordered_exclusions,
        }
        digest_values = {
            **values,
            "observations": tuple(item.model_dump(mode="python") for item in ordered_observations),
            "exclusions": tuple(item.model_dump(mode="python") for item in ordered_exclusions),
        }
        return cls(observation_set_id=canonical_digest(digest_values), **values)


def analyzer_observation_set_digest(observations: AnalyzerObservationSet) -> str:
    return canonical_digest(observations.model_dump(mode="python", exclude={"observation_set_id"}))


class AnalyzerImportPlan(DomainModel):
    plan_id: Digest
    snapshot_id: Digest
    snapshot_digest: Digest
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    adapter_digest: Digest
    limits: AnalyzerImportLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.plan_id != analyzer_import_plan_digest(self):
            raise ValueError("analyzer import plan content digest mismatch")
        if self.deadline <= self.created_at:
            raise ValueError("analyzer import deadline must be after creation")
        return self

    @classmethod
    def create(
        cls,
        *,
        snapshot: AnalyzerResultSnapshot,
        adapter_id: str,
        adapter_digest: str,
        limits: AnalyzerImportLimits,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AnalyzerImportPlan:
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


def analyzer_import_plan_digest(plan: AnalyzerImportPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class AnalyzerObservationArtifact(DomainModel):
    observation_set_id: Digest
    json_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/observations\.json$")

    @model_validator(mode="after")
    def reference_matches_identity(self) -> Self:
        if self.json_ref != f"objects/{self.observation_set_id}/observations.json":
            raise ValueError("analyzer Observation artifact reference mismatch")
        return self


class AnalyzerImportOutcome(DomainModel):
    plan_id: Digest
    snapshot_id: Digest
    observation_set: AnalyzerObservationSet
    artifact: AnalyzerObservationArtifact
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def artifact_is_bound(self) -> Self:
        if self.artifact.observation_set_id != self.observation_set.observation_set_id:
            raise ValueError("analyzer import artifact does not match Observation set")
        return self


def _valid_cwe(value: str) -> bool:
    return value.startswith("CWE-") and value[4:].isdigit() and not value.startswith("CWE-0")
