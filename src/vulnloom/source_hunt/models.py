"""Typed, provider-neutral contracts for bounded source investigations."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, SourceLocation
from vulnloom.evidence import Redactor

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SourceLanguage(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"


class SourceSymbolKind(StrEnum):
    FUNCTION = "function"
    CLASS = "class"


class SourceReferenceKind(StrEnum):
    CALL = "call"
    IMPORT = "import"


class SourceSymbol(DomainModel):
    symbol_id: Digest
    language: SourceLanguage
    qualified_name: str = Field(min_length=1, max_length=512)
    kind: SourceSymbolKind
    location: SourceLocation

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.symbol_id != canonical_digest(
            self.model_dump(mode="python", exclude={"symbol_id"})
        ):
            raise ValueError("SourceSymbol content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourceSymbol:
        digest_values = dict(values)
        digest_values["location"] = values["location"].model_dump(mode="python")  # type: ignore[union-attr]
        return cls(symbol_id=canonical_digest(digest_values), **values)


class SourceReference(DomainModel):
    reference_id: Digest
    language: SourceLanguage
    kind: SourceReferenceKind
    source_symbol: str
    target_name: str = Field(min_length=1, max_length=512)
    resolved_symbol_id: Digest | None = None
    location: SourceLocation

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reference_id != canonical_digest(
            self.model_dump(mode="python", exclude={"reference_id"})
        ):
            raise ValueError("SourceReference content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourceReference:
        digest_values = dict(values)
        digest_values["location"] = values["location"].model_dump(mode="python")  # type: ignore[union-attr]
        return cls(reference_id=canonical_digest(digest_values), **values)


class SourceFileRecord(DomainModel):
    path: str = Field(min_length=1, max_length=512)
    language: SourceLanguage
    size: int = Field(ge=0)
    sha256: Digest


class SourceExcerpt(DomainModel):
    symbol_id: Digest
    path: str = Field(min_length=1, max_length=512)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    redacted_text: str = Field(max_length=32_768)
    text_digest: Digest

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("Source excerpt line window is invalid")
        if self.text_digest != canonical_digest(self.redacted_text):
            raise ValueError("Source excerpt digest mismatch")
        if len(self.redacted_text.encode()) > 32_768:
            raise ValueError("Source excerpt exceeds its byte limit")
        if Redactor().text(self.redacted_text) != self.redacted_text:
            raise ValueError("Source excerpt contains unredacted sensitive text")
        return self


class SourcePartition(DomainModel):
    partition_id: Digest
    ordinal: int = Field(ge=0)
    paths: Annotated[tuple[str, ...], Field(min_length=1, max_length=2_000)]
    total_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if tuple(sorted(self.paths)) != self.paths or len(set(self.paths)) != len(self.paths):
            raise ValueError("SourcePartition paths must be sorted and unique")
        if self.partition_id != canonical_digest(
            self.model_dump(mode="python", exclude={"partition_id"})
        ):
            raise ValueError("SourcePartition content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourcePartition:
        return cls(partition_id=canonical_digest(values), **values)


class BuildSystem(StrEnum):
    PYPROJECT = "pyproject"
    REQUIREMENTS = "requirements"
    NPM = "npm"


class RepositoryIndex(DomainModel):
    index_id: Digest
    target_id: UUID
    target_version: str = Field(min_length=1)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    manifest_id: Digest
    adapter_versions: dict[SourceLanguage, str]
    source_files: tuple[SourceFileRecord, ...]
    files_indexed: tuple[str, ...]
    symbols: tuple[SourceSymbol, ...]
    references: tuple[SourceReference, ...]
    build_systems: tuple[BuildSystem, ...]
    partitions: Annotated[tuple[SourcePartition, ...], Field(max_length=10_000)]
    skipped_files: tuple[str, ...] = ()

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if tuple(sorted(self.files_indexed)) != self.files_indexed:
            raise ValueError("RepositoryIndex files must be sorted")
        if len(set(self.files_indexed)) != len(self.files_indexed):
            raise ValueError("RepositoryIndex files must be unique")
        if set(self.files_indexed) & set(self.skipped_files):
            raise ValueError("indexed and skipped files overlap")
        if tuple(item.path for item in self.source_files) != self.files_indexed:
            raise ValueError("RepositoryIndex source-file bindings are incomplete")
        if tuple(item.ordinal for item in self.partitions) != tuple(range(len(self.partitions))):
            raise ValueError("RepositoryIndex partition ordinals are not contiguous")
        if self.index_id != canonical_digest(
            self.model_dump(mode="python", exclude={"index_id"})
        ):
            raise ValueError("RepositoryIndex content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RepositoryIndex:
        digest_values = dict(values)
        for key in ("source_files", "symbols", "references", "partitions"):
            digest_values[key] = tuple(
                item.model_dump(mode="python") for item in values.get(key, ())  # type: ignore[union-attr]
            )
        return cls(index_id=canonical_digest(digest_values), **values)


class InvestigationStatus(StrEnum):
    ACTIVE = "active"
    READY_FOR_CANDIDATES = "ready_for_candidates"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class InvestigationQueryKind(StrEnum):
    SYMBOL = "symbol"
    CALLERS = "callers"
    CALLEES = "callees"
    REFERENCES = "references"
    SOURCE_WINDOW = "source_window"


class InvestigationQuery(DomainModel):
    kind: InvestigationQueryKind
    term: str = Field(min_length=1, max_length=512)
    max_results: int = Field(default=32, ge=1, le=128)


class InvestigationObservation(DomainModel):
    observation_id: Digest
    query_digest: Digest
    kind: InvestigationQueryKind
    matched_symbols: tuple[SourceSymbol, ...] = ()
    matched_references: tuple[SourceReference, ...] = ()
    source_excerpts: tuple[SourceExcerpt, ...] = ()
    truncated: bool = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.observation_id != canonical_digest(
            self.model_dump(mode="python", exclude={"observation_id"})
        ):
            raise ValueError("InvestigationObservation content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> InvestigationObservation:
        digest_values = dict(values)
        for key in ("matched_symbols", "matched_references", "source_excerpts"):
            digest_values[key] = tuple(
                item.model_dump(mode="python") for item in values.get(key, ())  # type: ignore[union-attr]
            )
        return cls(observation_id=canonical_digest(digest_values), **values)


class SourceHuntLimits(DomainModel):
    max_files: int = Field(default=20_000, ge=1, le=100_000)
    max_total_bytes: int = Field(default=200 * 1024 * 1024, ge=1)
    max_single_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1)
    max_files_per_partition: int = Field(default=500, ge=1, le=2_000)
    max_queries: int = Field(default=64, ge=1, le=1_000)
    max_observations: int = Field(default=64, ge=1, le=1_000)
    timeout_seconds: float = Field(default=120.0, gt=0, le=3_600)


class InvestigationPlan(DomainModel):
    plan_id: Digest
    index_id: Digest
    target_id: UUID
    target_version: str = Field(min_length=1)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    seed_signal_ids: tuple[Digest, ...] = ()
    limits: SourceHuntLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("InvestigationPlan deadline must be after creation")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("InvestigationPlan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> InvestigationPlan:
        digest_values = dict(values)
        limits = values["limits"]
        digest_values["limits"] = limits.model_dump(mode="python")  # type: ignore[union-attr]
        return cls(plan_id=canonical_digest(digest_values), **values)


class InvestigationCheckpoint(DomainModel):
    checkpoint_id: Digest
    plan_id: Digest
    index_id: Digest
    status: InvestigationStatus
    revision: int = Field(ge=0)
    queries_used: int = Field(ge=0)
    observation_ids: tuple[Digest, ...]
    query_digests: tuple[Digest, ...]
    conclusion_digest: Digest | None = None
    reason_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        terminal = self.status is not InvestigationStatus.ACTIVE
        if (self.conclusion_digest is not None) != (
            self.status is InvestigationStatus.READY_FOR_CANDIDATES
        ):
            raise ValueError("only a completed investigation has a conclusion")
        if terminal != (self.reason_code is not None):
            raise ValueError("terminal investigation checkpoint requires a reason")
        if self.queries_used != len(self.query_digests):
            raise ValueError("investigation query counter mismatch")
        if len(set(self.query_digests)) != len(self.query_digests):
            raise ValueError("investigation queries must be unique")
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ValueError("investigation observations must be unique")
        if self.checkpoint_id != canonical_digest(
            self.model_dump(mode="python", exclude={"checkpoint_id"})
        ):
            raise ValueError("InvestigationCheckpoint content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> InvestigationCheckpoint:
        complete = {"conclusion_digest": None, "reason_code": None, **values}
        return cls(checkpoint_id=canonical_digest(complete), **complete)
