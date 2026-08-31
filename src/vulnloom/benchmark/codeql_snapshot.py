"""Sealed, read-only prebuilt CodeQL database and query-pack snapshots."""

from __future__ import annotations

import hashlib
import os
import stat
import time
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

CODEQL_TOOL_VERSION = "2.26.2"
CODEQL_DATABASE_MARKER = "database/codeql-database.yml"
CODEQL_QUERY_PACK_MARKER = "queries/qlpack.yml"


class CodeQLSnapshotRejected(ValueError):
    """A prebuilt CodeQL snapshot failed the trusted sealing boundary."""


class CodeQLSnapshotLimits(DomainModel):
    max_files: int = Field(default=100_000, gt=0, le=500_000)
    max_single_file_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        gt=0,
        le=10 * 1024 * 1024 * 1024,
    )
    max_total_bytes: int = Field(
        default=8 * 1024 * 1024 * 1024,
        gt=0,
        le=10 * 1024 * 1024 * 1024,
    )
    timeout_seconds: float = Field(default=120.0, gt=0, le=1800)


class CodeQLSnapshotFile(DomainModel):
    path: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0)
    sha256: Digest

    @field_validator("path")
    @classmethod
    def normalized_admitted_path(cls, value: str) -> str:
        if (
            "\\" in value
            or unicodedata.normalize("NFC", value) != value
            or any(unicodedata.category(character).startswith("C") for character in value)
        ):
            raise ValueError("CodeQL snapshot path is not normalized")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] not in {"database", "queries"}
        ):
            raise ValueError("CodeQL snapshot path is outside an admitted root")
        return path.as_posix()


class CodeQLSnapshot(DomainModel):
    snapshot_id: Digest
    tool_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    database_language: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    query_pack_name: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*$")
    query_suite_path: str
    files: Annotated[tuple[CodeQLSnapshotFile, ...], Field(min_length=3, max_length=500_000)]
    total_size: int = Field(gt=0)

    @field_validator("query_suite_path")
    @classmethod
    def admitted_query_suite_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            "\\" in value
            or path.is_absolute()
            or not value.startswith("queries/")
            or path.suffix != ".qls"
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("CodeQL query suite must be a normalized sealed .qls path")
        return value

    @model_validator(mode="after")
    def content_addressed_and_complete(self) -> Self:
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("CodeQL snapshot files must be unique and sorted")
        required = {CODEQL_DATABASE_MARKER, CODEQL_QUERY_PACK_MARKER, self.query_suite_path}
        if not required <= set(paths):
            raise ValueError("CodeQL snapshot is missing its database or query-pack markers")
        if not any(path.startswith("queries/") and path.endswith(".qlx") for path in paths):
            raise ValueError("CodeQL snapshot requires at least one precompiled query")
        if any(
            path == "database/results" or path.startswith("database/results/") for path in paths
        ):
            raise ValueError("CodeQL snapshot cannot contain prior query results")
        if self.total_size != sum(item.size for item in self.files):
            raise ValueError("CodeQL snapshot total size mismatch")
        if self.snapshot_id != codeql_snapshot_digest(self):
            raise ValueError("CodeQL snapshot content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        tool_version: str,
        database_language: str,
        query_pack_name: str,
        query_suite_path: str,
        files: tuple[CodeQLSnapshotFile, ...],
    ) -> CodeQLSnapshot:
        ordered = tuple(sorted(files, key=lambda item: item.path))
        values = {
            "tool_version": tool_version,
            "database_language": database_language,
            "query_pack_name": query_pack_name,
            "query_suite_path": query_suite_path,
            "files": ordered,
            "total_size": sum(item.size for item in ordered),
        }
        digest_values = {
            **values,
            "files": tuple(item.model_dump(mode="python") for item in ordered),
        }
        return cls(snapshot_id=canonical_digest(digest_values), **values)


def codeql_snapshot_digest(snapshot: CodeQLSnapshot) -> str:
    return canonical_digest(snapshot.model_dump(mode="python", exclude={"snapshot_id"}))


def inspect_codeql_snapshot(
    root: Path,
    *,
    database_language: str,
    query_pack_name: str,
    query_suite_path: str,
    tool_version: str = CODEQL_TOOL_VERSION,
    limits: CodeQLSnapshotLimits | None = None,
) -> CodeQLSnapshot:
    selected = limits or CodeQLSnapshotLimits()
    files = _inspect_tree(root, limits=selected)
    by_path = {item.path: item for item in files}
    metadata_deadline = time.monotonic() + selected.timeout_seconds
    database_language_value = _read_yaml_scalar(
        root,
        by_path.get(CODEQL_DATABASE_MARKER),
        "primaryLanguage",
        deadline=metadata_deadline,
    )
    query_pack_name_value = _read_yaml_scalar(
        root,
        by_path.get(CODEQL_QUERY_PACK_MARKER),
        "name",
        deadline=metadata_deadline,
    )
    if database_language_value != database_language or query_pack_name_value != query_pack_name:
        raise CodeQLSnapshotRejected("CodeQL snapshot metadata does not match its declaration")
    if _inspect_tree(root, limits=selected) != files:
        raise CodeQLSnapshotRejected("CodeQL snapshot changed while it was being sealed")
    return CodeQLSnapshot.create(
        tool_version=tool_version,
        database_language=database_language,
        query_pack_name=query_pack_name,
        query_suite_path=query_suite_path,
        files=files,
    )


def verify_codeql_snapshot(
    root: Path,
    snapshot: CodeQLSnapshot,
    *,
    limits: CodeQLSnapshotLimits | None = None,
) -> None:
    observed = inspect_codeql_snapshot(
        root,
        database_language=snapshot.database_language,
        query_pack_name=snapshot.query_pack_name,
        query_suite_path=snapshot.query_suite_path,
        tool_version=snapshot.tool_version,
        limits=limits,
    )
    if observed != snapshot:
        raise CodeQLSnapshotRejected("CodeQL snapshot no longer matches its sealed manifest")


def _inspect_tree(root: Path, *, limits: CodeQLSnapshotLimits) -> tuple[CodeQLSnapshotFile, ...]:
    deadline = time.monotonic() + limits.timeout_seconds
    absolute = _inspect_root(root)
    files: list[CodeQLSnapshotFile] = []
    seen: set[str] = set()
    total = 0
    pending = [absolute]
    while pending:
        _check_deadline(deadline)
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise CodeQLSnapshotRejected("CodeQL snapshot directory is unavailable") from exc
        for entry in entries:
            _check_deadline(deadline)
            path = Path(entry.path)
            relative = path.relative_to(absolute).as_posix()
            try:
                relative = CodeQLSnapshotFile(
                    path=relative,
                    size=0,
                    sha256="0" * 64,
                ).path
                metadata = entry.stat(follow_symlinks=False)
            except (OSError, ValueError) as exc:
                raise CodeQLSnapshotRejected("CodeQL snapshot entry is unsafe") from exc
            collision_key = relative.casefold()
            if collision_key in seen:
                raise CodeQLSnapshotRejected("CodeQL snapshot contains a path collision")
            seen.add(collision_key)
            if stat.S_ISLNK(metadata.st_mode):
                raise CodeQLSnapshotRejected("CodeQL snapshot symbolic links are forbidden")
            if metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                raise CodeQLSnapshotRejected("CodeQL snapshot entries must be read-only")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise CodeQLSnapshotRejected("CodeQL snapshot special files are forbidden")
            if len(files) >= limits.max_files or metadata.st_size > limits.max_single_file_bytes:
                raise CodeQLSnapshotRejected("CodeQL snapshot exceeds a file limit")
            item = _inspect_file(
                path,
                relative,
                max_bytes=limits.max_single_file_bytes,
                deadline=deadline,
            )
            total += item.size
            if total > limits.max_total_bytes:
                raise CodeQLSnapshotRejected("CodeQL snapshot exceeds its total size limit")
            files.append(item)
    return tuple(sorted(files, key=lambda item: item.path))


def _inspect_root(root: Path) -> Path:
    requested = root.absolute()
    try:
        metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise CodeQLSnapshotRejected("CodeQL snapshot root is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != requested
    ):
        raise CodeQLSnapshotRejected("CodeQL snapshot root must be a direct directory")
    if metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        raise CodeQLSnapshotRejected("CodeQL snapshot root must be read-only")
    return resolved


def _inspect_file(
    path: Path,
    relative: str,
    *,
    max_bytes: int,
    deadline: float,
) -> CodeQLSnapshotFile:
    if not hasattr(os, "O_NOFOLLOW"):
        raise CodeQLSnapshotRejected("platform cannot enforce no-follow CodeQL reads")
    try:
        before = os.lstat(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise CodeQLSnapshotRejected("CodeQL snapshot file is unavailable or unsafe") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > max_bytes
        ):
            raise CodeQLSnapshotRejected("CodeQL snapshot file failed identity checks")
        while block := os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size)):
            _check_deadline(deadline)
            size += len(block)
            if size > max_bytes:
                raise CodeQLSnapshotRejected("CodeQL snapshot file exceeds its size limit")
            digest.update(block)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise CodeQLSnapshotRejected("CodeQL snapshot changed during inspection") from exc
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) or size != before.st_size:
        raise CodeQLSnapshotRejected("CodeQL snapshot changed during inspection")
    return CodeQLSnapshotFile(path=relative, size=size, sha256=digest.hexdigest())


def _read_yaml_scalar(
    root: Path,
    expected: CodeQLSnapshotFile | None,
    key: str,
    *,
    deadline: float,
) -> str:
    if expected is None or expected.size > 1024 * 1024:
        raise CodeQLSnapshotRejected("CodeQL snapshot metadata marker is missing or oversized")
    path = root.absolute().joinpath(*PurePosixPath(expected.path).parts)
    if not hasattr(os, "O_NOFOLLOW"):
        raise CodeQLSnapshotRejected("platform cannot enforce no-follow CodeQL reads")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise CodeQLSnapshotRejected("CodeQL snapshot metadata is unavailable") from exc
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected.size:
            raise CodeQLSnapshotRejected("CodeQL snapshot metadata changed after inspection")
        while block := os.read(descriptor, min(64 * 1024, expected.size + 1 - size)):
            _check_deadline(deadline)
            size += len(block)
            if size > expected.size:
                raise CodeQLSnapshotRejected("CodeQL snapshot metadata changed after inspection")
            chunks.append(block)
            digest.update(block)
    finally:
        os.close(descriptor)
    if size != expected.size or digest.hexdigest() != expected.sha256:
        raise CodeQLSnapshotRejected("CodeQL snapshot metadata changed after inspection")
    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodeQLSnapshotRejected("CodeQL snapshot metadata is not UTF-8") from exc
    values: list[str] = []
    for line in text.splitlines():
        _check_deadline(deadline)
        if not line.startswith(f"{key}:"):
            continue
        value = line.split(":", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if not value or "#" in value or any(character in value for character in "\r\n\x00"):
            raise CodeQLSnapshotRejected("CodeQL snapshot metadata scalar is unsafe")
        values.append(value)
    if len(values) != 1:
        raise CodeQLSnapshotRejected("CodeQL snapshot metadata scalar is missing or duplicated")
    return values[0]


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise CodeQLSnapshotRejected("CodeQL snapshot inspection timed out")
