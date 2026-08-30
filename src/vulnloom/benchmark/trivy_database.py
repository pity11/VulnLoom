"""Sealed, read-only Trivy vulnerability database snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Self

from pydantic import Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

TRIVY_DATABASE_PATHS = ("db/metadata.json", "db/trivy.db")


class TrivyDatabaseRejected(ValueError):
    """A Trivy database directory failed the trusted sealing boundary."""


class TrivyDatabaseLimits(DomainModel):
    max_database_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        gt=0,
        le=10 * 1024 * 1024 * 1024,
    )
    max_metadata_bytes: int = Field(default=64 * 1024, gt=0, le=1024 * 1024)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)


class TrivyDatabaseFile(DomainModel):
    path: str
    size: int = Field(gt=0)
    sha256: Digest

    @field_validator("path")
    @classmethod
    def safe_fixed_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            value not in TRIVY_DATABASE_PATHS
            or "\\" in value
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("Trivy database file path is not admitted")
        return value


class TrivyDatabaseSnapshot(DomainModel):
    snapshot_id: Digest
    tool_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    schema_version: int = Field(ge=2, le=2)
    files: Annotated[tuple[TrivyDatabaseFile, ...], Field(min_length=2, max_length=2)]
    total_size: int = Field(gt=0)

    @model_validator(mode="after")
    def content_addressed_and_complete(self) -> Self:
        if tuple(item.path for item in self.files) != TRIVY_DATABASE_PATHS:
            raise ValueError("Trivy database snapshot requires the exact admitted files")
        if self.total_size != sum(item.size for item in self.files):
            raise ValueError("Trivy database snapshot size mismatch")
        if self.snapshot_id != trivy_database_snapshot_digest(self):
            raise ValueError("Trivy database snapshot content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        tool_version: str,
        schema_version: int,
        files: tuple[TrivyDatabaseFile, ...],
    ) -> TrivyDatabaseSnapshot:
        values = {
            "tool_version": tool_version,
            "schema_version": schema_version,
            "files": files,
            "total_size": sum(item.size for item in files),
        }
        digest_values = {
            **values,
            "files": tuple(item.model_dump(mode="python") for item in files),
        }
        return cls(snapshot_id=canonical_digest(digest_values), **values)


def trivy_database_snapshot_digest(snapshot: TrivyDatabaseSnapshot) -> str:
    return canonical_digest(snapshot.model_dump(mode="python", exclude={"snapshot_id"}))


def inspect_trivy_database(
    root: Path,
    *,
    tool_version: str,
    limits: TrivyDatabaseLimits | None = None,
) -> TrivyDatabaseSnapshot:
    sealed_limits = limits or TrivyDatabaseLimits()
    deadline = time.monotonic() + sealed_limits.timeout_seconds
    resolved_root = _inspect_root(root)
    actual_paths = _walk_exact_tree(resolved_root, deadline=deadline)
    if actual_paths != TRIVY_DATABASE_PATHS:
        raise TrivyDatabaseRejected("Trivy database contains unexpected or missing files")
    files = tuple(
        _inspect_file(
            resolved_root,
            relative_path,
            max_bytes=(
                sealed_limits.max_metadata_bytes
                if relative_path.endswith("metadata.json")
                else sealed_limits.max_database_bytes
            ),
            deadline=deadline,
        )
        for relative_path in TRIVY_DATABASE_PATHS
    )
    metadata = _load_metadata(
        resolved_root / "db" / "metadata.json",
        files[0],
        deadline=deadline,
    )
    schema_version = metadata.get("Version")
    if schema_version != 2:
        raise TrivyDatabaseRejected("Trivy database schema version is not admitted")
    snapshot = TrivyDatabaseSnapshot.create(
        tool_version=tool_version,
        schema_version=schema_version,
        files=files,
    )
    verify_trivy_database(resolved_root, snapshot, limits=sealed_limits)
    return snapshot


def verify_trivy_database(
    root: Path,
    snapshot: TrivyDatabaseSnapshot,
    *,
    limits: TrivyDatabaseLimits | None = None,
) -> None:
    sealed_limits = limits or TrivyDatabaseLimits()
    observed = inspect_trivy_database_once(
        root,
        tool_version=snapshot.tool_version,
        limits=sealed_limits,
    )
    if observed != snapshot:
        raise TrivyDatabaseRejected("Trivy database no longer matches its sealed snapshot")


def inspect_trivy_database_once(
    root: Path,
    *,
    tool_version: str,
    limits: TrivyDatabaseLimits,
) -> TrivyDatabaseSnapshot:
    deadline = time.monotonic() + limits.timeout_seconds
    resolved_root = _inspect_root(root)
    if _walk_exact_tree(resolved_root, deadline=deadline) != TRIVY_DATABASE_PATHS:
        raise TrivyDatabaseRejected("Trivy database contains unexpected or missing files")
    files = tuple(
        _inspect_file(
            resolved_root,
            relative_path,
            max_bytes=(
                limits.max_metadata_bytes
                if relative_path.endswith("metadata.json")
                else limits.max_database_bytes
            ),
            deadline=deadline,
        )
        for relative_path in TRIVY_DATABASE_PATHS
    )
    metadata = _load_metadata(
        resolved_root / "db" / "metadata.json",
        files[0],
        deadline=deadline,
    )
    schema_version = metadata.get("Version")
    if schema_version != 2:
        raise TrivyDatabaseRejected("Trivy database schema version is not admitted")
    return TrivyDatabaseSnapshot.create(
        tool_version=tool_version,
        schema_version=schema_version,
        files=files,
    )


def _inspect_root(root: Path) -> Path:
    try:
        metadata = os.lstat(root)
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise TrivyDatabaseRejected("Trivy database directory is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or resolved != root:
        raise TrivyDatabaseRejected("Trivy database root must be a direct directory path")
    if metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        raise TrivyDatabaseRejected("Trivy database root must be read-only")
    return resolved


def _walk_exact_tree(root: Path, *, deadline: float) -> tuple[str, ...]:
    files: list[str] = []
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        _check_deadline(deadline)
        current_path = Path(current)
        for name in (*directories, *names):
            path = current_path / name
            try:
                metadata = os.lstat(path)
            except OSError as exc:
                raise TrivyDatabaseRejected("Trivy database entry is unavailable") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise TrivyDatabaseRejected("Trivy database symbolic links are forbidden")
            if metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                raise TrivyDatabaseRejected("Trivy database entries must be read-only")
            if name in directories and not stat.S_ISDIR(metadata.st_mode):
                raise TrivyDatabaseRejected("Trivy database tree contains a special entry")
            if name in names:
                if not stat.S_ISREG(metadata.st_mode):
                    raise TrivyDatabaseRejected("Trivy database tree contains a special entry")
                files.append(path.relative_to(root).as_posix())
    return tuple(sorted(files))


def _inspect_file(
    root: Path,
    relative_path: str,
    *,
    max_bytes: int,
    deadline: float,
) -> TrivyDatabaseFile:
    _check_deadline(deadline)
    path = root / relative_path
    try:
        before = os.lstat(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise TrivyDatabaseRejected("Trivy database file is unavailable or unsafe") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size <= 0
            or opened.st_size > max_bytes
        ):
            raise TrivyDatabaseRejected("Trivy database file failed size or identity checks")
        while True:
            _check_deadline(deadline)
            block = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise TrivyDatabaseRejected("Trivy database file exceeds its size limit")
            digest.update(block)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise TrivyDatabaseRejected("Trivy database changed during inspection") from exc
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) or total != before.st_size:
        raise TrivyDatabaseRejected("Trivy database changed during inspection")
    return TrivyDatabaseFile(path=relative_path, size=total, sha256=digest.hexdigest())


def _load_metadata(path: Path, sealed: TrivyDatabaseFile, *, deadline: float) -> dict[str, Any]:
    _check_deadline(deadline)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise TrivyDatabaseRejected("Trivy database metadata is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != sealed.size:
            raise TrivyDatabaseRejected("Trivy database metadata changed before parsing")
        chunks: list[bytes] = []
        total = 0
        while True:
            _check_deadline(deadline)
            block = os.read(descriptor, min(64 * 1024, sealed.size + 1 - total))
            if not block:
                break
            total += len(block)
            if total > sealed.size:
                raise TrivyDatabaseRejected("Trivy database metadata changed before parsing")
            chunks.append(block)
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    try:
        document = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrivyDatabaseRejected("Trivy database metadata is invalid JSON") from exc
    if (
        len(content) != sealed.size
        or hashlib.sha256(content).hexdigest() != sealed.sha256
        or not isinstance(document, dict)
    ):
        raise TrivyDatabaseRejected("Trivy database metadata does not match its manifest")
    return document


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrivyDatabaseRejected("Trivy database metadata contains duplicate keys")
        result[key] = value
    return result


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TrivyDatabaseRejected("Trivy database inspection timed out")
