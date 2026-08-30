"""No-follow, bounded local snapshot inspection for external benchmarks."""

from __future__ import annotations

import hashlib
import os
import stat
import time
import unicodedata
from pathlib import Path, PurePosixPath

from .external_models import (
    ExternalBenchmarkKind,
    ExternalBenchmarkSnapshot,
    ExternalImportLimits,
    SnapshotFile,
)


class ExternalBenchmarkRejected(ValueError):
    """An external benchmark snapshot failed a trusted local import check."""


class ImportDeadline:
    def __init__(self, seconds: float):
        self.ends_at = time.monotonic() + seconds

    def check(self) -> None:
        if time.monotonic() >= self.ends_at:
            raise ExternalBenchmarkRejected("external benchmark import timed out")


def inspect_snapshot_directory(
    root: Path,
    *,
    limits: ExternalImportLimits,
    deadline: ImportDeadline,
) -> tuple[SnapshotFile, ...]:
    absolute = resolve_snapshot_root(root)

    files: list[SnapshotFile] = []
    seen: set[str] = set()
    total = 0
    pending = [absolute]
    while pending:
        deadline.check()
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise ExternalBenchmarkRejected("snapshot directory cannot be inspected") from exc
        for entry in entries:
            deadline.check()
            path = Path(entry.path)
            relative = path.relative_to(absolute).as_posix()
            normalized = unicodedata.normalize("NFC", relative)
            parts = PurePosixPath(normalized).parts
            if (
                normalized != relative
                or "\\" in normalized
                or any(
                    unicodedata.category(character).startswith("C")
                    for character in normalized
                )
                or any(part in {"", ".", ".."} for part in parts)
            ):
                raise ExternalBenchmarkRejected("snapshot contains a non-normalized path")
            collision_key = normalized.casefold()
            if collision_key in seen:
                raise ExternalBenchmarkRejected("snapshot contains a normalized path collision")
            seen.add(collision_key)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ExternalBenchmarkRejected("snapshot member cannot be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ExternalBenchmarkRejected("snapshot symbolic links are forbidden")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ExternalBenchmarkRejected("snapshot special files are forbidden")
            if len(files) >= limits.max_files:
                raise ExternalBenchmarkRejected("snapshot exceeds maximum file count")
            if metadata.st_size > limits.max_single_file_bytes:
                raise ExternalBenchmarkRejected("snapshot member exceeds maximum size")
            total += metadata.st_size
            if total > limits.max_total_bytes:
                raise ExternalBenchmarkRejected("snapshot exceeds maximum total size")
            digest, size = _hash_regular_file(path, limits.max_single_file_bytes, deadline)
            if size != metadata.st_size:
                raise ExternalBenchmarkRejected("snapshot member changed while being inspected")
            files.append(SnapshotFile(path=normalized, size=size, sha256=digest))
    return tuple(sorted(files, key=lambda item: item.path))


def resolve_snapshot_root(root: Path) -> Path:
    requested = root.absolute()
    try:
        root_stat = requested.lstat()
    except OSError as exc:
        raise ExternalBenchmarkRejected("snapshot root is unavailable") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or requested.is_symlink():
        raise ExternalBenchmarkRejected("snapshot root must be a non-symlink directory")
    try:
        return requested.resolve(strict=True)
    except OSError as exc:
        raise ExternalBenchmarkRejected("snapshot root cannot be resolved safely") from exc


def create_external_snapshot(
    root: Path,
    *,
    kind: ExternalBenchmarkKind,
    upstream_revision: str,
    license_spdx: str,
    limits: ExternalImportLimits | None = None,
) -> ExternalBenchmarkSnapshot:
    selected_limits = limits or ExternalImportLimits()
    deadline = ImportDeadline(selected_limits.timeout_seconds)
    return ExternalBenchmarkSnapshot.create(
        kind=kind,
        upstream_revision=upstream_revision,
        license_spdx=license_spdx,
        files=inspect_snapshot_directory(root, limits=selected_limits, deadline=deadline),
    )


def verify_snapshot_directory(
    root: Path,
    snapshot: ExternalBenchmarkSnapshot,
    *,
    limits: ExternalImportLimits,
    deadline: ImportDeadline,
) -> None:
    observed = inspect_snapshot_directory(root, limits=limits, deadline=deadline)
    if observed != snapshot.files:
        raise ExternalBenchmarkRejected("snapshot directory does not match its sealed manifest")


def read_verified_snapshot_file(
    root: Path,
    snapshot: ExternalBenchmarkSnapshot,
    relative_path: str,
    *,
    limits: ExternalImportLimits,
    deadline: ImportDeadline,
) -> bytes:
    expected = next((item for item in snapshot.files if item.path == relative_path), None)
    if expected is None:
        raise ExternalBenchmarkRejected("adapter requested an unsealed snapshot file")
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    digest, size, content = _read_regular_file(
        path, min(limits.max_single_file_bytes, expected.size), deadline
    )
    if size != expected.size or digest != expected.sha256:
        raise ExternalBenchmarkRejected("snapshot metadata file failed integrity verification")
    return content


def _hash_regular_file(path: Path, max_bytes: int, deadline: ImportDeadline) -> tuple[str, int]:
    digest, size, _ = _read_regular_file(path, max_bytes, deadline, retain=False)
    return digest, size


def _read_regular_file(
    path: Path,
    max_bytes: int,
    deadline: ImportDeadline,
    *,
    retain: bool = True,
) -> tuple[str, int, bytes]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ExternalBenchmarkRejected("platform cannot enforce no-follow snapshot reads")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ExternalBenchmarkRejected("snapshot member is unavailable or unsafe") from exc
    digest = hashlib.sha256()
    size = 0
    chunks: list[bytes] = []
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ExternalBenchmarkRejected("snapshot member is unavailable or oversized")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(1024 * 1024):
                deadline.check()
                size += len(chunk)
                if size > max_bytes:
                    raise ExternalBenchmarkRejected("snapshot member exceeds read budget")
                digest.update(chunk)
                if retain:
                    chunks.append(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size, b"".join(chunks)
