#!/usr/bin/env python3
"""Narrow CodeQL query wrapper for a bounded writable tmpfs database copy."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
import time
import unicodedata
from pathlib import Path, PurePosixPath

CODEQL_PATH = Path("/opt/codeql/codeql")
SOURCE_DATABASE = Path("/workspace/analyzer-data/database")
QUERY_ROOT = Path("/workspace/analyzer-data/queries")
WORKING_DATABASE = Path("/workspace/output/codeql-database")
SARIF_PATH = Path("/workspace/output/codeql-output.sarif")


class CodeQLWrapperRejected(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--query", required=True)
    parser.add_argument("--max-files", required=True, type=int)
    parser.add_argument("--max-entries", required=True, type=int)
    parser.add_argument("--max-database-bytes", required=True, type=int)
    parser.add_argument("--max-output-bytes", required=True, type=int)
    parser.add_argument("--timeout-seconds", required=True, type=float)
    return parser


def main(argv: tuple[str, ...] | None = None) -> int:
    try:
        values = _parser().parse_args(argv)
        query = _safe_query(values.query)
        if (
            values.max_files <= 0
            or values.max_entries < values.max_files
            or values.max_database_bytes <= 0
            or values.max_output_bytes <= 0
            or not 0 < values.timeout_seconds <= 3600
        ):
            raise CodeQLWrapperRejected("wrapper limits are invalid")
        deadline = time.monotonic() + values.timeout_seconds
        _copy_database(
            SOURCE_DATABASE,
            WORKING_DATABASE,
            max_files=values.max_files,
            max_entries=values.max_entries,
            max_bytes=values.max_database_bytes,
            deadline=deadline,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CodeQLWrapperRejected("database copy exceeded its deadline")
        result = subprocess.run(
            (
                str(CODEQL_PATH),
                "database",
                "analyze",
                str(WORKING_DATABASE),
                str(query),
                "--format=sarifv2.1.0",
                f"--output={SARIF_PATH}",
                "--threads=1",
                "--common-caches=/tmp/codeql-common-cache",
                "--compilation-cache=/tmp/codeql-compilation-cache",
                "--no-default-compilation-cache",
                f"--search-path={QUERY_ROOT}",
                "--no-sarif-add-file-contents",
                "--no-sarif-add-snippets",
                "--sarif-include-query-help=never",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=remaining,
            env={
                "HOME": "/tmp",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "TMPDIR": "/tmp",
            },
        )
        if result.returncode != 0:
            raise CodeQLWrapperRejected("CodeQL query execution failed")
        _stream_regular(SARIF_PATH, max_bytes=values.max_output_bytes, deadline=deadline)
        return 0
    except (CodeQLWrapperRejected, OSError, subprocess.TimeoutExpired):
        return 70


def _safe_query(value: str) -> Path:
    path = PurePosixPath(value)
    if (
        not value.startswith(f"{QUERY_ROOT}/")
        or path.suffix != ".qls"
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise CodeQLWrapperRejected("query path is outside the sealed query root")
    return Path(value)


def _copy_database(
    source: Path,
    destination: Path,
    *,
    max_files: int,
    max_entries: int,
    max_bytes: int,
    deadline: float,
) -> None:
    source_metadata = os.lstat(source)
    if (
        not stat.S_ISDIR(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or source_metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise CodeQLWrapperRejected("source database root is unsafe")
    destination.mkdir(mode=0o700)
    pending = [(source, destination)]
    files = 0
    entries = 0
    total = 0
    while pending:
        _deadline(deadline)
        source_directory, destination_directory = pending.pop()
        members = sorted(os.scandir(source_directory), key=lambda item: item.name)
        if not members:
            raise CodeQLWrapperRejected("source database contains an empty directory")
        for member in members:
            _deadline(deadline)
            entries += 1
            if entries > max_entries:
                raise CodeQLWrapperRejected("source database exceeds its entry limit")
            _safe_name(member.name)
            metadata = member.stat(follow_symlinks=False)
            target = destination_directory / member.name
            if stat.S_ISLNK(metadata.st_mode):
                raise CodeQLWrapperRejected("source database symbolic links are forbidden")
            if metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                raise CodeQLWrapperRejected("source database entries must be read-only")
            if stat.S_ISDIR(metadata.st_mode):
                target.mkdir(mode=0o700)
                pending.append((Path(member.path), target))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise CodeQLWrapperRejected("source database special files are forbidden")
            files += 1
            total += metadata.st_size
            if files > max_files or total > max_bytes:
                raise CodeQLWrapperRejected("source database exceeds its copy limit")
            _copy_regular(Path(member.path), target, metadata, deadline=deadline)
    if files != max_files or entries != max_entries or total != max_bytes:
        raise CodeQLWrapperRejected("source database does not match its sealed copy limits")


def _copy_regular(source: Path, target: Path, expected: os.stat_result, *, deadline: float) -> None:
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise CodeQLWrapperRejected("source database file identity changed")
        with target.open("xb") as output:
            while block := os.read(descriptor, 1024 * 1024):
                _deadline(deadline)
                output.write(block)
    finally:
        os.close(descriptor)
    after = os.lstat(source)
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_size,
        expected.st_mtime_ns,
    ):
        raise CodeQLWrapperRejected("source database file changed during copy")
    if target.stat().st_size != expected.st_size:
        raise CodeQLWrapperRejected("source database copy size mismatch")


def _stream_regular(path: Path, *, max_bytes: int, deadline: float) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    total = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= max_bytes:
            raise CodeQLWrapperRejected("CodeQL SARIF output is empty or oversized")
        while block := os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total)):
            _deadline(deadline)
            total += len(block)
            if total > max_bytes:
                raise CodeQLWrapperRejected("CodeQL SARIF output exceeds its limit")
            sys.stdout.buffer.write(block)
        sys.stdout.buffer.flush()
    finally:
        os.close(descriptor)


def _safe_name(value: str) -> None:
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise CodeQLWrapperRejected("source database contains an unsafe path")


def _deadline(value: float) -> None:
    if time.monotonic() >= value:
        raise CodeQLWrapperRejected("CodeQL wrapper timed out")


if __name__ == "__main__":
    raise SystemExit(main())
