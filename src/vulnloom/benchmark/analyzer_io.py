"""No-follow, bounded reads for precomputed local analyzer output."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any
from uuid import UUID

from .analyzer_models import (
    AnalyzerImportLimits,
    AnalyzerKind,
    AnalyzerResultFile,
    AnalyzerResultSnapshot,
)


class AnalyzerImportRejected(ValueError):
    """A precomputed analyzer result failed a trusted import gate."""


class AnalyzerDeadline:
    def __init__(self, seconds: float):
        if seconds <= 0:
            raise AnalyzerImportRejected("analyzer import deadline is exhausted")
        self.expires_at = time.monotonic() + seconds

    def check(self) -> None:
        if time.monotonic() >= self.expires_at:
            raise AnalyzerImportRejected("analyzer import timed out")


def inspect_result_file(
    path: Path,
    *,
    logical_name: str,
    max_bytes: int,
    deadline: AnalyzerDeadline,
) -> AnalyzerResultFile:
    deadline.check()
    if not hasattr(os, "O_NOFOLLOW"):
        raise AnalyzerImportRejected("platform cannot enforce no-follow analyzer reads")
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise AnalyzerImportRejected("analyzer result file is unavailable") from exc
    if stat.S_ISLNK(before.st_mode):
        raise AnalyzerImportRejected("analyzer result symbolic links are forbidden")
    if not stat.S_ISREG(before.st_mode):
        raise AnalyzerImportRejected("analyzer result must be a regular file")
    if before.st_size > max_bytes:
        raise AnalyzerImportRejected("analyzer result exceeds configured size limit")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise AnalyzerImportRejected("analyzer result file is unavailable or unsafe") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise AnalyzerImportRejected("analyzer result changed before it could be opened")
        while True:
            deadline.check()
            block = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise AnalyzerImportRejected("analyzer result exceeds configured size limit")
            digest.update(block)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise AnalyzerImportRejected("analyzer result changed while being inspected") from exc
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) or total != before.st_size:
        raise AnalyzerImportRejected("analyzer result changed while being inspected")
    return AnalyzerResultFile(
        logical_name=logical_name,
        size=total,
        sha256=digest.hexdigest(),
    )


def create_analyzer_snapshot(
    output_path: Path,
    *,
    analyzer: AnalyzerKind,
    target_id: UUID,
    target_version: str,
    tool_version: str,
    rules_digest: str,
    cwe_map_path: Path | None = None,
    limits: AnalyzerImportLimits | None = None,
) -> AnalyzerResultSnapshot:
    sealed_limits = limits or AnalyzerImportLimits()
    deadline = AnalyzerDeadline(sealed_limits.timeout_seconds)
    output = inspect_result_file(
        output_path,
        logical_name="output.json",
        max_bytes=sealed_limits.max_output_bytes,
        deadline=deadline,
    )
    cwe_map = (
        inspect_result_file(
            cwe_map_path,
            logical_name="cwe-map.json",
            max_bytes=sealed_limits.max_cwe_map_bytes,
            deadline=deadline,
        )
        if cwe_map_path is not None
        else None
    )
    return AnalyzerResultSnapshot.create(
        analyzer=analyzer,
        target_id=target_id,
        target_version=target_version,
        tool_version=tool_version,
        rules_digest=rules_digest,
        output=output,
        cwe_map=cwe_map,
    )


def load_sealed_json(
    path: Path,
    sealed: AnalyzerResultFile,
    *,
    max_bytes: int,
    deadline: AnalyzerDeadline,
) -> Any:
    observed = inspect_result_file(
        path,
        logical_name=sealed.logical_name,
        max_bytes=max_bytes,
        deadline=deadline,
    )
    if observed != sealed:
        raise AnalyzerImportRejected("analyzer result does not match its sealed manifest")
    if not hasattr(os, "O_NOFOLLOW"):
        raise AnalyzerImportRejected("platform cannot enforce no-follow analyzer reads")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise AnalyzerImportRejected("analyzer result is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != sealed.size:
            raise AnalyzerImportRejected("analyzer result changed before parsing")
        chunks: list[bytes] = []
        total = 0
        while True:
            deadline.check()
            block = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise AnalyzerImportRejected("analyzer result exceeds configured size limit")
            chunks.append(block)
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if len(content) != sealed.size or hashlib.sha256(content).hexdigest() != sealed.sha256:
        raise AnalyzerImportRejected("analyzer result changed before parsing")
    deadline.check()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnalyzerImportRejected("analyzer result is not valid UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except AnalyzerImportRejected:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AnalyzerImportRejected("analyzer result is not valid bounded JSON") from exc


def verify_result_files(
    output_path: Path,
    cwe_map_path: Path | None,
    snapshot: AnalyzerResultSnapshot,
    *,
    limits: AnalyzerImportLimits,
    deadline: AnalyzerDeadline,
) -> None:
    output = inspect_result_file(
        output_path,
        logical_name="output.json",
        max_bytes=limits.max_output_bytes,
        deadline=deadline,
    )
    if output != snapshot.output:
        raise AnalyzerImportRejected("analyzer output does not match its sealed manifest")
    if (snapshot.cwe_map is None) != (cwe_map_path is None):
        raise AnalyzerImportRejected("analyzer CWE map binding mismatch")
    if snapshot.cwe_map is not None and cwe_map_path is not None:
        cwe_map = inspect_result_file(
            cwe_map_path,
            logical_name="cwe-map.json",
            max_bytes=limits.max_cwe_map_bytes,
            deadline=deadline,
        )
        if cwe_map != snapshot.cwe_map:
            raise AnalyzerImportRejected("analyzer CWE map does not match its sealed manifest")


def load_cwe_map(
    path: Path | None,
    sealed: AnalyzerResultFile | None,
    *,
    limits: AnalyzerImportLimits,
    deadline: AnalyzerDeadline,
) -> dict[str, tuple[str, ...]]:
    if path is None or sealed is None:
        if path is not None or sealed is not None:
            raise AnalyzerImportRejected("analyzer CWE map binding mismatch")
        return {}
    document = load_sealed_json(
        path,
        sealed,
        max_bytes=limits.max_cwe_map_bytes,
        deadline=deadline,
    )
    if not isinstance(document, dict):
        raise AnalyzerImportRejected("analyzer CWE map must be a JSON object")
    normalized: dict[str, tuple[str, ...]] = {}
    for rule_id, raw_cwes in document.items():
        deadline.check()
        if not isinstance(rule_id, str) or not _safe_rule_id(rule_id):
            raise AnalyzerImportRejected("analyzer CWE map contains an invalid rule identity")
        values = raw_cwes if isinstance(raw_cwes, list) else [raw_cwes]
        cwes = tuple(sorted({_normalize_cwe(value) for value in values}))
        if not cwes or None in cwes:
            raise AnalyzerImportRejected("analyzer CWE map contains an invalid CWE")
        normalized[rule_id] = tuple(item for item in cwes if item is not None)
    return normalized


def safe_rule_id(value: object) -> str | None:
    return value if isinstance(value, str) and _safe_rule_id(value) else None


def normalize_cwes(values: object) -> tuple[str, ...]:
    if values is None:
        return ()
    candidates = values if isinstance(values, list | tuple | set) else [values]
    normalized: set[str] = set()
    for value in candidates:
        cwe = _normalize_cwe(value)
        if cwe is not None:
            normalized.add(cwe)
    return tuple(sorted(normalized))


def _normalize_cwe(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.search(r"(?:^|[/_: -])CWE[-_: ]?([1-9][0-9]*)$", value.strip().upper())
    return f"CWE-{int(match.group(1))}" if match else None


def _safe_rule_id(value: str) -> bool:
    if not 1 <= len(value) <= 256 or not value[0].isalnum():
        return False
    return all(character.isalnum() or character in "._:/+-" for character in value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AnalyzerImportRejected("analyzer JSON contains duplicate object keys")
        result[key] = value
    return result
