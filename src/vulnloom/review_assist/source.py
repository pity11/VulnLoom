"""Read one explicitly selected Python snapshot file without executing it."""

import ast
import hashlib
import io
import os
import stat
import time
import tokenize
from pathlib import Path, PurePosixPath

from vulnloom.domain.digests import canonical_digest
from vulnloom.evidence import Redactor
from vulnloom.ingestion import IngestionService

from .models import CodeReviewSnippet, ReviewLine


def _parts(path):
    value = PurePosixPath(path)
    if value.is_absolute() or str(value) != path or any(p in {"", ".", ".."} for p in value.parts):
        raise ValueError("review path rejected")
    if not value.parts or "\\" in path:
        raise ValueError("review path rejected")
    return value.parts


def _read(root: Path, path: str):
    parts = _parts(path)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(child, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                raise ValueError("review file type or size rejected")
            raw = handle.read(65537)
        if len(raw) > 65536:
            raise ValueError("review file over budget")
        return raw
    finally:
        os.close(fd)


def _masked_lines(raw, check):
    source = raw.decode("utf-8").replace("\r\n", "\n")
    if "\r" in source or any(ord(c) < 32 and c not in "\n\t" for c in source):
        raise ValueError("review source control characters rejected")
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    encoded = source.encode()
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line.encode()))
    spans = []
    literal_types = (ast.Constant, ast.JoinedStr)
    if hasattr(ast, "TemplateStr"):
        literal_types += (ast.TemplateStr,)
    for node in ast.walk(tree):
        check()
        if isinstance(node, literal_types):
            spans.append(
                (
                    offsets[node.lineno - 1] + node.col_offset,
                    offsets[node.end_lineno - 1] + node.end_col_offset,
                )
            )
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        check()
        if token.type == tokenize.COMMENT:
            row, col = token.start
            end_row, end_col = token.end
            spans.append(
                (
                    offsets[row - 1] + len(lines[row - 1][:col].encode()),
                    offsets[end_row - 1] + len(lines[end_row - 1][:end_col].encode()),
                )
            )
    # Merge nested literals (including f-strings) before replacing, preserving all newlines.
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        replacement = b"\n".join(
            b"[REDACTED]" if p else b"" for p in encoded[start:end].split(b"\n")
        )
        encoded = encoded[:start] + replacement + encoded[end:]
    check()
    return [Redactor().text(line) for line in encoded.decode().splitlines()]


def select_snippet(
    *, ingestion, snapshot, scope, path, start_line, end_line, now, clock=time.monotonic
):
    started = clock()

    def check():
        if clock() - started >= 2:
            raise TimeoutError("review source preparation timed out")

    IngestionService.require_snapshot_scope(snapshot, scope, now)
    _parts(path)
    if not path.endswith(".py") or not 1 <= start_line <= end_line <= 65536:
        raise ValueError("review selection rejected")
    if end_line - start_line >= 80 or snapshot.root_ref is None:
        raise ValueError("review selection over budget or unavailable")
    selected = [f for f in snapshot.manifest.files if f.path == path]
    if len(selected) != 1 or selected[0].size > 65536:
        raise ValueError("review file is not a bounded snapshot member")
    _parts(snapshot.root_ref)
    raw = _read(ingestion.root, snapshot.root_ref + "/" + path)
    if len(raw) != selected[0].size or hashlib.sha256(raw).hexdigest() != selected[0].sha256:
        raise ValueError("review source integrity mismatch")
    check()
    lines = _masked_lines(raw, check)
    if end_line > len(lines):
        raise ValueError("review selection exceeds source lines")
    numbered = tuple(
        ReviewLine(number=i, text=lines[i - 1]) for i in range(start_line, end_line + 1)
    )
    return CodeReviewSnippet.create(
        snapshot_id=snapshot.manifest.manifest_id,
        target_id=snapshot.target.target_id,
        path_digest=canonical_digest(path),
        file_digest=selected[0].sha256,
        lines=numbered,
    )
