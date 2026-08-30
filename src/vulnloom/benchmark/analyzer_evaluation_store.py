"""Crash-safe checkpoints and immutable analyzer evaluation artifacts."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from vulnloom.domain.digests import canonical_digest

from .analyzer_evaluation_models import (
    AnalyzerEvaluationArtifact,
    AnalyzerEvaluationOutcome,
    AnalyzerEvaluationPlan,
    AnalyzerEvaluationResult,
)


class AnalyzerEvaluationIdempotencyConflict(ValueError):
    """An evaluation idempotency key was reused for different sealed content."""


class AnalyzerEvaluationRecoveryRequired(RuntimeError):
    """An unfinished analyzer evaluation requires explicit operator recovery."""


@dataclass(frozen=True)
class AnalyzerEvaluationClaim:
    created: bool
    outcome: AnalyzerEvaluationOutcome | None = None


class AnalyzerEvaluationStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyzer_evaluations (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: AnalyzerEvaluationPlan, *, now: datetime) -> AnalyzerEvaluationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO analyzer_evaluations (
                        plan_id, idempotency_key, state, started_at
                    ) VALUES (?, ?, 'started', ?)
                    """,
                    (plan.plan_id, plan.idempotency_key, now.isoformat()),
                )
            return AnalyzerEvaluationClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM analyzer_evaluations WHERE plan_id = ? OR idempotency_key = ?",
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id:
                raise AnalyzerEvaluationIdempotencyConflict(
                    "analyzer evaluation idempotency key was reused for different content"
                ) from None
            if row["state"] == "started":
                raise AnalyzerEvaluationRecoveryRequired(
                    "analyzer evaluation has an unfinished STARTED checkpoint; replay is refused"
                ) from None
            return AnalyzerEvaluationClaim(
                created=False,
                outcome=AnalyzerEvaluationOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: AnalyzerEvaluationOutcome, *, completed_at: datetime) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE analyzer_evaluations
                SET state = 'completed', completed_at = ?, outcome_json = ?
                WHERE plan_id = ? AND state = 'started'
                """,
                (completed_at.isoformat(), outcome.model_dump_json(), outcome.plan_id),
            ).rowcount
        if changed != 1:
            raise AnalyzerEvaluationRecoveryRequired(
                "analyzer evaluation STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AnalyzerEvaluationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AnalyzerEvaluationArtifactStore:
    def __init__(self, root: Path, *, max_artifact_bytes: int = 8 * 1024 * 1024):
        if max_artifact_bytes <= 0:
            raise ValueError("analyzer evaluation artifact size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_artifact_bytes = max_artifact_bytes

    def put(self, result: AnalyzerEvaluationResult) -> AnalyzerEvaluationArtifact:
        result_digest = canonical_digest(result.model_dump(mode="python"))
        destination = self.objects / result_digest
        json_bytes = (result.model_dump_json(indent=2) + "\n").encode()
        markdown_bytes = _render_markdown(result).encode()
        self._check_size(json_bytes)
        self._check_size(markdown_bytes)
        artifact = AnalyzerEvaluationArtifact(
            result_digest=result_digest,
            json_sha256=hashlib.sha256(json_bytes).hexdigest(),
            markdown_sha256=hashlib.sha256(markdown_bytes).hexdigest(),
            json_ref=f"objects/{result_digest}/result.json",
            markdown_ref=f"objects/{result_digest}/result.md",
        )
        if destination.exists():
            self._verify(artifact)
            return artifact
        temporary = Path(tempfile.mkdtemp(prefix="analyzer-evaluation-", dir=self.objects))
        try:
            self._write(temporary / "result.json", json_bytes)
            self._write(temporary / "result.md", markdown_bytes)
            os.chmod(temporary, 0o500)
            try:
                os.rename(temporary, destination)
            except FileExistsError:
                self._verify(artifact)
            self._verify(artifact)
            return artifact
        finally:
            if temporary.exists():
                os.chmod(temporary, 0o700)
                shutil.rmtree(temporary)

    def read_result(self, artifact: AnalyzerEvaluationArtifact) -> AnalyzerEvaluationResult:
        self._verify(artifact)
        return AnalyzerEvaluationResult.model_validate_json(
            self._read(self.root / artifact.json_ref)
        )

    def read_markdown(self, artifact: AnalyzerEvaluationArtifact) -> str:
        self._verify(artifact)
        return self._read(self.root / artifact.markdown_ref).decode()

    def _verify(self, artifact: AnalyzerEvaluationArtifact) -> None:
        directory = self.objects / artifact.result_digest
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise ValueError("analyzer evaluation object is unavailable or unsafe") from exc
        if not stat.S_ISDIR(metadata.st_mode) or {item.name for item in directory.iterdir()} != {
            "result.json",
            "result.md",
        }:
            raise ValueError("analyzer evaluation object is unavailable or unsafe")
        json_bytes = self._read(self.root / artifact.json_ref)
        markdown_bytes = self._read(self.root / artifact.markdown_ref)
        if hashlib.sha256(json_bytes).hexdigest() != artifact.json_sha256:
            raise ValueError("analyzer evaluation JSON integrity check failed")
        if hashlib.sha256(markdown_bytes).hexdigest() != artifact.markdown_sha256:
            raise ValueError("analyzer evaluation Markdown integrity check failed")
        result = AnalyzerEvaluationResult.model_validate_json(json_bytes)
        if canonical_digest(result.model_dump(mode="python")) != artifact.result_digest:
            raise ValueError("analyzer evaluation result content identity mismatch")

    def _read(self, path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("platform cannot enforce no-follow analyzer evaluation reads")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ValueError("analyzer evaluation artifact is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_artifact_bytes:
                raise ValueError("analyzer evaluation artifact is unavailable or unsafe")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(
                    descriptor,
                    min(1024 * 1024, self.max_artifact_bytes + 1 - total),
                )
                if not block:
                    break
                total += len(block)
                if total > self.max_artifact_bytes:
                    raise ValueError("analyzer evaluation artifact exceeds size limit")
                chunks.append(block)
        finally:
            os.close(descriptor)
        return b"".join(chunks)

    def _check_size(self, content: bytes) -> None:
        if len(content) > self.max_artifact_bytes:
            raise ValueError("analyzer evaluation artifact exceeds size limit")

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())


def _render_markdown(result: AnalyzerEvaluationResult) -> str:
    metrics = result.metrics
    lines = [
        "# VulnLoom Offline Analyzer Evaluation",
        "",
        f"- Gate: `{result.gate_status.value}`",
        f"- Suite: `{result.suite_id}`",
        f"- Plan: `{result.plan_id}`",
        f"- Truth recall: `{metrics.truth_recall:.9f}`",
        f"- Observation precision: `{metrics.observation_precision:.9f}`",
        f"- Duplicate rate: `{metrics.duplicate_rate:.9f}`",
        f"- Exclusion rate: `{metrics.exclusion_rate:.9f}`",
        "",
        "## Per analyzer",
        "",
    ]
    lines.extend(
        (
            f"- `{item.analyzer.value}`: recall={item.truth_recall:.9f}, "
            f"precision={item.observation_precision:.9f}, "
            f"duplicates={item.duplicate_rate:.9f}, exclusions={item.exclusion_rate:.9f}"
        )
        for item in metrics.by_analyzer
    )
    lines.extend(("", "## Gate violations", ""))
    if result.violations:
        lines.extend(
            f"- `{item.code}`: {item.metric}={item.actual:g}, limit={item.limit:g}"
            for item in result.violations
        )
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"
