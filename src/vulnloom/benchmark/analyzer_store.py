"""Transactional checkpoints and immutable artifacts for analyzer imports."""

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

from .analyzer_models import (
    AnalyzerImportOutcome,
    AnalyzerImportPlan,
    AnalyzerObservationArtifact,
    AnalyzerObservationSet,
)


class AnalyzerImportIdempotencyConflict(ValueError):
    """An analyzer import idempotency key was reused for different content."""


class AnalyzerImportRecoveryRequired(RuntimeError):
    """An unfinished analyzer import checkpoint requires operator recovery."""


@dataclass(frozen=True)
class AnalyzerImportClaim:
    created: bool
    outcome: AnalyzerImportOutcome | None = None


class AnalyzerImportStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyzer_imports (
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

    def claim(self, plan: AnalyzerImportPlan, *, now: datetime) -> AnalyzerImportClaim:
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO analyzer_imports (
                        plan_id, idempotency_key, state, started_at
                    ) VALUES (?, ?, 'started', ?)
                    """,
                    (plan.plan_id, plan.idempotency_key, now.isoformat()),
                )
            return AnalyzerImportClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM analyzer_imports WHERE plan_id = ? OR idempotency_key = ?",
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id:
                raise AnalyzerImportIdempotencyConflict(
                    "analyzer import idempotency key was reused for different content"
                ) from None
            if row["state"] == "started":
                raise AnalyzerImportRecoveryRequired(
                    "analyzer import has an unfinished STARTED checkpoint; replay is refused"
                ) from None
            return AnalyzerImportClaim(
                created=False,
                outcome=AnalyzerImportOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: AnalyzerImportOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE analyzer_imports
                SET state = 'completed', completed_at = ?, outcome_json = ?
                WHERE plan_id = ? AND state = 'started'
                """,
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AnalyzerImportRecoveryRequired(
                "analyzer import STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AnalyzerImportStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AnalyzerObservationArtifactStore:
    def __init__(self, root: Path, *, max_artifact_bytes: int = 32 * 1024 * 1024):
        if max_artifact_bytes <= 0:
            raise ValueError("analyzer artifact size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_artifact_bytes = max_artifact_bytes

    def put(self, observations: AnalyzerObservationSet) -> AnalyzerObservationArtifact:
        content = (observations.model_dump_json(indent=2) + "\n").encode()
        self._check_size(content)
        artifact = AnalyzerObservationArtifact(
            observation_set_id=observations.observation_set_id,
            json_sha256=hashlib.sha256(content).hexdigest(),
            json_ref=f"objects/{observations.observation_set_id}/observations.json",
        )
        destination = self.objects / observations.observation_set_id
        if destination.exists():
            self._verify(artifact)
            return artifact
        temporary = Path(tempfile.mkdtemp(prefix="analyzer-observations-", dir=self.objects))
        try:
            self._write(temporary / "observations.json", content)
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

    def read(self, artifact: AnalyzerObservationArtifact) -> AnalyzerObservationSet:
        content = self._verify(artifact)
        return AnalyzerObservationSet.model_validate_json(content)

    def _verify(self, artifact: AnalyzerObservationArtifact) -> bytes:
        directory = self.objects / artifact.observation_set_id
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise ValueError("analyzer Observation object is unavailable or unsafe") from exc
        if not stat.S_ISDIR(metadata.st_mode) or {item.name for item in directory.iterdir()} != {
            "observations.json"
        }:
            raise ValueError("analyzer Observation object is unavailable or unsafe")
        content = self._read(self.root / artifact.json_ref)
        if hashlib.sha256(content).hexdigest() != artifact.json_sha256:
            raise ValueError("analyzer Observation artifact integrity check failed")
        observations = AnalyzerObservationSet.model_validate_json(content)
        if observations.observation_set_id != artifact.observation_set_id:
            raise ValueError("analyzer Observation artifact identity mismatch")
        return content

    def _read(self, path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("platform cannot enforce no-follow analyzer artifact reads")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ValueError("analyzer Observation artifact is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_artifact_bytes:
                raise ValueError("analyzer Observation artifact is unavailable or unsafe")
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
                    raise ValueError("analyzer Observation artifact exceeds configured size limit")
                chunks.append(block)
        finally:
            os.close(descriptor)
        content = b"".join(chunks)
        self._check_size(content)
        return content

    def _check_size(self, content: bytes) -> None:
        if len(content) > self.max_artifact_bytes:
            raise ValueError("analyzer Observation artifact exceeds configured size limit")

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
