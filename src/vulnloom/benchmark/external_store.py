"""Transactional checkpoints and immutable artifacts for external benchmark imports."""

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

from .external_models import (
    ExternalBenchmarkArtifact,
    ExternalBenchmarkImportOutcome,
    ExternalBenchmarkImportPlan,
)
from .models import BenchmarkSuite


class ExternalImportIdempotencyConflict(ValueError):
    """An import idempotency key was reused for different sealed content."""


class ExternalImportRecoveryRequired(RuntimeError):
    """An unfinished external import checkpoint requires operator recovery."""


@dataclass(frozen=True)
class ExternalImportClaim:
    created: bool
    outcome: ExternalBenchmarkImportOutcome | None = None


class ExternalBenchmarkImportStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS external_benchmark_imports (
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

    def claim(self, plan: ExternalBenchmarkImportPlan, *, now: datetime) -> ExternalImportClaim:
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO external_benchmark_imports (
                        plan_id, idempotency_key, state, started_at
                    ) VALUES (?, ?, 'started', ?)
                    """,
                    (plan.plan_id, plan.idempotency_key, now.isoformat()),
                )
            return ExternalImportClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                """
                SELECT * FROM external_benchmark_imports
                WHERE plan_id = ? OR idempotency_key = ?
                """,
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id:
                raise ExternalImportIdempotencyConflict(
                    "external import idempotency key was reused for different content"
                ) from None
            if row["state"] == "started":
                raise ExternalImportRecoveryRequired(
                    "external import has an unfinished STARTED checkpoint; replay is refused"
                ) from None
            return ExternalImportClaim(
                created=False,
                outcome=ExternalBenchmarkImportOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: ExternalBenchmarkImportOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE external_benchmark_imports
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
            raise ExternalImportRecoveryRequired(
                "external import STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> ExternalBenchmarkImportStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ExternalBenchmarkArtifactStore:
    def __init__(self, root: Path, *, max_artifact_bytes: int = 8 * 1024 * 1024):
        if max_artifact_bytes <= 0:
            raise ValueError("external Benchmark artifact size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_artifact_bytes = max_artifact_bytes

    def put(self, suite: BenchmarkSuite) -> ExternalBenchmarkArtifact:
        suite_digest = canonical_digest(suite.model_dump(mode="python"))
        destination = self.objects / suite_digest
        content = (suite.model_dump_json(indent=2) + "\n").encode()
        self._check_size(content)
        artifact = ExternalBenchmarkArtifact(
            suite_digest=suite_digest,
            json_sha256=hashlib.sha256(content).hexdigest(),
            json_ref=f"objects/{suite_digest}/suite.json",
        )
        if destination.exists():
            self._verify(artifact)
            return artifact
        temporary = Path(tempfile.mkdtemp(prefix="external-benchmark-", dir=self.objects))
        try:
            self._write(temporary / "suite.json", content)
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

    def read_suite(self, artifact: ExternalBenchmarkArtifact) -> BenchmarkSuite:
        self._verify(artifact)
        return BenchmarkSuite.model_validate_json(self._read(self.root / artifact.json_ref))

    def _verify(self, artifact: ExternalBenchmarkArtifact) -> None:
        directory = self.objects / artifact.suite_digest
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise ValueError("external Benchmark object is unavailable or unsafe") from exc
        if not stat.S_ISDIR(metadata.st_mode) or {item.name for item in directory.iterdir()} != {
            "suite.json"
        }:
            raise ValueError("external Benchmark object is unavailable or unsafe")
        content = self._read(self.root / artifact.json_ref)
        if hashlib.sha256(content).hexdigest() != artifact.json_sha256:
            raise ValueError("external Benchmark artifact integrity check failed")
        suite = BenchmarkSuite.model_validate_json(content)
        if canonical_digest(suite.model_dump(mode="python")) != artifact.suite_digest:
            raise ValueError("external Benchmark suite identity mismatch")

    def _read(self, path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("platform cannot enforce no-follow external Benchmark reads")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ValueError("external Benchmark artifact is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_artifact_bytes:
                raise ValueError("external Benchmark artifact is unavailable or unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(self.max_artifact_bytes + 1)
        finally:
            os.close(descriptor)
        self._check_size(content)
        return content

    def _check_size(self, content: bytes) -> None:
        if len(content) > self.max_artifact_bytes:
            raise ValueError("external Benchmark artifact exceeds configured size limit")

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
