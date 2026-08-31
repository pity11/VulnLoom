"""Transactional checkpoints for analyzer qualification runs."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .analyzer_qualification_models import (
    AnalyzerQualificationOutcome,
    AnalyzerQualificationPlan,
)


class AnalyzerQualificationIdempotencyConflict(ValueError):
    pass


class AnalyzerQualificationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AnalyzerQualificationClaim:
    created: bool
    outcome: AnalyzerQualificationOutcome | None = None


class AnalyzerQualificationStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyzer_qualifications (
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

    def claim(
        self, plan: AnalyzerQualificationPlan, *, now: datetime
    ) -> AnalyzerQualificationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO analyzer_qualifications "
                    "(plan_id, idempotency_key, state, started_at) VALUES (?, ?, 'started', ?)",
                    (plan.plan_id, plan.idempotency_key, now.isoformat()),
                )
            return AnalyzerQualificationClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM analyzer_qualifications WHERE plan_id = ? OR idempotency_key = ?",
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id:
                raise AnalyzerQualificationIdempotencyConflict(
                    "analyzer qualification idempotency key was reused for different content"
                ) from None
            if row["state"] == "started":
                raise AnalyzerQualificationRecoveryRequired(
                    "analyzer qualification has an unfinished STARTED checkpoint"
                ) from None
            return AnalyzerQualificationClaim(
                created=False,
                outcome=AnalyzerQualificationOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: AnalyzerQualificationOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE analyzer_qualifications SET state = 'completed', completed_at = ?, "
                "outcome_json = ? WHERE plan_id = ? AND state = 'started'",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AnalyzerQualificationRecoveryRequired(
                "analyzer qualification STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AnalyzerQualificationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
