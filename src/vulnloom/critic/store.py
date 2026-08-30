"""Transactional, fail-closed checkpoints for Critic executions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import CriticOutcome, CriticPlan


class CriticIdempotencyConflict(ValueError):
    """A Critic idempotency key was reused for different sealed content."""


class CriticRecoveryRequired(RuntimeError):
    """An unfinished Critic checkpoint requires explicit operator recovery."""


@dataclass(frozen=True)
class CriticClaim:
    created: bool
    outcome: CriticOutcome | None = None


class CriticStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS critic_executions (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: CriticPlan, *, now: datetime) -> CriticClaim:
        encoded = plan.model_dump_json()
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO critic_executions (
                        plan_id, idempotency_key, plan_json, state, started_at
                    ) VALUES (?, ?, ?, 'started', ?)
                    """,
                    (plan.plan_id, plan.idempotency_key, encoded, now.isoformat()),
                )
            return CriticClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                """
                SELECT * FROM critic_executions
                WHERE plan_id = ? OR idempotency_key = ?
                """,
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id or row["plan_json"] != encoded:
                raise CriticIdempotencyConflict(
                    "Critic idempotency key or plan id was reused for different content"
                ) from None
            if row["state"] == "started":
                raise CriticRecoveryRequired(
                    "Critic has an unfinished STARTED checkpoint; automatic replay is refused"
                ) from None
            return CriticClaim(
                created=False,
                outcome=CriticOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: CriticOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE critic_executions
                SET state = 'completed', completed_at = ?, outcome_json = ?
                WHERE plan_id = ? AND state = 'started'
                """,
                (outcome.completed_at.isoformat(), outcome.model_dump_json(), outcome.plan_id),
            ).rowcount
        if changed != 1:
            raise CriticRecoveryRequired("Critic STARTED checkpoint is unavailable")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> CriticStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
