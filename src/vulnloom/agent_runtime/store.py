"""Transactional checkpoints for Agent Runtime executions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import AgentRunOutcome, AgentRunPlan


class AgentRunIdempotencyConflict(ValueError):
    pass


class AgentRunRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentRunClaim:
    created: bool
    outcome: AgentRunOutcome | None = None


class AgentRunStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_runs (
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

    def claim(self, plan: AgentRunPlan, *, now: datetime) -> AgentRunClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO agent_runs "
                    "(plan_id, idempotency_key, state, started_at) VALUES (?, ?, 'started', ?)",
                    (plan.plan_id, plan.idempotency_key, now.isoformat()),
                )
            return AgentRunClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM agent_runs WHERE plan_id = ? OR idempotency_key = ?",
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id:
                raise AgentRunIdempotencyConflict(
                    "Agent run idempotency key was reused for different content"
                ) from None
            if row["state"] == "started":
                raise AgentRunRecoveryRequired(
                    "Agent run has an unfinished STARTED checkpoint"
                ) from None
            return AgentRunClaim(
                created=False,
                outcome=AgentRunOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: AgentRunOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_runs SET state = 'completed', completed_at = ?, outcome_json = ? "
                "WHERE plan_id = ? AND state = 'started'",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentRunRecoveryRequired("Agent run STARTED checkpoint is unavailable")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentRunStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
