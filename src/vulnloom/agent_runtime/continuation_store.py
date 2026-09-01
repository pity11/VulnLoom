"""Transactional checkpoints for one-shot Agent continuations."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .continuation_models import AgentContinuationOutcome, AgentContinuationPlan


class AgentContinuationIdempotencyConflict(ValueError):
    pass


class AgentContinuationObservationConflict(ValueError):
    pass


class AgentContinuationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentContinuationClaim:
    created: bool
    outcome: AgentContinuationOutcome | None = None


class AgentContinuationStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_continuations (
                continuation_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                observation_id TEXT NOT NULL UNIQUE,
                root_plan_id TEXT NOT NULL,
                continuation_plan_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                status TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(
        self, plan: AgentContinuationPlan, *, now: datetime
    ) -> AgentContinuationClaim:
        existing = self.connection.execute(
            "SELECT * FROM agent_continuations "
            "WHERE continuation_id = ? OR idempotency_key = ? OR observation_id = ?",
            (plan.continuation_id, plan.idempotency_key, plan.observation_id),
        ).fetchone()
        if existing is not None:
            if existing["continuation_id"] == plan.continuation_id:
                if existing["state"] == "started":
                    raise AgentContinuationRecoveryRequired(
                        "Agent continuation has an unfinished STARTED checkpoint"
                    )
                if existing["outcome_json"] is None:
                    raise AgentContinuationRecoveryRequired(
                        "Agent continuation completed checkpoint has no outcome"
                    )
                outcome = AgentContinuationOutcome.model_validate_json(
                    existing["outcome_json"]
                )
                if (
                    outcome.continuation_id != plan.continuation_id
                    or outcome.root_plan_id != plan.root_plan.plan_id
                    or outcome.observation_id != plan.observation_id
                    or outcome.continuation_plan_id != plan.continuation_plan.plan_id
                ):
                    raise AgentContinuationRecoveryRequired(
                        "Agent continuation completed checkpoint binding mismatch"
                    )
                return AgentContinuationClaim(
                    created=False,
                    outcome=outcome,
                )
            if existing["idempotency_key"] == plan.idempotency_key:
                raise AgentContinuationIdempotencyConflict(
                    "Agent continuation idempotency key was reused for different content"
                )
            raise AgentContinuationObservationConflict(
                "Agent tool Observation already has a continuation"
            )
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO agent_continuations "
                    "(continuation_id, idempotency_key, observation_id, root_plan_id, "
                    "continuation_plan_id, state, started_at) "
                    "VALUES (?, ?, ?, ?, ?, 'started', ?)",
                    (
                        plan.continuation_id,
                        plan.idempotency_key,
                        plan.observation_id,
                        plan.root_plan.plan_id,
                        plan.continuation_plan.plan_id,
                        now.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AgentContinuationObservationConflict(
                "Agent continuation checkpoint conflicted concurrently"
            ) from exc
        return AgentContinuationClaim(created=True)

    def complete(self, outcome: AgentContinuationOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_continuations SET state = 'completed', status = ?, "
                "completed_at = ?, outcome_json = ? "
                "WHERE continuation_id = ? AND observation_id = ? "
                "AND root_plan_id = ? AND continuation_plan_id = ? AND state = 'started'",
                (
                    outcome.status.value,
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.continuation_id,
                    outcome.observation_id,
                    outcome.root_plan_id,
                    outcome.continuation_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentContinuationRecoveryRequired(
                "Agent continuation STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentContinuationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
