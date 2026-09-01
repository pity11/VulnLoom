"""Transactional checkpoints for Agent-to-Broker tool handoffs."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .tool_handoff_models import (
    AgentToolHandoffOutcome,
    AgentToolHandoffPlan,
    AgentToolHandoffStatus,
)


class AgentToolHandoffIdempotencyConflict(ValueError):
    pass


class AgentToolHandoffRecoveryRequired(RuntimeError):
    pass


class AgentToolHandoffRetryRejected(ValueError):
    pass


@dataclass(frozen=True)
class AgentToolHandoffClaim:
    created: bool
    outcome: AgentToolHandoffOutcome | None = None


class AgentToolHandoffStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_tool_handoffs (
                handoff_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                agent_outcome_digest TEXT NOT NULL,
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 2),
                previous_handoff_id TEXT,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                status TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: AgentToolHandoffPlan, *, now: datetime) -> AgentToolHandoffClaim:
        with self.connection:
            existing = self.connection.execute(
                "SELECT * FROM agent_tool_handoffs "
                "WHERE handoff_id = ? OR idempotency_key = ?",
                (plan.handoff_id, plan.idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["handoff_id"] != plan.handoff_id:
                    raise AgentToolHandoffIdempotencyConflict(
                        "Agent handoff idempotency key was reused for different content"
                    )
                if existing["state"] == "started":
                    raise AgentToolHandoffRecoveryRequired(
                        "Agent handoff has an unfinished STARTED checkpoint"
                    )
                return AgentToolHandoffClaim(
                    created=False,
                    outcome=AgentToolHandoffOutcome.model_validate_json(
                        existing["outcome_json"]
                    ),
                )
            prior = self.connection.execute(
                "SELECT * FROM agent_tool_handoffs WHERE agent_outcome_digest = ? "
                "ORDER BY attempt",
                (plan.agent_outcome_digest,),
            ).fetchall()
            if plan.attempt == 1:
                if prior:
                    raise AgentToolHandoffRetryRejected(
                        "Agent tool intent already has a handoff attempt"
                    )
            elif (
                len(prior) != 1
                or prior[0]["state"] != "completed"
                or prior[0]["status"] != AgentToolHandoffStatus.APPROVAL_REQUIRED.value
                or prior[0]["attempt"] != 1
                or prior[0]["handoff_id"] != plan.previous_handoff_id
            ):
                raise AgentToolHandoffRetryRejected(
                    "Agent handoff retry is not bound to one approval-required attempt"
                )
            self.connection.execute(
                "INSERT INTO agent_tool_handoffs "
                "(handoff_id, idempotency_key, agent_outcome_digest, attempt, "
                "previous_handoff_id, state, started_at) "
                "VALUES (?, ?, ?, ?, ?, 'started', ?)",
                (
                    plan.handoff_id,
                    plan.idempotency_key,
                    plan.agent_outcome_digest,
                    plan.attempt,
                    plan.previous_handoff_id,
                    now.isoformat(),
                ),
            )
        return AgentToolHandoffClaim(created=True)

    def complete(self, outcome: AgentToolHandoffOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_tool_handoffs SET state = 'completed', status = ?, "
                "completed_at = ?, outcome_json = ? "
                "WHERE handoff_id = ? AND agent_outcome_digest = ? "
                "AND attempt = ? AND state = 'started'",
                (
                    outcome.status.value,
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.handoff_id,
                    outcome.agent_outcome_digest,
                    outcome.attempt,
                ),
            ).rowcount
        if changed != 1:
            raise AgentToolHandoffRecoveryRequired(
                "Agent handoff STARTED checkpoint is unavailable"
            )

    def require_completed(self, handoff_id: str) -> AgentToolHandoffOutcome:
        row = self.connection.execute(
            "SELECT * FROM agent_tool_handoffs WHERE handoff_id = ?", (handoff_id,)
        ).fetchone()
        if row is None or row["state"] != "completed" or row["outcome_json"] is None:
            raise AgentToolHandoffRecoveryRequired(
                "Agent handoff does not have an authoritative completed checkpoint"
            )
        outcome = AgentToolHandoffOutcome.model_validate_json(row["outcome_json"])
        if (
            outcome.handoff_id != handoff_id
            or outcome.agent_outcome_digest != row["agent_outcome_digest"]
            or outcome.attempt != row["attempt"]
            or outcome.status.value != row["status"]
        ):
            raise AgentToolHandoffRecoveryRequired(
                "Agent handoff checkpoint binding mismatch"
            )
        return outcome

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentToolHandoffStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
