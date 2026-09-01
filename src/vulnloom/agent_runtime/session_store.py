"""Transactional checkpoints for fixed two-tool Agent sessions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .session_models import AgentSessionOutcome, AgentSessionPlan


class AgentSessionIdempotencyConflict(ValueError):
    pass


class AgentSessionObservationConflict(ValueError):
    pass


class AgentSessionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentSessionClaim:
    created: bool
    outcome: AgentSessionOutcome | None = None


class AgentSessionStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_sessions (
                session_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                root_plan_id TEXT NOT NULL,
                first_observation_id TEXT NOT NULL UNIQUE,
                round_plan_id TEXT NOT NULL UNIQUE,
                authorized_call_set_id TEXT NOT NULL,
                second_observation_id TEXT UNIQUE,
                selected_call_commitment TEXT,
                state TEXT NOT NULL CHECK(
                    state IN ('started', 'waiting_approval', 'resuming', 'completed')
                ),
                status TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: AgentSessionPlan, *, now: datetime) -> AgentSessionClaim:
        existing = self.connection.execute(
            "SELECT * FROM agent_sessions WHERE session_id = ? "
            "OR idempotency_key = ? OR first_observation_id = ?",
            (plan.session_id, plan.idempotency_key, plan.first_observation_id),
        ).fetchone()
        if existing is not None:
            if existing["session_id"] == plan.session_id:
                if existing["state"] in {"started", "resuming"}:
                    raise AgentSessionRecoveryRequired(
                        "Agent session has an unfinished STARTED checkpoint"
                    )
                if existing["outcome_json"] is None:
                    raise AgentSessionRecoveryRequired(
                        "Agent session completed checkpoint has no outcome"
                    )
                outcome = AgentSessionOutcome.model_validate_json(
                    existing["outcome_json"]
                )
                if (
                    outcome.session_id != plan.session_id
                    or outcome.root_plan_id != plan.root_plan.plan_id
                    or outcome.first_observation_id != plan.first_observation_id
                    or outcome.round_plan_id != plan.round_plan.plan_id
                    or outcome.authorized_call_set_id
                    != plan.authorized_calls.call_set_id
                    or outcome.authorized_call_set_id
                    != existing["authorized_call_set_id"]
                    or outcome.status.value != existing["status"]
                    or outcome.selected_call_commitment
                    != existing["selected_call_commitment"]
                ):
                    raise AgentSessionRecoveryRequired(
                        "Agent session completed checkpoint binding mismatch"
                    )
                return AgentSessionClaim(created=False, outcome=outcome)
            if existing["idempotency_key"] == plan.idempotency_key:
                raise AgentSessionIdempotencyConflict(
                    "Agent session idempotency key was reused for different content"
                )
            raise AgentSessionObservationConflict(
                "Agent tool Observation already belongs to a session"
            )
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO agent_sessions "
                    "(session_id, idempotency_key, root_plan_id, first_observation_id, "
                    "round_plan_id, authorized_call_set_id, state, started_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'started', ?)",
                    (
                        plan.session_id,
                        plan.idempotency_key,
                        plan.root_plan.plan_id,
                        plan.first_observation_id,
                        plan.round_plan.plan_id,
                        plan.authorized_calls.call_set_id,
                        now.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AgentSessionObservationConflict(
                "Agent session checkpoint conflicted concurrently"
            ) from exc
        return AgentSessionClaim(created=True)

    def claim_resume(
        self,
        plan: AgentSessionPlan,
        waiting_outcome: AgentSessionOutcome,
        *,
        now: datetime,
    ) -> AgentSessionClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_sessions WHERE session_id = ?",
            (plan.session_id,),
        ).fetchone()
        if row is None or row["outcome_json"] is None:
            raise AgentSessionRecoveryRequired(
                "Agent session Approval wait checkpoint is unavailable"
            )
        stored = AgentSessionOutcome.model_validate_json(row["outcome_json"])
        if row["state"] == "completed":
            return AgentSessionClaim(created=False, outcome=stored)
        if row["state"] != "waiting_approval":
            raise AgentSessionRecoveryRequired(
                "Agent session Approval resume has an unfinished checkpoint"
            )
        if (
            stored != waiting_outcome
            or stored.session_id != plan.session_id
            or stored.status.value != "approval_required"
            or stored.authorized_call_set_id != plan.authorized_calls.call_set_id
            or stored.second_handoff_outcome is None
            or stored.second_handoff_outcome.status.value != "approval_required"
        ):
            raise AgentSessionRecoveryRequired(
                "Agent session Approval wait binding mismatch"
            )
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_sessions SET state = 'resuming', started_at = ? "
                "WHERE session_id = ? AND state = 'waiting_approval'",
                (now.isoformat(), plan.session_id),
            ).rowcount
        if changed != 1:
            raise AgentSessionRecoveryRequired(
                "Agent session Approval wait was resumed concurrently"
            )
        return AgentSessionClaim(created=True)

    def pause_for_approval(self, outcome: AgentSessionOutcome) -> None:
        if outcome.status.value != "approval_required":
            raise AgentSessionRecoveryRequired(
                "Agent session pause requires an Approval outcome"
            )
        self._write_outcome(
            outcome, from_states=("started",), target_state="waiting_approval"
        )

    def complete(self, outcome: AgentSessionOutcome) -> None:
        self._write_outcome(
            outcome, from_states=("started", "resuming"), target_state="completed"
        )

    def _write_outcome(
        self,
        outcome: AgentSessionOutcome,
        *,
        from_states: tuple[str, ...],
        target_state: str,
    ) -> None:
        second_observation_id = None
        if (
            outcome.second_handoff_outcome is not None
            and outcome.second_handoff_outcome.observation is not None
        ):
            second_observation_id = (
                outcome.second_handoff_outcome.observation.observation_id
            )
        try:
            with self.connection:
                placeholders = ",".join("?" for _ in from_states)
                changed = self.connection.execute(
                    f"UPDATE agent_sessions SET state = ?, status = ?, "
                    "second_observation_id = ?, selected_call_commitment = ?, "
                    "completed_at = ?, outcome_json = ? "
                    "WHERE session_id = ? AND first_observation_id = ? "
                    "AND round_plan_id = ? AND authorized_call_set_id = ? "
                    f"AND state IN ({placeholders})",
                    (
                        target_state,
                        outcome.status.value,
                        second_observation_id,
                        outcome.selected_call_commitment,
                        outcome.completed_at.isoformat(),
                        outcome.model_dump_json(),
                        outcome.session_id,
                        outcome.first_observation_id,
                        outcome.round_plan_id,
                        outcome.authorized_call_set_id,
                        *from_states,
                    ),
                ).rowcount
        except sqlite3.IntegrityError as exc:
            raise AgentSessionObservationConflict(
                "Agent session reused a tool Observation"
            ) from exc
        if changed != 1:
            raise AgentSessionRecoveryRequired(
                "Agent session STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentSessionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
