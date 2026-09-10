"""Transactional STARTED/COMPLETED ledger for Attack Surface comparisons."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .drift_models import (
    AttackSurfaceDriftOutcome,
    AttackSurfaceDriftPlan,
    AttackSurfaceDriftState,
)


class AttackSurfaceDriftIdempotencyConflict(ValueError):
    pass


class AttackSurfaceDriftRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AttackSurfaceDriftClaim:
    created: bool
    attempt: int
    outcome: AttackSurfaceDriftOutcome | None = None


class AttackSurfaceDriftStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS red_team_surface_drift (
                comparison_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: AttackSurfaceDriftPlan, *, now: datetime) -> AttackSurfaceDriftClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_surface_drift VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.comparison_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return AttackSurfaceDriftClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] == AttackSurfaceDriftState.STARTED.value:
                raise AttackSurfaceDriftRecoveryRequired(
                    "Attack Surface drift has an unfinished STARTED checkpoint"
                ) from None
            outcome = AttackSurfaceDriftOutcome.model_validate_json(row["outcome_json"])
            return AttackSurfaceDriftClaim(
                created=False, attempt=row["attempt"], outcome=outcome
            )

    def recover(self, plan: AttackSurfaceDriftPlan, *, now: datetime) -> AttackSurfaceDriftClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] != AttackSurfaceDriftState.STARTED.value:
                raise AttackSurfaceDriftRecoveryRequired(
                    "Attack Surface drift is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise AttackSurfaceDriftRecoveryRequired(
                    "Attack Surface drift recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_surface_drift SET attempt=?,started_at=? "
                "WHERE comparison_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.comparison_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise AttackSurfaceDriftRecoveryRequired(
                    "Attack Surface drift recovery raced"
                )
        return AttackSurfaceDriftClaim(created=True, attempt=attempt)

    def complete(self, outcome: AttackSurfaceDriftOutcome, *, completed_at: datetime) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE red_team_surface_drift "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE comparison_id=? AND state='started' AND attempt=?",
                (
                    completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.comparison_id,
                    outcome.attempt,
                ),
            ).rowcount
        if changed != 1:
            raise AttackSurfaceDriftRecoveryRequired(
                "Attack Surface drift STARTED checkpoint is unavailable"
            )

    def state(self, comparison_id: str) -> tuple[AttackSurfaceDriftState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_surface_drift WHERE comparison_id=?",
            (comparison_id,),
        ).fetchone()
        return (
            (AttackSurfaceDriftState(row["state"]), row["attempt"])
            if row is not None
            else None
        )

    def outcome(self, comparison_id: str) -> AttackSurfaceDriftOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_surface_drift WHERE comparison_id=?",
            (comparison_id,),
        ).fetchone()
        if row is None or row["state"] != AttackSurfaceDriftState.COMPLETED.value:
            raise AttackSurfaceDriftRecoveryRequired(
                "completed Attack Surface drift is unavailable"
            )
        return AttackSurfaceDriftOutcome.model_validate_json(row["outcome_json"])

    def _by_identity(self, plan: AttackSurfaceDriftPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_surface_drift "
            "WHERE comparison_id=? OR idempotency_key=?",
            (plan.comparison_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise AttackSurfaceDriftRecoveryRequired(
                "Attack Surface drift checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same_plan(row: sqlite3.Row, plan: AttackSurfaceDriftPlan) -> None:
        if (
            row["comparison_id"] != plan.comparison_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise AttackSurfaceDriftIdempotencyConflict(
                "Attack Surface drift identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AttackSurfaceDriftStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
