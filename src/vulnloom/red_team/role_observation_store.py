"""Transactional ledger for role-differential observations."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .role_observation_models import (
    RoleDifferentialOutcome,
    RoleDifferentialPlan,
    RoleDifferentialState,
)


class RoleDifferentialStoreRejected(ValueError):
    pass


class RoleDifferentialRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RoleDifferentialClaim:
    created: bool
    attempt: int
    outcome: RoleDifferentialOutcome | None = None


class RoleDifferentialStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_role_differentials (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )"""
        )
        self.connection.commit()

    def claim(self, plan: RoleDifferentialPlan, *, now: datetime) -> RoleDifferentialClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_role_differentials VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return RoleDifferentialClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == RoleDifferentialState.STARTED.value:
                raise RoleDifferentialRecoveryRequired(
                    "Role Differential has unfinished STARTED checkpoint"
                ) from None
            return RoleDifferentialClaim(
                created=False,
                attempt=row["attempt"],
                outcome=RoleDifferentialOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: RoleDifferentialPlan, *, now: datetime) -> RoleDifferentialClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != RoleDifferentialState.STARTED.value:
                raise RoleDifferentialRecoveryRequired("Role Differential is not awaiting recovery")
            if row["attempt"] >= plan.limits.max_attempts:
                raise RoleDifferentialRecoveryRequired(
                    "Role Differential recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_role_differentials SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise RoleDifferentialRecoveryRequired("Role Differential recovery raced")
        return RoleDifferentialClaim(created=True, attempt=attempt)

    def complete(self, plan: RoleDifferentialPlan, outcome: RoleDifferentialOutcome) -> None:
        if outcome.plan_id != plan.plan_id:
            raise RoleDifferentialStoreRejected("Role Differential completion binding is invalid")
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != RoleDifferentialState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise RoleDifferentialRecoveryRequired(
                    "Role Differential STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_role_differentials "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    plan.plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise RoleDifferentialRecoveryRequired("Role Differential completion raced")

    def state(self, plan_id: str) -> tuple[RoleDifferentialState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_role_differentials WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return RoleDifferentialState(row["state"]), row["attempt"]

    def _row(self, plan: RoleDifferentialPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_role_differentials WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise RoleDifferentialRecoveryRequired("Role Differential checkpoint is unavailable")
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: RoleDifferentialPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise RoleDifferentialStoreRejected(
                "Role Differential identity was reused for different content"
            )
