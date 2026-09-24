"""Transactional ledger for materialized local business invariants."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .business_flow_models import (
    BusinessInvariantOutcome,
    BusinessInvariantPlan,
    BusinessInvariantState,
)


class BusinessInvariantStoreRejected(ValueError):
    pass


class BusinessInvariantRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BusinessInvariantClaim:
    created: bool
    attempt: int
    outcome: BusinessInvariantOutcome | None = None


class BusinessInvariantStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_business_invariants (
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

    def claim(self, plan: BusinessInvariantPlan, *, now: datetime) -> BusinessInvariantClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_business_invariants VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (plan.plan_id, plan.idempotency_key, plan.model_dump_json(), now.isoformat()),
                )
            return BusinessInvariantClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == BusinessInvariantState.STARTED.value:
                raise BusinessInvariantRecoveryRequired(
                    "Business Invariant has unfinished STARTED checkpoint"
                ) from None
            return BusinessInvariantClaim(
                created=False,
                attempt=row["attempt"],
                outcome=BusinessInvariantOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: BusinessInvariantPlan, *, now: datetime) -> BusinessInvariantClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != BusinessInvariantState.STARTED.value:
                raise BusinessInvariantRecoveryRequired(
                    "Business Invariant is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise BusinessInvariantRecoveryRequired(
                    "Business Invariant recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_business_invariants SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise BusinessInvariantRecoveryRequired("Business Invariant recovery raced")
        return BusinessInvariantClaim(created=True, attempt=attempt)

    def complete(self, plan: BusinessInvariantPlan, outcome: BusinessInvariantOutcome) -> None:
        if outcome.plan_id != plan.plan_id:
            raise BusinessInvariantStoreRejected("Business Invariant completion binding is invalid")
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != BusinessInvariantState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise BusinessInvariantRecoveryRequired(
                    "Business Invariant STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_business_invariants "
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
                raise BusinessInvariantRecoveryRequired("Business Invariant completion raced")

    def state(self, plan_id: str) -> tuple[BusinessInvariantState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_business_invariants WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return BusinessInvariantState(row["state"]), row["attempt"]

    def _row(self, plan: BusinessInvariantPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_business_invariants WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise BusinessInvariantRecoveryRequired(
                "Business Invariant checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: BusinessInvariantPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise BusinessInvariantStoreRejected(
                "Business Invariant identity was reused for different content"
            )
