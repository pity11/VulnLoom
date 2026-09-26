"""Transactional ledger for B5.1 Adaptive Flow qualifications."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .adaptive_qualification_models import (
    AdaptiveFlowQualificationOutcome,
    AdaptiveFlowQualificationPlan,
    AdaptiveQualificationState,
)


class AdaptiveQualificationStoreRejected(ValueError):
    pass


class AdaptiveQualificationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AdaptiveQualificationClaim:
    created: bool
    attempt: int
    outcome: AdaptiveFlowQualificationOutcome | None = None


class AdaptiveQualificationStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_adaptive_qualifications (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                flow_plan_id TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )"""
        )
        self.connection.commit()

    def claim(
        self, plan: AdaptiveFlowQualificationPlan, *, now: datetime
    ) -> AdaptiveQualificationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_adaptive_qualifications VALUES "
                    "(?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.flow_plan_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return AdaptiveQualificationClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == AdaptiveQualificationState.STARTED.value:
                raise AdaptiveQualificationRecoveryRequired(
                    "Adaptive Flow Qualification has unfinished STARTED checkpoint"
                ) from None
            return AdaptiveQualificationClaim(
                created=False,
                attempt=row["attempt"],
                outcome=AdaptiveFlowQualificationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: AdaptiveFlowQualificationPlan, *, now: datetime
    ) -> AdaptiveQualificationClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != AdaptiveQualificationState.STARTED.value:
                raise AdaptiveQualificationRecoveryRequired(
                    "Adaptive Flow Qualification is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise AdaptiveQualificationRecoveryRequired(
                    "Adaptive Flow Qualification recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_adaptive_qualifications SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise AdaptiveQualificationRecoveryRequired(
                    "Adaptive Flow Qualification recovery raced"
                )
        return AdaptiveQualificationClaim(created=True, attempt=attempt)

    def complete(
        self,
        plan: AdaptiveFlowQualificationPlan,
        outcome: AdaptiveFlowQualificationOutcome,
    ) -> None:
        if outcome.plan_id != plan.plan_id:
            raise AdaptiveQualificationStoreRejected(
                "Adaptive Flow Qualification completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != AdaptiveQualificationState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise AdaptiveQualificationRecoveryRequired(
                    "Adaptive Flow Qualification STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_adaptive_qualifications "
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
                raise AdaptiveQualificationRecoveryRequired(
                    "Adaptive Flow Qualification completion raced"
                )

    def state(self, plan_id: str) -> tuple[AdaptiveQualificationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_adaptive_qualifications WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return AdaptiveQualificationState(row["state"]), row["attempt"]

    def _row(self, plan: AdaptiveFlowQualificationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_adaptive_qualifications "
            "WHERE plan_id=? OR idempotency_key=? OR flow_plan_id=?",
            (plan.plan_id, plan.idempotency_key, plan.flow_plan_id),
        ).fetchone()
        if row is None:
            raise AdaptiveQualificationRecoveryRequired(
                "Adaptive Flow Qualification checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: AdaptiveFlowQualificationPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise AdaptiveQualificationStoreRejected(
                "Adaptive Flow Qualification identity was reused for different content"
            )
