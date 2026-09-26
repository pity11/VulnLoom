"""Transactional B5.2 ledger for A3 runtime qualifications."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .adaptive_runtime_models import (
    AdaptiveRuntimeQualificationOutcome,
    AdaptiveRuntimeQualificationPlan,
)


class AdaptiveRuntimeQualificationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class AdaptiveRuntimeStoreRejected(ValueError):
    pass


class AdaptiveRuntimeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AdaptiveRuntimeClaim:
    created: bool
    attempt: int
    outcome: AdaptiveRuntimeQualificationOutcome | None = None


class AdaptiveRuntimeQualificationStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_adaptive_runtime_qualifications (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                adaptive_outcome_id TEXT NOT NULL UNIQUE,
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
        self, plan: AdaptiveRuntimeQualificationPlan, *, now: datetime
    ) -> AdaptiveRuntimeClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_adaptive_runtime_qualifications VALUES "
                    "(?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.adaptive_outcome_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return AdaptiveRuntimeClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == AdaptiveRuntimeQualificationState.STARTED.value:
                raise AdaptiveRuntimeRecoveryRequired(
                    "Adaptive Runtime Qualification has unfinished STARTED checkpoint"
                ) from None
            return AdaptiveRuntimeClaim(
                created=False,
                attempt=row["attempt"],
                outcome=AdaptiveRuntimeQualificationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: AdaptiveRuntimeQualificationPlan, *, now: datetime
    ) -> AdaptiveRuntimeClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != AdaptiveRuntimeQualificationState.STARTED.value:
                raise AdaptiveRuntimeRecoveryRequired(
                    "Adaptive Runtime Qualification is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise AdaptiveRuntimeRecoveryRequired(
                    "Adaptive Runtime Qualification recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_adaptive_runtime_qualifications "
                "SET attempt=?,started_at=? WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise AdaptiveRuntimeRecoveryRequired(
                    "Adaptive Runtime Qualification recovery raced"
                )
        return AdaptiveRuntimeClaim(created=True, attempt=attempt)

    def complete(
        self,
        plan: AdaptiveRuntimeQualificationPlan,
        outcome: AdaptiveRuntimeQualificationOutcome,
    ) -> None:
        if outcome.plan_id != plan.plan_id:
            raise AdaptiveRuntimeStoreRejected(
                "Adaptive Runtime Qualification completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != AdaptiveRuntimeQualificationState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise AdaptiveRuntimeRecoveryRequired(
                    "Adaptive Runtime Qualification STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_adaptive_runtime_qualifications "
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
                raise AdaptiveRuntimeRecoveryRequired(
                    "Adaptive Runtime Qualification completion raced"
                )

    def state(self, plan_id: str) -> tuple[AdaptiveRuntimeQualificationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_adaptive_runtime_qualifications WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return AdaptiveRuntimeQualificationState(row["state"]), row["attempt"]

    def _row(self, plan: AdaptiveRuntimeQualificationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_adaptive_runtime_qualifications "
            "WHERE plan_id=? OR idempotency_key=? OR adaptive_outcome_id=?",
            (plan.plan_id, plan.idempotency_key, plan.adaptive_outcome_id),
        ).fetchone()
        if row is None:
            raise AdaptiveRuntimeRecoveryRequired(
                "Adaptive Runtime Qualification checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: AdaptiveRuntimeQualificationPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise AdaptiveRuntimeStoreRejected(
                "Adaptive Runtime Qualification identity was reused for different content"
            )
