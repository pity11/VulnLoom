"""Transactional Hybrid validation checkpoints."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import HybridRunState, HybridValidationOutcome, HybridValidationPlan


class HybridIdempotencyConflict(ValueError):
    pass


class HybridRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HybridClaim:
    created: bool
    attempt: int
    outcome: HybridValidationOutcome | None = None


class HybridValidationStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS hybrid_validations (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN
                    ('started','completed','timed_out','failed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: HybridValidationPlan, *, now: datetime) -> HybridClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO hybrid_validations VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (plan.plan_id, plan.idempotency_key, plan.model_dump_json(), now.isoformat()),
                )
            return HybridClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] == HybridRunState.STARTED.value:
                raise HybridRecoveryRequired(
                    "Hybrid validation has an unfinished STARTED checkpoint"
                ) from None
            return HybridClaim(
                created=False,
                attempt=row["attempt"],
                outcome=HybridValidationOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: HybridValidationPlan, *, now: datetime) -> HybridClaim:
        exhausted = False
        attempt = 0
        with self.connection:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] != HybridRunState.STARTED.value:
                raise HybridRecoveryRequired("Hybrid validation is not awaiting recovery")
            if row["attempt"] >= plan.limits.max_attempts:
                outcome = HybridValidationOutcome(
                    plan_id=plan.plan_id,
                    state=HybridRunState.FAILED,
                    attempt=row["attempt"],
                    reason_code="recovery_attempts_exhausted",
                    cleanup_complete=True,
                    completed_at=now,
                )
                self.connection.execute(
                    "UPDATE hybrid_validations SET state='failed',completed_at=?,outcome_json=? "
                    "WHERE plan_id=? AND state='started' AND attempt=?",
                    (
                        now.isoformat(),
                        outcome.model_dump_json(),
                        plan.plan_id,
                        row["attempt"],
                    ),
                )
                exhausted = True
            else:
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE hybrid_validations SET attempt=?,started_at=? "
                    "WHERE plan_id=? AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise HybridRecoveryRequired("Hybrid validation recovery raced")
        if exhausted:
            raise HybridRecoveryRequired("Hybrid validation recovery attempts are exhausted")
        return HybridClaim(created=True, attempt=attempt)

    def finish(self, outcome: HybridValidationOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE hybrid_validations SET state=?,completed_at=?,outcome_json=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.state.value,
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.plan_id,
                    outcome.attempt,
                ),
            ).rowcount
        if changed != 1:
            raise HybridRecoveryRequired("Hybrid STARTED checkpoint is unavailable")

    def state(self, plan_id: str) -> tuple[HybridRunState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM hybrid_validations WHERE plan_id=?", (plan_id,)
        ).fetchone()
        return (HybridRunState(row["state"]), row["attempt"]) if row else None

    def outcome(self, plan_id: str) -> HybridValidationOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM hybrid_validations WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None or row["state"] == HybridRunState.STARTED.value:
            raise HybridRecoveryRequired("terminal Hybrid outcome is unavailable")
        return HybridValidationOutcome.model_validate_json(row["outcome_json"])

    def _by_identity(self, plan: HybridValidationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM hybrid_validations WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise HybridRecoveryRequired("Hybrid checkpoint is unavailable")
        return row

    @staticmethod
    def _same_plan(row: sqlite3.Row, plan: HybridValidationPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise HybridIdempotencyConflict(
                "Hybrid identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> HybridValidationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
