"""Transactional checkpoints for Hybrid release gate evaluation."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .release_gate_models import (
    HybridReleaseGateOutcome,
    HybridReleaseGatePlan,
    HybridReleaseGateState,
)


class HybridReleaseGateConflict(ValueError):
    pass


class HybridReleaseGateRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HybridReleaseGateClaim:
    created: bool
    attempt: int
    outcome: HybridReleaseGateOutcome | None = None


class HybridReleaseGateStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS hybrid_release_gates (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                hybrid_chain_id TEXT NOT NULL,
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

    def claim(self, plan: HybridReleaseGatePlan, *, now: datetime) -> HybridReleaseGateClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO hybrid_release_gates VALUES "
                    "(?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.hybrid_chain_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return HybridReleaseGateClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] == HybridReleaseGateState.STARTED.value:
                raise HybridReleaseGateRecoveryRequired(
                    "Hybrid release gate has an unfinished STARTED checkpoint"
                ) from None
            return HybridReleaseGateClaim(
                created=False,
                attempt=row["attempt"],
                outcome=HybridReleaseGateOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(
        self, plan: HybridReleaseGatePlan, *, now: datetime
    ) -> HybridReleaseGateClaim:
        exhausted = False
        attempt = 0
        with self.connection:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] != HybridReleaseGateState.STARTED.value:
                raise HybridReleaseGateRecoveryRequired(
                    "Hybrid release gate is not awaiting recovery"
                )
            if row["attempt"] >= plan.policy.max_attempts:
                outcome = HybridReleaseGateOutcome(
                    plan_id=plan.plan_id,
                    state=HybridReleaseGateState.FAILED,
                    attempt=row["attempt"],
                    reason_code="recovery_attempts_exhausted",
                    cleanup_complete=True,
                    completed_at=now,
                )
                changed = self.connection.execute(
                    "UPDATE hybrid_release_gates SET state='failed',completed_at=?,"
                    "outcome_json=? WHERE plan_id=? AND state='started' AND attempt=?",
                    (
                        now.isoformat(),
                        outcome.model_dump_json(),
                        plan.plan_id,
                        row["attempt"],
                    ),
                ).rowcount
                if changed != 1:
                    raise HybridReleaseGateRecoveryRequired(
                        "Hybrid release gate recovery raced"
                    )
                exhausted = True
            else:
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE hybrid_release_gates SET attempt=?,started_at=? "
                    "WHERE plan_id=? AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise HybridReleaseGateRecoveryRequired(
                        "Hybrid release gate recovery raced"
                    )
        if exhausted:
            raise HybridReleaseGateRecoveryRequired(
                "Hybrid release gate recovery attempts are exhausted"
            )
        return HybridReleaseGateClaim(created=True, attempt=attempt)

    def finish(self, outcome: HybridReleaseGateOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE hybrid_release_gates SET state=?,completed_at=?,outcome_json=? "
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
            raise HybridReleaseGateRecoveryRequired(
                "Hybrid release gate STARTED checkpoint is unavailable"
            )

    def state(self, plan_id: str) -> tuple[HybridReleaseGateState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM hybrid_release_gates WHERE plan_id=?", (plan_id,)
        ).fetchone()
        return (HybridReleaseGateState(row["state"]), row["attempt"]) if row else None

    def outcome(self, plan_id: str) -> HybridReleaseGateOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM hybrid_release_gates WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None or row["state"] == HybridReleaseGateState.STARTED.value:
            raise HybridReleaseGateRecoveryRequired(
                "terminal Hybrid release gate outcome is unavailable"
            )
        return HybridReleaseGateOutcome.model_validate_json(row["outcome_json"])

    def _by_identity(self, plan: HybridReleaseGatePlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM hybrid_release_gates WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise HybridReleaseGateRecoveryRequired(
                "Hybrid release gate checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same_plan(row: sqlite3.Row, plan: HybridReleaseGatePlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise HybridReleaseGateConflict(
                "Hybrid release gate identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> HybridReleaseGateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
