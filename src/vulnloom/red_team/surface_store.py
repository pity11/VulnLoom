"""Transactional STARTED/COMPLETED ledger for Attack Surface reductions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .surface_models import (
    AttackSurfaceReductionOutcome,
    AttackSurfaceReductionPlan,
    AttackSurfaceReductionState,
)


class AttackSurfaceReductionIdempotencyConflict(ValueError):
    pass


class AttackSurfaceReductionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AttackSurfaceReductionClaim:
    created: bool
    attempt: int
    outcome: AttackSurfaceReductionOutcome | None = None


class AttackSurfaceReductionStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS red_team_surface_reductions (
                reduction_id TEXT PRIMARY KEY,
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

    def claim(
        self, plan: AttackSurfaceReductionPlan, *, now: datetime
    ) -> AttackSurfaceReductionClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_surface_reductions VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.reduction_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return AttackSurfaceReductionClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] == AttackSurfaceReductionState.STARTED.value:
                raise AttackSurfaceReductionRecoveryRequired(
                    "Attack Surface reduction has an unfinished STARTED checkpoint"
                ) from None
            outcome = AttackSurfaceReductionOutcome.model_validate_json(row["outcome_json"])
            return AttackSurfaceReductionClaim(
                created=False, attempt=row["attempt"], outcome=outcome
            )

    def recover(
        self, plan: AttackSurfaceReductionPlan, *, now: datetime
    ) -> AttackSurfaceReductionClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] != AttackSurfaceReductionState.STARTED.value:
                raise AttackSurfaceReductionRecoveryRequired(
                    "Attack Surface reduction is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise AttackSurfaceReductionRecoveryRequired(
                    "Attack Surface reduction recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_surface_reductions SET attempt=?,started_at=? "
                "WHERE reduction_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.reduction_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise AttackSurfaceReductionRecoveryRequired(
                    "Attack Surface reduction recovery raced"
                )
        return AttackSurfaceReductionClaim(created=True, attempt=attempt)

    def complete(
        self, outcome: AttackSurfaceReductionOutcome, *, completed_at: datetime
    ) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE red_team_surface_reductions "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE reduction_id=? AND state='started' AND attempt=?",
                (
                    completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.reduction_id,
                    outcome.attempt,
                ),
            ).rowcount
        if changed != 1:
            raise AttackSurfaceReductionRecoveryRequired(
                "Attack Surface reduction STARTED checkpoint is unavailable"
            )

    def state(self, reduction_id: str) -> tuple[AttackSurfaceReductionState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_surface_reductions WHERE reduction_id=?",
            (reduction_id,),
        ).fetchone()
        return (
            (AttackSurfaceReductionState(row["state"]), row["attempt"])
            if row is not None
            else None
        )

    def outcome(self, reduction_id: str) -> AttackSurfaceReductionOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_surface_reductions WHERE reduction_id=?",
            (reduction_id,),
        ).fetchone()
        if row is None or row["state"] != AttackSurfaceReductionState.COMPLETED.value:
            raise AttackSurfaceReductionRecoveryRequired(
                "completed Attack Surface reduction is unavailable"
            )
        return AttackSurfaceReductionOutcome.model_validate_json(row["outcome_json"])

    def _by_identity(self, plan: AttackSurfaceReductionPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_surface_reductions "
            "WHERE reduction_id=? OR idempotency_key=?",
            (plan.reduction_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise AttackSurfaceReductionRecoveryRequired(
                "Attack Surface reduction checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same_plan(row: sqlite3.Row, plan: AttackSurfaceReductionPlan) -> None:
        if (
            row["reduction_id"] != plan.reduction_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise AttackSurfaceReductionIdempotencyConflict(
                "Attack Surface reduction identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AttackSurfaceReductionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
