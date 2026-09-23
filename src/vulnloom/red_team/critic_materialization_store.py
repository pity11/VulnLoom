"""Transactional ledger for Critic Assertion materialization."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .critic_materialization_models import (
    CriticAssertionMaterializationOutcome,
    CriticAssertionMaterializationPlan,
    CriticAssertionMaterializationState,
)


class CriticAssertionMaterializationStoreRejected(ValueError):
    pass


class CriticAssertionMaterializationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CriticAssertionMaterializationClaim:
    created: bool
    attempt: int
    outcome: CriticAssertionMaterializationOutcome | None = None


class CriticAssertionMaterializationStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS red_team_critic_assertion_materializations (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(
        self, plan: CriticAssertionMaterializationPlan, *, now: datetime
    ) -> CriticAssertionMaterializationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_critic_assertion_materializations VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CriticAssertionMaterializationClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] == CriticAssertionMaterializationState.STARTED.value:
                raise CriticAssertionMaterializationRecoveryRequired(
                    "Critic Assertion materialization has an unfinished STARTED checkpoint"
                ) from None
            return CriticAssertionMaterializationClaim(
                created=False,
                attempt=row["attempt"],
                outcome=CriticAssertionMaterializationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: CriticAssertionMaterializationPlan, *, now: datetime
    ) -> CriticAssertionMaterializationClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] != CriticAssertionMaterializationState.STARTED.value:
                raise CriticAssertionMaterializationRecoveryRequired(
                    "Critic Assertion materialization is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise CriticAssertionMaterializationRecoveryRequired(
                    "Critic Assertion materialization recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_critic_assertion_materializations "
                "SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise CriticAssertionMaterializationRecoveryRequired(
                    "Critic Assertion materialization recovery raced"
                )
        return CriticAssertionMaterializationClaim(created=True, attempt=attempt)

    def complete(
        self,
        outcome: CriticAssertionMaterializationOutcome,
        *,
        completed_at: datetime,
    ) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE red_team_critic_assertion_materializations "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (
                    completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.plan_id,
                    outcome.attempt,
                ),
            ).rowcount
        if changed != 1:
            raise CriticAssertionMaterializationRecoveryRequired(
                "Critic Assertion materialization STARTED checkpoint is unavailable"
            )

    def state(
        self, plan_id: str
    ) -> tuple[CriticAssertionMaterializationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_critic_assertion_materializations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        return (
            (CriticAssertionMaterializationState(row["state"]), row["attempt"])
            if row is not None
            else None
        )

    def outcome(self, plan_id: str) -> CriticAssertionMaterializationOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_critic_assertion_materializations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] != CriticAssertionMaterializationState.COMPLETED.value
        ):
            raise CriticAssertionMaterializationRecoveryRequired(
                "completed Critic Assertion materialization is unavailable"
            )
        return CriticAssertionMaterializationOutcome.model_validate_json(
            row["outcome_json"]
        )

    def plan(self, plan_id: str) -> CriticAssertionMaterializationPlan:
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_critic_assertion_materializations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise CriticAssertionMaterializationRecoveryRequired(
                "Critic Assertion materialization plan is unavailable"
            )
        return CriticAssertionMaterializationPlan.model_validate_json(row["plan_json"])

    def _by_identity(self, plan: CriticAssertionMaterializationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_critic_assertion_materializations "
            "WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise CriticAssertionMaterializationRecoveryRequired(
                "Critic Assertion materialization checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CriticAssertionMaterializationPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise CriticAssertionMaterializationStoreRejected(
                "Critic Assertion materialization identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> CriticAssertionMaterializationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
