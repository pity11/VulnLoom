"""Transactional ledger for independent Evidence replay validation."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .replay_validation_models import (
    EvidenceReplayValidationOutcome,
    EvidenceReplayValidationPlan,
    EvidenceReplayValidationState,
)


class EvidenceReplayValidationStoreRejected(ValueError):
    pass


class EvidenceReplayValidationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceReplayValidationClaim:
    created: bool
    attempt: int
    outcome: EvidenceReplayValidationOutcome | None = None


class EvidenceReplayValidationStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS red_team_evidence_replay_validations (
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
        self, plan: EvidenceReplayValidationPlan, *, now: datetime
    ) -> EvidenceReplayValidationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_evidence_replay_validations VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return EvidenceReplayValidationClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] == EvidenceReplayValidationState.STARTED.value:
                raise EvidenceReplayValidationRecoveryRequired(
                    "Evidence replay validation has an unfinished STARTED checkpoint"
                ) from None
            return EvidenceReplayValidationClaim(
                created=False,
                attempt=row["attempt"],
                outcome=EvidenceReplayValidationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: EvidenceReplayValidationPlan, *, now: datetime
    ) -> EvidenceReplayValidationClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] != EvidenceReplayValidationState.STARTED.value:
                raise EvidenceReplayValidationRecoveryRequired(
                    "Evidence replay validation is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise EvidenceReplayValidationRecoveryRequired(
                    "Evidence replay validation recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_evidence_replay_validations "
                "SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise EvidenceReplayValidationRecoveryRequired(
                    "Evidence replay validation recovery raced"
                )
        return EvidenceReplayValidationClaim(created=True, attempt=attempt)

    def complete(
        self,
        outcome: EvidenceReplayValidationOutcome,
        *,
        completed_at: datetime,
    ) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE red_team_evidence_replay_validations "
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
            raise EvidenceReplayValidationRecoveryRequired(
                "Evidence replay validation STARTED checkpoint is unavailable"
            )

    def state(self, plan_id: str) -> tuple[EvidenceReplayValidationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_evidence_replay_validations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        return (
            (EvidenceReplayValidationState(row["state"]), row["attempt"])
            if row is not None
            else None
        )

    def outcome(self, plan_id: str) -> EvidenceReplayValidationOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_evidence_replay_validations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] != EvidenceReplayValidationState.COMPLETED.value:
            raise EvidenceReplayValidationRecoveryRequired(
                "completed Evidence replay validation is unavailable"
            )
        return EvidenceReplayValidationOutcome.model_validate_json(row["outcome_json"])

    def plan(self, plan_id: str) -> EvidenceReplayValidationPlan:
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_evidence_replay_validations WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise EvidenceReplayValidationRecoveryRequired(
                "Evidence replay validation plan is unavailable"
            )
        return EvidenceReplayValidationPlan.model_validate_json(row["plan_json"])

    def _by_identity(self, plan: EvidenceReplayValidationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_evidence_replay_validations "
            "WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise EvidenceReplayValidationRecoveryRequired(
                "Evidence replay validation checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: EvidenceReplayValidationPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise EvidenceReplayValidationStoreRejected(
                "Evidence replay validation identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> EvidenceReplayValidationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
