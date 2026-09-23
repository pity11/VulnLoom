"""Transactional ledger for isolated credential-session runs."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .credential_session_models import (
    CredentialSessionOutcome,
    CredentialSessionPlan,
    CredentialSessionState,
)


class CredentialSessionStoreRejected(ValueError):
    pass


class CredentialSessionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CredentialSessionClaim:
    created: bool
    attempt: int
    outcome: CredentialSessionOutcome | None = None


class CredentialSessionStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_credential_sessions (
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
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "red_team_credential_sessions_one_admission "
            "ON red_team_credential_sessions "
            "(json_extract(plan_json,'$.admission_id'))"
        )
        self.connection.commit()

    def claim(self, plan: CredentialSessionPlan, *, now: datetime) -> CredentialSessionClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_credential_sessions VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (plan.plan_id, plan.idempotency_key, plan.model_dump_json(), now.isoformat()),
                )
            return CredentialSessionClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == CredentialSessionState.STARTED.value:
                raise CredentialSessionRecoveryRequired(
                    "Credential Session has unfinished STARTED checkpoint"
                ) from None
            return CredentialSessionClaim(
                created=False,
                attempt=row["attempt"],
                outcome=CredentialSessionOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: CredentialSessionPlan, *, now: datetime) -> CredentialSessionClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != CredentialSessionState.STARTED.value:
                raise CredentialSessionRecoveryRequired(
                    "Credential Session is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise CredentialSessionRecoveryRequired(
                    "Credential Session recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_credential_sessions SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise CredentialSessionRecoveryRequired("Credential Session recovery raced")
        return CredentialSessionClaim(created=True, attempt=attempt)

    def complete(self, plan: CredentialSessionPlan, outcome: CredentialSessionOutcome) -> None:
        if outcome.plan_id != plan.plan_id:
            raise CredentialSessionStoreRejected("Credential Session completion binding is invalid")
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != CredentialSessionState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise CredentialSessionRecoveryRequired(
                    "Credential Session STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_credential_sessions "
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
                raise CredentialSessionRecoveryRequired("Credential Session completion raced")

    def state(self, plan_id: str) -> tuple[CredentialSessionState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_credential_sessions WHERE plan_id=?", (plan_id,)
        ).fetchone()
        return None if row is None else (CredentialSessionState(row["state"]), row["attempt"])

    def _row(self, plan: CredentialSessionPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_credential_sessions "
            "WHERE plan_id=? OR idempotency_key=? "
            "OR json_extract(plan_json,'$.admission_id')=?",
            (plan.plan_id, plan.idempotency_key, plan.admission_id),
        ).fetchone()
        if row is None:
            raise CredentialSessionRecoveryRequired("Credential Session checkpoint is unavailable")
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CredentialSessionPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise CredentialSessionStoreRejected(
                "Credential Session identity was reused for different content"
            )

    def plan(self, plan_id: str) -> CredentialSessionPlan:
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_credential_sessions WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise CredentialSessionStoreRejected("Credential Session Plan is unavailable")
        return CredentialSessionPlan.model_validate_json(row["plan_json"])

    def outcome(self, plan_id: str) -> CredentialSessionOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_credential_sessions WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] != CredentialSessionState.COMPLETED.value:
            raise CredentialSessionStoreRejected("completed Credential Session is unavailable")
        return CredentialSessionOutcome.model_validate_json(row["outcome_json"])
