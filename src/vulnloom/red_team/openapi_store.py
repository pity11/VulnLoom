"""Transactional STARTED/COMPLETED ledger for OpenAPI observations."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .openapi_models import (
    OpenApiDocumentObservationOutcome,
    OpenApiDocumentObservationPlan,
    OpenApiObservationState,
)


class OpenApiObservationStoreRejected(ValueError):
    pass


class OpenApiObservationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class OpenApiObservationClaim:
    created: bool
    attempt: int
    outcome: OpenApiDocumentObservationOutcome | None = None


class OpenApiObservationStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS red_team_openapi_observations (
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
        self, plan: OpenApiDocumentObservationPlan, *, now: datetime
    ) -> OpenApiObservationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_openapi_observations VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return OpenApiObservationClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] == OpenApiObservationState.STARTED.value:
                raise OpenApiObservationRecoveryRequired(
                    "OpenAPI observation has an unfinished STARTED checkpoint"
                ) from None
            return OpenApiObservationClaim(
                created=False,
                attempt=row["attempt"],
                outcome=OpenApiDocumentObservationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: OpenApiDocumentObservationPlan, *, now: datetime
    ) -> OpenApiObservationClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] != OpenApiObservationState.STARTED.value:
                raise OpenApiObservationRecoveryRequired(
                    "OpenAPI observation is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise OpenApiObservationRecoveryRequired(
                    "OpenAPI observation recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_openapi_observations SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise OpenApiObservationRecoveryRequired(
                    "OpenAPI observation recovery raced"
                )
        return OpenApiObservationClaim(created=True, attempt=attempt)

    def complete(
        self, outcome: OpenApiDocumentObservationOutcome, *, completed_at: datetime
    ) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE red_team_openapi_observations "
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
            raise OpenApiObservationRecoveryRequired(
                "OpenAPI observation STARTED checkpoint is unavailable"
            )

    def state(self, plan_id: str) -> tuple[OpenApiObservationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_openapi_observations WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        return (
            (OpenApiObservationState(row["state"]), row["attempt"])
            if row is not None
            else None
        )

    def outcome(self, plan_id: str) -> OpenApiDocumentObservationOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_openapi_observations WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] != OpenApiObservationState.COMPLETED.value:
            raise OpenApiObservationRecoveryRequired(
                "completed OpenAPI observation is unavailable"
            )
        return OpenApiDocumentObservationOutcome.model_validate_json(row["outcome_json"])

    def _by_identity(self, plan: OpenApiDocumentObservationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_openapi_observations "
            "WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise OpenApiObservationRecoveryRequired(
                "OpenAPI observation checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: OpenApiDocumentObservationPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise OpenApiObservationStoreRejected(
                "OpenAPI observation identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> OpenApiObservationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
