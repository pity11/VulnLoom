"""Transactional and crash-safe idempotency checkpoints for validation runs."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import ValidationOutcome, ValidationPlan


class ValidationIdempotencyConflict(ValueError):
    """An idempotency key or plan id was reused for different content."""


class ValidationRecoveryRequired(RuntimeError):
    """A previous execution stopped after STARTED and requires explicit recovery."""


@dataclass(frozen=True)
class ValidationClaim:
    created: bool
    outcome: ValidationOutcome | None = None


class ValidationStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS validation_executions (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: ValidationPlan, *, now: datetime) -> ValidationClaim:
        plan_json = plan.model_dump_json()
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO validation_executions (
                        plan_id, idempotency_key, plan_json, state, started_at
                    ) VALUES (?, ?, ?, 'started', ?)
                    """,
                    (plan.plan_id, plan.idempotency_key, plan_json, now.isoformat()),
                )
            return ValidationClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                """
                SELECT * FROM validation_executions
                WHERE plan_id = ? OR idempotency_key = ?
                """,
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id or row["plan_json"] != plan_json:
                raise ValidationIdempotencyConflict(
                    "validation idempotency key or plan id was reused for different content"
                ) from None
            if row["state"] == "started":
                raise ValidationRecoveryRequired(
                    "validation has an unfinished STARTED checkpoint; automatic replay is refused"
                ) from None
            return ValidationClaim(
                created=False,
                outcome=ValidationOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: ValidationOutcome) -> None:
        encoded = outcome.model_dump_json()
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE validation_executions
                SET state = 'completed', completed_at = ?, outcome_json = ?
                WHERE plan_id = ? AND state = 'started'
                """,
                (outcome.completed_at.isoformat(), encoded, outcome.plan_id),
            ).rowcount
        if changed != 1:
            raise ValidationRecoveryRequired("validation STARTED checkpoint is unavailable")

    def load_completed(self, plan_id: str) -> tuple[ValidationPlan, ValidationOutcome]:
        row = self.connection.execute(
            "SELECT plan_json, state, completed_at, outcome_json "
            "FROM validation_executions WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("validation checkpoint is unavailable")
        if row["state"] != "completed" or row["outcome_json"] is None:
            raise ValidationRecoveryRequired("validation has an unfinished STARTED checkpoint")
        plan = ValidationPlan.model_validate_json(row["plan_json"])
        outcome = ValidationOutcome.model_validate_json(row["outcome_json"])
        if (
            plan.plan_id != plan_id
            or outcome.plan_id != plan_id
            or row["completed_at"] != outcome.completed_at.isoformat()
        ):
            raise ValidationRecoveryRequired("validation checkpoint binding mismatch")
        return plan, outcome

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> ValidationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
