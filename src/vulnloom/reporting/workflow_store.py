"""Transactional checkpoints for human review and local export."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .review_models import (
    ReportExportOutcome,
    ReportExportPlan,
    ReportReviewCommand,
    ReportReviewOutcome,
    ReportReviewPlan,
)


class ReportWorkflowConflict(ValueError):
    """A review/export idempotency key was reused for different content."""


class ReportWorkflowRecoveryRequired(RuntimeError):
    """An unfinished review/export checkpoint requires explicit recovery."""


@dataclass(frozen=True)
class ReportReviewClaim:
    created: bool
    outcome: ReportReviewOutcome | None = None


@dataclass(frozen=True)
class ReportExportClaim:
    created: bool
    outcome: ReportExportOutcome | None = None


class ReportReviewStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS report_reviews (
                command_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL UNIQUE,
                idempotency_key TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(
        self,
        plan: ReportReviewPlan,
        command: ReportReviewCommand,
        *,
        now: datetime,
    ) -> ReportReviewClaim:
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO report_reviews (
                        command_id, plan_id, idempotency_key, state, started_at
                    ) VALUES (?, ?, ?, 'started', ?)
                    """,
                    (command.command_id, plan.plan_id, plan.idempotency_key, now.isoformat()),
                )
            return ReportReviewClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                """
                SELECT * FROM report_reviews
                WHERE command_id = ? OR plan_id = ? OR idempotency_key = ?
                """,
                (command.command_id, plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["command_id"] != command.command_id or row["plan_id"] != plan.plan_id:
                raise ReportWorkflowConflict(
                    "Report review plan or idempotency key was reused for different content"
                ) from None
            if row["state"] == "started":
                raise ReportWorkflowRecoveryRequired(
                    "Report review has an unfinished STARTED checkpoint"
                ) from None
            return ReportReviewClaim(
                created=False,
                outcome=ReportReviewOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: ReportReviewOutcome, *, command_id: str) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE report_reviews
                SET state = 'completed', completed_at = ?, outcome_json = ?
                WHERE command_id = ? AND state = 'started'
                """,
                (outcome.completed_at.isoformat(), outcome.model_dump_json(), command_id),
            ).rowcount
        if changed != 1:
            raise ReportWorkflowRecoveryRequired("Report review STARTED checkpoint is unavailable")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> ReportReviewStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ReportExportStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS report_exports (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: ReportExportPlan, *, now: datetime) -> ReportExportClaim:
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO report_exports (
                        plan_id, idempotency_key, state, started_at
                    ) VALUES (?, ?, 'started', ?)
                    """,
                    (plan.plan_id, plan.idempotency_key, now.isoformat()),
                )
            return ReportExportClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                """
                SELECT * FROM report_exports WHERE plan_id = ? OR idempotency_key = ?
                """,
                (plan.plan_id, plan.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["plan_id"] != plan.plan_id:
                raise ReportWorkflowConflict(
                    "Report export idempotency key was reused for different content"
                ) from None
            if row["state"] == "started":
                raise ReportWorkflowRecoveryRequired(
                    "Report export has an unfinished STARTED checkpoint"
                ) from None
            return ReportExportClaim(
                created=False,
                outcome=ReportExportOutcome.model_validate_json(row["outcome_json"]),
            )

    def complete(self, outcome: ReportExportOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE report_exports
                SET state = 'completed', completed_at = ?, outcome_json = ?
                WHERE plan_id = ? AND state = 'started'
                """,
                (outcome.completed_at.isoformat(), outcome.model_dump_json(), outcome.plan_id),
            ).rowcount
        if changed != 1:
            raise ReportWorkflowRecoveryRequired("Report export STARTED checkpoint is unavailable")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> ReportExportStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
