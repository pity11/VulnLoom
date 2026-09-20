"""Transactional binding checkpoints for Hybrid Report drafting."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .report_models import HybridReportOutcome, HybridReportPlan


class HybridReportConflict(ValueError):
    pass


class HybridReportRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HybridReportClaim:
    created: bool
    attempt: int
    outcome: HybridReportOutcome | None = None


class HybridReportStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS hybrid_reports (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                hybrid_finding_plan_id TEXT NOT NULL,
                report_draft_plan_id TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed','timed_out','failed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: HybridReportPlan, *, now: datetime) -> HybridReportClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO hybrid_reports VALUES (?,?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.hybrid_finding_plan_id,
                        plan.report_draft_plan_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return HybridReportClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] == "started":
                raise HybridReportRecoveryRequired(
                    "Hybrid Report has an unfinished STARTED checkpoint"
                ) from None
            return HybridReportClaim(
                created=False,
                attempt=row["attempt"],
                outcome=HybridReportOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: HybridReportPlan, *, now: datetime) -> HybridReportClaim:
        exhausted = False
        with self.connection:
            row = self._by_identity(plan)
            self._same_plan(row, plan)
            if row["state"] != "started":
                raise HybridReportRecoveryRequired("Hybrid Report is not awaiting recovery")
            if row["attempt"] >= plan.max_attempts:
                outcome = HybridReportOutcome(
                    plan_id=plan.plan_id,
                    state="failed",
                    attempt=row["attempt"],
                    hybrid_finding_plan_id=plan.hybrid_finding_plan_id,
                    hybrid_chain_id=plan.hybrid_chain_id,
                    report_draft_plan_id=plan.report_draft_plan_id,
                    reason_code="recovery_attempts_exhausted",
                    cleanup_complete=True,
                    completed_at=now,
                )
                changed = self.connection.execute(
                    "UPDATE hybrid_reports SET state='failed',completed_at=?,outcome_json=? "
                    "WHERE plan_id=? AND state='started' AND attempt=?",
                    (
                        now.isoformat(),
                        outcome.model_dump_json(),
                        plan.plan_id,
                        row["attempt"],
                    ),
                ).rowcount
                if changed != 1:
                    raise HybridReportRecoveryRequired("Hybrid Report recovery raced")
                exhausted = True
            else:
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE hybrid_reports SET attempt=?,started_at=? "
                    "WHERE plan_id=? AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise HybridReportRecoveryRequired("Hybrid Report recovery raced")
        if exhausted:
            raise HybridReportRecoveryRequired("Hybrid Report recovery attempts are exhausted")
        return HybridReportClaim(created=True, attempt=attempt)

    def finish(self, outcome: HybridReportOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE hybrid_reports SET state=?,completed_at=?,outcome_json=? "
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
            raise HybridReportRecoveryRequired("Hybrid Report STARTED checkpoint is unavailable")

    def state(self, plan_id: str) -> tuple[str, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM hybrid_reports WHERE plan_id=?", (plan_id,)
        ).fetchone()
        return (row["state"], row["attempt"]) if row else None

    def outcome(self, plan_id: str) -> HybridReportOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM hybrid_reports WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None or row["state"] == "started" or row["outcome_json"] is None:
            raise HybridReportRecoveryRequired("terminal Hybrid Report outcome is unavailable")
        outcome = HybridReportOutcome.model_validate_json(row["outcome_json"])
        if outcome.plan_id != plan_id or outcome.state.value != row["state"]:
            raise HybridReportRecoveryRequired("Hybrid Report checkpoint drifted")
        return outcome

    def _by_identity(self, plan: HybridReportPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM hybrid_reports WHERE plan_id=? OR idempotency_key=? "
            "OR report_draft_plan_id=?",
            (
                plan.plan_id,
                plan.idempotency_key,
                plan.report_draft_plan_id,
            ),
        ).fetchone()
        if row is None:
            raise HybridReportRecoveryRequired("Hybrid Report checkpoint is unavailable")
        return row

    @staticmethod
    def _same_plan(row: sqlite3.Row, plan: HybridReportPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise HybridReportConflict("Hybrid Report identity was reused for different content")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> HybridReportStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
