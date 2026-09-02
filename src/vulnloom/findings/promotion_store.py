"""Transactional checkpoints for deterministic Finding promotion."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .promotion_models import FindingPromotionExecutionPlan, FindingPromotionOutcome


class FindingPromotionConflict(ValueError):
    pass


class FindingPromotionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class FindingPromotionClaim:
    created: bool
    outcome: FindingPromotionOutcome | None = None


class FindingPromotionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS finding_promotions (
            execution_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            intake_record_id TEXT NOT NULL UNIQUE, promotion_plan_id TEXT NOT NULL UNIQUE,
            finding_id TEXT NOT NULL UNIQUE, approval_id TEXT NOT NULL UNIQUE,
            approval_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, outcome_json TEXT)"""
        )
        self.connection.commit()

    def claim(self, plan: FindingPromotionExecutionPlan, *, now: datetime) -> FindingPromotionClaim:
        row = self.connection.execute(
            "SELECT * FROM finding_promotions WHERE execution_plan_id=? OR idempotency_key=? "
            "OR intake_record_id=? OR promotion_plan_id=? OR finding_id=? OR approval_id=?",
            (
                plan.execution_plan_id,
                plan.idempotency_key,
                plan.intake_record_id,
                plan.promotion_plan_id,
                str(plan.finding_id),
                str(plan.approval_id),
            ),
        ).fetchone()
        if row is not None:
            if row["execution_plan_id"] != plan.execution_plan_id:
                raise FindingPromotionConflict("Finding promotion input or Approval was consumed")
            if row["state"] != "completed" or row["outcome_json"] is None:
                raise FindingPromotionRecoveryRequired(
                    "Finding promotion has unfinished STARTED checkpoint"
                )
            outcome = FindingPromotionOutcome.model_validate_json(row["outcome_json"])
            if (
                row["idempotency_key"] != plan.idempotency_key
                or row["intake_record_id"] != plan.intake_record_id
                or row["promotion_plan_id"] != plan.promotion_plan_id
                or row["finding_id"] != str(plan.finding_id)
                or row["approval_id"] != str(plan.approval_id)
                or row["approval_digest"] != plan.approval_digest
                or outcome.execution_plan_id != plan.execution_plan_id
                or outcome.finding.finding_id != plan.finding_id
            ):
                raise FindingPromotionRecoveryRequired("Finding promotion checkpoint drifted")
            return FindingPromotionClaim(False, outcome)
        with self.connection:
            self.connection.execute(
                "INSERT INTO finding_promotions VALUES (?,?,?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.execution_plan_id,
                    plan.idempotency_key,
                    plan.intake_record_id,
                    plan.promotion_plan_id,
                    str(plan.finding_id),
                    str(plan.approval_id),
                    plan.approval_digest,
                    now.isoformat(),
                ),
            )
        return FindingPromotionClaim(True)

    def complete(self, outcome: FindingPromotionOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE finding_promotions SET state='completed', completed_at=?, outcome_json=? "
                "WHERE execution_plan_id=? AND state='started'",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.execution_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise FindingPromotionRecoveryRequired(
                "Finding promotion STARTED checkpoint is unavailable"
            )

    def load_completed(self, execution_plan_id: str) -> FindingPromotionOutcome:
        row = self.connection.execute(
            "SELECT * FROM finding_promotions WHERE execution_plan_id=?", (execution_plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Finding promotion is unavailable")
        if row["state"] != "completed" or row["outcome_json"] is None:
            raise FindingPromotionRecoveryRequired(
                "Finding promotion has unfinished STARTED checkpoint"
            )
        outcome = FindingPromotionOutcome.model_validate_json(row["outcome_json"])
        if (
            outcome.execution_plan_id != execution_plan_id
            or str(outcome.approval_id) != row["approval_id"]
            or outcome.approval_digest != row["approval_digest"]
            or outcome.intake_record_id != row["intake_record_id"]
            or outcome.promotion_plan_id != row["promotion_plan_id"]
            or str(outcome.finding.finding_id) != row["finding_id"]
            or outcome.completed_at.isoformat() != row["completed_at"]
        ):
            raise FindingPromotionRecoveryRequired("Finding promotion checkpoint drifted")
        return outcome

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
