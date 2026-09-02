"""Transactional checkpoints for Approval-gated Report review execution."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .review_execution_models import (
    AgentReportReviewExecutionPlan,
    AgentReportReviewOutcomeBinding,
)


class AgentReportReviewExecutionConflict(ValueError):
    pass


class AgentReportReviewExecutionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentReportReviewExecutionClaim:
    created: bool
    binding: AgentReportReviewOutcomeBinding | None = None


class AgentReportReviewExecutionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_report_review_executions (
            execution_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            review_intake_record_id TEXT NOT NULL UNIQUE,
            report_review_plan_id TEXT NOT NULL UNIQUE,
            report_review_command_id TEXT NOT NULL UNIQUE,
            report_id TEXT NOT NULL UNIQUE, approval_id TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self, plan: AgentReportReviewExecutionPlan, *, now: datetime
    ) -> AgentReportReviewExecutionClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_report_review_executions WHERE execution_plan_id=? "
            "OR idempotency_key=? OR review_intake_record_id=? OR report_review_plan_id=? "
            "OR report_review_command_id=? OR report_id=? OR approval_id=?",
            (
                plan.execution_plan_id,
                plan.idempotency_key,
                plan.review_intake_record_id,
                plan.report_review_plan_id,
                plan.report_review_command_id,
                str(plan.report_id),
                str(plan.approval_id),
            ),
        ).fetchone()
        if row is not None:
            if row["execution_plan_id"] != plan.execution_plan_id:
                raise AgentReportReviewExecutionConflict(
                    "Report review input, Approval, or idempotency key was consumed"
                )
            if row["state"] != "completed" or row["binding_json"] is None:
                raise AgentReportReviewExecutionRecoveryRequired(
                    "Report review execution has unfinished STARTED checkpoint"
                )
            binding = AgentReportReviewOutcomeBinding.model_validate_json(row["binding_json"])
            if (
                row["idempotency_key"] != plan.idempotency_key
                or row["review_intake_record_id"] != plan.review_intake_record_id
                or row["report_review_plan_id"] != plan.report_review_plan_id
                or row["report_review_command_id"] != plan.report_review_command_id
                or row["report_id"] != str(plan.report_id)
                or row["approval_id"] != str(plan.approval_id)
                or binding.execution_plan_id != plan.execution_plan_id
                or binding.completed_at.isoformat() != row["completed_at"]
            ):
                raise AgentReportReviewExecutionRecoveryRequired(
                    "Report review execution checkpoint drifted"
                )
            return AgentReportReviewExecutionClaim(False, binding)
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_report_review_executions VALUES "
                "(?,?,?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.execution_plan_id,
                    plan.idempotency_key,
                    plan.review_intake_record_id,
                    plan.report_review_plan_id,
                    plan.report_review_command_id,
                    str(plan.report_id),
                    str(plan.approval_id),
                    now.isoformat(),
                ),
            )
        return AgentReportReviewExecutionClaim(True)

    def complete(self, binding: AgentReportReviewOutcomeBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_report_review_executions SET state='completed', completed_at=?, "
                "binding_json=? WHERE execution_plan_id=? AND state='started'",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.execution_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentReportReviewExecutionRecoveryRequired(
                "Report review execution STARTED checkpoint is unavailable"
            )

    def has_checkpoint(self, execution_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM agent_report_review_executions WHERE execution_plan_id=?",
                (execution_plan_id,),
            ).fetchone()
            is not None
        )

    def load_completed(self, execution_plan_id: str) -> AgentReportReviewOutcomeBinding:
        row = self.connection.execute(
            "SELECT * FROM agent_report_review_executions WHERE execution_plan_id=?",
            (execution_plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Report review execution is unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise AgentReportReviewExecutionRecoveryRequired(
                "Report review execution has unfinished STARTED checkpoint"
            )
        binding = AgentReportReviewOutcomeBinding.model_validate_json(row["binding_json"])
        if (
            binding.execution_plan_id != execution_plan_id
            or binding.review_intake_record_id != row["review_intake_record_id"]
            or binding.report_review_plan_id != row["report_review_plan_id"]
            or binding.report_review_command_id != row["report_review_command_id"]
            or str(binding.report_id) != row["report_id"]
            or str(binding.approval_id) != row["approval_id"]
            or binding.completed_at.isoformat() != row["completed_at"]
        ):
            raise AgentReportReviewExecutionRecoveryRequired(
                "Report review execution checkpoint drifted"
            )
        return binding

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
