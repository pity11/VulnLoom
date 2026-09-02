"""Transactional checkpoints for accepted Report Intake execution."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .execution_models import AgentReportDraftExecutionPlan, AgentReportDraftOutcomeBinding


class AgentReportDraftExecutionConflict(ValueError):
    pass


class AgentReportDraftExecutionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentReportDraftExecutionClaim:
    created: bool
    binding: AgentReportDraftOutcomeBinding | None = None


class AgentReportDraftExecutionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_report_draft_executions (
            execution_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            report_intake_record_id TEXT NOT NULL UNIQUE,
            report_draft_plan_id TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self, plan: AgentReportDraftExecutionPlan, *, now: datetime
    ) -> AgentReportDraftExecutionClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_report_draft_executions WHERE execution_plan_id=? "
            "OR idempotency_key=? OR report_intake_record_id=? OR report_draft_plan_id=?",
            (
                plan.execution_plan_id,
                plan.idempotency_key,
                plan.report_intake_record_id,
                plan.report_draft_plan_id,
            ),
        ).fetchone()
        if row is not None:
            if row["execution_plan_id"] != plan.execution_plan_id:
                raise AgentReportDraftExecutionConflict(
                    "Report Intake, draft plan, or idempotency key was consumed"
                )
            if row["state"] != "completed" or row["binding_json"] is None:
                raise AgentReportDraftExecutionRecoveryRequired(
                    "Report draft execution has unfinished STARTED checkpoint"
                )
            binding = AgentReportDraftOutcomeBinding.model_validate_json(row["binding_json"])
            if (
                row["idempotency_key"] != plan.idempotency_key
                or row["report_intake_record_id"] != plan.report_intake_record_id
                or row["report_draft_plan_id"] != plan.report_draft_plan_id
                or binding.execution_plan_id != plan.execution_plan_id
                or binding.report_intake_record_id != plan.report_intake_record_id
                or binding.report_draft_plan_id != plan.report_draft_plan_id
            ):
                raise AgentReportDraftExecutionRecoveryRequired(
                    "Report draft execution checkpoint drifted"
                )
            return AgentReportDraftExecutionClaim(False, binding)
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_report_draft_executions VALUES (?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.execution_plan_id,
                    plan.idempotency_key,
                    plan.report_intake_record_id,
                    plan.report_draft_plan_id,
                    now.isoformat(),
                ),
            )
        return AgentReportDraftExecutionClaim(True)

    def complete(self, binding: AgentReportDraftOutcomeBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_report_draft_executions SET state='completed', completed_at=?, "
                "binding_json=? WHERE execution_plan_id=? AND state='started'",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.execution_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentReportDraftExecutionRecoveryRequired(
                "Report draft execution STARTED checkpoint is unavailable"
            )

    def has_checkpoint(self, execution_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM agent_report_draft_executions WHERE execution_plan_id=?",
                (execution_plan_id,),
            ).fetchone()
            is not None
        )

    def load_completed(self, execution_plan_id: str) -> AgentReportDraftOutcomeBinding:
        row = self.connection.execute(
            "SELECT * FROM agent_report_draft_executions WHERE execution_plan_id=?",
            (execution_plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Report draft execution is unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise AgentReportDraftExecutionRecoveryRequired(
                "Report draft execution has unfinished STARTED checkpoint"
            )
        binding = AgentReportDraftOutcomeBinding.model_validate_json(row["binding_json"])
        if (
            binding.execution_plan_id != execution_plan_id
            or binding.report_intake_record_id != row["report_intake_record_id"]
            or binding.report_draft_plan_id != row["report_draft_plan_id"]
            or binding.completed_at.isoformat() != row["completed_at"]
        ):
            raise AgentReportDraftExecutionRecoveryRequired(
                "Report draft execution checkpoint drifted"
            )
        return binding

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
