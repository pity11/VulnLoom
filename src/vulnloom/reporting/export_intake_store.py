"""Transactional checkpoints for human local Report export selection."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .export_intake_models import (
    AgentReportExportIntakeCommand,
    AgentReportExportIntakePlan,
    AgentReportExportIntakeRecord,
)


class AgentReportExportIntakeConflict(ValueError):
    pass


class AgentReportExportIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentReportExportIntakeClaim:
    created: bool
    record: AgentReportExportIntakeRecord | None = None


class AgentReportExportIntakeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_report_export_intakes (
            intake_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            review_outcome_binding_id TEXT NOT NULL UNIQUE,
            report_export_plan_id TEXT NOT NULL UNIQUE,
            report_id TEXT NOT NULL UNIQUE, command_id TEXT NOT NULL UNIQUE,
            decision TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, record_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self,
        plan: AgentReportExportIntakePlan,
        command: AgentReportExportIntakeCommand,
        *,
        now: datetime,
    ) -> AgentReportExportIntakeClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_report_export_intakes WHERE intake_plan_id=? "
            "OR idempotency_key=? OR review_outcome_binding_id=? "
            "OR report_export_plan_id=? OR report_id=? OR command_id=?",
            (
                plan.intake_plan_id,
                plan.idempotency_key,
                plan.review_outcome_binding_id,
                plan.report_export_plan_id,
                str(plan.report_id),
                command.command_id,
            ),
        ).fetchone()
        if row is not None:
            if (
                row["intake_plan_id"] != plan.intake_plan_id
                or row["command_id"] != command.command_id
            ):
                raise AgentReportExportIntakeConflict(
                    "Report, review binding, export plan, command, or key was consumed"
                )
            if row["state"] != "completed" or row["record_json"] is None:
                raise AgentReportExportIntakeRecoveryRequired(
                    "Report export Intake has unfinished STARTED checkpoint"
                )
            record = AgentReportExportIntakeRecord.model_validate_json(row["record_json"])
            if (
                row["idempotency_key"] != plan.idempotency_key
                or row["review_outcome_binding_id"] != plan.review_outcome_binding_id
                or row["report_export_plan_id"] != plan.report_export_plan_id
                or row["report_id"] != str(plan.report_id)
                or row["decision"] != command.decision.value
                or record.intake_plan_id != plan.intake_plan_id
                or record.command_id != command.command_id
                or record.decided_at.isoformat() != row["completed_at"]
            ):
                raise AgentReportExportIntakeRecoveryRequired(
                    "Report export Intake checkpoint drifted"
                )
            return AgentReportExportIntakeClaim(False, record)
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_report_export_intakes VALUES "
                "(?,?,?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.intake_plan_id,
                    plan.idempotency_key,
                    plan.review_outcome_binding_id,
                    plan.report_export_plan_id,
                    str(plan.report_id),
                    command.command_id,
                    command.decision.value,
                    now.isoformat(),
                ),
            )
        return AgentReportExportIntakeClaim(True)

    def complete(self, record: AgentReportExportIntakeRecord) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_report_export_intakes SET state='completed', completed_at=?, "
                "record_json=? WHERE intake_plan_id=? AND state='started'",
                (
                    record.decided_at.isoformat(),
                    record.model_dump_json(),
                    record.intake_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentReportExportIntakeRecoveryRequired(
                "Report export Intake STARTED checkpoint is unavailable"
            )

    def load_completed(self, intake_plan_id: str) -> AgentReportExportIntakeRecord:
        row = self.connection.execute(
            "SELECT * FROM agent_report_export_intakes WHERE intake_plan_id=?",
            (intake_plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Report export Intake is unavailable")
        if row["state"] != "completed" or row["record_json"] is None:
            raise AgentReportExportIntakeRecoveryRequired(
                "Report export Intake has unfinished STARTED checkpoint"
            )
        record = AgentReportExportIntakeRecord.model_validate_json(row["record_json"])
        if (
            record.intake_plan_id != intake_plan_id
            or record.command_id != row["command_id"]
            or record.review_outcome_binding_id != row["review_outcome_binding_id"]
            or record.report_export_plan_id != row["report_export_plan_id"]
            or str(record.report_id) != row["report_id"]
            or record.decision.value != row["decision"]
            or record.decided_at.isoformat() != row["completed_at"]
        ):
            raise AgentReportExportIntakeRecoveryRequired(
                "Report export Intake checkpoint drifted"
            )
        return record

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
