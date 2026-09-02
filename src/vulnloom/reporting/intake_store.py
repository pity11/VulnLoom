"""Transactional checkpoints for human Report draft selection."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .intake_models import AgentReportIntakeCommand, AgentReportIntakePlan, AgentReportIntakeRecord


class AgentReportIntakeConflict(ValueError):
    pass


class AgentReportIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentReportIntakeClaim:
    created: bool
    record: AgentReportIntakeRecord | None = None


class AgentReportIntakeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_report_intakes (
            intake_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            report_draft_plan_id TEXT NOT NULL UNIQUE, report_family_id TEXT NOT NULL,
            report_version INTEGER NOT NULL,
            command_id TEXT NOT NULL UNIQUE, finding_promotion_outcome_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, record_json TEXT,
            UNIQUE(report_family_id, report_version))"""
        )
        self.connection.commit()

    def claim(
        self, plan: AgentReportIntakePlan, command: AgentReportIntakeCommand, *, now: datetime
    ) -> AgentReportIntakeClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_report_intakes WHERE intake_plan_id=? OR idempotency_key=? "
            "OR report_draft_plan_id=? OR (report_family_id=? AND report_version=?) "
            "OR command_id=?",
            (
                plan.intake_plan_id,
                plan.idempotency_key,
                plan.report_draft_plan_id,
                str(plan.report_family_id),
                plan.report_version,
                command.command_id,
            ),
        ).fetchone()
        if row is not None:
            if (
                row["intake_plan_id"] != plan.intake_plan_id
                or row["command_id"] != command.command_id
            ):
                raise AgentReportIntakeConflict("Report plan, family, command, or key was consumed")
            if row["state"] != "completed" or row["record_json"] is None:
                raise AgentReportIntakeRecoveryRequired(
                    "Report Intake has unfinished STARTED checkpoint"
                )
            record = AgentReportIntakeRecord.model_validate_json(row["record_json"])
            if (
                row["idempotency_key"] != plan.idempotency_key
                or row["report_draft_plan_id"] != plan.report_draft_plan_id
                or row["report_family_id"] != str(plan.report_family_id)
                or row["report_version"] != plan.report_version
                or row["finding_promotion_outcome_id"] != plan.finding_promotion_outcome_id
                or row["decision"] != command.decision.value
                or record.intake_plan_id != plan.intake_plan_id
                or record.command_id != command.command_id
            ):
                raise AgentReportIntakeRecoveryRequired("Report Intake checkpoint drifted")
            return AgentReportIntakeClaim(False, record)
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_report_intakes VALUES "
                "(?,?,?,?,?,?,?,?, 'started',?,NULL,NULL)",
                (
                    plan.intake_plan_id,
                    plan.idempotency_key,
                    plan.report_draft_plan_id,
                    str(plan.report_family_id),
                    plan.report_version,
                    command.command_id,
                    plan.finding_promotion_outcome_id,
                    command.decision.value,
                    now.isoformat(),
                ),
            )
        return AgentReportIntakeClaim(True)

    def complete(self, record: AgentReportIntakeRecord) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_report_intakes SET state='completed', completed_at=?, record_json=? "
                "WHERE intake_plan_id=? AND state='started'",
                (record.decided_at.isoformat(), record.model_dump_json(), record.intake_plan_id),
            ).rowcount
        if changed != 1:
            raise AgentReportIntakeRecoveryRequired(
                "Report Intake STARTED checkpoint is unavailable"
            )

    def load_completed(self, intake_plan_id: str) -> AgentReportIntakeRecord:
        row = self.connection.execute(
            "SELECT * FROM agent_report_intakes WHERE intake_plan_id=?", (intake_plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Report Intake is unavailable")
        if row["state"] != "completed" or row["record_json"] is None:
            raise AgentReportIntakeRecoveryRequired(
                "Report Intake has unfinished STARTED checkpoint"
            )
        record = AgentReportIntakeRecord.model_validate_json(row["record_json"])
        if (
            record.intake_plan_id != intake_plan_id
            or record.command_id != row["command_id"]
            or record.report_draft_plan_id != row["report_draft_plan_id"]
            or str(record.report_family_id) != row["report_family_id"]
            or record.report_version != row["report_version"]
            or record.finding_promotion_outcome_id != row["finding_promotion_outcome_id"]
            or record.decision.value != row["decision"]
            or record.decided_at.isoformat() != row["completed_at"]
        ):
            raise AgentReportIntakeRecoveryRequired("Report Intake checkpoint drifted")
        return record

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
