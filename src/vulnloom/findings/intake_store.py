"""Transactional checkpoints for human Finding promotion decisions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .intake_models import (
    AgentFindingIntakeCommand,
    AgentFindingIntakePlan,
    AgentFindingIntakeRecord,
)


class AgentFindingIntakeConflict(ValueError):
    pass


class AgentFindingIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentFindingIntakeClaim:
    created: bool
    record: AgentFindingIntakeRecord | None = None


class AgentFindingIntakeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_finding_intakes (
            intake_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            critic_outcome_binding_id TEXT NOT NULL UNIQUE,
            promotion_plan_id TEXT NOT NULL UNIQUE, duplicate_check_id TEXT NOT NULL UNIQUE,
            finding_id TEXT NOT NULL UNIQUE, command_id TEXT NOT NULL UNIQUE,
            decision TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, record_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self, plan: AgentFindingIntakePlan, command: AgentFindingIntakeCommand, *, now: datetime
    ) -> AgentFindingIntakeClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_finding_intakes WHERE intake_plan_id=? OR idempotency_key=? "
            "OR critic_outcome_binding_id=? OR promotion_plan_id=? OR duplicate_check_id=? "
            "OR finding_id=? OR command_id=?",
            (
                plan.intake_plan_id,
                plan.idempotency_key,
                plan.critic_outcome_binding_id,
                plan.promotion_plan_id,
                plan.duplicate_check_id,
                str(plan.finding_id),
                command.command_id,
            ),
        ).fetchone()
        if row is not None:
            if (
                row["intake_plan_id"] == plan.intake_plan_id
                and row["command_id"] == command.command_id
            ):
                if row["state"] != "completed" or row["record_json"] is None:
                    raise AgentFindingIntakeRecoveryRequired(
                        "Finding Intake has unfinished STARTED checkpoint"
                    )
                record = AgentFindingIntakeRecord.model_validate_json(row["record_json"])
                if (
                    row["idempotency_key"] != plan.idempotency_key
                    or row["critic_outcome_binding_id"] != plan.critic_outcome_binding_id
                    or row["promotion_plan_id"] != plan.promotion_plan_id
                    or row["duplicate_check_id"] != plan.duplicate_check_id
                    or row["finding_id"] != str(plan.finding_id)
                    or row["decision"] != command.decision.value
                    or record.intake_plan_id != plan.intake_plan_id
                    or record.command_id != command.command_id
                    or record.promotion_plan_id != plan.promotion_plan_id
                ):
                    raise AgentFindingIntakeRecoveryRequired(
                        "Finding Intake completed checkpoint drifted"
                    )
                return AgentFindingIntakeClaim(False, record)
            raise AgentFindingIntakeConflict(
                "Finding binding, promotion, duplicate check, finding, command, or key was consumed"
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_finding_intakes VALUES (?,?,?,?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.intake_plan_id,
                    plan.idempotency_key,
                    plan.critic_outcome_binding_id,
                    plan.promotion_plan_id,
                    plan.duplicate_check_id,
                    str(plan.finding_id),
                    command.command_id,
                    command.decision.value,
                    now.isoformat(),
                ),
            )
        return AgentFindingIntakeClaim(True)

    def complete(self, record: AgentFindingIntakeRecord) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_finding_intakes SET state='completed', completed_at=?, "
                "record_json=? WHERE intake_plan_id=? AND state='started'",
                (record.decided_at.isoformat(), record.model_dump_json(), record.intake_plan_id),
            ).rowcount
        if changed != 1:
            raise AgentFindingIntakeRecoveryRequired(
                "Finding Intake STARTED checkpoint is unavailable"
            )

    def load_completed(self, intake_plan_id: str) -> AgentFindingIntakeRecord:
        row = self.connection.execute(
            "SELECT * FROM agent_finding_intakes WHERE intake_plan_id=?", (intake_plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Finding Intake is unavailable")
        if row["state"] != "completed" or row["record_json"] is None:
            raise AgentFindingIntakeRecoveryRequired(
                "Finding Intake has unfinished STARTED checkpoint"
            )
        record = AgentFindingIntakeRecord.model_validate_json(row["record_json"])
        if (
            record.intake_plan_id != intake_plan_id
            or record.command_id != row["command_id"]
            or record.critic_outcome_binding_id != row["critic_outcome_binding_id"]
            or record.promotion_plan_id != row["promotion_plan_id"]
            or record.duplicate_check_id != row["duplicate_check_id"]
            or str(record.finding_id) != row["finding_id"]
            or record.decision.value != row["decision"]
            or record.decided_at.isoformat() != row["completed_at"]
        ):
            raise AgentFindingIntakeRecoveryRequired("Finding Intake checkpoint drifted")
        return record

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
