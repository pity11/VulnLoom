"""Crash-safe digest-only checkpoints for Agent Validation Intake decisions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .intake_models import (
    AgentValidationIntakeCommand,
    AgentValidationIntakePlan,
    AgentValidationIntakeRecord,
)


class AgentValidationIntakeIdempotencyConflict(ValueError):
    pass


class AgentValidationIntakeConsumptionConflict(ValueError):
    pass


class AgentValidationIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentValidationIntakeClaim:
    created: bool
    record: AgentValidationIntakeRecord | None = None


class AgentValidationIntakeStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_validation_intakes (
                intake_plan_id TEXT PRIMARY KEY,
                plan_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                audit_bundle_id TEXT NOT NULL UNIQUE,
                candidate_set_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                candidate_digest TEXT NOT NULL,
                validation_plan_id TEXT NOT NULL UNIQUE,
                validation_plan_digest TEXT NOT NULL,
                command_id TEXT NOT NULL UNIQUE,
                decision TEXT NOT NULL CHECK(decision IN ('accept', 'reject', 'defer')),
                reason_code TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                record_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(
        self,
        plan: AgentValidationIntakePlan,
        command: AgentValidationIntakeCommand,
        *,
        now: datetime,
    ) -> AgentValidationIntakeClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_validation_intakes WHERE intake_plan_id = ? "
            "OR idempotency_key = ? OR audit_bundle_id = ? "
            "OR validation_plan_id = ? OR command_id = ?",
            (
                plan.intake_plan_id,
                plan.idempotency_key,
                plan.audit_bundle_id,
                plan.validation_plan_id,
                command.command_id,
            ),
        ).fetchone()
        if row is not None:
            same = (
                row["intake_plan_id"] == plan.intake_plan_id
                and row["plan_digest"] == plan.intake_plan_id
                and row["command_id"] == command.command_id
            )
            if same:
                if row["state"] == "started" or row["record_json"] is None:
                    raise AgentValidationIntakeRecoveryRequired(
                        "Agent Validation Intake has an unfinished STARTED checkpoint"
                    )
                return AgentValidationIntakeClaim(
                    created=False,
                    record=AgentValidationIntakeRecord.model_validate_json(
                        row["record_json"]
                    ),
                )
            if row["idempotency_key"] == plan.idempotency_key:
                raise AgentValidationIntakeIdempotencyConflict(
                    "Agent Validation Intake idempotency key was reused"
                )
            raise AgentValidationIntakeConsumptionConflict(
                "Audit recommendation or ValidationPlan was already consumed"
            )
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO agent_validation_intakes (
                        intake_plan_id, plan_digest, idempotency_key, audit_bundle_id,
                        candidate_set_id, candidate_id, candidate_digest,
                        validation_plan_id, validation_plan_digest, command_id,
                        decision, reason_code, reviewer, state, started_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'started', ?)
                    """,
                    (
                        plan.intake_plan_id,
                        plan.intake_plan_id,
                        plan.idempotency_key,
                        plan.audit_bundle_id,
                        plan.candidate_set_id,
                        str(plan.candidate_id),
                        plan.candidate_digest,
                        plan.validation_plan_id,
                        plan.validation_plan_digest,
                        command.command_id,
                        command.decision.value,
                        command.reason_code.value,
                        command.reviewer,
                        now.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AgentValidationIntakeConsumptionConflict(
                "Agent Validation Intake checkpoint conflicted concurrently"
            ) from exc
        return AgentValidationIntakeClaim(created=True)

    def complete(self, record: AgentValidationIntakeRecord) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_validation_intakes SET state = 'completed', "
                "completed_at = ?, record_json = ? WHERE intake_plan_id = ? "
                "AND command_id = ? AND state = 'started'",
                (
                    record.decided_at.isoformat(),
                    record.model_dump_json(),
                    record.intake_plan_id,
                    record.command_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentValidationIntakeRecoveryRequired(
                "Agent Validation Intake STARTED checkpoint is unavailable"
            )

    def load_completed(self, intake_plan_id: str) -> AgentValidationIntakeRecord:
        row = self.connection.execute(
            "SELECT state, record_json FROM agent_validation_intakes "
            "WHERE intake_plan_id = ?",
            (intake_plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Agent Validation Intake checkpoint is unavailable")
        if row["state"] != "completed" or row["record_json"] is None:
            raise AgentValidationIntakeRecoveryRequired(
                "Agent Validation Intake has an unfinished STARTED checkpoint"
            )
        record = AgentValidationIntakeRecord.model_validate_json(row["record_json"])
        if record.intake_plan_id != intake_plan_id:
            raise AgentValidationIntakeRecoveryRequired(
                "Agent Validation Intake checkpoint binding mismatch"
            )
        return record

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentValidationIntakeStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
