"""Transactional checkpoints for human Critic Intake decisions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .intake_models import AgentCriticIntakeCommand, AgentCriticIntakePlan, AgentCriticIntakeRecord


class AgentCriticIntakeConflict(ValueError):
    pass


class AgentCriticIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentCriticIntakeClaim:
    created: bool
    record: AgentCriticIntakeRecord | None = None


class AgentCriticIntakeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_critic_intakes (
            intake_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            outcome_binding_id TEXT NOT NULL UNIQUE, critic_plan_id TEXT NOT NULL UNIQUE,
            command_id TEXT NOT NULL UNIQUE, decision TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, record_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self, plan: AgentCriticIntakePlan, command: AgentCriticIntakeCommand, *, now: datetime
    ):
        row = self.connection.execute(
            "SELECT * FROM agent_critic_intakes WHERE intake_plan_id=? OR idempotency_key=? "
            "OR outcome_binding_id=? OR critic_plan_id=? OR command_id=?",
            (
                plan.intake_plan_id,
                plan.idempotency_key,
                plan.outcome_binding_id,
                plan.critic_plan_id,
                command.command_id,
            ),
        ).fetchone()
        if row is not None:
            if (
                row["intake_plan_id"] == plan.intake_plan_id
                and row["command_id"] == command.command_id
            ):
                if row["state"] != "completed" or row["record_json"] is None:
                    raise AgentCriticIntakeRecoveryRequired(
                        "Critic Intake has unfinished STARTED checkpoint"
                    )
                record = AgentCriticIntakeRecord.model_validate_json(row["record_json"])
                if (
                    row["idempotency_key"] != plan.idempotency_key
                    or row["outcome_binding_id"] != plan.outcome_binding_id
                    or row["critic_plan_id"] != plan.critic_plan_id
                    or row["decision"] != command.decision.value
                    or record.intake_plan_id != plan.intake_plan_id
                    or record.command_id != command.command_id
                    or record.outcome_binding_id != plan.outcome_binding_id
                    or record.critic_plan_id != plan.critic_plan_id
                ):
                    raise AgentCriticIntakeRecoveryRequired(
                        "Critic Intake completed checkpoint drifted"
                    )
                return AgentCriticIntakeClaim(False, record)
            raise AgentCriticIntakeConflict(
                "Critic binding, plan, command, or key was already consumed"
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_critic_intakes VALUES (?,?,?,?,?,?, 'started',?,NULL,NULL)",
                (
                    plan.intake_plan_id,
                    plan.idempotency_key,
                    plan.outcome_binding_id,
                    plan.critic_plan_id,
                    command.command_id,
                    command.decision.value,
                    now.isoformat(),
                ),
            )
        return AgentCriticIntakeClaim(True)

    def complete(self, record: AgentCriticIntakeRecord) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_critic_intakes SET state='completed', completed_at=?, record_json=? "
                "WHERE intake_plan_id=? AND state='started'",
                (record.decided_at.isoformat(), record.model_dump_json(), record.intake_plan_id),
            ).rowcount
        if changed != 1:
            raise AgentCriticIntakeRecoveryRequired("Critic Intake STARTED checkpoint unavailable")

    def load_completed(self, intake_plan_id: str) -> AgentCriticIntakeRecord:
        row = self.connection.execute(
            "SELECT * FROM agent_critic_intakes WHERE intake_plan_id=?", (intake_plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Critic Intake is unavailable")
        if row["state"] != "completed" or row["record_json"] is None:
            raise AgentCriticIntakeRecoveryRequired(
                "Critic Intake has unfinished STARTED checkpoint"
            )
        record = AgentCriticIntakeRecord.model_validate_json(row["record_json"])
        if (
            record.intake_plan_id != intake_plan_id
            or record.command_id != row["command_id"]
            or record.outcome_binding_id != row["outcome_binding_id"]
            or record.critic_plan_id != row["critic_plan_id"]
            or record.decision.value != row["decision"]
            or record.decided_at.isoformat() != row["completed_at"]
        ):
            raise AgentCriticIntakeRecoveryRequired("Critic Intake checkpoint drifted")
        return record

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
