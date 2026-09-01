"""Transactional checkpoints for digest-only Validation outcome bindings."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .outcome_binding_models import (
    AgentValidationOutcomeBinding,
    AgentValidationOutcomeBindingPlan,
)


class AgentValidationOutcomeBindingConflict(ValueError):
    pass


class AgentValidationOutcomeBindingRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentValidationOutcomeBindingClaim:
    created: bool
    binding: AgentValidationOutcomeBinding | None = None


class AgentValidationOutcomeBindingStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_validation_outcome_bindings (
                binding_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                intake_record_id TEXT NOT NULL UNIQUE,
                validation_plan_id TEXT NOT NULL UNIQUE,
                validation_outcome_digest TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                binding_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: AgentValidationOutcomeBindingPlan, *, now: datetime):
        row = self.connection.execute(
            "SELECT * FROM agent_validation_outcome_bindings WHERE binding_plan_id = ? "
            "OR idempotency_key = ? OR intake_record_id = ? OR validation_plan_id = ? "
            "OR validation_outcome_digest = ?",
            (
                plan.binding_plan_id,
                plan.idempotency_key,
                plan.intake_record_id,
                plan.validation_plan_id,
                plan.validation_outcome_digest,
            ),
        ).fetchone()
        if row is not None:
            if row["binding_plan_id"] == plan.binding_plan_id:
                if row["state"] != "completed" or row["binding_json"] is None:
                    raise AgentValidationOutcomeBindingRecoveryRequired(
                        "Agent Validation outcome binding has unfinished STARTED checkpoint"
                    )
                return AgentValidationOutcomeBindingClaim(
                    False,
                    AgentValidationOutcomeBinding.model_validate_json(row["binding_json"]),
                )
            raise AgentValidationOutcomeBindingConflict(
                "Agent Validation Intake or outcome was already bound"
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_validation_outcome_bindings VALUES "
                "(?, ?, ?, ?, ?, 'started', ?, NULL, NULL)",
                (
                    plan.binding_plan_id,
                    plan.idempotency_key,
                    plan.intake_record_id,
                    plan.validation_plan_id,
                    plan.validation_outcome_digest,
                    now.isoformat(),
                ),
            )
        return AgentValidationOutcomeBindingClaim(True)

    def complete(self, binding: AgentValidationOutcomeBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_validation_outcome_bindings SET state='completed', "
                "completed_at=?, binding_json=? WHERE binding_plan_id=? AND state='started'",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.binding_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentValidationOutcomeBindingRecoveryRequired(
                "Agent Validation outcome binding STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
