"""Transactional checkpoints for pilot-bound M8.1 Intake decisions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_intake_models import PilotValidationIntakeBinding, PilotValidationIntakePlan


class PilotValidationIntakeConflict(ValueError):
    pass


class PilotValidationIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotValidationIntakeClaim:
    created: bool
    binding: PilotValidationIntakeBinding | None = None


class PilotValidationIntakeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS pilot_validation_intakes (
            plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            selection_record_id TEXT NOT NULL UNIQUE, intake_plan_id TEXT NOT NULL UNIQUE,
            validation_plan_id TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self, plan: PilotValidationIntakePlan, *, now: datetime
    ) -> PilotValidationIntakeClaim:
        row = self.connection.execute(
            "SELECT * FROM pilot_validation_intakes WHERE plan_id=? OR idempotency_key=? "
            "OR selection_record_id=? OR intake_plan_id=? OR validation_plan_id=?",
            (
                plan.plan_id,
                plan.idempotency_key,
                plan.selection_record_id,
                plan.intake_plan_id,
                plan.validation_plan_id,
            ),
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id:
                raise PilotValidationIntakeConflict(
                    "pilot selection or Validation Intake was already consumed"
                )
            if row["state"] != "completed" or row["binding_json"] is None:
                raise PilotValidationIntakeRecoveryRequired(
                    "pilot Validation Intake has unfinished STARTED state"
                )
            return PilotValidationIntakeClaim(
                created=False,
                binding=PilotValidationIntakeBinding.model_validate_json(row["binding_json"]),
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO pilot_validation_intakes VALUES (?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.plan_id,
                    plan.idempotency_key,
                    plan.selection_record_id,
                    plan.intake_plan_id,
                    plan.validation_plan_id,
                    now.isoformat(),
                ),
            )
        return PilotValidationIntakeClaim(created=True)

    def complete(self, binding: PilotValidationIntakeBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_validation_intakes SET state='completed',completed_at=?,"
                "binding_json=? WHERE plan_id=? AND state='started'",
                (binding.completed_at.isoformat(), binding.model_dump_json(), binding.plan_id),
            ).rowcount
        if changed != 1:
            raise PilotValidationIntakeRecoveryRequired(
                "pilot Validation Intake STARTED checkpoint is unavailable"
            )

    def load_completed(self, plan_id: str) -> PilotValidationIntakeBinding:
        row = self.connection.execute(
            "SELECT state,binding_json FROM pilot_validation_intakes WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("pilot Validation Intake binding is unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise PilotValidationIntakeRecoveryRequired(
                "pilot Validation Intake has unfinished STARTED state"
            )
        binding = PilotValidationIntakeBinding.model_validate_json(row["binding_json"])
        if binding.plan_id != plan_id:
            raise PilotValidationIntakeRecoveryRequired(
                "pilot Validation Intake checkpoint binding mismatch"
            )
        return binding

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> PilotValidationIntakeStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
