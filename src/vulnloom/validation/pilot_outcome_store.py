"""Transactional checkpoints for pilot M8.2 outcome provenance."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_outcome_models import PilotValidationOutcomeBinding, PilotValidationOutcomePlan


class PilotValidationOutcomeConflict(ValueError):
    pass


class PilotValidationOutcomeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotValidationOutcomeClaim:
    created: bool
    binding: PilotValidationOutcomeBinding | None = None


class PilotValidationOutcomeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS pilot_validation_outcomes (
            plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            execution_binding_id TEXT NOT NULL UNIQUE, outcome_binding_plan_id TEXT NOT NULL UNIQUE,
            validation_plan_id TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def has_validation_checkpoint(self, validation_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_validation_outcomes WHERE validation_plan_id=?",
                (validation_plan_id,),
            ).fetchone()
            is not None
        )

    def claim(
        self, plan: PilotValidationOutcomePlan, *, now: datetime
    ) -> PilotValidationOutcomeClaim:
        row = self.connection.execute(
            "SELECT * FROM pilot_validation_outcomes WHERE plan_id=? OR idempotency_key=? "
            "OR execution_binding_id=? OR outcome_binding_plan_id=? OR validation_plan_id=?",
            (
                plan.plan_id,
                plan.idempotency_key,
                plan.execution_binding_id,
                plan.outcome_binding_plan_id,
                plan.validation_plan_id,
            ),
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id:
                raise PilotValidationOutcomeConflict(
                    "pilot execution or outcome was already consumed"
                )
            if any(
                row[field] != getattr(plan, field)
                for field in (
                    "idempotency_key",
                    "execution_binding_id",
                    "outcome_binding_plan_id",
                    "validation_plan_id",
                )
            ):
                raise PilotValidationOutcomeRecoveryRequired("pilot outcome checkpoint drifted")
            if row["state"] != "completed" or row["binding_json"] is None:
                raise PilotValidationOutcomeRecoveryRequired(
                    "pilot Validation outcome has unfinished STARTED state"
                )
            return PilotValidationOutcomeClaim(
                created=False,
                binding=self.load_completed(plan.plan_id),
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO pilot_validation_outcomes VALUES (?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.plan_id,
                    plan.idempotency_key,
                    plan.execution_binding_id,
                    plan.outcome_binding_plan_id,
                    plan.validation_plan_id,
                    now.isoformat(),
                ),
            )
        return PilotValidationOutcomeClaim(created=True)

    def complete(self, binding: PilotValidationOutcomeBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_validation_outcomes SET state='completed',completed_at=?,"
                "binding_json=? WHERE plan_id=? AND state='started'",
                (binding.completed_at.isoformat(), binding.model_dump_json(), binding.plan_id),
            ).rowcount
        if changed != 1:
            raise PilotValidationOutcomeRecoveryRequired(
                "pilot Validation outcome STARTED checkpoint is unavailable"
            )

    def load_completed(self, plan_id: str) -> PilotValidationOutcomeBinding:
        row = self.connection.execute(
            "SELECT * FROM pilot_validation_outcomes WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("pilot Validation outcome binding is unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise PilotValidationOutcomeRecoveryRequired(
                "pilot Validation outcome has unfinished STARTED state"
            )
        binding = PilotValidationOutcomeBinding.model_validate_json(row["binding_json"])
        if (
            binding.plan_id != plan_id
            or binding.execution_binding_id != row["execution_binding_id"]
            or binding.outcome_binding_plan_id != row["outcome_binding_plan_id"]
            or binding.validation_plan_id != row["validation_plan_id"]
            or binding.completed_at.isoformat() != row["completed_at"]
            or row["started_at"] != row["completed_at"]
        ):
            raise PilotValidationOutcomeRecoveryRequired(
                "pilot Validation outcome checkpoint binding mismatch"
            )
        return binding

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> PilotValidationOutcomeStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
