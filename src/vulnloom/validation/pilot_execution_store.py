"""Crash-safe checkpoints for Approval-gated pilot Validation execution."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_execution_models import (
    PilotValidationExecutionBinding,
    PilotValidationExecutionPlan,
)


class PilotValidationExecutionConflict(ValueError):
    pass


class PilotValidationExecutionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotValidationExecutionClaim:
    created: bool
    binding: PilotValidationExecutionBinding | None = None


class PilotValidationExecutionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS pilot_validation_executions (
            execution_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            pilot_intake_plan_id TEXT NOT NULL UNIQUE, validation_plan_id TEXT NOT NULL UNIQUE,
            approval_id TEXT NOT NULL UNIQUE,
            plan_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def has_checkpoint(self, execution_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_validation_executions WHERE execution_plan_id=?",
                (execution_plan_id,),
            ).fetchone()
            is not None
        )

    def has_validation_plan_checkpoint(self, validation_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_validation_executions WHERE validation_plan_id=?",
                (validation_plan_id,),
            ).fetchone()
            is not None
        )

    def claim(
        self, plan: PilotValidationExecutionPlan, *, now: datetime
    ) -> PilotValidationExecutionClaim:
        encoded = plan.model_dump_json()
        row = self.connection.execute(
            "SELECT * FROM pilot_validation_executions WHERE execution_plan_id=? "
            "OR idempotency_key=? OR pilot_intake_plan_id=? OR validation_plan_id=? "
            "OR approval_id=?",
            (
                plan.execution_plan_id,
                plan.idempotency_key,
                plan.pilot_intake_plan_id,
                plan.validation_plan_id,
                str(plan.approval_id),
            ),
        ).fetchone()
        if row is not None:
            if row["execution_plan_id"] != plan.execution_plan_id or row["plan_json"] != encoded:
                raise PilotValidationExecutionConflict(
                    "pilot Intake, ValidationPlan, Approval, or key was already consumed"
                )
            if row["state"] != "completed" or row["binding_json"] is None:
                raise PilotValidationExecutionRecoveryRequired(
                    "pilot Validation execution has unfinished STARTED state"
                )
            return PilotValidationExecutionClaim(
                created=False,
                binding=PilotValidationExecutionBinding.model_validate_json(row["binding_json"]),
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO pilot_validation_executions VALUES "
                "(?,?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.execution_plan_id,
                    plan.idempotency_key,
                    plan.pilot_intake_plan_id,
                    plan.validation_plan_id,
                    str(plan.approval_id),
                    encoded,
                    now.isoformat(),
                ),
            )
        return PilotValidationExecutionClaim(created=True)

    def complete(self, binding: PilotValidationExecutionBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_validation_executions SET state='completed',completed_at=?,"
                "binding_json=? WHERE execution_plan_id=? AND state='started'",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.execution_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise PilotValidationExecutionRecoveryRequired(
                "pilot Validation execution STARTED checkpoint is unavailable"
            )

    def load_completed(self, execution_plan_id: str) -> PilotValidationExecutionBinding:
        row = self.connection.execute(
            "SELECT state,binding_json FROM pilot_validation_executions WHERE execution_plan_id=?",
            (execution_plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("pilot Validation execution binding is unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise PilotValidationExecutionRecoveryRequired(
                "pilot Validation execution has unfinished STARTED state"
            )
        binding = PilotValidationExecutionBinding.model_validate_json(row["binding_json"])
        if binding.execution_plan_id != execution_plan_id:
            raise PilotValidationExecutionRecoveryRequired(
                "pilot Validation execution checkpoint binding mismatch"
            )
        return binding

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> PilotValidationExecutionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
