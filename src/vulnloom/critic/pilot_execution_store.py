"""Crash-safe checkpoints for Approval-gated pilot Critic execution."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_execution_models import (
    PilotCriticExecutionBinding,
    PilotCriticExecutionPlan,
)


class PilotCriticExecutionConflict(ValueError):
    pass


class PilotCriticExecutionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotCriticExecutionClaim:
    created: bool
    binding: PilotCriticExecutionBinding | None = None


class PilotCriticExecutionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS pilot_critic_executions (
            execution_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            pilot_intake_plan_id TEXT NOT NULL UNIQUE, critic_plan_id TEXT NOT NULL UNIQUE,
            approval_id TEXT NOT NULL UNIQUE,
            plan_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def has_checkpoint(self, execution_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_critic_executions WHERE execution_plan_id=?",
                (execution_plan_id,),
            ).fetchone()
            is not None
        )

    def has_critic_plan_checkpoint(self, critic_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_critic_executions WHERE critic_plan_id=?",
                (critic_plan_id,),
            ).fetchone()
            is not None
        )

    def claim(self, plan: PilotCriticExecutionPlan, *, now: datetime) -> PilotCriticExecutionClaim:
        encoded = plan.model_dump_json()
        row = self.connection.execute(
            "SELECT * FROM pilot_critic_executions WHERE execution_plan_id=? "
            "OR idempotency_key=? OR pilot_intake_plan_id=? OR critic_plan_id=? "
            "OR approval_id=?",
            (
                plan.execution_plan_id,
                plan.idempotency_key,
                plan.pilot_intake_plan_id,
                plan.critic_plan_id,
                str(plan.approval_id),
            ),
        ).fetchone()
        if row is not None:
            if row["execution_plan_id"] != plan.execution_plan_id or row["plan_json"] != encoded:
                raise PilotCriticExecutionConflict(
                    "pilot Intake, CriticPlan, Approval, or key was already consumed"
                )
            if row["state"] != "completed" or row["binding_json"] is None:
                raise PilotCriticExecutionRecoveryRequired(
                    "pilot Critic execution has unfinished STARTED state"
                )
            return PilotCriticExecutionClaim(
                created=False,
                binding=self.load_completed(plan.execution_plan_id),
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO pilot_critic_executions VALUES (?,?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.execution_plan_id,
                    plan.idempotency_key,
                    plan.pilot_intake_plan_id,
                    plan.critic_plan_id,
                    str(plan.approval_id),
                    encoded,
                    now.isoformat(),
                ),
            )
        return PilotCriticExecutionClaim(created=True)

    def complete(self, binding: PilotCriticExecutionBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_critic_executions SET state='completed',completed_at=?,"
                "binding_json=? WHERE execution_plan_id=? AND state='started'",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.execution_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise PilotCriticExecutionRecoveryRequired(
                "pilot Critic execution STARTED checkpoint is unavailable"
            )

    def load_completed(self, execution_plan_id: str) -> PilotCriticExecutionBinding:
        row = self.connection.execute(
            "SELECT * FROM pilot_critic_executions WHERE execution_plan_id=?",
            (execution_plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("pilot Critic execution binding is unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise PilotCriticExecutionRecoveryRequired(
                "pilot Critic execution has unfinished STARTED state"
            )
        binding = PilotCriticExecutionBinding.model_validate_json(row["binding_json"])
        plan = PilotCriticExecutionPlan.model_validate_json(row["plan_json"])
        if (
            binding.execution_plan_id != execution_plan_id
            or plan.execution_plan_id != execution_plan_id
            or row["idempotency_key"] != plan.idempotency_key
            or row["pilot_intake_plan_id"] != plan.pilot_intake_plan_id
            or row["critic_plan_id"] != plan.critic_plan_id
            or row["approval_id"] != str(plan.approval_id)
            or row["started_at"] != binding.completed_at.isoformat()
            or row["completed_at"] != binding.completed_at.isoformat()
            or not plan.created_at <= binding.completed_at < plan.deadline
            or any(
                getattr(binding, field) != getattr(plan, field)
                for field in (
                    "approval_action_id",
                    "approval_id",
                    "approval_digest",
                    "pilot_intake_binding_id",
                    "intake_record_id",
                    "critic_plan_id",
                    "candidate_id",
                )
            )
            or binding.validated_candidate_digest != plan.validated_candidate_digest
        ):
            raise PilotCriticExecutionRecoveryRequired(
                "pilot Critic execution checkpoint binding mismatch"
            )
        return binding

    def load_completed_plan(self, execution_plan_id: str) -> PilotCriticExecutionPlan:
        self.load_completed(execution_plan_id)
        row = self.connection.execute(
            "SELECT plan_json FROM pilot_critic_executions WHERE execution_plan_id=?",
            (execution_plan_id,),
        ).fetchone()
        return PilotCriticExecutionPlan.model_validate_json(row["plan_json"])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> PilotCriticExecutionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
