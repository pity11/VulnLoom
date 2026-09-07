"""Crash-safe unique consumption of pilot outcome and human Critic Intake."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_intake_models import PilotCriticIntakeBinding, PilotCriticIntakePlan


class PilotCriticIntakeConflict(ValueError):
    pass


class PilotCriticIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotCriticIntakeClaim:
    created: bool
    binding: PilotCriticIntakeBinding | None = None


class PilotCriticIntakeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS pilot_critic_intakes (
            plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            pilot_outcome_binding_id TEXT NOT NULL UNIQUE, intake_plan_id TEXT NOT NULL UNIQUE,
            critic_plan_id TEXT NOT NULL UNIQUE, command_id TEXT NOT NULL UNIQUE,
            plan_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def has_critic_checkpoint(self, critic_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_critic_intakes WHERE critic_plan_id=?", (critic_plan_id,)
            ).fetchone()
            is not None
        )

    def claim(self, plan: PilotCriticIntakePlan, *, now: datetime) -> PilotCriticIntakeClaim:
        row = self.connection.execute(
            "SELECT * FROM pilot_critic_intakes WHERE plan_id=? OR idempotency_key=? "
            "OR pilot_outcome_binding_id=? OR intake_plan_id=? OR critic_plan_id=? OR command_id=?",
            (
                plan.plan_id,
                plan.idempotency_key,
                plan.pilot_outcome_binding_id,
                plan.intake_plan_id,
                plan.critic_plan_id,
                plan.command_id,
            ),
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
                raise PilotCriticIntakeConflict("pilot outcome, Intake, CriticPlan or key consumed")
            return PilotCriticIntakeClaim(False, self.load_completed(plan.plan_id))
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO pilot_critic_intakes VALUES (?,?,?,?,?,?,?,'started',?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.pilot_outcome_binding_id,
                        plan.intake_plan_id,
                        plan.critic_plan_id,
                        plan.command_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise PilotCriticIntakeConflict("concurrent pilot Critic Intake claim") from exc
        return PilotCriticIntakeClaim(True)

    def complete(self, binding: PilotCriticIntakeBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_critic_intakes SET state='completed',completed_at=?,binding_json=? "
                "WHERE plan_id=? AND state='started' AND pilot_outcome_binding_id=? "
                "AND intake_plan_id=? AND critic_plan_id=? AND command_id=? AND started_at=?",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.plan_id,
                    binding.pilot_outcome_binding_id,
                    binding.intake_plan_id,
                    binding.critic_plan_id,
                    binding.command_id,
                    binding.completed_at.isoformat(),
                ),
            ).rowcount
        if changed != 1:
            raise PilotCriticIntakeRecoveryRequired("pilot Critic Intake STARTED unavailable")

    def load_completed(self, plan_id: str) -> PilotCriticIntakeBinding:
        row = self.connection.execute(
            "SELECT * FROM pilot_critic_intakes WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("pilot Critic Intake unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise PilotCriticIntakeRecoveryRequired("pilot Critic Intake unfinished STARTED")
        plan = PilotCriticIntakePlan.model_validate_json(row["plan_json"])
        binding = PilotCriticIntakeBinding.model_validate_json(row["binding_json"])
        if (
            plan.plan_id != plan_id
            or binding.plan_id != plan_id
            or any(
                row[field] != getattr(plan, field)
                for field in (
                    "idempotency_key",
                    "pilot_outcome_binding_id",
                    "intake_plan_id",
                    "critic_plan_id",
                    "command_id",
                )
            )
            or any(
                getattr(binding, field) != getattr(plan, field)
                for field in (
                    "pilot_outcome_binding_id",
                    "intake_plan_id",
                    "critic_plan_id",
                    "command_id",
                    "candidate_id",
                    "validated_candidate_digest",
                    "scope_id",
                    "scope_version",
                )
            )
            or row["started_at"] != binding.completed_at.isoformat()
            or row["completed_at"] != binding.completed_at.isoformat()
            or not plan.created_at <= binding.completed_at < plan.deadline
        ):
            raise PilotCriticIntakeRecoveryRequired("pilot Critic Intake checkpoint drifted")
        return binding

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
