"""Crash-safe unique consumption of pilot Critic outcome and human Finding Intake."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_intake_models import PilotFindingIntakeBinding, PilotFindingIntakePlan

# SQL column names are code-owned, never derived from a caller or Agent.
_UNIQUE_FIELDS = (
    "idempotency_key",
    "critic_execution_binding_id",
    "intake_plan_id",
    "promotion_plan_id",
    "duplicate_check_id",
    "finding_id",
    "command_id",
)


class PilotFindingIntakeConflict(ValueError):
    pass


class PilotFindingIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotFindingIntakeClaim:
    created: bool
    binding: PilotFindingIntakeBinding | None = None


class PilotFindingIntakeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        columns = ", ".join(f"{field} TEXT NOT NULL UNIQUE" for field in _UNIQUE_FIELDS)
        self.connection.execute(
            f"""CREATE TABLE IF NOT EXISTS pilot_finding_intakes (
            plan_id TEXT PRIMARY KEY, {columns}, plan_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def has_promotion_checkpoint(self, promotion_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_finding_intakes WHERE promotion_plan_id=?",
                (promotion_plan_id,),
            ).fetchone()
            is not None
        )

    def claim(self, plan: PilotFindingIntakePlan, *, now: datetime) -> PilotFindingIntakeClaim:
        params = (plan.plan_id, *(str(getattr(plan, field)) for field in _UNIQUE_FIELDS))
        conditions = " OR ".join(f"{field}=?" for field in ("plan_id", *_UNIQUE_FIELDS))
        row = self.connection.execute(
            f"SELECT * FROM pilot_finding_intakes WHERE {conditions}", params
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
                raise PilotFindingIntakeConflict("pilot Critic, Intake, promotion or key consumed")
            return PilotFindingIntakeClaim(False, self.load_completed(plan.plan_id))
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO pilot_finding_intakes VALUES "
                    "(?,?,?,?,?,?,?,?,?,'started',?,NULL,NULL)",
                    (*params, plan.model_dump_json(), now.isoformat()),
                )
        except sqlite3.IntegrityError as exc:
            raise PilotFindingIntakeConflict("concurrent pilot Finding Intake claim") from exc
        return PilotFindingIntakeClaim(True)

    def complete(self, binding: PilotFindingIntakeBinding) -> None:
        fields = _UNIQUE_FIELDS[1:]
        conditions = " AND ".join(f"{field}=?" for field in fields)
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_finding_intakes SET state='completed',completed_at=?,binding_json=? "
                f"WHERE plan_id=? AND state='started' AND {conditions} AND started_at=?",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.plan_id,
                    *(str(getattr(binding, field)) for field in fields),
                    binding.completed_at.isoformat(),
                ),
            ).rowcount
        if changed != 1:
            raise PilotFindingIntakeRecoveryRequired("pilot Finding Intake STARTED unavailable")

    def load_completed(self, plan_id: str) -> PilotFindingIntakeBinding:
        row = self.connection.execute(
            "SELECT * FROM pilot_finding_intakes WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("pilot Finding Intake unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise PilotFindingIntakeRecoveryRequired("pilot Finding Intake unfinished STARTED")
        plan = PilotFindingIntakePlan.model_validate_json(row["plan_json"])
        binding = PilotFindingIntakeBinding.model_validate_json(row["binding_json"])
        if (
            plan.plan_id != plan_id
            or binding.plan_id != plan_id
            or any(row[field] != str(getattr(plan, field)) for field in _UNIQUE_FIELDS)
            or any(
                getattr(binding, field) != getattr(plan, field)
                for field in (
                    *_UNIQUE_FIELDS[1:],
                    "candidate_id",
                    "candidate_digest",
                    "scope_id",
                    "scope_version",
                )
            )
            or row["started_at"] != binding.completed_at.isoformat()
            or row["completed_at"] != binding.completed_at.isoformat()
            or not plan.created_at <= binding.completed_at < plan.deadline
        ):
            raise PilotFindingIntakeRecoveryRequired("pilot Finding Intake checkpoint drifted")
        return binding

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
