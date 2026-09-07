"""Crash-safe unique consumption of pilot Intake and Finding promotion Approval."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_promotion_models import PilotFindingPromotionBinding, PilotFindingPromotionPlan

# SQL column names are code-owned, never derived from a caller or Agent.
_UNIQUE_FIELDS = (
    "idempotency_key",
    "pilot_intake_binding_id",
    "execution_plan_id",
    "approval_id",
    "intake_record_id",
    "promotion_plan_id",
    "finding_id",
)


class PilotFindingPromotionConflict(ValueError):
    pass


class PilotFindingPromotionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotFindingPromotionClaim:
    created: bool
    binding: PilotFindingPromotionBinding | None = None


class PilotFindingPromotionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        columns = ", ".join(f"{field} TEXT NOT NULL UNIQUE" for field in _UNIQUE_FIELDS)
        self.connection.execute(
            f"""CREATE TABLE IF NOT EXISTS pilot_finding_promotions (
            plan_id TEXT PRIMARY KEY, {columns}, plan_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def has_promotion_checkpoint(self, promotion_plan_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM pilot_finding_promotions WHERE promotion_plan_id=?",
                (promotion_plan_id,),
            ).fetchone()
            is not None
        )

    def claim(
        self, plan: PilotFindingPromotionPlan, *, now: datetime
    ) -> PilotFindingPromotionClaim:
        params = (plan.plan_id, *(str(getattr(plan, field)) for field in _UNIQUE_FIELDS))
        conditions = " OR ".join(f"{field}=?" for field in ("plan_id", *_UNIQUE_FIELDS))
        row = self.connection.execute(
            f"SELECT * FROM pilot_finding_promotions WHERE {conditions}", params
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
                raise PilotFindingPromotionConflict("pilot Intake, promotion or Approval consumed")
            return PilotFindingPromotionClaim(False, self.load_completed(plan.plan_id))
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO pilot_finding_promotions VALUES "
                    "(?,?,?,?,?,?,?,?,?,'started',?,NULL,NULL)",
                    (*params, plan.model_dump_json(), now.isoformat()),
                )
        except sqlite3.IntegrityError as exc:
            raise PilotFindingPromotionConflict("concurrent pilot Finding promotion claim") from exc
        return PilotFindingPromotionClaim(True)

    def complete(self, binding: PilotFindingPromotionBinding) -> None:
        fields = _UNIQUE_FIELDS[1:]
        conditions = " AND ".join(f"{field}=?" for field in fields)
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_finding_promotions SET state='completed',"
                "completed_at=?,binding_json=? "
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
            raise PilotFindingPromotionRecoveryRequired(
                "pilot Finding promotion STARTED unavailable"
            )

    def load_completed(self, plan_id: str) -> PilotFindingPromotionBinding:
        row = self.connection.execute(
            "SELECT * FROM pilot_finding_promotions WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ValueError("pilot Finding promotion unavailable")
        if row["state"] != "completed" or row["binding_json"] is None:
            raise PilotFindingPromotionRecoveryRequired(
                "pilot Finding promotion unfinished STARTED"
            )
        plan = PilotFindingPromotionPlan.model_validate_json(row["plan_json"])
        binding = PilotFindingPromotionBinding.model_validate_json(row["binding_json"])
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
                    "approval_digest",
                )
            )
            or row["started_at"] != binding.completed_at.isoformat()
            or row["completed_at"] != binding.completed_at.isoformat()
            or not plan.created_at <= binding.completed_at < plan.deadline
        ):
            raise PilotFindingPromotionRecoveryRequired(
                "pilot Finding promotion checkpoint drifted"
            )
        return binding

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
