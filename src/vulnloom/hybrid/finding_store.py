"""Transactional checkpoints for Hybrid Finding promotion."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import UUID

from .finding_models import HybridFindingPromotionOutcome, HybridFindingPromotionPlan


class HybridFindingConflict(ValueError):
    pass


class HybridFindingRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HybridFindingClaim:
    created: bool
    attempt: int
    outcome: HybridFindingPromotionOutcome | None = None


class HybridFindingPromotionStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS hybrid_finding_promotions (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                hybrid_chain_id TEXT NOT NULL UNIQUE,
                finding_id TEXT NOT NULL UNIQUE,
                approval_id TEXT NOT NULL UNIQUE,
                approval_digest TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed','timed_out','failed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(
        self,
        plan: HybridFindingPromotionPlan,
        *,
        approval_id: UUID,
        approval_digest: str,
        now: datetime,
    ) -> HybridFindingClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO hybrid_finding_promotions "
                    "(plan_id,idempotency_key,hybrid_chain_id,finding_id,approval_id,"
                    "approval_digest,plan_json,state,attempt,started_at) "
                    "VALUES (?,?,?,?,?,?,?,'started',1,?)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.hybrid_chain_id,
                        str(plan.finding_id),
                        str(approval_id),
                        approval_digest,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return HybridFindingClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan, approval_id=approval_id)
            self._same_plan(
                row,
                plan,
                approval_id=approval_id,
                approval_digest=approval_digest,
            )
            if row["state"] == "started":
                raise HybridFindingRecoveryRequired(
                    "Hybrid Finding promotion has an unfinished STARTED checkpoint"
                ) from None
            return HybridFindingClaim(
                created=False,
                attempt=row["attempt"],
                outcome=HybridFindingPromotionOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(
        self,
        plan: HybridFindingPromotionPlan,
        *,
        approval_id: UUID,
        approval_digest: str,
        now: datetime,
    ) -> HybridFindingClaim:
        exhausted = False
        with self.connection:
            row = self._by_identity(plan, approval_id=approval_id)
            self._same_plan(
                row,
                plan,
                approval_id=approval_id,
                approval_digest=approval_digest,
            )
            if row["state"] != "started":
                raise HybridFindingRecoveryRequired(
                    "Hybrid Finding promotion is not awaiting recovery"
                )
            if row["attempt"] >= plan.max_attempts:
                outcome = HybridFindingPromotionOutcome(
                    plan_id=plan.plan_id,
                    state="failed",
                    attempt=row["attempt"],
                    hybrid_chain_id=plan.hybrid_chain_id,
                    approval_id=approval_id,
                    approval_digest=approval_digest,
                    reason_code="recovery_attempts_exhausted",
                    cleanup_complete=True,
                    completed_at=now,
                )
                self.connection.execute(
                    "UPDATE hybrid_finding_promotions SET state='failed',completed_at=?,"
                    "outcome_json=? WHERE plan_id=? AND state='started' AND attempt=?",
                    (
                        now.isoformat(),
                        outcome.model_dump_json(),
                        plan.plan_id,
                        row["attempt"],
                    ),
                )
                exhausted = True
            else:
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE hybrid_finding_promotions SET attempt=?,started_at=? "
                    "WHERE plan_id=? AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise HybridFindingRecoveryRequired("Hybrid Finding promotion recovery raced")
        if exhausted:
            raise HybridFindingRecoveryRequired(
                "Hybrid Finding promotion recovery attempts are exhausted"
            )
        return HybridFindingClaim(created=True, attempt=attempt)

    def finish(self, outcome: HybridFindingPromotionOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE hybrid_finding_promotions SET state=?,completed_at=?,outcome_json=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.state.value,
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.plan_id,
                    outcome.attempt,
                ),
            ).rowcount
        if changed != 1:
            raise HybridFindingRecoveryRequired(
                "Hybrid Finding promotion STARTED checkpoint is unavailable"
            )

    def state(self, plan_id: str) -> tuple[str, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM hybrid_finding_promotions WHERE plan_id=?", (plan_id,)
        ).fetchone()
        return (row["state"], row["attempt"]) if row else None

    def outcome(self, plan_id: str) -> HybridFindingPromotionOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM hybrid_finding_promotions WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] == "started" or row["outcome_json"] is None:
            raise HybridFindingRecoveryRequired(
                "terminal Hybrid Finding outcome is unavailable"
            )
        return HybridFindingPromotionOutcome.model_validate_json(row["outcome_json"])

    def _by_identity(
        self, plan: HybridFindingPromotionPlan, *, approval_id: UUID
    ) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM hybrid_finding_promotions WHERE plan_id=? OR idempotency_key=? "
            "OR hybrid_chain_id=? OR finding_id=? OR approval_id=?",
            (
                plan.plan_id,
                plan.idempotency_key,
                plan.hybrid_chain_id,
                str(plan.finding_id),
                str(approval_id),
            ),
        ).fetchone()
        if row is None:
            raise HybridFindingRecoveryRequired("Hybrid Finding checkpoint is unavailable")
        return row

    @staticmethod
    def _same_plan(
        row: sqlite3.Row,
        plan: HybridFindingPromotionPlan,
        *,
        approval_id: UUID,
        approval_digest: str,
    ) -> None:
        if (
            row["plan_id"] != plan.plan_id
            or row["plan_json"] != plan.model_dump_json()
            or row["approval_id"] != str(approval_id)
            or row["approval_digest"] != approval_digest
        ):
            raise HybridFindingConflict(
                "Hybrid Finding identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> HybridFindingPromotionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
