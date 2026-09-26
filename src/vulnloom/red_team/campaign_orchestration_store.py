"""Transactional resumable ledger for B5.5 Campaign orchestration."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .campaign_orchestration_models import (
    CampaignOrchestrationOutcome,
    CampaignOrchestrationPlan,
    CampaignOrchestrationState,
    CampaignPhaseCheckpoint,
)


class CampaignOrchestrationStoreRejected(ValueError):
    pass


class CampaignOrchestrationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignOrchestrationClaim:
    created: bool
    attempt: int
    checkpoints: tuple[CampaignPhaseCheckpoint, ...] = ()
    outcome: CampaignOrchestrationOutcome | None = None


class CampaignOrchestrationStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_campaign_orchestrations (
                orchestration_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                checkpoints_json TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )"""
        )
        self.connection.commit()

    def claim(
        self, plan: CampaignOrchestrationPlan, *, now: datetime
    ) -> CampaignOrchestrationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_orchestrations VALUES "
                    "(?,?,?,'started',1,'[]',?,NULL,NULL)",
                    (
                        plan.orchestration_plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignOrchestrationClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            with self.connection:
                row = self._row(plan)
                self._same(row, plan)
                checkpoints = self._checkpoints(row)
                if row["state"] == CampaignOrchestrationState.COMPLETED.value:
                    return CampaignOrchestrationClaim(
                        created=False,
                        attempt=row["attempt"],
                        checkpoints=checkpoints,
                        outcome=CampaignOrchestrationOutcome.model_validate_json(
                            row["outcome_json"]
                        ),
                    )
                if row["attempt"] >= plan.limits.max_attempts:
                    raise CampaignOrchestrationRecoveryRequired(
                        "Campaign Orchestration recovery attempts are exhausted"
                    ) from None
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE red_team_campaign_orchestrations SET attempt=?,started_at=? "
                    "WHERE orchestration_plan_id=? AND state='started' AND attempt=?",
                    (
                        attempt,
                        now.isoformat(),
                        plan.orchestration_plan_id,
                        row["attempt"],
                    ),
                ).rowcount
                if changed != 1:
                    raise CampaignOrchestrationRecoveryRequired(
                        "Campaign Orchestration recovery raced"
                    ) from None
            return CampaignOrchestrationClaim(
                created=False, attempt=attempt, checkpoints=checkpoints
            )

    def record(self, plan: CampaignOrchestrationPlan, checkpoint: CampaignPhaseCheckpoint) -> None:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != CampaignOrchestrationState.STARTED.value:
                raise CampaignOrchestrationStoreRejected(
                    "completed Campaign Orchestration cannot accept checkpoints"
                )
            checkpoints = self._checkpoints(row)
            index = checkpoint.ordinal - 1
            if index < len(checkpoints):
                if checkpoints[index] != checkpoint:
                    raise CampaignOrchestrationStoreRejected(
                        "Campaign Phase checkpoint content drifted"
                    )
                return
            if index != len(checkpoints):
                raise CampaignOrchestrationStoreRejected(
                    "Campaign Phase checkpoint order is invalid"
                )
            encoded = json.dumps(
                [item.model_dump(mode="json") for item in (*checkpoints, checkpoint)],
                sort_keys=True,
                separators=(",", ":"),
            )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_orchestrations SET checkpoints_json=? "
                "WHERE orchestration_plan_id=? AND state='started' AND checkpoints_json=?",
                (encoded, plan.orchestration_plan_id, row["checkpoints_json"]),
            ).rowcount
            if changed != 1:
                raise CampaignOrchestrationRecoveryRequired("Campaign Phase checkpoint raced")

    def complete(
        self,
        plan: CampaignOrchestrationPlan,
        outcome: CampaignOrchestrationOutcome,
        *,
        now: datetime,
    ) -> None:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            checkpoints = self._checkpoints(row)
            if (
                row["state"] != CampaignOrchestrationState.STARTED.value
                or row["attempt"] != outcome.attempt
                or len(checkpoints) != 6
                or tuple(item.checkpoint_id for item in checkpoints)
                != outcome.closure.phase_checkpoint_ids
            ):
                raise CampaignOrchestrationRecoveryRequired(
                    "Campaign Orchestration completion checkpoint is unavailable"
                )
            self.connection.execute(
                "UPDATE red_team_campaign_orchestrations "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE orchestration_plan_id=? AND state='started'",
                (
                    now.isoformat(),
                    outcome.model_dump_json(),
                    plan.orchestration_plan_id,
                ),
            )

    def state(self, plan_id: str) -> tuple[CampaignOrchestrationState, int, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt,checkpoints_json FROM red_team_campaign_orchestrations "
            "WHERE orchestration_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return (
            CampaignOrchestrationState(row["state"]),
            row["attempt"],
            len(json.loads(row["checkpoints_json"])),
        )

    def _row(self, plan: CampaignOrchestrationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_orchestrations "
            "WHERE orchestration_plan_id=? OR idempotency_key=?",
            (plan.orchestration_plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise CampaignOrchestrationRecoveryRequired(
                "Campaign Orchestration checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CampaignOrchestrationPlan) -> None:
        if (
            row["orchestration_plan_id"] != plan.orchestration_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignOrchestrationStoreRejected(
                "Campaign Orchestration identity was reused for different content"
            )

    @staticmethod
    def _checkpoints(row: sqlite3.Row) -> tuple[CampaignPhaseCheckpoint, ...]:
        return tuple(
            CampaignPhaseCheckpoint.model_validate(item)
            for item in json.loads(row["checkpoints_json"])
        )
