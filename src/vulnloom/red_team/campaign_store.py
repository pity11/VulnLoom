"""Transactional B5.3 ledger for A4 Campaign qualifications."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .campaign_models import (
    CampaignQualificationState,
    GoalDrivenCampaignPlan,
    GoalDrivenCampaignQualificationOutcome,
)


class CampaignQualificationStoreRejected(ValueError):
    pass


class CampaignQualificationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignQualificationClaim:
    created: bool
    attempt: int
    outcome: GoalDrivenCampaignQualificationOutcome | None = None


class CampaignQualificationStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_campaign_qualifications (
                campaign_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                goal_id TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )"""
        )
        self.connection.commit()

    def claim(
        self, plan: GoalDrivenCampaignPlan, *, now: datetime
    ) -> CampaignQualificationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_qualifications VALUES "
                    "(?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.campaign_plan_id,
                        plan.idempotency_key,
                        plan.goal.goal_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignQualificationClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == CampaignQualificationState.STARTED.value:
                raise CampaignQualificationRecoveryRequired(
                    "Campaign Qualification has unfinished STARTED checkpoint"
                ) from None
            return CampaignQualificationClaim(
                created=False,
                attempt=row["attempt"],
                outcome=GoalDrivenCampaignQualificationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: GoalDrivenCampaignPlan, *, now: datetime
    ) -> CampaignQualificationClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != CampaignQualificationState.STARTED.value:
                raise CampaignQualificationRecoveryRequired(
                    "Campaign Qualification is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise CampaignQualificationRecoveryRequired(
                    "Campaign Qualification recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_campaign_qualifications SET attempt=?,started_at=? "
                "WHERE campaign_plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.campaign_plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise CampaignQualificationRecoveryRequired(
                    "Campaign Qualification recovery raced"
                )
        return CampaignQualificationClaim(created=True, attempt=attempt)

    def complete(
        self,
        plan: GoalDrivenCampaignPlan,
        outcome: GoalDrivenCampaignQualificationOutcome,
    ) -> None:
        if outcome.campaign_plan_id != plan.campaign_plan_id:
            raise CampaignQualificationStoreRejected(
                "Campaign Qualification completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != CampaignQualificationState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise CampaignQualificationRecoveryRequired(
                    "Campaign Qualification STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_qualifications "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE campaign_plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    plan.campaign_plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise CampaignQualificationRecoveryRequired(
                    "Campaign Qualification completion raced"
                )

    def state(self, campaign_plan_id: str) -> tuple[CampaignQualificationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_campaign_qualifications "
            "WHERE campaign_plan_id=?",
            (campaign_plan_id,),
        ).fetchone()
        if row is None:
            return None
        return CampaignQualificationState(row["state"]), row["attempt"]

    def _row(self, plan: GoalDrivenCampaignPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_qualifications "
            "WHERE campaign_plan_id=? OR idempotency_key=?",
            (plan.campaign_plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise CampaignQualificationRecoveryRequired(
                "Campaign Qualification checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: GoalDrivenCampaignPlan) -> None:
        if (
            row["campaign_plan_id"] != plan.campaign_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignQualificationStoreRejected(
                "Campaign Qualification identity was reused for different content"
            )
