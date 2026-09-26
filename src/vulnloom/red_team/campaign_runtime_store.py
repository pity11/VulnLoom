"""Transactional B5.4 ledger for isolated Campaign runtime qualifications."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .campaign_runtime_models import (
    CampaignRuntimeQualificationOutcome,
    CampaignRuntimeQualificationPlan,
    CampaignRuntimeQualificationState,
)


class CampaignRuntimeStoreRejected(ValueError):
    pass


class CampaignRuntimeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignRuntimeClaim:
    created: bool
    attempt: int
    outcome: CampaignRuntimeQualificationOutcome | None = None


class CampaignRuntimeQualificationStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_campaign_runtime_qualifications (
                runtime_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                campaign_outcome_id TEXT NOT NULL UNIQUE,
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
        self, plan: CampaignRuntimeQualificationPlan, *, now: datetime
    ) -> CampaignRuntimeClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_runtime_qualifications VALUES "
                    "(?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.runtime_plan_id,
                        plan.idempotency_key,
                        plan.campaign_outcome_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignRuntimeClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == CampaignRuntimeQualificationState.STARTED.value:
                raise CampaignRuntimeRecoveryRequired(
                    "Campaign Runtime Qualification has unfinished STARTED checkpoint"
                ) from None
            return CampaignRuntimeClaim(
                created=False,
                attempt=row["attempt"],
                outcome=CampaignRuntimeQualificationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: CampaignRuntimeQualificationPlan, *, now: datetime
    ) -> CampaignRuntimeClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != CampaignRuntimeQualificationState.STARTED.value:
                raise CampaignRuntimeRecoveryRequired(
                    "Campaign Runtime Qualification is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise CampaignRuntimeRecoveryRequired(
                    "Campaign Runtime Qualification recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_campaign_runtime_qualifications "
                "SET attempt=?,started_at=? "
                "WHERE runtime_plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.runtime_plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise CampaignRuntimeRecoveryRequired(
                    "Campaign Runtime Qualification recovery raced"
                )
        return CampaignRuntimeClaim(created=True, attempt=attempt)

    def complete(
        self,
        plan: CampaignRuntimeQualificationPlan,
        outcome: CampaignRuntimeQualificationOutcome,
    ) -> None:
        if (
            outcome.runtime_plan_id != plan.runtime_plan_id
            or outcome.campaign_plan_id != plan.campaign_plan_id
            or outcome.campaign_outcome_id != plan.campaign_outcome_id
        ):
            raise CampaignRuntimeStoreRejected(
                "Campaign Runtime Qualification completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != CampaignRuntimeQualificationState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise CampaignRuntimeRecoveryRequired(
                    "Campaign Runtime Qualification STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_runtime_qualifications "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE runtime_plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    plan.runtime_plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise CampaignRuntimeRecoveryRequired(
                    "Campaign Runtime Qualification completion raced"
                )

    def state(
        self, runtime_plan_id: str
    ) -> tuple[CampaignRuntimeQualificationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_campaign_runtime_qualifications "
            "WHERE runtime_plan_id=?",
            (runtime_plan_id,),
        ).fetchone()
        if row is None:
            return None
        return CampaignRuntimeQualificationState(row["state"]), row["attempt"]

    def _row(self, plan: CampaignRuntimeQualificationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_runtime_qualifications "
            "WHERE runtime_plan_id=? OR idempotency_key=? OR campaign_outcome_id=?",
            (
                plan.runtime_plan_id,
                plan.idempotency_key,
                plan.campaign_outcome_id,
            ),
        ).fetchone()
        if row is None:
            raise CampaignRuntimeRecoveryRequired(
                "Campaign Runtime Qualification checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CampaignRuntimeQualificationPlan) -> None:
        if (
            row["runtime_plan_id"] != plan.runtime_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignRuntimeStoreRejected(
                "Campaign Runtime Qualification identity was reused for different content"
            )
