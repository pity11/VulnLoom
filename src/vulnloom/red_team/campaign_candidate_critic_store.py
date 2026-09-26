"""Transactional B5.9 ledger for Campaign Candidate Critic Intake."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .campaign_candidate_critic_models import (
    CampaignCandidateCriticIntakeCheckpoint,
    CampaignCandidateCriticIntakeOutcome,
    CampaignCandidateCriticIntakePlan,
    CampaignCandidateCriticIntakeState,
)


class CampaignCandidateCriticIntakeStoreRejected(ValueError):
    pass


class CampaignCandidateCriticIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignCandidateCriticIntakeClaim:
    created: bool
    attempt: int
    outcome: CampaignCandidateCriticIntakeOutcome | None = None


class CampaignCandidateCriticIntakeStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_campaign_candidate_critic_intakes (
                critic_intake_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                candidate_id TEXT NOT NULL UNIQUE,
                candidate_digest TEXT NOT NULL UNIQUE,
                validation_run_id TEXT NOT NULL UNIQUE,
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
        self, plan: CampaignCandidateCriticIntakePlan, *, now: datetime
    ) -> CampaignCandidateCriticIntakeClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_candidate_critic_intakes VALUES "
                    "(?,?,?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.critic_intake_plan_id,
                        plan.idempotency_key,
                        str(plan.candidate_id),
                        plan.candidate_digest,
                        str(plan.validation_run_id),
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignCandidateCriticIntakeClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            with self.connection:
                row = self._row(plan)
                self._same(row, plan)
                if row["state"] == CampaignCandidateCriticIntakeState.COMPLETED.value:
                    return CampaignCandidateCriticIntakeClaim(
                        created=False,
                        attempt=row["attempt"],
                        outcome=CampaignCandidateCriticIntakeOutcome.model_validate_json(
                            row["outcome_json"]
                        ),
                    )
                if row["attempt"] >= plan.limits.max_attempts:
                    raise CampaignCandidateCriticIntakeRecoveryRequired(
                        "Campaign Candidate Critic Intake recovery attempts are exhausted"
                    ) from None
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE red_team_campaign_candidate_critic_intakes "
                    "SET attempt=?,started_at=? WHERE critic_intake_plan_id=? "
                    "AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.critic_intake_plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise CampaignCandidateCriticIntakeRecoveryRequired(
                        "Campaign Candidate Critic Intake recovery raced"
                    ) from None
            return CampaignCandidateCriticIntakeClaim(created=False, attempt=attempt)

    def complete(
        self,
        plan: CampaignCandidateCriticIntakePlan,
        outcome: CampaignCandidateCriticIntakeOutcome,
    ) -> None:
        if (
            outcome.critic_intake_plan_id != plan.critic_intake_plan_id
            or outcome.checkpoint.candidate_id != plan.candidate_id
            or outcome.checkpoint.candidate_digest != plan.candidate_digest
            or outcome.checkpoint.validation_run_id != plan.validation_run_id
        ):
            raise CampaignCandidateCriticIntakeStoreRejected(
                "Campaign Candidate Critic Intake completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != CampaignCandidateCriticIntakeState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise CampaignCandidateCriticIntakeRecoveryRequired(
                    "Campaign Candidate Critic Intake STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_candidate_critic_intakes "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE critic_intake_plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    plan.critic_intake_plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise CampaignCandidateCriticIntakeRecoveryRequired(
                    "Campaign Candidate Critic Intake completion raced"
                )

    def checkpoint(self, candidate_id: UUID) -> CampaignCandidateCriticIntakeCheckpoint:
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_critic_intakes "
            "WHERE candidate_id=? AND state='completed'",
            (str(candidate_id),),
        ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return CampaignCandidateCriticIntakeOutcome.model_validate_json(
            row["outcome_json"]
        ).checkpoint

    def plan(self, plan_id: str) -> CampaignCandidateCriticIntakePlan:
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_campaign_candidate_critic_intakes "
            "WHERE critic_intake_plan_id=? AND state='completed'",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return CampaignCandidateCriticIntakePlan.model_validate_json(row["plan_json"])

    def outcome(self, plan_id: str) -> CampaignCandidateCriticIntakeOutcome:
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_critic_intakes "
            "WHERE critic_intake_plan_id=? AND state='completed'",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return CampaignCandidateCriticIntakeOutcome.model_validate_json(row["outcome_json"])

    def state(self, plan_id: str) -> tuple[CampaignCandidateCriticIntakeState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_campaign_candidate_critic_intakes "
            "WHERE critic_intake_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return CampaignCandidateCriticIntakeState(row["state"]), row["attempt"]

    def _row(self, plan: CampaignCandidateCriticIntakePlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_candidate_critic_intakes "
            "WHERE critic_intake_plan_id=? OR idempotency_key=? "
            "OR candidate_id=? OR candidate_digest=? OR validation_run_id=?",
            (
                plan.critic_intake_plan_id,
                plan.idempotency_key,
                str(plan.candidate_id),
                plan.candidate_digest,
                str(plan.validation_run_id),
            ),
        ).fetchone()
        if row is None:
            raise CampaignCandidateCriticIntakeRecoveryRequired(
                "Campaign Candidate Critic Intake checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CampaignCandidateCriticIntakePlan) -> None:
        if (
            row["critic_intake_plan_id"] != plan.critic_intake_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignCandidateCriticIntakeStoreRejected(
                "Campaign Candidate Critic Intake identity was reused for different content"
            )
