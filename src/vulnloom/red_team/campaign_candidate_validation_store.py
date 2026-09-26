"""Transactional B5.7 ledger for Campaign Candidate Validation Intake."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .campaign_candidate_validation_models import (
    CampaignCandidateLifecycleCheckpoint,
    CampaignCandidateValidationIntakeOutcome,
    CampaignCandidateValidationIntakePlan,
    CampaignCandidateValidationIntakeState,
)


class CampaignCandidateValidationIntakeStoreRejected(ValueError):
    pass


class CampaignCandidateValidationIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignCandidateValidationIntakeClaim:
    created: bool
    attempt: int
    outcome: CampaignCandidateValidationIntakeOutcome | None = None


class CampaignCandidateValidationIntakeStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_campaign_candidate_validation_intakes (
                validation_intake_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                candidate_id TEXT NOT NULL UNIQUE,
                candidate_digest TEXT NOT NULL UNIQUE,
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
        self, plan: CampaignCandidateValidationIntakePlan, *, now: datetime
    ) -> CampaignCandidateValidationIntakeClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_candidate_validation_intakes VALUES "
                    "(?,?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.validation_intake_plan_id,
                        plan.idempotency_key,
                        str(plan.candidate_id),
                        plan.candidate_digest,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignCandidateValidationIntakeClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            with self.connection:
                row = self._row(plan)
                self._same(row, plan)
                if row["state"] == CampaignCandidateValidationIntakeState.COMPLETED.value:
                    return CampaignCandidateValidationIntakeClaim(
                        created=False,
                        attempt=row["attempt"],
                        outcome=CampaignCandidateValidationIntakeOutcome.model_validate_json(
                            row["outcome_json"]
                        ),
                    )
                if row["attempt"] >= plan.limits.max_attempts:
                    raise CampaignCandidateValidationIntakeRecoveryRequired(
                        "Campaign Candidate Validation Intake recovery attempts are exhausted"
                    ) from None
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE red_team_campaign_candidate_validation_intakes "
                    "SET attempt=?,started_at=? WHERE validation_intake_plan_id=? "
                    "AND state='started' AND attempt=?",
                    (
                        attempt,
                        now.isoformat(),
                        plan.validation_intake_plan_id,
                        row["attempt"],
                    ),
                ).rowcount
                if changed != 1:
                    raise CampaignCandidateValidationIntakeRecoveryRequired(
                        "Campaign Candidate Validation Intake recovery raced"
                    ) from None
            return CampaignCandidateValidationIntakeClaim(created=False, attempt=attempt)

    def complete(
        self,
        plan: CampaignCandidateValidationIntakePlan,
        outcome: CampaignCandidateValidationIntakeOutcome,
    ) -> None:
        if (
            outcome.validation_intake_plan_id != plan.validation_intake_plan_id
            or outcome.checkpoint.candidate_id != plan.candidate_id
            or outcome.checkpoint.candidate_digest != plan.candidate_digest
        ):
            raise CampaignCandidateValidationIntakeStoreRejected(
                "Campaign Candidate Validation Intake completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != CampaignCandidateValidationIntakeState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise CampaignCandidateValidationIntakeRecoveryRequired(
                    "Campaign Candidate Validation Intake STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_candidate_validation_intakes "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE validation_intake_plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    plan.validation_intake_plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise CampaignCandidateValidationIntakeRecoveryRequired(
                    "Campaign Candidate Validation Intake completion raced"
                )

    def checkpoint(self, candidate_id: UUID) -> CampaignCandidateLifecycleCheckpoint:
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_validation_intakes "
            "WHERE candidate_id=? AND state='completed'",
            (str(candidate_id),),
        ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return CampaignCandidateValidationIntakeOutcome.model_validate_json(
            row["outcome_json"]
        ).checkpoint

    def state(self, plan_id: str) -> tuple[CampaignCandidateValidationIntakeState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_campaign_candidate_validation_intakes "
            "WHERE validation_intake_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return CampaignCandidateValidationIntakeState(row["state"]), row["attempt"]

    def _row(self, plan: CampaignCandidateValidationIntakePlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_candidate_validation_intakes "
            "WHERE validation_intake_plan_id=? OR idempotency_key=? "
            "OR candidate_id=? OR candidate_digest=?",
            (
                plan.validation_intake_plan_id,
                plan.idempotency_key,
                str(plan.candidate_id),
                plan.candidate_digest,
            ),
        ).fetchone()
        if row is None:
            raise CampaignCandidateValidationIntakeRecoveryRequired(
                "Campaign Candidate Validation Intake checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CampaignCandidateValidationIntakePlan) -> None:
        if (
            row["validation_intake_plan_id"] != plan.validation_intake_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignCandidateValidationIntakeStoreRejected(
                "Campaign Candidate Validation Intake identity was reused for different content"
            )
