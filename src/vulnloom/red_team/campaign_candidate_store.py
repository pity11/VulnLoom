"""Transactional B5.6 ledger for Campaign Candidate Intake."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .campaign_candidate_models import (
    CampaignCandidate,
    CampaignCandidateIntakeOutcome,
    CampaignCandidateIntakePlan,
    CampaignCandidateIntakeState,
)


class CampaignCandidateIntakeStoreRejected(ValueError):
    pass


class CampaignCandidateIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignCandidateIntakeClaim:
    created: bool
    attempt: int
    outcome: CampaignCandidateIntakeOutcome | None = None


class CampaignCandidateIntakeStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_campaign_candidate_intakes (
                intake_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                closure_id TEXT NOT NULL UNIQUE,
                candidate_id TEXT NOT NULL UNIQUE,
                duplicate_fingerprint TEXT NOT NULL UNIQUE,
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
        self, plan: CampaignCandidateIntakePlan, *, now: datetime
    ) -> CampaignCandidateIntakeClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_candidate_intakes VALUES "
                    "(?,?,?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.intake_plan_id,
                        plan.idempotency_key,
                        plan.closure_id,
                        str(plan.candidate_id),
                        plan.duplicate_fingerprint,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignCandidateIntakeClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            with self.connection:
                row = self._row(plan)
                self._same(row, plan)
                if row["state"] == CampaignCandidateIntakeState.COMPLETED.value:
                    return CampaignCandidateIntakeClaim(
                        created=False,
                        attempt=row["attempt"],
                        outcome=CampaignCandidateIntakeOutcome.model_validate_json(
                            row["outcome_json"]
                        ),
                    )
                if row["attempt"] >= plan.limits.max_attempts:
                    raise CampaignCandidateIntakeRecoveryRequired(
                        "Campaign Candidate Intake recovery attempts are exhausted"
                    ) from None
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE red_team_campaign_candidate_intakes SET attempt=?,started_at=? "
                    "WHERE intake_plan_id=? AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.intake_plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise CampaignCandidateIntakeRecoveryRequired(
                        "Campaign Candidate Intake recovery raced"
                    ) from None
            return CampaignCandidateIntakeClaim(created=False, attempt=attempt)

    def complete(
        self, plan: CampaignCandidateIntakePlan, outcome: CampaignCandidateIntakeOutcome
    ) -> None:
        if (
            outcome.intake_plan_id != plan.intake_plan_id
            or outcome.candidate.candidate_id != plan.candidate_id
            or outcome.candidate.closure_id != plan.closure_id
        ):
            raise CampaignCandidateIntakeStoreRejected(
                "Campaign Candidate Intake completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != CampaignCandidateIntakeState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise CampaignCandidateIntakeRecoveryRequired(
                    "Campaign Candidate Intake STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_candidate_intakes "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE intake_plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    plan.intake_plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise CampaignCandidateIntakeRecoveryRequired(
                    "Campaign Candidate Intake completion raced"
                )

    def candidate(self, candidate_id: UUID) -> CampaignCandidate:
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_intakes "
            "WHERE candidate_id=? AND state='completed'",
            (str(candidate_id),),
        ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return CampaignCandidateIntakeOutcome.model_validate_json(row["outcome_json"]).candidate

    def plan(self, plan_id: str) -> CampaignCandidateIntakePlan:
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_campaign_candidate_intakes WHERE intake_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return CampaignCandidateIntakePlan.model_validate_json(row["plan_json"])

    def outcome(self, plan_id: str) -> CampaignCandidateIntakeOutcome:
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_intakes "
            "WHERE intake_plan_id=? AND state='completed'",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return CampaignCandidateIntakeOutcome.model_validate_json(row["outcome_json"])

    def state(self, plan_id: str) -> tuple[CampaignCandidateIntakeState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_campaign_candidate_intakes WHERE intake_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return CampaignCandidateIntakeState(row["state"]), row["attempt"]

    def _row(self, plan: CampaignCandidateIntakePlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_candidate_intakes "
            "WHERE intake_plan_id=? OR idempotency_key=? OR closure_id=? "
            "OR candidate_id=? OR duplicate_fingerprint=?",
            (
                plan.intake_plan_id,
                plan.idempotency_key,
                plan.closure_id,
                str(plan.candidate_id),
                plan.duplicate_fingerprint,
            ),
        ).fetchone()
        if row is None:
            raise CampaignCandidateIntakeRecoveryRequired(
                "Campaign Candidate Intake checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CampaignCandidateIntakePlan) -> None:
        if (
            row["intake_plan_id"] != plan.intake_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignCandidateIntakeStoreRejected(
                "Campaign Candidate Intake identity was reused for different content"
            )
