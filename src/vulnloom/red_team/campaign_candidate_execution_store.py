"""Transactional B5.8 ledger for Campaign Candidate validation execution."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .campaign_candidate_execution_models import (
    CampaignCandidateValidationCompletionCheckpoint,
    CampaignCandidateValidationExecutionOutcome,
    CampaignCandidateValidationExecutionPlan,
    CampaignCandidateValidationExecutionState,
)


class CampaignCandidateValidationExecutionStoreRejected(ValueError):
    pass


class CampaignCandidateValidationExecutionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignCandidateValidationExecutionClaim:
    created: bool
    attempt: int
    outcome: CampaignCandidateValidationExecutionOutcome | None = None


class CampaignCandidateValidationExecutionStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS red_team_campaign_candidate_validation_executions (
                execution_plan_id TEXT PRIMARY KEY,
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
        self, plan: CampaignCandidateValidationExecutionPlan, *, now: datetime
    ) -> CampaignCandidateValidationExecutionClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_candidate_validation_executions VALUES "
                    "(?,?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.execution_plan_id,
                        plan.idempotency_key,
                        str(plan.candidate_id),
                        plan.candidate_digest,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignCandidateValidationExecutionClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            with self.connection:
                row = self._row(plan)
                self._same(row, plan)
                if row["state"] == CampaignCandidateValidationExecutionState.COMPLETED.value:
                    return CampaignCandidateValidationExecutionClaim(
                        created=False,
                        attempt=row["attempt"],
                        outcome=CampaignCandidateValidationExecutionOutcome.model_validate_json(
                            row["outcome_json"]
                        ),
                    )
                if row["attempt"] >= plan.limits.max_attempts:
                    raise CampaignCandidateValidationExecutionRecoveryRequired(
                        "Campaign Candidate validation execution recovery attempts are exhausted"
                    ) from None
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE red_team_campaign_candidate_validation_executions "
                    "SET attempt=?,started_at=? WHERE execution_plan_id=? "
                    "AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.execution_plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise CampaignCandidateValidationExecutionRecoveryRequired(
                        "Campaign Candidate validation execution recovery raced"
                    ) from None
            return CampaignCandidateValidationExecutionClaim(created=False, attempt=attempt)

    def complete(
        self,
        plan: CampaignCandidateValidationExecutionPlan,
        outcome: CampaignCandidateValidationExecutionOutcome,
    ) -> None:
        if (
            outcome.execution_plan_id != plan.execution_plan_id
            or outcome.checkpoint.candidate_id != plan.candidate_id
            or outcome.checkpoint.candidate_digest != plan.candidate_digest
        ):
            raise CampaignCandidateValidationExecutionStoreRejected(
                "Campaign Candidate validation execution completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if (
                row["state"] != CampaignCandidateValidationExecutionState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise CampaignCandidateValidationExecutionRecoveryRequired(
                    "Campaign Candidate validation execution STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_candidate_validation_executions "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE execution_plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    plan.execution_plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise CampaignCandidateValidationExecutionRecoveryRequired(
                    "Campaign Candidate validation execution completion raced"
                )

    def checkpoint(self, candidate_id: UUID) -> CampaignCandidateValidationCompletionCheckpoint:
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_validation_executions "
            "WHERE candidate_id=? AND state='completed'",
            (str(candidate_id),),
        ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return CampaignCandidateValidationExecutionOutcome.model_validate_json(
            row["outcome_json"]
        ).checkpoint

    def state(self, plan_id: str) -> tuple[CampaignCandidateValidationExecutionState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_campaign_candidate_validation_executions "
            "WHERE execution_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return CampaignCandidateValidationExecutionState(row["state"]), row["attempt"]

    def _row(self, plan: CampaignCandidateValidationExecutionPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_candidate_validation_executions "
            "WHERE execution_plan_id=? OR idempotency_key=? "
            "OR candidate_id=? OR candidate_digest=?",
            (
                plan.execution_plan_id,
                plan.idempotency_key,
                str(plan.candidate_id),
                plan.candidate_digest,
            ),
        ).fetchone()
        if row is None:
            raise CampaignCandidateValidationExecutionRecoveryRequired(
                "Campaign Candidate validation execution checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: CampaignCandidateValidationExecutionPlan) -> None:
        if (
            row["execution_plan_id"] != plan.execution_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignCandidateValidationExecutionStoreRejected(
                "Campaign Candidate validation execution identity was reused for different content"
            )
