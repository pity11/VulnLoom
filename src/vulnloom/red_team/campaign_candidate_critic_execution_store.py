"""Transactional B5.10 Campaign Candidate Critic execution ledger."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .campaign_candidate_critic_execution_models import (
    CampaignCandidateCriticExecutionOutcome,
    CampaignCandidateCriticExecutionPlan,
    CampaignCandidateCriticExecutionState,
)


class CampaignCandidateCriticExecutionStoreRejected(ValueError):
    pass


class CampaignCandidateCriticExecutionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignCandidateCriticExecutionClaim:
    created: bool
    attempt: int
    outcome: CampaignCandidateCriticExecutionOutcome | None = None


class CampaignCandidateCriticExecutionStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        connection.row_factory = sqlite3.Row
        connection.execute("""CREATE TABLE IF NOT EXISTS
            red_team_campaign_candidate_critic_executions (
            execution_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            candidate_id TEXT NOT NULL UNIQUE, candidate_digest TEXT NOT NULL UNIQUE,
            critic_intake_plan_id TEXT NOT NULL UNIQUE, plan_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3), started_at TEXT NOT NULL,
            completed_at TEXT, outcome_json TEXT)""")
        connection.commit()

    def claim(
        self, plan: CampaignCandidateCriticExecutionPlan, *, now: datetime
    ) -> CampaignCandidateCriticExecutionClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_campaign_candidate_critic_executions "
                    "VALUES (?,?,?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.execution_plan_id,
                        plan.idempotency_key,
                        str(plan.candidate_id),
                        plan.candidate_digest,
                        plan.critic_intake_plan_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return CampaignCandidateCriticExecutionClaim(True, 1)
        except sqlite3.IntegrityError:
            with self.connection:
                row = self._row(plan)
                self._same(row, plan)
                if row["state"] == CampaignCandidateCriticExecutionState.COMPLETED.value:
                    return CampaignCandidateCriticExecutionClaim(
                        False,
                        row["attempt"],
                        CampaignCandidateCriticExecutionOutcome.model_validate_json(
                            row["outcome_json"]
                        ),
                    )
                if row["attempt"] >= plan.limits.max_attempts:
                    raise CampaignCandidateCriticExecutionRecoveryRequired(
                        "Campaign Candidate Critic execution recovery attempts are exhausted"
                    ) from None
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE red_team_campaign_candidate_critic_executions "
                    "SET attempt=?,started_at=? WHERE execution_plan_id=? "
                    "AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.execution_plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise CampaignCandidateCriticExecutionRecoveryRequired(
                        "Campaign Candidate Critic execution recovery raced"
                    ) from None
            return CampaignCandidateCriticExecutionClaim(False, attempt)

    def complete(self, plan, outcome):
        if (
            outcome.execution_plan_id != plan.execution_plan_id
            or outcome.checkpoint.candidate_id != plan.candidate_id
        ):
            raise CampaignCandidateCriticExecutionStoreRejected(
                "Campaign Candidate Critic execution completion binding is invalid"
            )
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != "started" or row["attempt"] != outcome.attempt:
                raise CampaignCandidateCriticExecutionRecoveryRequired(
                    "Campaign Candidate Critic execution STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_campaign_candidate_critic_executions "
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
                raise CampaignCandidateCriticExecutionRecoveryRequired(
                    "Campaign Candidate Critic execution completion raced"
                )

    def plan(self, plan_id):
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_campaign_candidate_critic_executions "
            "WHERE execution_plan_id=? AND state='completed'",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return CampaignCandidateCriticExecutionPlan.model_validate_json(row["plan_json"])

    def outcome(self, plan_id):
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_critic_executions "
            "WHERE execution_plan_id=? AND state='completed'",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return CampaignCandidateCriticExecutionOutcome.model_validate_json(row["outcome_json"])

    def checkpoint(self, candidate_id: UUID):
        return self._outcome_by_candidate(candidate_id).checkpoint

    def _outcome_by_candidate(self, candidate_id):
        row = self.connection.execute(
            "SELECT outcome_json FROM red_team_campaign_candidate_critic_executions "
            "WHERE candidate_id=? AND state='completed'",
            (str(candidate_id),),
        ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return CampaignCandidateCriticExecutionOutcome.model_validate_json(row["outcome_json"])

    def state(self, plan_id):
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_campaign_candidate_critic_executions "
            "WHERE execution_plan_id=?",
            (plan_id,),
        ).fetchone()
        return (
            None
            if row is None
            else (CampaignCandidateCriticExecutionState(row["state"]), row["attempt"])
        )

    def _row(self, plan):
        row = self.connection.execute(
            "SELECT * FROM red_team_campaign_candidate_critic_executions "
            "WHERE execution_plan_id=? OR idempotency_key=? OR candidate_id=? "
            "OR candidate_digest=? OR critic_intake_plan_id=?",
            (
                plan.execution_plan_id,
                plan.idempotency_key,
                str(plan.candidate_id),
                plan.candidate_digest,
                plan.critic_intake_plan_id,
            ),
        ).fetchone()
        if row is None:
            raise CampaignCandidateCriticExecutionRecoveryRequired(
                "Campaign Candidate Critic execution checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row, plan):
        if (
            row["execution_plan_id"] != plan.execution_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise CampaignCandidateCriticExecutionStoreRejected(
                "Campaign Candidate Critic execution identity was reused for different content"
            )
