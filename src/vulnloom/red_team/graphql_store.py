"""Transactional STARTED/COMPLETED ledger for GraphQL SDL observations."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .graphql_models import (
    GraphQlSchemaObservationOutcome,
    GraphQlSchemaObservationPlan,
    GraphQlSchemaObservationState,
)


class GraphQlSchemaObservationStoreRejected(ValueError):
    pass


class GraphQlSchemaObservationRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GraphQlSchemaObservationClaim:
    created: bool
    attempt: int
    outcome: GraphQlSchemaObservationOutcome | None = None


class GraphQlSchemaObservationStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS red_team_graphql_schema_observations (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(
        self, plan: GraphQlSchemaObservationPlan, *, now: datetime
    ) -> GraphQlSchemaObservationClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_graphql_schema_observations VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return GraphQlSchemaObservationClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] == GraphQlSchemaObservationState.STARTED.value:
                raise GraphQlSchemaObservationRecoveryRequired(
                    "GraphQL schema observation has an unfinished STARTED checkpoint"
                ) from None
            return GraphQlSchemaObservationClaim(
                created=False,
                attempt=row["attempt"],
                outcome=GraphQlSchemaObservationOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: GraphQlSchemaObservationPlan, *, now: datetime
    ) -> GraphQlSchemaObservationClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] != GraphQlSchemaObservationState.STARTED.value:
                raise GraphQlSchemaObservationRecoveryRequired(
                    "GraphQL schema observation is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise GraphQlSchemaObservationRecoveryRequired(
                    "GraphQL schema observation recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_graphql_schema_observations "
                "SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise GraphQlSchemaObservationRecoveryRequired(
                    "GraphQL schema observation recovery raced"
                )
        return GraphQlSchemaObservationClaim(created=True, attempt=attempt)

    def complete(
        self, outcome: GraphQlSchemaObservationOutcome, *, completed_at: datetime
    ) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE red_team_graphql_schema_observations "
                "SET state='completed',completed_at=?,outcome_json=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (
                    completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.plan_id,
                    outcome.attempt,
                ),
            ).rowcount
        if changed != 1:
            raise GraphQlSchemaObservationRecoveryRequired(
                "GraphQL schema observation STARTED checkpoint is unavailable"
            )

    def state(self, plan_id: str) -> tuple[GraphQlSchemaObservationState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_graphql_schema_observations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        return (
            (GraphQlSchemaObservationState(row["state"]), row["attempt"])
            if row is not None
            else None
        )

    def outcome(self, plan_id: str) -> GraphQlSchemaObservationOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_graphql_schema_observations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] != GraphQlSchemaObservationState.COMPLETED.value
        ):
            raise GraphQlSchemaObservationRecoveryRequired(
                "completed GraphQL schema observation is unavailable"
            )
        return GraphQlSchemaObservationOutcome.model_validate_json(row["outcome_json"])

    def plan(self, plan_id: str) -> GraphQlSchemaObservationPlan:
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_graphql_schema_observations "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise GraphQlSchemaObservationRecoveryRequired(
                "GraphQL schema observation plan is unavailable"
            )
        return GraphQlSchemaObservationPlan.model_validate_json(row["plan_json"])

    def _by_identity(self, plan: GraphQlSchemaObservationPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_graphql_schema_observations "
            "WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise GraphQlSchemaObservationRecoveryRequired(
                "GraphQL schema observation checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: GraphQlSchemaObservationPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise GraphQlSchemaObservationStoreRejected(
                "GraphQL schema observation identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> GraphQlSchemaObservationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
