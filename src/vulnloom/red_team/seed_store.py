"""Transactional storage for sealed Endpoint Seed Sets and Recon runs."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .seed_models import (
    EndpointReconOutcome,
    EndpointReconPlan,
    EndpointReconRunState,
    EndpointSeedSet,
)


class EndpointSeedIdempotencyConflict(ValueError):
    pass


class EndpointReconRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EndpointReconClaim:
    created: bool
    attempt: int
    outcome: EndpointReconOutcome | None = None


class EndpointReconStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS endpoint_seed_sets (
                seed_set_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS endpoint_recon_runs (
                endpoint_recon_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                outcome_json TEXT
            );
            CREATE TABLE IF NOT EXISTS endpoint_recon_plans (
                endpoint_recon_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                source_checkpoint_id TEXT NOT NULL,
                request_count INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def seal(self, seed_set: EndpointSeedSet) -> EndpointSeedSet:
        row = self.connection.execute(
            "SELECT seed_set_id,payload FROM endpoint_seed_sets "
            "WHERE seed_set_id=? OR idempotency_key=?",
            (seed_set.seed_set_id, seed_set.idempotency_key),
        ).fetchone()
        if row is not None:
            existing = EndpointSeedSet.model_validate_json(row["payload"])
            if existing != seed_set:
                raise EndpointSeedIdempotencyConflict(
                    "Endpoint Seed Set identity was reused for different content"
                )
            return existing
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO endpoint_seed_sets VALUES (?,?,?)",
                    (seed_set.seed_set_id, seed_set.idempotency_key, seed_set.model_dump_json()),
                )
        except sqlite3.IntegrityError as exc:
            raise EndpointSeedIdempotencyConflict("Endpoint Seed Set seal raced") from exc
        return seed_set

    def seed_set(self, seed_set_id: str) -> EndpointSeedSet:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_seed_sets WHERE seed_set_id=?", (seed_set_id,)
        ).fetchone()
        if row is None:
            raise EndpointSeedIdempotencyConflict("Endpoint Seed Set is unavailable")
        return EndpointSeedSet.model_validate_json(row["payload"])

    def reserve(self, plan: EndpointReconPlan, *, remaining_actions: int) -> EndpointReconPlan:
        with self.connection:
            row = self.connection.execute(
                "SELECT endpoint_recon_plan_id,payload FROM endpoint_recon_plans "
                "WHERE endpoint_recon_plan_id=? OR idempotency_key=?",
                (plan.endpoint_recon_plan_id, plan.idempotency_key),
            ).fetchone()
            if row is not None:
                existing = EndpointReconPlan.model_validate_json(row["payload"])
                if existing != plan:
                    raise EndpointSeedIdempotencyConflict(
                        "Endpoint Recon plan identity was reused for different content"
                    )
                return existing
            reserved = self.connection.execute(
                "SELECT COALESCE(SUM(request_count),0) FROM endpoint_recon_plans "
                "WHERE source_checkpoint_id=?",
                (plan.source_checkpoint_id,),
            ).fetchone()[0]
            if reserved + len(plan.steps) > remaining_actions:
                raise EndpointSeedIdempotencyConflict(
                    "Endpoint Recon reservations exceed the remaining action budget"
                )
            self.connection.execute(
                "INSERT INTO endpoint_recon_plans VALUES (?,?,?,?,?)",
                (
                    plan.endpoint_recon_plan_id,
                    plan.idempotency_key,
                    plan.source_checkpoint_id,
                    len(plan.steps),
                    plan.model_dump_json(),
                ),
            )
        return plan

    def plan(self, plan_id: str) -> EndpointReconPlan:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_recon_plans WHERE endpoint_recon_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise EndpointSeedIdempotencyConflict("Endpoint Recon plan is unavailable")
        return EndpointReconPlan.model_validate_json(row["payload"])

    def claim(self, plan: EndpointReconPlan, *, now: datetime) -> EndpointReconClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO endpoint_recon_runs VALUES (?,?,?,'started',1,?,NULL)",
                    (
                        plan.endpoint_recon_plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return EndpointReconClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] == EndpointReconRunState.STARTED.value:
                raise EndpointReconRecoveryRequired(
                    "Endpoint Recon has an unfinished STARTED checkpoint"
                ) from None
            return EndpointReconClaim(
                created=False,
                attempt=row["attempt"],
                outcome=EndpointReconOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: EndpointReconPlan, *, now: datetime) -> EndpointReconClaim:
        with self.connection:
            row = self._row(plan)
            self._same(row, plan)
            if row["state"] != EndpointReconRunState.STARTED.value:
                raise EndpointReconRecoveryRequired("Endpoint Recon is not awaiting recovery")
            if row["attempt"] >= plan.limits.max_attempts:
                raise EndpointReconRecoveryRequired(
                    "Endpoint Recon recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE endpoint_recon_runs SET attempt=?,started_at=? "
                "WHERE endpoint_recon_plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.endpoint_recon_plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise EndpointReconRecoveryRequired("Endpoint Recon recovery raced")
        return EndpointReconClaim(created=True, attempt=attempt)

    def complete(self, outcome: EndpointReconOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE endpoint_recon_runs SET state='completed',outcome_json=? "
                "WHERE endpoint_recon_plan_id=? AND state='started' AND attempt=?",
                (outcome.model_dump_json(), outcome.endpoint_recon_plan_id, outcome.attempt),
            ).rowcount
        if changed != 1:
            raise EndpointReconRecoveryRequired("Endpoint Recon STARTED checkpoint is unavailable")

    def state(self, plan_id: str) -> tuple[EndpointReconRunState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM endpoint_recon_runs WHERE endpoint_recon_plan_id=?",
            (plan_id,),
        ).fetchone()
        return (EndpointReconRunState(row["state"]), row["attempt"]) if row else None

    def outcome(self, plan_id: str) -> EndpointReconOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM endpoint_recon_runs WHERE endpoint_recon_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] != EndpointReconRunState.COMPLETED.value:
            raise EndpointReconRecoveryRequired("Completed Endpoint Recon is unavailable")
        return EndpointReconOutcome.model_validate_json(row["outcome_json"])

    def _row(self, plan: EndpointReconPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM endpoint_recon_runs WHERE endpoint_recon_plan_id=? OR idempotency_key=?",
            (plan.endpoint_recon_plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise EndpointReconRecoveryRequired("Endpoint Recon checkpoint is unavailable")
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: EndpointReconPlan) -> None:
        if (
            row["endpoint_recon_plan_id"] != plan.endpoint_recon_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise EndpointSeedIdempotencyConflict(
                "Endpoint Recon identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> EndpointReconStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
