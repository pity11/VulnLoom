"""Transactional storage for sealed Endpoint Seed Sets and Recon runs."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .seed_models import (
    EndpointReconOutcome,
    EndpointReconPlan,
    EndpointReconReservation,
    EndpointReconReservationState,
    EndpointReconRunState,
    EndpointSeedSet,
)
from .seed_state_machine import (
    cancel_endpoint_recon,
    consume_endpoint_recon_request,
    expire_endpoint_recon,
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
                flow_plan_id TEXT NOT NULL,
                source_checkpoint_id TEXT NOT NULL,
                request_count INTEGER NOT NULL,
                payload TEXT NOT NULL,
                reservation_state TEXT NOT NULL DEFAULT 'active',
                consumed_count INTEGER NOT NULL DEFAULT 0,
                reservation_updated_at TEXT,
                terminal_reason TEXT
            );
            """
        )
        self._migrate_plan_table()
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

    def seed_set_by_key(self, key: str) -> EndpointSeedSet | None:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_seed_sets WHERE idempotency_key=?", (key,)
        ).fetchone()
        return EndpointSeedSet.model_validate_json(row["payload"]) if row else None

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
                "SELECT COALESCE(SUM(request_count-consumed_count),0) "
                "FROM endpoint_recon_plans "
                "WHERE flow_plan_id=? AND reservation_state='active'",
                (plan.flow_plan_id,),
            ).fetchone()[0]
            if reserved + len(plan.steps) > remaining_actions:
                raise EndpointSeedIdempotencyConflict(
                    "Endpoint Recon reservations exceed the remaining action budget"
                )
            self.connection.execute(
                "INSERT INTO endpoint_recon_plans "
                "(endpoint_recon_plan_id,idempotency_key,flow_plan_id,source_checkpoint_id,"
                "request_count,payload,reservation_state,consumed_count,"
                "reservation_updated_at,terminal_reason) VALUES (?,?,?,?,?,?,'active',0,?,NULL)",
                (
                    plan.endpoint_recon_plan_id,
                    plan.idempotency_key,
                    plan.flow_plan_id,
                    plan.source_checkpoint_id,
                    len(plan.steps),
                    plan.model_dump_json(),
                    plan.created_at.isoformat(),
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

    def plan_by_key(self, key: str) -> EndpointReconPlan | None:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_recon_plans WHERE idempotency_key=?", (key,)
        ).fetchone()
        return EndpointReconPlan.model_validate_json(row["payload"]) if row else None

    def reservation(self, plan_id: str) -> EndpointReconReservation:
        row = self.connection.execute(
            "SELECT payload,reservation_state,consumed_count,"
            "reservation_updated_at,terminal_reason FROM endpoint_recon_plans "
            "WHERE endpoint_recon_plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise EndpointSeedIdempotencyConflict("Endpoint Recon plan is unavailable")
        plan = EndpointReconPlan.model_validate_json(row["payload"])
        return EndpointReconReservation(
            endpoint_recon_plan_id=plan.endpoint_recon_plan_id,
            state=EndpointReconReservationState(row["reservation_state"]),
            reserved_requests=len(plan.steps),
            consumed_requests=row["consumed_count"],
            created_at=plan.created_at,
            updated_at=datetime.fromisoformat(
                row["reservation_updated_at"] or plan.created_at.isoformat()
            ),
            terminal_reason=row["terminal_reason"],
        )

    def consume_request(self, plan_id: str, *, now: datetime) -> EndpointReconReservation:
        with self.connection:
            before = self.reservation(plan_id)
            after = consume_endpoint_recon_request(before, now=now)
            changed = self.connection.execute(
                "UPDATE endpoint_recon_plans SET reservation_state=?,consumed_count=?,"
                "reservation_updated_at=?,terminal_reason=? "
                "WHERE endpoint_recon_plan_id=? AND reservation_state=? "
                "AND consumed_count=?",
                (
                    after.state.value,
                    after.consumed_requests,
                    after.updated_at.isoformat(),
                    after.terminal_reason,
                    plan_id,
                    before.state.value,
                    before.consumed_requests,
                ),
            ).rowcount
            if changed != 1:
                raise EndpointReconRecoveryRequired("Endpoint Recon reservation consumption raced")
        return after

    def cancel_reservation(
        self,
        plan_id: str,
        *,
        now: datetime,
        reason: str = "operator_cancelled",
    ) -> EndpointReconReservation:
        return self._terminal_reservation(plan_id, now=now, expire=False, reason=reason)

    def expire_reservation(self, plan_id: str, *, now: datetime) -> EndpointReconReservation:
        return self._terminal_reservation(
            plan_id, now=now, expire=True, reason="reservation_expired"
        )

    def claim(self, plan: EndpointReconPlan, *, now: datetime) -> EndpointReconClaim:
        with self.connection:
            row = self.connection.execute(
                "SELECT * FROM endpoint_recon_runs "
                "WHERE endpoint_recon_plan_id=? OR idempotency_key=?",
                (plan.endpoint_recon_plan_id, plan.idempotency_key),
            ).fetchone()
            if row is not None:
                self._same(row, plan)
                if row["state"] == EndpointReconRunState.STARTED.value:
                    raise EndpointReconRecoveryRequired(
                        "Endpoint Recon has an unfinished STARTED checkpoint"
                    )
                return EndpointReconClaim(
                    created=False,
                    attempt=row["attempt"],
                    outcome=EndpointReconOutcome.model_validate_json(row["outcome_json"]),
                )
            if (
                self.reservation(plan.endpoint_recon_plan_id).state
                is not EndpointReconReservationState.ACTIVE
            ):
                raise EndpointReconRecoveryRequired("Endpoint Recon reservation is not active")
            try:
                self.connection.execute(
                    "INSERT INTO endpoint_recon_runs VALUES (?,?,?,'started',1,?,NULL)",
                    (
                        plan.endpoint_recon_plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise EndpointReconRecoveryRequired("Endpoint Recon claim raced") from exc
        return EndpointReconClaim(created=True, attempt=1)

    def recover(self, plan: EndpointReconPlan, *, now: datetime) -> EndpointReconClaim:
        if (
            self.reservation(plan.endpoint_recon_plan_id).state
            is not EndpointReconReservationState.ACTIVE
        ):
            raise EndpointReconRecoveryRequired("Endpoint Recon reservation is not active")
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

    def _terminal_reservation(
        self,
        plan_id: str,
        *,
        now: datetime,
        expire: bool,
        reason: str,
    ) -> EndpointReconReservation:
        with self.connection:
            before = self.reservation(plan_id)
            transition = expire_endpoint_recon if expire else cancel_endpoint_recon
            after = (
                transition(before, now=now)
                if expire
                else transition(before, now=now, reason=reason)
            )
            if after == before:
                return before
            changed = self.connection.execute(
                "UPDATE endpoint_recon_plans SET reservation_state=?,"
                "reservation_updated_at=?,terminal_reason=? "
                "WHERE endpoint_recon_plan_id=? AND reservation_state=? "
                "AND consumed_count=?",
                (
                    after.state.value,
                    after.updated_at.isoformat(),
                    after.terminal_reason,
                    plan_id,
                    before.state.value,
                    before.consumed_requests,
                ),
            ).rowcount
            if changed != 1:
                raise EndpointReconRecoveryRequired("Endpoint Recon reservation transition raced")
        return after

    def _migrate_plan_table(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(endpoint_recon_plans)").fetchall()
        }
        additions = {
            "flow_plan_id": "TEXT",
            "reservation_state": "TEXT NOT NULL DEFAULT 'active'",
            "consumed_count": "INTEGER NOT NULL DEFAULT 0",
            "reservation_updated_at": "TEXT",
            "terminal_reason": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in columns:
                self.connection.execute(
                    f"ALTER TABLE endpoint_recon_plans ADD COLUMN {name} {declaration}"
                )
        rows = self.connection.execute(
            "SELECT endpoint_recon_plan_id,payload FROM endpoint_recon_plans "
            "WHERE flow_plan_id IS NULL"
        ).fetchall()
        for row in rows:
            plan = EndpointReconPlan.model_validate_json(row["payload"])
            self.connection.execute(
                "UPDATE endpoint_recon_plans SET flow_plan_id=? "
                "WHERE endpoint_recon_plan_id=? AND flow_plan_id IS NULL",
                (plan.flow_plan_id, row["endpoint_recon_plan_id"]),
            )

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
