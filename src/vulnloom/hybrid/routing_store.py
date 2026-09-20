"""Transactional ledger and restricted plan repository for Hybrid routing."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from vulnloom.domain.digests import canonical_digest
from vulnloom.validation import ValidationPlan

from .routing_models import HybridRouteOutcome, HybridRouteRequest, HybridRouteState


class HybridRouteIdempotencyConflict(ValueError):
    pass


class HybridRouteRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HybridRouteClaim:
    created: bool
    attempt: int
    outcome: HybridRouteOutcome | None = None


class HybridRouteStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        os.chmod(path, 0o600)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS hybrid_routes (
                route_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                request_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN
                    ('started','completed','timed_out','failed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            );
            CREATE TABLE IF NOT EXISTS hybrid_prepared_validations (
                route_id TEXT PRIMARY KEY,
                validation_plan_id TEXT NOT NULL UNIQUE,
                validation_plan_digest TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                FOREIGN KEY(route_id) REFERENCES hybrid_routes(route_id)
            );
            """
        )
        self.connection.execute("PRAGMA foreign_keys = ON")

    def claim(self, request: HybridRouteRequest, *, now: datetime) -> HybridRouteClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO hybrid_routes VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        request.route_id,
                        request.idempotency_key,
                        request.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return HybridRouteClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(request)
            self._same_request(row, request)
            if row["state"] == HybridRouteState.STARTED.value:
                raise HybridRouteRecoveryRequired(
                    "Hybrid Route has an unfinished STARTED checkpoint"
                ) from None
            return HybridRouteClaim(
                created=False,
                attempt=row["attempt"],
                outcome=HybridRouteOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(
        self, request: HybridRouteRequest, policy, *, now: datetime
    ) -> HybridRouteClaim:
        exhausted = False
        attempt = 0
        with self.connection:
            row = self._by_identity(request)
            self._same_request(row, request)
            if row["state"] != HybridRouteState.STARTED.value:
                raise HybridRouteRecoveryRequired("Hybrid Route is not awaiting recovery")
            if row["attempt"] >= policy.max_attempts:
                outcome = HybridRouteOutcome(
                    route_id=request.route_id,
                    state=HybridRouteState.FAILED,
                    attempt=row["attempt"],
                    endpoint_reference_id=request.endpoint_reference.reference_id,
                    endpoint_url_digest=request.endpoint_url_digest,
                    reason_code="recovery_attempts_exhausted",
                    cleanup_complete=True,
                    completed_at=now,
                )
                self.connection.execute(
                    "UPDATE hybrid_routes SET state='failed',completed_at=?,outcome_json=? "
                    "WHERE route_id=? AND state='started' AND attempt=?",
                    (
                        now.isoformat(),
                        outcome.model_dump_json(),
                        request.route_id,
                        row["attempt"],
                    ),
                )
                exhausted = True
            else:
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE hybrid_routes SET attempt=?,started_at=? "
                    "WHERE route_id=? AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), request.route_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise HybridRouteRecoveryRequired("Hybrid Route recovery raced")
        if exhausted:
            raise HybridRouteRecoveryRequired("Hybrid Route recovery attempts are exhausted")
        return HybridRouteClaim(created=True, attempt=attempt)

    def complete(
        self,
        outcome: HybridRouteOutcome,
        *,
        validation_plan: ValidationPlan | None = None,
    ) -> None:
        plan_digest = (
            canonical_digest(validation_plan.model_dump(mode="python"))
            if validation_plan is not None
            else None
        )
        if validation_plan is not None and (
            outcome.state is not HybridRouteState.COMPLETED
            or outcome.validation_plan_id != validation_plan.plan_id
            or outcome.validation_plan_digest != plan_digest
        ):
            raise HybridRouteRecoveryRequired("Hybrid prepared Validation binding is invalid")
        with self.connection:
            if validation_plan is not None:
                self.connection.execute(
                    "INSERT INTO hybrid_prepared_validations VALUES (?,?,?,?)",
                    (
                        outcome.route_id,
                        validation_plan.plan_id,
                        plan_digest,
                        validation_plan.model_dump_json(),
                    ),
                )
            changed = self.connection.execute(
                "UPDATE hybrid_routes SET state=?,completed_at=?,outcome_json=? "
                "WHERE route_id=? AND state='started' AND attempt=?",
                (
                    outcome.state.value,
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.route_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise HybridRouteRecoveryRequired("Hybrid Route STARTED checkpoint is unavailable")

    def prepared_validation(self, route_id: str) -> ValidationPlan:
        row = self.connection.execute(
            "SELECT r.state,p.validation_plan_id,p.validation_plan_digest,p.plan_json "
            "FROM hybrid_routes r JOIN hybrid_prepared_validations p USING(route_id) "
            "WHERE r.route_id=?",
            (route_id,),
        ).fetchone()
        if row is None or row["state"] != HybridRouteState.COMPLETED.value:
            raise HybridRouteRecoveryRequired("prepared Hybrid Validation is unavailable")
        plan = ValidationPlan.model_validate_json(row["plan_json"])
        if (
            plan.plan_id != row["validation_plan_id"]
            or canonical_digest(plan.model_dump(mode="python"))
            != row["validation_plan_digest"]
        ):
            raise HybridRouteRecoveryRequired("prepared Hybrid Validation integrity failed")
        return plan

    def state(self, route_id: str) -> tuple[HybridRouteState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM hybrid_routes WHERE route_id=?", (route_id,)
        ).fetchone()
        return (HybridRouteState(row["state"]), row["attempt"]) if row else None

    def _by_identity(self, request: HybridRouteRequest) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM hybrid_routes WHERE route_id=? OR idempotency_key=?",
            (request.route_id, request.idempotency_key),
        ).fetchone()
        if row is None:
            raise HybridRouteRecoveryRequired("Hybrid Route checkpoint is unavailable")
        return row

    @staticmethod
    def _same_request(row: sqlite3.Row, request: HybridRouteRequest) -> None:
        if (
            row["route_id"] != request.route_id
            or row["request_json"] != request.model_dump_json()
        ):
            raise HybridRouteIdempotencyConflict(
                "Hybrid Route identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> HybridRouteStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
