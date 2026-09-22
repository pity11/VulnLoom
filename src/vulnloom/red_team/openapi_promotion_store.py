"""Atomic ledger and Endpoint Seed publication for reviewed OpenAPI discoveries."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .openapi_promotion_models import (
    OpenApiDiscoveryPromotionOutcome,
    OpenApiDiscoveryPromotionPlan,
    OpenApiDiscoveryPromotionState,
)
from .seed_models import EndpointSeedSet
from .seed_store import EndpointReconStore


class OpenApiDiscoveryPromotionStoreRejected(ValueError):
    pass


class OpenApiDiscoveryPromotionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class OpenApiDiscoveryPromotionClaim:
    created: bool
    attempt: int
    outcome: OpenApiDiscoveryPromotionOutcome | None = None


class OpenApiDiscoveryPromotionStore:
    """Shares the Endpoint Recon connection so publication and completion are atomic."""

    def __init__(self, endpoint_recon_store: EndpointReconStore):
        self.endpoint_recon_store = endpoint_recon_store
        self.connection = endpoint_recon_store.connection
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS red_team_openapi_discovery_promotions (
                promotion_plan_id TEXT PRIMARY KEY,
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
        self, plan: OpenApiDiscoveryPromotionPlan, *, now: datetime
    ) -> OpenApiDiscoveryPromotionClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_openapi_discovery_promotions VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.promotion_plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return OpenApiDiscoveryPromotionClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] == OpenApiDiscoveryPromotionState.STARTED.value:
                raise OpenApiDiscoveryPromotionRecoveryRequired(
                    "OpenAPI discovery promotion has an unfinished STARTED checkpoint"
                ) from None
            return OpenApiDiscoveryPromotionClaim(
                created=False,
                attempt=row["attempt"],
                outcome=OpenApiDiscoveryPromotionOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: OpenApiDiscoveryPromotionPlan, *, now: datetime
    ) -> OpenApiDiscoveryPromotionClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] != OpenApiDiscoveryPromotionState.STARTED.value:
                raise OpenApiDiscoveryPromotionRecoveryRequired(
                    "OpenAPI discovery promotion is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise OpenApiDiscoveryPromotionRecoveryRequired(
                    "OpenAPI discovery promotion recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_openapi_discovery_promotions "
                "SET attempt=?,started_at=? "
                "WHERE promotion_plan_id=? AND state='started' AND attempt=?",
                (
                    attempt,
                    now.isoformat(),
                    plan.promotion_plan_id,
                    row["attempt"],
                ),
            ).rowcount
            if changed != 1:
                raise OpenApiDiscoveryPromotionRecoveryRequired(
                    "OpenAPI discovery promotion recovery raced"
                )
        return OpenApiDiscoveryPromotionClaim(created=True, attempt=attempt)

    def complete(
        self,
        plan: OpenApiDiscoveryPromotionPlan,
        outcome: OpenApiDiscoveryPromotionOutcome,
        seed_set: EndpointSeedSet,
    ) -> None:
        if (
            outcome.promotion_plan_id != plan.promotion_plan_id
            or outcome.seed_set_id != seed_set.seed_set_id
        ):
            raise OpenApiDiscoveryPromotionStoreRejected(
                "OpenAPI discovery promotion completion binding is invalid"
            )
        try:
            with self.connection:
                row = self._by_identity(plan)
                self._same(row, plan)
                if (
                    row["state"] != OpenApiDiscoveryPromotionState.STARTED.value
                    or row["attempt"] != outcome.attempt
                ):
                    raise OpenApiDiscoveryPromotionRecoveryRequired(
                        "OpenAPI discovery promotion STARTED checkpoint is unavailable"
                    )
                existing = self.connection.execute(
                    "SELECT payload FROM endpoint_seed_sets "
                    "WHERE seed_set_id=? OR idempotency_key=?",
                    (seed_set.seed_set_id, seed_set.idempotency_key),
                ).fetchone()
                if existing is None:
                    self.connection.execute(
                        "INSERT INTO endpoint_seed_sets VALUES (?,?,?)",
                        (
                            seed_set.seed_set_id,
                            seed_set.idempotency_key,
                            seed_set.model_dump_json(),
                        ),
                    )
                elif EndpointSeedSet.model_validate_json(existing["payload"]) != seed_set:
                    raise OpenApiDiscoveryPromotionStoreRejected(
                        "OpenAPI discovery promotion Seed Set identity conflicted"
                    )
                changed = self.connection.execute(
                    "UPDATE red_team_openapi_discovery_promotions "
                    "SET state='completed',completed_at=?,outcome_json=? "
                    "WHERE promotion_plan_id=? AND state='started' AND attempt=?",
                    (
                        outcome.completed_at.isoformat(),
                        outcome.model_dump_json(),
                        plan.promotion_plan_id,
                        outcome.attempt,
                    ),
                ).rowcount
                if changed != 1:
                    raise OpenApiDiscoveryPromotionRecoveryRequired(
                        "OpenAPI discovery promotion completion raced"
                    )
        except sqlite3.IntegrityError as exc:
            raise OpenApiDiscoveryPromotionStoreRejected(
                "OpenAPI discovery promotion publication raced"
            ) from exc

    def state(
        self, promotion_plan_id: str
    ) -> tuple[OpenApiDiscoveryPromotionState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_openapi_discovery_promotions "
            "WHERE promotion_plan_id=?",
            (promotion_plan_id,),
        ).fetchone()
        return (
            (OpenApiDiscoveryPromotionState(row["state"]), row["attempt"])
            if row is not None
            else None
        )

    def outcome(self, promotion_plan_id: str) -> OpenApiDiscoveryPromotionOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_openapi_discovery_promotions "
            "WHERE promotion_plan_id=?",
            (promotion_plan_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] != OpenApiDiscoveryPromotionState.COMPLETED.value
        ):
            raise OpenApiDiscoveryPromotionRecoveryRequired(
                "completed OpenAPI discovery promotion is unavailable"
            )
        return OpenApiDiscoveryPromotionOutcome.model_validate_json(row["outcome_json"])

    def _by_identity(self, plan: OpenApiDiscoveryPromotionPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_openapi_discovery_promotions "
            "WHERE promotion_plan_id=? OR idempotency_key=?",
            (plan.promotion_plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise OpenApiDiscoveryPromotionRecoveryRequired(
                "OpenAPI discovery promotion checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: OpenApiDiscoveryPromotionPlan) -> None:
        if (
            row["promotion_plan_id"] != plan.promotion_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise OpenApiDiscoveryPromotionStoreRejected(
                "OpenAPI discovery promotion identity was reused for different content"
            )
