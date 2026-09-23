"""Atomic SQLite ledger for asset discovery and AuthorizedAsset publication."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .asset_discovery_models import (
    AssetAdmissionVerdict,
    AssetDiscoveryBatch,
    AssetDiscoveryOutcome,
    AssetDiscoveryPlan,
    AssetDiscoveryState,
    AuthorizedAsset,
)


class AssetDiscoveryStoreRejected(ValueError):
    pass


class AssetDiscoveryRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AssetDiscoveryClaim:
    created: bool
    attempt: int
    outcome: AssetDiscoveryOutcome | None = None


class AssetDiscoveryStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS red_team_asset_discovery_runs (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            );
            CREATE TABLE IF NOT EXISTS red_team_authorized_assets (
                authorized_asset_id TEXT PRIMARY KEY,
                authorization_id TEXT NOT NULL,
                decision_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS red_team_asset_discovery_batches (
                plan_id TEXT NOT NULL,
                query_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY(plan_id, query_id),
                FOREIGN KEY(plan_id) REFERENCES red_team_asset_discovery_runs(plan_id)
            );
            """
        )
        self.connection.commit()

    def claim(self, plan: AssetDiscoveryPlan, *, now: datetime) -> AssetDiscoveryClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_asset_discovery_runs VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return AssetDiscoveryClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] == AssetDiscoveryState.STARTED.value:
                raise AssetDiscoveryRecoveryRequired(
                    "asset discovery has an unfinished STARTED checkpoint"
                ) from None
            return AssetDiscoveryClaim(
                created=False,
                attempt=row["attempt"],
                outcome=AssetDiscoveryOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: AssetDiscoveryPlan, *, now: datetime) -> AssetDiscoveryClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] != AssetDiscoveryState.STARTED.value:
                raise AssetDiscoveryRecoveryRequired(
                    "asset discovery is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise AssetDiscoveryRecoveryRequired(
                    "asset discovery recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_asset_discovery_runs SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise AssetDiscoveryRecoveryRequired("asset discovery recovery raced")
        return AssetDiscoveryClaim(created=True, attempt=attempt)

    def complete(
        self,
        plan: AssetDiscoveryPlan,
        outcome: AssetDiscoveryOutcome,
        authorized_assets: tuple[AuthorizedAsset, ...],
    ) -> None:
        expected_ids = tuple(
            sorted(item.authorized_asset_id for item in authorized_assets)
        )
        decisions = {item.decision_id: item for item in outcome.decisions}
        if outcome.plan_id != plan.plan_id or outcome.authorized_asset_ids != expected_ids:
            raise AssetDiscoveryStoreRejected(
                "asset discovery completion binding is invalid"
            )
        if any(
            asset.authorization_id != plan.authorization.authorization_id
            or asset.decision_id not in decisions
            or decisions[asset.decision_id].verdict is not AssetAdmissionVerdict.ADMITTED
            or decisions[asset.decision_id].asset_id != asset.asset.asset_id
            for asset in authorized_assets
        ):
            raise AssetDiscoveryStoreRejected(
                "AuthorizedAsset publication is not backed by an admitted decision"
            )
        try:
            with self.connection:
                row = self._by_identity(plan)
                self._same(row, plan)
                if (
                    row["state"] != AssetDiscoveryState.STARTED.value
                    or row["attempt"] != outcome.attempt
                ):
                    raise AssetDiscoveryRecoveryRequired(
                        "asset discovery STARTED checkpoint is unavailable"
                    )
                for asset in authorized_assets:
                    existing = self.connection.execute(
                        "SELECT payload FROM red_team_authorized_assets "
                        "WHERE authorized_asset_id=? OR decision_id=?",
                        (asset.authorized_asset_id, asset.decision_id),
                    ).fetchone()
                    if existing is None:
                        self.connection.execute(
                            "INSERT INTO red_team_authorized_assets VALUES (?,?,?,?)",
                            (
                                asset.authorized_asset_id,
                                asset.authorization_id,
                                asset.decision_id,
                                asset.model_dump_json(),
                            ),
                        )
                    elif AuthorizedAsset.model_validate_json(existing["payload"]) != asset:
                        raise AssetDiscoveryStoreRejected(
                            "AuthorizedAsset identity conflicted"
                        )
                changed = self.connection.execute(
                    "UPDATE red_team_asset_discovery_runs "
                    "SET state='completed',completed_at=?,outcome_json=? "
                    "WHERE plan_id=? AND state='started' AND attempt=?",
                    (
                        outcome.completed_at.isoformat(),
                        outcome.model_dump_json(),
                        plan.plan_id,
                        outcome.attempt,
                    ),
                ).rowcount
                if changed != 1:
                    raise AssetDiscoveryRecoveryRequired(
                        "asset discovery completion raced"
                    )
        except sqlite3.IntegrityError as exc:
            raise AssetDiscoveryStoreRejected(
                "asset discovery publication raced"
            ) from exc

    def save_batch(
        self, plan: AssetDiscoveryPlan, batch: AssetDiscoveryBatch
    ) -> None:
        if batch.query_id not in {item.query_id for item in plan.queries}:
            raise AssetDiscoveryStoreRejected(
                "asset discovery batch is not part of the plan"
            )
        with self.connection:
            run = self._by_identity(plan)
            self._same(run, plan)
            if run["state"] != AssetDiscoveryState.STARTED.value:
                raise AssetDiscoveryRecoveryRequired(
                    "asset discovery is not accepting query checkpoints"
                )
            existing = self.connection.execute(
                "SELECT payload FROM red_team_asset_discovery_batches "
                "WHERE plan_id=? AND query_id=?",
                (plan.plan_id, batch.query_id),
            ).fetchone()
            if existing is None:
                self.connection.execute(
                    "INSERT INTO red_team_asset_discovery_batches VALUES (?,?,?)",
                    (plan.plan_id, batch.query_id, batch.model_dump_json()),
                )
            elif AssetDiscoveryBatch.model_validate_json(existing["payload"]) != batch:
                raise AssetDiscoveryStoreRejected(
                    "asset discovery query checkpoint conflicted"
                )

    def batch(self, plan_id: str, query_id: str) -> AssetDiscoveryBatch | None:
        row = self.connection.execute(
            "SELECT payload FROM red_team_asset_discovery_batches "
            "WHERE plan_id=? AND query_id=?",
            (plan_id, query_id),
        ).fetchone()
        if row is None:
            return None
        return AssetDiscoveryBatch.model_validate_json(row["payload"])

    def state(self, plan_id: str) -> tuple[AssetDiscoveryState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_asset_discovery_runs WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return AssetDiscoveryState(row["state"]), row["attempt"]

    def outcome(self, plan_id: str) -> AssetDiscoveryOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM red_team_asset_discovery_runs WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] != AssetDiscoveryState.COMPLETED.value:
            raise AssetDiscoveryRecoveryRequired(
                "completed asset discovery outcome is unavailable"
            )
        return AssetDiscoveryOutcome.model_validate_json(row["outcome_json"])

    def authorized_asset(self, authorized_asset_id: str) -> AuthorizedAsset:
        row = self.connection.execute(
            "SELECT payload FROM red_team_authorized_assets WHERE authorized_asset_id=?",
            (authorized_asset_id,),
        ).fetchone()
        if row is None:
            raise AssetDiscoveryStoreRejected("AuthorizedAsset is unavailable")
        return AuthorizedAsset.model_validate_json(row["payload"])

    def authorized_asset_count(self) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM red_team_authorized_assets"
            ).fetchone()[0]
        )

    def _by_identity(self, plan: AssetDiscoveryPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_asset_discovery_runs "
            "WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise AssetDiscoveryRecoveryRequired(
                "asset discovery checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: AssetDiscoveryPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise AssetDiscoveryStoreRejected(
                "asset discovery identity was reused for different content"
            )
