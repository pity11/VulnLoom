"""Transactional checkpoints for resumable Source Hunt investigations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import (
    InvestigationCheckpoint,
    InvestigationObservation,
    InvestigationPlan,
    RepositoryIndex,
)


class SourceHuntStoreRejected(ValueError):
    pass


class SourceHuntStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS source_hunt_indexes (
                index_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS source_hunt_plans (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                index_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                FOREIGN KEY(index_id) REFERENCES source_hunt_indexes(index_id)
            );
            CREATE TABLE IF NOT EXISTS source_hunt_checkpoints (
                plan_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                checkpoint_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                PRIMARY KEY(plan_id, revision),
                FOREIGN KEY(plan_id) REFERENCES source_hunt_plans(plan_id)
            );
            CREATE TABLE IF NOT EXISTS source_hunt_observations (
                plan_id TEXT NOT NULL,
                query_digest TEXT NOT NULL,
                observation_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                PRIMARY KEY(plan_id, query_digest),
                FOREIGN KEY(plan_id) REFERENCES source_hunt_plans(plan_id)
            );
            """
        )

    def start(
        self,
        *,
        index: RepositoryIndex,
        plan: InvestigationPlan,
        checkpoint: InvestigationCheckpoint,
    ) -> InvestigationCheckpoint:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO source_hunt_indexes VALUES (?, ?)",
                    (index.index_id, index.model_dump_json()),
                )
                existing = self.connection.execute(
                    "SELECT plan_id, payload FROM source_hunt_plans WHERE idempotency_key = ?",
                    (plan.idempotency_key,),
                ).fetchone()
                if existing is not None:
                    if existing[0] != plan.plan_id or InvestigationPlan.model_validate_json(
                        existing[1]
                    ) != plan:
                        raise SourceHuntStoreRejected("Source Hunt idempotency collision")
                    return self.latest(plan.plan_id)
                self.connection.execute(
                    "INSERT INTO source_hunt_plans VALUES (?, ?, ?, ?)",
                    (plan.plan_id, plan.idempotency_key, index.index_id, plan.model_dump_json()),
                )
                self.connection.execute(
                    "INSERT INTO source_hunt_checkpoints VALUES (?, ?, ?, ?)",
                    (
                        plan.plan_id,
                        checkpoint.revision,
                        checkpoint.checkpoint_id,
                        checkpoint.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise SourceHuntStoreRejected("Source Hunt start transaction was rejected") from exc
        return checkpoint

    def advance(
        self,
        *,
        previous: InvestigationCheckpoint,
        checkpoint: InvestigationCheckpoint,
        observation: InvestigationObservation | None = None,
    ) -> tuple[InvestigationCheckpoint, InvestigationObservation | None]:
        if checkpoint.plan_id != previous.plan_id or checkpoint.revision != previous.revision + 1:
            raise SourceHuntStoreRejected("Source Hunt checkpoint sequence is invalid")
        try:
            with self.connection:
                current = self.latest(previous.plan_id)
                if current.checkpoint_id != previous.checkpoint_id:
                    if observation is not None:
                        replay = self.observation(previous.plan_id, observation.query_digest)
                        if replay == observation:
                            return current, replay
                    raise SourceHuntStoreRejected("Source Hunt checkpoint is stale")
                if observation is not None:
                    self.connection.execute(
                        "INSERT INTO source_hunt_observations VALUES (?, ?, ?, ?)",
                        (
                            previous.plan_id,
                            observation.query_digest,
                            observation.observation_id,
                            observation.model_dump_json(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO source_hunt_checkpoints VALUES (?, ?, ?, ?)",
                    (
                        checkpoint.plan_id,
                        checkpoint.revision,
                        checkpoint.checkpoint_id,
                        checkpoint.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise SourceHuntStoreRejected(
                "Source Hunt checkpoint transaction was rejected"
            ) from exc
        return checkpoint, observation

    def latest(self, plan_id: str) -> InvestigationCheckpoint:
        row = self.connection.execute(
            "SELECT payload FROM source_hunt_checkpoints WHERE plan_id = ? "
            "ORDER BY revision DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise SourceHuntStoreRejected("Source Hunt plan is unavailable")
        return InvestigationCheckpoint.model_validate_json(row[0])

    def plan(self, plan_id: str) -> InvestigationPlan:
        row = self.connection.execute(
            "SELECT payload FROM source_hunt_plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            raise SourceHuntStoreRejected("Source Hunt plan is unavailable")
        return InvestigationPlan.model_validate_json(row[0])

    def plan_by_idempotency_key(self, key: str) -> InvestigationPlan | None:
        row = self.connection.execute(
            "SELECT payload FROM source_hunt_plans WHERE idempotency_key = ?", (key,)
        ).fetchone()
        return InvestigationPlan.model_validate_json(row[0]) if row is not None else None

    def index(self, index_id: str) -> RepositoryIndex:
        row = self.connection.execute(
            "SELECT payload FROM source_hunt_indexes WHERE index_id = ?", (index_id,)
        ).fetchone()
        if row is None:
            raise SourceHuntStoreRejected("Source Hunt index is unavailable")
        return RepositoryIndex.model_validate_json(row[0])

    def observation(self, plan_id: str, query_digest: str) -> InvestigationObservation:
        row = self.connection.execute(
            "SELECT payload FROM source_hunt_observations "
            "WHERE plan_id = ? AND query_digest = ?",
            (plan_id, query_digest),
        ).fetchone()
        if row is None:
            raise SourceHuntStoreRejected("Source Hunt observation is unavailable")
        return InvestigationObservation.model_validate_json(row[0])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> SourceHuntStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
