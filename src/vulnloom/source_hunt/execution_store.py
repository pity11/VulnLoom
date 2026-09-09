"""Crash-resumable persistence for the Source Hunt execution chain."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .execution_models import SourceExecutionOutcome, SourceExecutionPlan


class SourceExecutionStoreRejected(ValueError):
    pass


class SourceExecutionStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_executions (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_payload TEXT NOT NULL,
                outcome_payload TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_validation_bindings (
                execution_plan_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )
            """
        )

    def claim(
        self, plan: SourceExecutionPlan, initial: SourceExecutionOutcome
    ) -> SourceExecutionOutcome:
        with self.connection:
            row = self.connection.execute(
                "SELECT plan_payload, outcome_payload FROM source_executions "
                "WHERE idempotency_key = ?",
                (plan.idempotency_key,),
            ).fetchone()
            if row is not None:
                if SourceExecutionPlan.model_validate_json(row[0]) != plan:
                    raise SourceExecutionStoreRejected("Source execution idempotency collision")
                return SourceExecutionOutcome.model_validate_json(row[1])
            self.connection.execute(
                "INSERT INTO source_executions VALUES (?, ?, ?, ?)",
                (
                    plan.plan_id,
                    plan.idempotency_key,
                    plan.model_dump_json(),
                    initial.model_dump_json(),
                ),
            )
        return initial

    def save(
        self,
        plan: SourceExecutionPlan,
        previous: SourceExecutionOutcome,
        outcome: SourceExecutionOutcome,
    ) -> None:
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE source_executions SET outcome_payload = ? "
                "WHERE plan_id = ? AND outcome_payload = ?",
                (outcome.model_dump_json(), plan.plan_id, previous.model_dump_json()),
            )
            if cursor.rowcount != 1:
                raise SourceExecutionStoreRejected("Source execution checkpoint is stale")

    def load(self, plan_id: str) -> SourceExecutionOutcome:
        row = self.connection.execute(
            "SELECT outcome_payload FROM source_executions WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            raise SourceExecutionStoreRejected("Source execution is unavailable")
        return SourceExecutionOutcome.model_validate_json(row[0])

    def put_validation_binding(self, binding):
        with self.connection:
            row = self.connection.execute(
                "SELECT payload FROM source_validation_bindings "
                "WHERE execution_plan_id = ?",
                (binding.execution_plan_id,),
            ).fetchone()
            if row is not None:
                from .execution_models import SourceValidationBinding

                existing = SourceValidationBinding.model_validate_json(row[0])
                if existing != binding:
                    raise SourceExecutionStoreRejected(
                        "Source validation binding collision"
                    )
                return existing
            self.connection.execute(
                "INSERT INTO source_validation_bindings VALUES (?, ?)",
                (binding.execution_plan_id, binding.model_dump_json()),
            )
        return binding

    def load_validation_binding(self, execution_plan_id: str):
        from .execution_models import SourceValidationBinding

        row = self.connection.execute(
            "SELECT payload FROM source_validation_bindings "
            "WHERE execution_plan_id = ?",
            (execution_plan_id,),
        ).fetchone()
        if row is None:
            raise SourceExecutionStoreRejected("Source validation binding is unavailable")
        return SourceValidationBinding.model_validate_json(row[0])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> SourceExecutionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
