"""Crash-resumable persistence for project recipe runs."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import ProjectRecipeRunOutcome, ProjectRecipeRunPlan


class ProjectRecipeRunStoreError(ValueError):
    pass


class ProjectRecipeRunStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS project_recipe_runs (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_payload TEXT NOT NULL,
                outcome_payload TEXT NOT NULL
            )
            """
        )

    def claim(
        self, plan: ProjectRecipeRunPlan, initial: ProjectRecipeRunOutcome
    ) -> ProjectRecipeRunOutcome:
        with self.connection:
            row = self.connection.execute(
                "SELECT plan_payload, outcome_payload FROM project_recipe_runs "
                "WHERE idempotency_key = ?",
                (plan.idempotency_key,),
            ).fetchone()
            if row is not None:
                if ProjectRecipeRunPlan.model_validate_json(row[0]) != plan:
                    raise ProjectRecipeRunStoreError(
                        "project recipe idempotency key was reused for a different plan"
                    )
                return ProjectRecipeRunOutcome.model_validate_json(row[1])
            self.connection.execute(
                "INSERT INTO project_recipe_runs VALUES (?, ?, ?, ?)",
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
        plan: ProjectRecipeRunPlan,
        previous: ProjectRecipeRunOutcome,
        outcome: ProjectRecipeRunOutcome,
    ) -> None:
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE project_recipe_runs SET outcome_payload = ? "
                "WHERE plan_id = ? AND outcome_payload = ?",
                (outcome.model_dump_json(), plan.plan_id, previous.model_dump_json()),
            )
            if cursor.rowcount != 1:
                raise ProjectRecipeRunStoreError("project recipe checkpoint is stale")

    def load(self, plan_id: str) -> ProjectRecipeRunOutcome:
        row = self.connection.execute(
            "SELECT outcome_payload FROM project_recipe_runs WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise ProjectRecipeRunStoreError("project recipe run is unavailable")
        return ProjectRecipeRunOutcome.model_validate_json(row[0])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> ProjectRecipeRunStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
