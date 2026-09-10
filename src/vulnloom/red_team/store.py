"""Transactional Red Team plans, action attempts, observations, and checkpoints."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import (
    RedTeamCheckpoint,
    RedTeamFlowPlan,
    RedTeamReconAction,
    RedTeamReconCommand,
    RedTeamReconObservation,
)


class RedTeamStoreRejected(ValueError):
    pass


class RedTeamRecoveryRequired(RuntimeError):
    pass


class RedTeamStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS red_team_plans (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS red_team_checkpoints (
                plan_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                checkpoint_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                PRIMARY KEY(plan_id, revision),
                FOREIGN KEY(plan_id) REFERENCES red_team_plans(plan_id)
            );
            CREATE TABLE IF NOT EXISTS red_team_actions (
                action_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                action_json TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                command_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                observation_id TEXT,
                FOREIGN KEY(plan_id) REFERENCES red_team_plans(plan_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS red_team_one_started_action
                ON red_team_actions(plan_id) WHERE state='started';
            CREATE TABLE IF NOT EXISTS red_team_observations (
                observation_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                FOREIGN KEY(action_id) REFERENCES red_team_actions(action_id)
            );
            """
        )

    def create(
        self, plan: RedTeamFlowPlan, checkpoint: RedTeamCheckpoint
    ) -> RedTeamCheckpoint:
        try:
            with self.connection:
                existing = self.connection.execute(
                    "SELECT plan_id,payload FROM red_team_plans WHERE idempotency_key=?",
                    (plan.idempotency_key,),
                ).fetchone()
                if existing is not None:
                    if existing[0] != plan.plan_id or RedTeamFlowPlan.model_validate_json(
                        existing[1]
                    ) != plan:
                        raise RedTeamStoreRejected("Red Team idempotency collision")
                    return self.latest(plan.plan_id)
                self.connection.execute(
                    "INSERT INTO red_team_plans VALUES (?,?,?)",
                    (plan.plan_id, plan.idempotency_key, plan.model_dump_json()),
                )
                self._insert_checkpoint(checkpoint)
        except sqlite3.IntegrityError as exc:
            raise RedTeamStoreRejected("Red Team plan transaction rejected") from exc
        return checkpoint

    def advance(
        self, previous: RedTeamCheckpoint, checkpoint: RedTeamCheckpoint
    ) -> RedTeamCheckpoint:
        if checkpoint.revision != previous.revision + 1:
            raise RedTeamStoreRejected("Red Team checkpoint sequence is invalid")
        with self.connection:
            self._assert_latest(previous)
            self._insert_checkpoint(checkpoint)
        return checkpoint

    def claim_action(
        self, command: RedTeamReconCommand
    ) -> RedTeamReconObservation | None:
        try:
            with self.connection:
                row = self.connection.execute(
                    "SELECT action_id,action_json,attempt,state,observation_id "
                    "FROM red_team_actions WHERE action_id=? OR idempotency_key=?",
                    (command.action.action_id, command.action.idempotency_key),
                ).fetchone()
                if row is not None:
                    if (
                        row[0] != command.action.action_id
                        or row[1] != command.action.model_dump_json()
                    ):
                        raise RedTeamStoreRejected("Red Team action identity conflict")
                    if row[3] == "completed":
                        return self.observation(row[4])
                    if command.attempt != row[2] + 1:
                        raise RedTeamRecoveryRequired(
                            "Red Team action requires next bounded attempt"
                        )
                    changed = self.connection.execute(
                        "UPDATE red_team_actions SET attempt=?,command_id=? "
                        "WHERE action_id=? AND state='started' AND attempt=?",
                        (
                            command.attempt,
                            command.command_id,
                            command.action.action_id,
                            row[2],
                        ),
                    ).rowcount
                    if changed != 1:
                        raise RedTeamRecoveryRequired("Red Team action recovery raced")
                    return None
                if command.attempt != 1:
                    raise RedTeamRecoveryRequired(
                        "Red Team first action attempt must be one"
                    )
                self._assert_latest_id(
                    command.action.plan_id, command.action.expected_checkpoint_id
                )
                self.connection.execute(
                    "INSERT INTO red_team_actions VALUES (?,?,?,?,?,?,'started',NULL)",
                    (
                        command.action.action_id,
                        command.action.plan_id,
                        command.action.idempotency_key,
                        command.action.model_dump_json(),
                        command.attempt,
                        command.command_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RedTeamStoreRejected("Red Team action claim rejected") from exc
        return None

    def completed_action(
        self, command: RedTeamReconCommand
    ) -> RedTeamReconObservation | None:
        row = self.connection.execute(
            "SELECT action_id,action_json,state,observation_id FROM red_team_actions "
            "WHERE action_id=? OR idempotency_key=?",
            (command.action.action_id, command.action.idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row[0] != command.action.action_id or row[1] != command.action.model_dump_json():
            raise RedTeamStoreRejected("Red Team action identity conflict")
        return self.observation(row[3]) if row[2] == "completed" else None

    def complete_action(
        self,
        command: RedTeamReconCommand,
        previous: RedTeamCheckpoint,
        checkpoint: RedTeamCheckpoint,
        observation: RedTeamReconObservation,
    ) -> RedTeamCheckpoint:
        try:
            with self.connection:
                self._assert_latest(previous)
                changed = self.connection.execute(
                    "UPDATE red_team_actions SET state='completed',observation_id=? "
                    "WHERE action_id=? AND command_id=? AND attempt=? AND state='started'",
                    (
                        observation.observation_id,
                        command.action.action_id,
                        command.command_id,
                        command.attempt,
                    ),
                ).rowcount
                if changed != 1:
                    raise RedTeamRecoveryRequired("Red Team action claim is unavailable")
                self.connection.execute(
                    "INSERT INTO red_team_observations VALUES (?,?,?)",
                    (
                        observation.observation_id,
                        observation.action_id,
                        observation.model_dump_json(),
                    ),
                )
                self._insert_checkpoint(checkpoint)
        except sqlite3.IntegrityError as exc:
            raise RedTeamStoreRejected("Red Team action completion rejected") from exc
        return checkpoint

    def plan(self, plan_id: str) -> RedTeamFlowPlan:
        row = self.connection.execute(
            "SELECT payload FROM red_team_plans WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team plan is unavailable")
        return RedTeamFlowPlan.model_validate_json(row[0])

    def plan_by_key(self, key: str) -> RedTeamFlowPlan | None:
        row = self.connection.execute(
            "SELECT payload FROM red_team_plans WHERE idempotency_key=?", (key,)
        ).fetchone()
        return RedTeamFlowPlan.model_validate_json(row[0]) if row else None

    def latest(self, plan_id: str) -> RedTeamCheckpoint:
        row = self.connection.execute(
            "SELECT payload FROM red_team_checkpoints WHERE plan_id=? "
            "ORDER BY revision DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team checkpoint is unavailable")
        return RedTeamCheckpoint.model_validate_json(row[0])

    def observation(self, observation_id: str) -> RedTeamReconObservation:
        row = self.connection.execute(
            "SELECT payload FROM red_team_observations WHERE observation_id=?",
            (observation_id,),
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team observation is unavailable")
        return RedTeamReconObservation.model_validate_json(row[0])

    def action(self, action_id: str) -> RedTeamReconAction:
        row = self.connection.execute(
            "SELECT action_json,state,observation_id FROM red_team_actions WHERE action_id=?",
            (action_id,),
        ).fetchone()
        if row is None or row[1] != "completed" or row[2] is None:
            raise RedTeamStoreRejected("Red Team completed action is unavailable")
        return RedTeamReconAction.model_validate_json(row[0])

    def _assert_latest(self, checkpoint: RedTeamCheckpoint) -> None:
        if self.latest(checkpoint.plan_id).checkpoint_id != checkpoint.checkpoint_id:
            raise RedTeamStoreRejected("Red Team checkpoint is stale")

    def _assert_latest_id(self, plan_id: str, checkpoint_id: str) -> None:
        row = self.connection.execute(
            "SELECT checkpoint_id FROM red_team_checkpoints WHERE plan_id=? "
            "ORDER BY revision DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        if row is None or row[0] != checkpoint_id:
            raise RedTeamStoreRejected("Red Team action checkpoint is stale")

    def _insert_checkpoint(self, checkpoint: RedTeamCheckpoint) -> None:
        self.connection.execute(
            "INSERT INTO red_team_checkpoints VALUES (?,?,?,?)",
            (
                checkpoint.plan_id,
                checkpoint.revision,
                checkpoint.checkpoint_id,
                checkpoint.model_dump_json(),
            ),
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> RedTeamStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
