"""Transactional persistence for sealed R11 Attack Chains."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .attack_models import (
    AttackActionAuditRecord,
    AttackActionCommand,
    AttackActionObservation,
    AttackChainCheckpoint,
    AttackChainPlan,
)


class AttackChainStoreRejected(ValueError):
    pass


class AttackChainRecoveryRequired(RuntimeError):
    pass


class AttackChainStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS attack_chain_plans (
                chain_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attack_chain_checkpoints (
                chain_plan_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                checkpoint_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                PRIMARY KEY(chain_plan_id, revision),
                FOREIGN KEY(chain_plan_id) REFERENCES attack_chain_plans(chain_plan_id)
            );
            CREATE TABLE IF NOT EXISTS attack_chain_actions (
                action_id TEXT NOT NULL,
                chain_plan_id TEXT NOT NULL,
                command_json TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                command_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                observation_id TEXT,
                PRIMARY KEY(chain_plan_id, action_id),
                FOREIGN KEY(chain_plan_id) REFERENCES attack_chain_plans(chain_plan_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS attack_chain_one_started_action
                ON attack_chain_actions(chain_plan_id) WHERE state='started';
            CREATE TABLE IF NOT EXISTS attack_chain_observations (
                observation_id TEXT PRIMARY KEY,
                chain_plan_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(chain_plan_id, action_id),
                FOREIGN KEY(chain_plan_id, action_id)
                    REFERENCES attack_chain_actions(chain_plan_id, action_id)
            );
            CREATE TABLE IF NOT EXISTS attack_chain_audit (
                audit_id TEXT PRIMARY KEY,
                chain_plan_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                FOREIGN KEY(chain_plan_id) REFERENCES attack_chain_plans(chain_plan_id)
            );
            """
        )

    def create(
        self, plan: AttackChainPlan, checkpoint: AttackChainCheckpoint
    ) -> AttackChainCheckpoint:
        try:
            with self.connection:
                row = self.connection.execute(
                    "SELECT chain_plan_id,payload FROM attack_chain_plans WHERE idempotency_key=?",
                    (plan.idempotency_key,),
                ).fetchone()
                if row is not None:
                    if (
                        row[0] != plan.chain_plan_id
                        or AttackChainPlan.model_validate_json(row[1]) != plan
                    ):
                        raise AttackChainStoreRejected("Attack Chain idempotency collision")
                    return self.latest(plan.chain_plan_id)
                self.connection.execute(
                    "INSERT INTO attack_chain_plans VALUES (?,?,?)",
                    (plan.chain_plan_id, plan.idempotency_key, plan.model_dump_json()),
                )
                self._insert_checkpoint(checkpoint)
        except sqlite3.IntegrityError as exc:
            raise AttackChainStoreRejected("Attack Chain creation rejected") from exc
        return checkpoint

    def advance(
        self, previous: AttackChainCheckpoint, checkpoint: AttackChainCheckpoint
    ) -> AttackChainCheckpoint:
        if checkpoint.revision != previous.revision + 1:
            raise AttackChainStoreRejected("Attack Chain revision is invalid")
        with self.connection:
            self._assert_latest(previous)
            self._insert_checkpoint(checkpoint)
        return checkpoint

    def claim(self, command: AttackActionCommand) -> AttackActionObservation | None:
        with self.connection:
            row = self.connection.execute(
                "SELECT command_json,attempt,state,observation_id "
                "FROM attack_chain_actions WHERE chain_plan_id=? AND action_id=?",
                (command.chain_plan_id, command.action_id),
            ).fetchone()
            if row is not None:
                stored = AttackActionCommand.model_validate_json(row[0])
                recovered = stored.model_copy(
                    update={
                        "attempt": command.attempt,
                        "command_id": command.command_id,
                    }
                )
                if recovered != command:
                    raise AttackChainStoreRejected("Attack Action identity conflict")
                if row[2] == "completed":
                    return self.observation(row[3])
                if command.attempt != row[1] + 1:
                    raise AttackChainRecoveryRequired(
                        "Attack Action requires the next bounded attempt"
                    )
                changed = self.connection.execute(
                    "UPDATE attack_chain_actions SET command_json=?,attempt=?,command_id=? "
                    "WHERE chain_plan_id=? AND action_id=? "
                    "AND state='started' AND attempt=?",
                    (
                        command.model_dump_json(),
                        command.attempt,
                        command.command_id,
                        command.chain_plan_id,
                        command.action_id,
                        row[1],
                    ),
                ).rowcount
                if changed != 1:
                    raise AttackChainRecoveryRequired("Attack Action recovery raced")
                return None
            if command.attempt != 1:
                raise AttackChainRecoveryRequired("Attack Action first attempt must be one")
            self.connection.execute(
                "INSERT INTO attack_chain_actions VALUES (?,?,?,?,?,'started',NULL)",
                (
                    command.action_id,
                    command.chain_plan_id,
                    command.model_dump_json(),
                    command.attempt,
                    command.command_id,
                ),
            )
        return None

    def completed(self, command: AttackActionCommand) -> AttackActionObservation | None:
        row = self.connection.execute(
            "SELECT command_json,state,observation_id FROM attack_chain_actions "
            "WHERE chain_plan_id=? AND action_id=?",
            (command.chain_plan_id, command.action_id),
        ).fetchone()
        if row is None:
            return None
        stored = AttackActionCommand.model_validate_json(row[0])
        if (
            stored.model_copy(update={"attempt": command.attempt, "command_id": command.command_id})
            != command
        ):
            raise AttackChainStoreRejected("Attack Action identity conflict")
        return self.observation(row[2]) if row[1] == "completed" else None

    def complete(
        self,
        command: AttackActionCommand,
        previous: AttackChainCheckpoint,
        checkpoint: AttackChainCheckpoint,
        observation: AttackActionObservation,
    ) -> AttackChainCheckpoint:
        try:
            with self.connection:
                self._assert_latest(previous)
                changed = self.connection.execute(
                    "UPDATE attack_chain_actions SET state='completed',observation_id=? "
                    "WHERE chain_plan_id=? AND action_id=? AND command_id=? "
                    "AND attempt=? AND state='started'",
                    (
                        observation.observation_id,
                        command.chain_plan_id,
                        command.action_id,
                        command.command_id,
                        command.attempt,
                    ),
                ).rowcount
                if changed != 1:
                    raise AttackChainRecoveryRequired("Attack Action claim is unavailable")
                self.connection.execute(
                    "INSERT INTO attack_chain_observations VALUES (?,?,?,?)",
                    (
                        observation.observation_id,
                        command.chain_plan_id,
                        observation.action_id,
                        observation.model_dump_json(),
                    ),
                )
                self._insert_checkpoint(checkpoint)
        except sqlite3.IntegrityError as exc:
            raise AttackChainStoreRejected("Attack Action completion rejected") from exc
        return checkpoint

    def append_audit(self, record: AttackActionAuditRecord) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO attack_chain_audit VALUES (?,?,?,?)",
                    (
                        record.audit_id,
                        record.chain_plan_id,
                        record.action_id,
                        record.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AttackChainStoreRejected("Attack Action audit rejected") from exc

    def audits(self, chain_plan_id: str) -> tuple[AttackActionAuditRecord, ...]:
        rows = self.connection.execute(
            "SELECT payload FROM attack_chain_audit WHERE chain_plan_id=? ORDER BY rowid",
            (chain_plan_id,),
        ).fetchall()
        return tuple(AttackActionAuditRecord.model_validate_json(row[0]) for row in rows)

    def plan(self, chain_plan_id: str) -> AttackChainPlan:
        row = self.connection.execute(
            "SELECT payload FROM attack_chain_plans WHERE chain_plan_id=?",
            (chain_plan_id,),
        ).fetchone()
        if row is None:
            raise AttackChainStoreRejected("Attack Chain Plan is unavailable")
        return AttackChainPlan.model_validate_json(row[0])

    def latest(self, chain_plan_id: str) -> AttackChainCheckpoint:
        row = self.connection.execute(
            "SELECT payload FROM attack_chain_checkpoints WHERE chain_plan_id=? "
            "ORDER BY revision DESC LIMIT 1",
            (chain_plan_id,),
        ).fetchone()
        if row is None:
            raise AttackChainStoreRejected("Attack Chain checkpoint is unavailable")
        return AttackChainCheckpoint.model_validate_json(row[0])

    def observation(self, observation_id: str) -> AttackActionObservation:
        row = self.connection.execute(
            "SELECT payload FROM attack_chain_observations WHERE observation_id=?",
            (observation_id,),
        ).fetchone()
        if row is None:
            raise AttackChainStoreRejected("Attack Action observation is unavailable")
        return AttackActionObservation.model_validate_json(row[0])

    def _assert_latest(self, checkpoint: AttackChainCheckpoint) -> None:
        if self.latest(checkpoint.chain_plan_id).checkpoint_id != checkpoint.checkpoint_id:
            raise AttackChainStoreRejected("Attack Chain checkpoint is stale")

    def _insert_checkpoint(self, checkpoint: AttackChainCheckpoint) -> None:
        self.connection.execute(
            "INSERT INTO attack_chain_checkpoints VALUES (?,?,?,?)",
            (
                checkpoint.chain_plan_id,
                checkpoint.revision,
                checkpoint.checkpoint_id,
                checkpoint.model_dump_json(),
            ),
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AttackChainStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
