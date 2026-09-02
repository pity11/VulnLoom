"""Transactional checkpoints for digest-only Critic outcome bindings."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .outcome_binding_models import AgentCriticOutcomeBinding, AgentCriticOutcomeBindingPlan


class AgentCriticOutcomeBindingConflict(ValueError):
    pass


class AgentCriticOutcomeBindingRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentCriticOutcomeBindingClaim:
    created: bool
    binding: AgentCriticOutcomeBinding | None = None


class AgentCriticOutcomeBindingStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_critic_outcome_bindings (
            binding_plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            critic_intake_record_id TEXT NOT NULL UNIQUE, critic_plan_id TEXT NOT NULL UNIQUE,
            critic_outcome_digest TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, binding_json TEXT)"""
        )
        self.connection.commit()

    def claim(self, plan: AgentCriticOutcomeBindingPlan, *, now: datetime):
        row = self.connection.execute(
            "SELECT * FROM agent_critic_outcome_bindings WHERE binding_plan_id=? "
            "OR idempotency_key=? OR critic_intake_record_id=? OR critic_plan_id=? "
            "OR critic_outcome_digest=?",
            (
                plan.binding_plan_id,
                plan.idempotency_key,
                plan.critic_intake_record_id,
                plan.critic_plan_id,
                plan.critic_outcome_digest,
            ),
        ).fetchone()
        if row is not None:
            if row["binding_plan_id"] != plan.binding_plan_id:
                raise AgentCriticOutcomeBindingConflict(
                    "Critic Intake or completed outcome was already bound"
                )
            if row["state"] != "completed" or row["binding_json"] is None:
                raise AgentCriticOutcomeBindingRecoveryRequired(
                    "Critic outcome binding has unfinished STARTED checkpoint"
                )
            binding = AgentCriticOutcomeBinding.model_validate_json(row["binding_json"])
            if (
                row["idempotency_key"] != plan.idempotency_key
                or binding.binding_plan_id != plan.binding_plan_id
                or binding.critic_intake_record_id != row["critic_intake_record_id"]
                or binding.critic_plan_id != row["critic_plan_id"]
                or binding.critic_outcome_digest != row["critic_outcome_digest"]
                or binding.completed_at.isoformat() != row["completed_at"]
            ):
                raise AgentCriticOutcomeBindingRecoveryRequired(
                    "Critic outcome binding checkpoint drifted"
                )
            return AgentCriticOutcomeBindingClaim(False, binding)
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_critic_outcome_bindings VALUES "
                "(?,?,?,?,?,'started',?,NULL,NULL)",
                (
                    plan.binding_plan_id,
                    plan.idempotency_key,
                    plan.critic_intake_record_id,
                    plan.critic_plan_id,
                    plan.critic_outcome_digest,
                    now.isoformat(),
                ),
            )
        return AgentCriticOutcomeBindingClaim(True)

    def complete(self, binding: AgentCriticOutcomeBinding) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_critic_outcome_bindings SET state='completed', completed_at=?, "
                "binding_json=? WHERE binding_plan_id=? AND state='started'",
                (
                    binding.completed_at.isoformat(),
                    binding.model_dump_json(),
                    binding.binding_plan_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentCriticOutcomeBindingRecoveryRequired(
                "Critic outcome binding STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
