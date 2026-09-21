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
from .replan_models import (
    RedTeamReplanAdmission,
    RedTeamReplanProposal,
    RedTeamReplanToolView,
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
        self.connection.execute("PRAGMA busy_timeout = 5000")
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
            CREATE TABLE IF NOT EXISTS red_team_external_action_reservations (
                reservation_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                source_checkpoint_id TEXT NOT NULL,
                action_count INTEGER NOT NULL CHECK(action_count > 0),
                FOREIGN KEY(plan_id) REFERENCES red_team_plans(plan_id)
            );
            CREATE INDEX IF NOT EXISTS red_team_external_budget_by_plan
                ON red_team_external_action_reservations(plan_id);
            CREATE TABLE IF NOT EXISTS red_team_replan_tool_views (
                tool_view_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                FOREIGN KEY(plan_id) REFERENCES red_team_plans(plan_id)
            );
            CREATE TABLE IF NOT EXISTS red_team_replan_proposals (
                proposal_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS red_team_replan_admissions (
                admission_id TEXT PRIMARY KEY,
                proposal_id TEXT NOT NULL UNIQUE,
                plan_id TEXT NOT NULL,
                source_checkpoint_id TEXT NOT NULL,
                action_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('reserved','consumed','cancelled','expired')),
                payload TEXT NOT NULL,
                FOREIGN KEY(proposal_id) REFERENCES red_team_replan_proposals(proposal_id),
                FOREIGN KEY(plan_id) REFERENCES red_team_plans(plan_id)
            );
            CREATE INDEX IF NOT EXISTS red_team_active_replan_budget
                ON red_team_replan_admissions(plan_id,state);
            """
        )

    def put_replan_tool_view(
        self, view: RedTeamReplanToolView
    ) -> RedTeamReplanToolView:
        with self.connection:
            row = self.connection.execute(
                "SELECT payload FROM red_team_replan_tool_views WHERE tool_view_id=?",
                (view.tool_view_id,),
            ).fetchone()
            if row is not None:
                existing = RedTeamReplanToolView.model_validate_json(row[0])
                if existing != view:
                    raise RedTeamStoreRejected("Red Team replan Tool View collision")
                return existing
            self.connection.execute(
                "INSERT INTO red_team_replan_tool_views VALUES (?,?,?)",
                (view.tool_view_id, view.flow_plan_id, view.model_dump_json()),
            )
        return view

    def replan_tool_view(self, tool_view_id: str) -> RedTeamReplanToolView:
        row = self.connection.execute(
            "SELECT payload FROM red_team_replan_tool_views WHERE tool_view_id=?",
            (tool_view_id,),
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team replan Tool View is unavailable")
        return RedTeamReplanToolView.model_validate_json(row[0])

    def replan_admission_for_proposal(
        self, proposal: RedTeamReplanProposal
    ) -> RedTeamReplanAdmission | None:
        row = self.connection.execute(
            "SELECT proposal_id,payload FROM red_team_replan_proposals "
            "WHERE proposal_id=? OR idempotency_key=?",
            (proposal.proposal_id, proposal.idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row[0] != proposal.proposal_id or (
            RedTeamReplanProposal.model_validate_json(row[1]) != proposal
        ):
            raise RedTeamStoreRejected("Red Team replan proposal collision")
        admission = self.connection.execute(
            "SELECT payload FROM red_team_replan_admissions WHERE proposal_id=?",
            (proposal.proposal_id,),
        ).fetchone()
        if admission is None:
            raise RedTeamStoreRejected("Red Team replan admission is incomplete")
        return RedTeamReplanAdmission.model_validate_json(admission[0])

    def admit_replan(
        self,
        proposal: RedTeamReplanProposal,
        admission: RedTeamReplanAdmission,
    ) -> RedTeamReplanAdmission:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                row = self.connection.execute(
                    "SELECT proposal_id,payload FROM red_team_replan_proposals "
                    "WHERE proposal_id=? OR idempotency_key=?",
                    (proposal.proposal_id, proposal.idempotency_key),
                ).fetchone()
                if row is not None:
                    if row[0] != proposal.proposal_id or RedTeamReplanProposal.model_validate_json(
                        row[1]
                    ) != proposal:
                        raise RedTeamStoreRejected("Red Team replan proposal collision")
                    existing = self.connection.execute(
                        "SELECT payload FROM red_team_replan_admissions WHERE proposal_id=?",
                        (proposal.proposal_id,),
                    ).fetchone()
                    if existing is None:
                        raise RedTeamStoreRejected("Red Team replan admission is incomplete")
                    persisted = RedTeamReplanAdmission.model_validate_json(existing[0])
                    if persisted != admission:
                        raise RedTeamStoreRejected("Red Team replan admission collision")
                    self.connection.commit()
                    return persisted
                checkpoint = self.latest(admission.flow_plan_id)
                if (
                    checkpoint.checkpoint_id != admission.source_checkpoint_id
                    or checkpoint.status.value != "running"
                    or self.remaining_action_budget(admission.flow_plan_id) < 1
                ):
                    raise RedTeamStoreRejected("Red Team replan budget or checkpoint is stale")
                self.connection.execute(
                    "INSERT INTO red_team_replan_proposals VALUES (?,?,?)",
                    (
                        proposal.proposal_id,
                        proposal.idempotency_key,
                        proposal.model_dump_json(),
                    ),
                )
                self.connection.execute(
                    "INSERT INTO red_team_replan_admissions VALUES (?,?,?,?,?,'reserved',?)",
                    (
                        admission.admission_id,
                        proposal.proposal_id,
                        admission.flow_plan_id,
                        admission.source_checkpoint_id,
                        admission.command.action.action_id,
                        admission.model_dump_json(),
                    ),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
        except sqlite3.IntegrityError as exc:
            raise RedTeamStoreRejected("Red Team replan admission transaction rejected") from exc
        return admission

    def replan_admission(self, admission_id: str) -> RedTeamReplanAdmission:
        row = self.connection.execute(
            "SELECT payload FROM red_team_replan_admissions WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team replan admission is unavailable")
        return RedTeamReplanAdmission.model_validate_json(row[0])

    def replan_admission_state(self, admission_id: str) -> str:
        row = self.connection.execute(
            "SELECT state FROM red_team_replan_admissions WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team replan admission is unavailable")
        return str(row[0])

    def release_replan_admission(self, admission_id: str, *, state: str) -> None:
        if state not in {"cancelled", "expired"}:
            raise RedTeamStoreRejected("Red Team replan release state is invalid")
        with self.connection:
            changed = self.connection.execute(
                "UPDATE red_team_replan_admissions SET state=? "
                "WHERE admission_id=? AND state='reserved'",
                (state, admission_id),
            ).rowcount
            if changed != 1:
                raise RedTeamStoreRejected(
                    "Red Team replan reservation is not releasable"
                )

    def remaining_action_budget(self, plan_id: str) -> int:
        plan = self.plan(plan_id)
        checkpoint = self.latest(plan_id)
        used = (
            checkpoint.actions_used
            + self._started_actions(plan_id)
            + self._reserved_actions(plan_id)
            + self._reserved_replan_actions(plan_id)
        )
        return max(0, plan.rules.stop_conditions.max_actions - used)

    def reserve_external_actions(
        self,
        *,
        plan_id: str,
        source_checkpoint_id: str,
        reservation_id: str,
        action_count: int,
    ) -> None:
        if action_count <= 0:
            raise RedTeamStoreRejected("Red Team external reservation is invalid")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self.connection.execute(
                    "SELECT plan_id,source_checkpoint_id,action_count "
                    "FROM red_team_external_action_reservations WHERE reservation_id=?",
                    (reservation_id,),
                ).fetchone()
                expected = (plan_id, source_checkpoint_id, action_count)
                if existing is not None:
                    if existing != expected:
                        raise RedTeamStoreRejected(
                            "Red Team external reservation identity conflict"
                        )
                    self.connection.commit()
                    return
                checkpoint = self.latest(plan_id)
                if (
                    checkpoint.checkpoint_id != source_checkpoint_id
                    or checkpoint.status.value != "running"
                ):
                    raise RedTeamStoreRejected(
                        "Red Team external reservation checkpoint is stale"
                    )
                plan = self.plan(plan_id)
                reserved = self._reserved_actions(plan_id)
                if (
                    checkpoint.actions_used
                    + self._started_actions(plan_id)
                    + reserved
                    + action_count
                    > plan.rules.stop_conditions.max_actions
                ):
                    raise RedTeamStoreRejected(
                        "Red Team external action budget is exhausted"
                    )
                self.connection.execute(
                    "INSERT INTO red_team_external_action_reservations VALUES (?,?,?,?)",
                    (reservation_id, plan_id, source_checkpoint_id, action_count),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
        except sqlite3.IntegrityError as exc:
            raise RedTeamStoreRejected(
                "Red Team external reservation rejected"
            ) from exc

    def reserved_external_actions(self, plan_id: str) -> int:
        return self._reserved_actions(plan_id)

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
            self.connection.execute("BEGIN IMMEDIATE")
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
                checkpoint = self.latest(command.action.plan_id)
                plan = self.plan(command.action.plan_id)
                replan = self.connection.execute(
                    "SELECT admission_id,state,payload FROM red_team_replan_admissions "
                    "WHERE action_id=?",
                    (command.action.action_id,),
                ).fetchone()
                if replan is not None:
                    admission = RedTeamReplanAdmission.model_validate_json(replan[2])
                    if (
                        replan[1] != "reserved"
                        or admission.command.action != command.action
                    ):
                        raise RedTeamStoreRejected(
                            "Red Team replan reservation is unavailable"
                        )
                if (
                    checkpoint.actions_used
                    + self._started_actions(command.action.plan_id)
                    + self._reserved_actions(command.action.plan_id)
                    + self._reserved_replan_actions(command.action.plan_id)
                    + (0 if replan is not None else 1)
                    > plan.rules.stop_conditions.max_actions
                ):
                    raise RedTeamStoreRejected(
                        "Red Team action budget is reserved by another workflow"
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
                if replan is not None:
                    changed = self.connection.execute(
                        "UPDATE red_team_replan_admissions SET state='consumed' "
                        "WHERE admission_id=? AND state='reserved'",
                        (replan[0],),
                    ).rowcount
                    if changed != 1:
                        raise RedTeamStoreRejected(
                            "Red Team replan reservation consumption raced"
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

    def checkpoint(self, checkpoint_id: str) -> RedTeamCheckpoint:
        row = self.connection.execute(
            "SELECT payload FROM red_team_checkpoints WHERE checkpoint_id=?",
            (checkpoint_id,),
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team checkpoint is unavailable")
        return RedTeamCheckpoint.model_validate_json(row[0])

    def checkpoint_revision(self, plan_id: str, revision: int) -> RedTeamCheckpoint:
        row = self.connection.execute(
            "SELECT payload FROM red_team_checkpoints WHERE plan_id=? AND revision=?",
            (plan_id, revision),
        ).fetchone()
        if row is None:
            raise RedTeamStoreRejected("Red Team checkpoint revision is unavailable")
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

    def _reserved_actions(self, plan_id: str) -> int:
        row = self.connection.execute(
            "SELECT COALESCE(SUM(action_count),0) "
            "FROM red_team_external_action_reservations WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        return int(row[0])

    def _started_actions(self, plan_id: str) -> int:
        row = self.connection.execute(
            "SELECT count(*) FROM red_team_actions WHERE plan_id=? AND state='started'",
            (plan_id,),
        ).fetchone()
        return int(row[0])

    def _reserved_replan_actions(self, plan_id: str) -> int:
        row = self.connection.execute(
            "SELECT count(*) FROM red_team_replan_admissions "
            "WHERE plan_id=? AND state='reserved'",
            (plan_id,),
        ).fetchone()
        return int(row[0])

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
