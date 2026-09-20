"""Transactional persistence for recurring Endpoint check schedules."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .schedule_models import (
    EndpointCheckSchedule,
    EndpointScheduleCheckpoint,
    EndpointScheduleRun,
    EndpointScheduleRunState,
)
from .schedule_state_machine import (
    claim_endpoint_schedule_run,
    fail_endpoint_schedule_run,
    materialize_endpoint_schedule_run,
    recover_endpoint_schedule_run,
    start_endpoint_schedule,
    timeout_endpoint_schedule_run,
)


class EndpointScheduleStoreRejected(ValueError):
    pass


class EndpointScheduleRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EndpointScheduleClaim:
    checkpoint: EndpointScheduleCheckpoint
    run: EndpointScheduleRun
    created: bool


class EndpointScheduleStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS endpoint_schedules (
                schedule_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS endpoint_schedule_checkpoints (
                schedule_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                checkpoint_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                PRIMARY KEY(schedule_id, revision),
                FOREIGN KEY(schedule_id) REFERENCES endpoint_schedules(schedule_id)
            );
            CREATE TABLE IF NOT EXISTS endpoint_schedule_runs (
                schedule_run_id TEXT PRIMARY KEY,
                schedule_id TEXT NOT NULL,
                scheduled_for TEXT NOT NULL,
                state TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(schedule_id, scheduled_for),
                FOREIGN KEY(schedule_id) REFERENCES endpoint_schedules(schedule_id)
            );
            """
        )
        self.connection.execute("PRAGMA foreign_keys = ON")

    def create(
        self, schedule: EndpointCheckSchedule
    ) -> tuple[EndpointCheckSchedule, EndpointScheduleCheckpoint]:
        initial = start_endpoint_schedule(schedule)
        try:
            with self.connection:
                row = self.connection.execute(
                    "SELECT schedule_id,payload FROM endpoint_schedules "
                    "WHERE schedule_id=? OR idempotency_key=?",
                    (schedule.schedule_id, schedule.idempotency_key),
                ).fetchone()
                if row is not None:
                    existing = EndpointCheckSchedule.model_validate_json(row["payload"])
                    if existing != schedule:
                        raise EndpointScheduleStoreRejected(
                            "Endpoint Schedule identity was reused for different content"
                        )
                    return existing, self.latest(existing.schedule_id)
                self.connection.execute(
                    "INSERT INTO endpoint_schedules VALUES (?,?,?)",
                    (
                        schedule.schedule_id,
                        schedule.idempotency_key,
                        schedule.model_dump_json(),
                    ),
                )
                self._insert_checkpoint(initial)
        except sqlite3.IntegrityError as exc:
            raise EndpointScheduleStoreRejected("Endpoint Schedule creation raced") from exc
        return schedule, initial

    def schedule(self, schedule_id: str) -> EndpointCheckSchedule:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_schedules WHERE schedule_id=?", (schedule_id,)
        ).fetchone()
        if row is None:
            raise EndpointScheduleStoreRejected("Endpoint Schedule is unavailable")
        return EndpointCheckSchedule.model_validate_json(row["payload"])

    def schedule_by_key(self, key: str) -> EndpointCheckSchedule | None:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_schedules WHERE idempotency_key=?", (key,)
        ).fetchone()
        return EndpointCheckSchedule.model_validate_json(row["payload"]) if row else None

    def latest(self, schedule_id: str) -> EndpointScheduleCheckpoint:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_schedule_checkpoints WHERE schedule_id=? "
            "ORDER BY revision DESC LIMIT 1",
            (schedule_id,),
        ).fetchone()
        if row is None:
            raise EndpointScheduleStoreRejected("Endpoint Schedule checkpoint is unavailable")
        return EndpointScheduleCheckpoint.model_validate_json(row["payload"])

    def run(self, run_id: str) -> EndpointScheduleRun:
        row = self.connection.execute(
            "SELECT payload FROM endpoint_schedule_runs WHERE schedule_run_id=?", (run_id,)
        ).fetchone()
        if row is None:
            raise EndpointScheduleStoreRejected("Endpoint Schedule Run is unavailable")
        return EndpointScheduleRun.model_validate_json(row["payload"])

    def claim(
        self,
        schedule: EndpointCheckSchedule,
        checkpoint: EndpointScheduleCheckpoint,
        *,
        now: datetime,
    ) -> EndpointScheduleClaim:
        advanced, run = claim_endpoint_schedule_run(schedule, checkpoint, now=now)
        try:
            with self.connection:
                if self.schedule(schedule.schedule_id) != schedule:
                    raise EndpointScheduleStoreRejected(
                        "Endpoint Schedule authoritative record changed"
                    )
                self._assert_latest(checkpoint)
                row = self.connection.execute(
                    "SELECT payload FROM endpoint_schedule_runs "
                    "WHERE schedule_run_id=? OR (schedule_id=? AND scheduled_for=?)",
                    (run.schedule_run_id, schedule.schedule_id, run.scheduled_for.isoformat()),
                ).fetchone()
                if row is not None:
                    existing = EndpointScheduleRun.model_validate_json(row["payload"])
                    if existing.schedule_run_id != run.schedule_run_id:
                        raise EndpointScheduleStoreRejected(
                            "Endpoint Schedule slot identity conflict"
                        )
                    if existing.state is EndpointScheduleRunState.STARTED:
                        raise EndpointScheduleRecoveryRequired(
                            "Endpoint Schedule Run requires explicit recovery"
                        )
                    return EndpointScheduleClaim(
                        checkpoint=self.latest(schedule.schedule_id),
                        run=existing,
                        created=False,
                    )
                self.connection.execute(
                    "INSERT INTO endpoint_schedule_runs VALUES (?,?,?,?,?,?)",
                    (
                        run.schedule_run_id,
                        run.schedule_id,
                        run.scheduled_for.isoformat(),
                        run.state.value,
                        run.attempt,
                        run.model_dump_json(),
                    ),
                )
                self._insert_checkpoint(advanced)
        except sqlite3.IntegrityError as exc:
            raise EndpointScheduleStoreRejected("Endpoint Schedule Run claim raced") from exc
        return EndpointScheduleClaim(checkpoint=advanced, run=run, created=True)

    def recover(self, run_id: str, *, now: datetime) -> EndpointScheduleClaim:
        with self.connection:
            run = self.run(run_id)
            checkpoint = self.latest(run.schedule_id)
            if checkpoint.active_run_id != run.schedule_run_id:
                raise EndpointScheduleRecoveryRequired(
                    "Endpoint Schedule active run binding is invalid"
                )
            recovered = recover_endpoint_schedule_run(run, now=now)
            changed = self.connection.execute(
                "UPDATE endpoint_schedule_runs SET attempt=?,payload=? "
                "WHERE schedule_run_id=? AND state='started' AND attempt=?",
                (
                    recovered.attempt,
                    recovered.model_dump_json(),
                    run_id,
                    run.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise EndpointScheduleRecoveryRequired(
                    "Endpoint Schedule Run recovery raced"
                )
        return EndpointScheduleClaim(checkpoint=checkpoint, run=recovered, created=True)

    def materialize(
        self,
        schedule: EndpointCheckSchedule,
        checkpoint: EndpointScheduleCheckpoint,
        run: EndpointScheduleRun,
        *,
        flow_plan_id: str,
        seed_set_id: str,
        endpoint_recon_plan_id: str,
        now: datetime,
    ) -> EndpointScheduleClaim:
        advanced, completed = materialize_endpoint_schedule_run(
            schedule,
            checkpoint,
            run,
            flow_plan_id=flow_plan_id,
            seed_set_id=seed_set_id,
            endpoint_recon_plan_id=endpoint_recon_plan_id,
            now=now,
        )
        return self._finish(checkpoint, advanced, run, completed)

    def timeout(
        self,
        schedule: EndpointCheckSchedule,
        checkpoint: EndpointScheduleCheckpoint,
        run: EndpointScheduleRun,
        *,
        cleanup_complete: bool,
        now: datetime,
    ) -> EndpointScheduleClaim:
        advanced, completed = timeout_endpoint_schedule_run(
            schedule,
            checkpoint,
            run,
            cleanup_complete=cleanup_complete,
            now=now,
        )
        return self._finish(checkpoint, advanced, run, completed)

    def fail(
        self,
        schedule: EndpointCheckSchedule,
        checkpoint: EndpointScheduleCheckpoint,
        run: EndpointScheduleRun,
        *,
        cleanup_complete: bool,
        now: datetime,
    ) -> EndpointScheduleClaim:
        advanced, completed = fail_endpoint_schedule_run(
            schedule,
            checkpoint,
            run,
            cleanup_complete=cleanup_complete,
            now=now,
        )
        return self._finish(checkpoint, advanced, run, completed)

    def advance(
        self,
        previous: EndpointScheduleCheckpoint,
        checkpoint: EndpointScheduleCheckpoint,
    ) -> EndpointScheduleCheckpoint:
        self._assert_transition(previous, checkpoint)
        with self.connection:
            self._assert_latest(previous)
            self._insert_checkpoint(checkpoint)
        return checkpoint

    def _finish(self, previous, checkpoint, before, after):
        self._assert_transition(previous, checkpoint)
        if (
            previous.active_run_id != before.schedule_run_id
            or after.schedule_run_id != before.schedule_run_id
            or checkpoint.active_run_id is not None
            or checkpoint.last_run_id != after.schedule_run_id
        ):
            raise EndpointScheduleStoreRejected(
                "Endpoint Schedule Run completion binding is invalid"
            )
        with self.connection:
            self._assert_latest(previous)
            changed = self.connection.execute(
                "UPDATE endpoint_schedule_runs SET state=?,attempt=?,payload=? "
                "WHERE schedule_run_id=? AND state='started' AND attempt=?",
                (
                    after.state.value,
                    after.attempt,
                    after.model_dump_json(),
                    after.schedule_run_id,
                    before.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise EndpointScheduleRecoveryRequired(
                    "Endpoint Schedule Run completion raced"
                )
            self._insert_checkpoint(checkpoint)
        return EndpointScheduleClaim(checkpoint=checkpoint, run=after, created=True)

    def _assert_latest(self, checkpoint: EndpointScheduleCheckpoint) -> None:
        if self.latest(checkpoint.schedule_id) != checkpoint:
            raise EndpointScheduleStoreRejected("Endpoint Schedule checkpoint is stale")

    @staticmethod
    def _assert_transition(
        previous: EndpointScheduleCheckpoint,
        checkpoint: EndpointScheduleCheckpoint,
    ) -> None:
        if (
            checkpoint.schedule_id != previous.schedule_id
            or checkpoint.revision != previous.revision + 1
            or checkpoint.updated_at < previous.updated_at
        ):
            raise EndpointScheduleStoreRejected(
                "Endpoint Schedule checkpoint transition is invalid"
            )

    def _insert_checkpoint(self, checkpoint: EndpointScheduleCheckpoint) -> None:
        self.connection.execute(
            "INSERT INTO endpoint_schedule_checkpoints VALUES (?,?,?,?)",
            (
                checkpoint.schedule_id,
                checkpoint.revision,
                checkpoint.checkpoint_id,
                checkpoint.model_dump_json(),
            ),
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> EndpointScheduleStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
