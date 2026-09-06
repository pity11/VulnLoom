"""Crash-safe digest-only ledger for human pilot Candidate selection."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .pilot_selection_models import (
    PilotCandidateSelectionCommand,
    PilotCandidateSelectionRecord,
)


class PilotCandidateSelectionIdempotencyConflict(ValueError):
    pass


class PilotCandidateSelectionConsumptionConflict(ValueError):
    pass


class PilotCandidateSelectionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class PilotCandidateSelectionClaim:
    created: bool
    record: PilotCandidateSelectionRecord | None = None


class PilotCandidateSelectionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS pilot_candidate_selections (
            command_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            readiness_plan_id TEXT NOT NULL UNIQUE, readiness_result_id TEXT NOT NULL,
            pilot_manifest_id TEXT NOT NULL, candidate_set_id TEXT NOT NULL,
            candidate_id TEXT NOT NULL, candidate_digest TEXT NOT NULL,
            reviewer TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, record_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self, command: PilotCandidateSelectionCommand, *, now: datetime
    ) -> PilotCandidateSelectionClaim:
        row = self.connection.execute(
            "SELECT * FROM pilot_candidate_selections WHERE command_id=? "
            "OR idempotency_key=? OR readiness_plan_id=?",
            (command.command_id, command.idempotency_key, command.readiness_plan_id),
        ).fetchone()
        if row is not None:
            if row["command_id"] == command.command_id:
                if row["state"] == "started" or row["record_json"] is None:
                    raise PilotCandidateSelectionRecoveryRequired(
                        "pilot Candidate selection has unfinished STARTED state"
                    )
                return PilotCandidateSelectionClaim(
                    created=False,
                    record=PilotCandidateSelectionRecord.model_validate_json(row["record_json"]),
                )
            if row["idempotency_key"] == command.idempotency_key:
                raise PilotCandidateSelectionIdempotencyConflict(
                    "pilot Candidate selection idempotency key was reused"
                )
            raise PilotCandidateSelectionConsumptionConflict(
                "pilot readiness result was already consumed by another Candidate"
            )
        try:
            with self.connection:
                self.connection.execute(
                    """INSERT INTO pilot_candidate_selections (
                    command_id,idempotency_key,readiness_plan_id,readiness_result_id,
                    pilot_manifest_id,candidate_set_id,candidate_id,candidate_digest,
                    reviewer,state,started_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,'started',?)""",
                    (
                        command.command_id,
                        command.idempotency_key,
                        command.readiness_plan_id,
                        command.readiness_result_id,
                        command.pilot_manifest_id,
                        command.candidate_set_id,
                        str(command.candidate_id),
                        command.candidate_digest,
                        command.reviewer,
                        now.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise PilotCandidateSelectionConsumptionConflict(
                "pilot Candidate selection checkpoint conflicted concurrently"
            ) from exc
        return PilotCandidateSelectionClaim(created=True)

    def complete(self, record: PilotCandidateSelectionRecord, *, now: datetime) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE pilot_candidate_selections SET state='completed',completed_at=?,"
                "record_json=? WHERE command_id=? AND state='started'",
                (now.isoformat(), record.model_dump_json(), record.command_id),
            ).rowcount
        if changed != 1:
            raise PilotCandidateSelectionRecoveryRequired(
                "pilot Candidate selection STARTED checkpoint is unavailable"
            )

    def load_completed(self, readiness_plan_id: str) -> PilotCandidateSelectionRecord:
        row = self.connection.execute(
            "SELECT state,record_json FROM pilot_candidate_selections WHERE readiness_plan_id=?",
            (readiness_plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("pilot Candidate selection checkpoint is unavailable")
        if row["state"] != "completed" or row["record_json"] is None:
            raise PilotCandidateSelectionRecoveryRequired(
                "pilot Candidate selection has unfinished STARTED state"
            )
        record = PilotCandidateSelectionRecord.model_validate_json(row["record_json"])
        if record.readiness_plan_id != readiness_plan_id:
            raise PilotCandidateSelectionRecoveryRequired(
                "pilot Candidate selection checkpoint binding mismatch"
            )
        return record

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> PilotCandidateSelectionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
