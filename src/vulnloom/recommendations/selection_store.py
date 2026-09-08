"""Crash-safe ledger for human Candidate recommendation selections."""

import sqlite3
from dataclasses import dataclass

from pydantic import ValidationError

from .selection_models import (
    CandidateRecommendationSelectionDecision,
    CandidateRecommendationSelectionRecord,
)


class CandidateRecommendationSelectionRecoveryRequired(RuntimeError):
    pass


class CandidateRecommendationSelectionConflict(ValueError):
    pass


@dataclass(frozen=True)
class CandidateRecommendationSelectionClaim:
    created: bool
    record: CandidateRecommendationSelectionRecord | None = None


class CandidateRecommendationSelectionStore:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS candidate_recommendation_selections (
            command_id TEXT PRIMARY KEY, admission_record_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE, decision TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            command_json TEXT NOT NULL, record_json TEXT)"""
        )
        self.db.commit()

    def claim(self, command):
        row = self.db.execute(
            "SELECT * FROM candidate_recommendation_selections "
            "WHERE command_id=? OR idempotency_key=?",
            (command.command_id, command.idempotency_key),
        ).fetchone()
        if row is not None:
            if (
                row["command_id"] != command.command_id
                or row["command_json"] != command.model_dump_json()
            ):
                raise CandidateRecommendationSelectionConflict(
                    "recommendation selection identity conflict"
                )
            if row["state"] != "completed" or row["record_json"] is None:
                raise CandidateRecommendationSelectionRecoveryRequired(
                    "recommendation selection has unfinished STARTED state"
                )
            try:
                record = CandidateRecommendationSelectionRecord.model_validate_json(
                    row["record_json"]
                )
            except ValidationError as exc:
                raise CandidateRecommendationSelectionRecoveryRequired(
                    "recommendation selection record is invalid"
                ) from exc
            return CandidateRecommendationSelectionClaim(created=False, record=record)
        prior = self.db.execute(
            "SELECT state, decision FROM candidate_recommendation_selections "
            "WHERE admission_record_id=? ORDER BY rowid DESC",
            (command.admission_record_id,),
        ).fetchall()
        if any(item["state"] != "completed" for item in prior):
            raise CandidateRecommendationSelectionRecoveryRequired(
                "recommendation selection has an unfinished prior decision"
            )
        if len(prior) >= 16:
            raise CandidateRecommendationSelectionConflict(
                "recommendation selection decision limit reached"
            )
        terminal = {
            CandidateRecommendationSelectionDecision.ACCEPT.value,
            CandidateRecommendationSelectionDecision.REJECT.value,
        }
        if any(item["decision"] in terminal for item in prior):
            raise CandidateRecommendationSelectionConflict(
                "recommendation selection was already finalized"
            )
        try:
            with self.db:
                self.db.execute(
                    "INSERT INTO candidate_recommendation_selections VALUES (?,?,?,?,"
                    "'started',?,NULL)",
                    (
                        command.command_id,
                        command.admission_record_id,
                        command.idempotency_key,
                        command.decision.value,
                        command.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise CandidateRecommendationSelectionConflict(
                "recommendation selection concurrent claim rejected"
            ) from exc
        return CandidateRecommendationSelectionClaim(created=True)

    def complete(self, record):
        record = CandidateRecommendationSelectionRecord.model_validate(record.model_dump())
        with self.db:
            changed = self.db.execute(
                "UPDATE candidate_recommendation_selections SET state='completed',record_json=? "
                "WHERE command_id=? AND state='started'",
                (record.model_dump_json(), record.command_id),
            ).rowcount
        if changed != 1:
            raise CandidateRecommendationSelectionRecoveryRequired(
                "recommendation selection STARTED checkpoint unavailable"
            )

    def list_completed(self):
        rows = self.db.execute(
            "SELECT record_json FROM candidate_recommendation_selections "
            "WHERE state='completed' ORDER BY rowid"
        ).fetchall()
        try:
            return tuple(
                CandidateRecommendationSelectionRecord.model_validate_json(row[0]) for row in rows
            )
        except ValidationError as exc:
            raise CandidateRecommendationSelectionRecoveryRequired(
                "completed recommendation selection is invalid"
            ) from exc

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()
