"""Crash-safe ledger for deterministic Candidate Recommendation admission."""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from .models import CandidateRecommendationAdmissionPlan, CandidateRecommendationRecord


class CandidateRecommendationRecoveryRequired(RuntimeError):
    pass


class CandidateRecommendationConflict(ValueError):
    pass


@dataclass(frozen=True)
class CandidateRecommendationClaim:
    created: bool
    record: CandidateRecommendationRecord | None = None


class CandidateRecommendationStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS candidate_recommendations (
            plan_id TEXT PRIMARY KEY, recommendation_id TEXT NOT NULL UNIQUE,
            idempotency_key TEXT NOT NULL UNIQUE, candidate_set_id TEXT NOT NULL,
            candidate_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('started','completed')),
            plan_json TEXT NOT NULL, record_json TEXT)"""
        )
        self.connection.commit()

    def claim(self, plan: CandidateRecommendationAdmissionPlan):
        row = self.connection.execute(
            "SELECT * FROM candidate_recommendations WHERE plan_id=? OR recommendation_id=? "
            "OR idempotency_key=?",
            (plan.plan_id, plan.recommendation_id, plan.idempotency_key),
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
                raise CandidateRecommendationConflict("recommendation admission identity conflict")
            if row["state"] != "completed" or row["record_json"] is None:
                raise CandidateRecommendationRecoveryRequired(
                    "recommendation admission has unfinished STARTED state"
                )
            try:
                record = CandidateRecommendationRecord.model_validate_json(row["record_json"])
            except ValidationError as exc:
                raise CandidateRecommendationRecoveryRequired(
                    "recommendation admission record is invalid"
                ) from exc
            return CandidateRecommendationClaim(created=False, record=record)
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO candidate_recommendations VALUES (?,?,?,?,?,'started',?,NULL)",
                    (
                        plan.plan_id,
                        plan.recommendation_id,
                        plan.idempotency_key,
                        plan.candidate_set_id,
                        str(plan.candidate_id),
                        plan.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise CandidateRecommendationConflict("recommendation admission conflict") from exc
        return CandidateRecommendationClaim(created=True)

    def complete(self, record: CandidateRecommendationRecord):
        with self.connection:
            changed = self.connection.execute(
                "UPDATE candidate_recommendations SET state='completed',record_json=? "
                "WHERE plan_id=? AND state='started'",
                (record.model_dump_json(), record.plan_id),
            ).rowcount
        if changed != 1:
            raise CandidateRecommendationRecoveryRequired(
                "recommendation admission STARTED checkpoint unavailable"
            )

    def list_completed(self):
        rows = self.connection.execute(
            "SELECT plan_json, record_json FROM candidate_recommendations "
            "WHERE state='completed' ORDER BY rowid"
        ).fetchall()
        records = []
        for row in rows:
            if row["record_json"] is None:
                raise CandidateRecommendationRecoveryRequired(
                    "completed recommendation admission has no record"
                )
            try:
                plan = CandidateRecommendationAdmissionPlan.model_validate_json(row["plan_json"])
                record = CandidateRecommendationRecord.model_validate_json(row["record_json"])
            except ValidationError as exc:
                raise CandidateRecommendationRecoveryRequired(
                    "completed recommendation admission is invalid"
                ) from exc
            if record.plan_id != plan.plan_id or record.recommendation_id != plan.recommendation_id:
                raise CandidateRecommendationRecoveryRequired(
                    "completed recommendation admission binding mismatch"
                )
            records.append(record)
        return tuple(records)

    def load_completed(self, record_id):
        matches = tuple(record for record in self.list_completed() if record.record_id == record_id)
        if len(matches) != 1:
            raise CandidateRecommendationRecoveryRequired(
                "completed recommendation admission record unavailable"
            )
        return matches[0]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.connection.close()
