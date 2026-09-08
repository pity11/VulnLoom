"""Crash-safe ledger for Recommendation-backed Validation Intake."""

import sqlite3
from dataclasses import dataclass

from pydantic import ValidationError

from .recommendation_intake_models import (
    CandidateRecommendationValidationIntakeRecord,
)


class CandidateRecommendationValidationIntakeConflict(ValueError):
    pass


class CandidateRecommendationValidationIntakeRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateRecommendationValidationIntakeClaim:
    created: bool
    record: CandidateRecommendationValidationIntakeRecord | None = None


class CandidateRecommendationValidationIntakeStore:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS candidate_recommendation_validation_intakes (
            plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            selection_record_id TEXT NOT NULL UNIQUE, validation_plan_id TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            plan_json TEXT NOT NULL, record_json TEXT)"""
        )
        self.connection.commit()

    def claim(self, plan):
        row = self.connection.execute(
            "SELECT * FROM candidate_recommendation_validation_intakes "
            "WHERE plan_id=? OR idempotency_key=? OR selection_record_id=? "
            "OR validation_plan_id=?",
            (
                plan.plan_id,
                plan.idempotency_key,
                plan.selection_record_id,
                plan.validation_plan_id,
            ),
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
                raise CandidateRecommendationValidationIntakeConflict(
                    "Recommendation selection or ValidationPlan was already consumed"
                )
            if row["state"] != "completed" or row["record_json"] is None:
                raise CandidateRecommendationValidationIntakeRecoveryRequired(
                    "Recommendation Validation Intake has unfinished STARTED state"
                )
            try:
                record = CandidateRecommendationValidationIntakeRecord.model_validate_json(
                    row["record_json"]
                )
            except ValidationError as exc:
                raise CandidateRecommendationValidationIntakeRecoveryRequired(
                    "Recommendation Validation Intake record is invalid"
                ) from exc
            return CandidateRecommendationValidationIntakeClaim(False, record)
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO candidate_recommendation_validation_intakes "
                    "VALUES (?,?,?,?,'started',?,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.selection_record_id,
                        plan.validation_plan_id,
                        plan.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise CandidateRecommendationValidationIntakeConflict(
                "Recommendation Validation Intake concurrent claim rejected"
            ) from exc
        return CandidateRecommendationValidationIntakeClaim(True)

    def complete(self, record):
        record = CandidateRecommendationValidationIntakeRecord.model_validate(record)
        with self.connection:
            changed = self.connection.execute(
                "UPDATE candidate_recommendation_validation_intakes "
                "SET state='completed',record_json=? WHERE plan_id=? AND state='started'",
                (record.model_dump_json(), record.plan_id),
            ).rowcount
        if changed != 1:
            raise CandidateRecommendationValidationIntakeRecoveryRequired(
                "Recommendation Validation Intake STARTED checkpoint unavailable"
            )

    def load_completed(self, plan_id):
        row = self.connection.execute(
            "SELECT state,record_json FROM candidate_recommendation_validation_intakes "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] != "completed" or row["record_json"] is None:
            raise CandidateRecommendationValidationIntakeRecoveryRequired(
                "Recommendation Validation Intake record unavailable"
            )
        try:
            record = CandidateRecommendationValidationIntakeRecord.model_validate_json(
                row["record_json"]
            )
        except ValidationError as exc:
            raise CandidateRecommendationValidationIntakeRecoveryRequired(
                "Recommendation Validation Intake record is invalid"
            ) from exc
        if record.plan_id != plan_id:
            raise CandidateRecommendationValidationIntakeRecoveryRequired(
                "Recommendation Validation Intake record binding mismatch"
            )
        return record

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.connection.close()
