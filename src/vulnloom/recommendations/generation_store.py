"""Single-attempt ledger for Candidate Recommendation generation."""

import sqlite3

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest

from .generation_models import CandidateRecommendationGenerationOutcome


class CandidateRecommendationGenerationRecoveryRequired(ValueError):
    pass


class CandidateRecommendationGenerationStore:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS candidate_recommendation_generations ("
            "plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, "
            "grant_id TEXT NOT NULL UNIQUE, approval_id TEXT NOT NULL UNIQUE, "
            "plan_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('started','completed')), "
            "result_json TEXT)"
        )
        self.db.commit()

    def claim(self, plan, approval):
        grant = plan.config.registration.egress_grant_id
        rows = self.db.execute(
            "SELECT plan_json, approval_id, state, result_json "
            "FROM candidate_recommendation_generations WHERE plan_id=? OR idempotency_key=? "
            "OR grant_id=? OR approval_id=?",
            (plan.plan_id, plan.idempotency_key, grant, str(approval.approval_id)),
        ).fetchall()
        if rows:
            if len(rows) != 1 or rows[0][:2] != (
                plan.model_dump_json(),
                str(approval.approval_id),
            ):
                raise CandidateRecommendationGenerationRecoveryRequired(
                    "recommendation generation identity conflict"
                )
            if rows[0][2] != "completed" or not rows[0][3]:
                raise CandidateRecommendationGenerationRecoveryRequired(
                    "recommendation generation interrupted"
                )
            try:
                outcome = CandidateRecommendationGenerationOutcome.model_validate_json(rows[0][3])
            except ValidationError as exc:
                raise CandidateRecommendationGenerationRecoveryRequired(
                    "recommendation generation result is invalid"
                ) from exc
            if (
                outcome.plan_id != plan.plan_id
                or outcome.projection_id != plan.projection.projection_id
            ):
                raise CandidateRecommendationGenerationRecoveryRequired(
                    "recommendation generation result binding mismatch"
                )
            if outcome.status == "recommendation_ready" and (
                outcome.transport.completed_at >= plan.deadline
                or outcome.transport.completed_at < plan.created_at
                or outcome.response is None
                or outcome.recommendation is None
            ):
                raise CandidateRecommendationGenerationRecoveryRequired(
                    "recommendation generation completion invalid"
                )
            if outcome.status == "recommendation_ready":
                self._verify_ready(outcome, plan)
            return outcome
        try:
            with self.db:
                self.db.execute(
                    "INSERT INTO candidate_recommendation_generations "
                    "VALUES (?,?,?,?,?,'started',NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        grant,
                        str(approval.approval_id),
                        plan.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise CandidateRecommendationGenerationRecoveryRequired(
                "recommendation generation concurrent claim rejected"
            ) from exc
        return None

    def complete(self, outcome):
        outcome = CandidateRecommendationGenerationOutcome.model_validate(outcome.model_dump())
        with self.db:
            changed = self.db.execute(
                "UPDATE candidate_recommendation_generations SET state='completed',result_json=? "
                "WHERE plan_id=? AND state='started'",
                (outcome.model_dump_json(), outcome.plan_id),
            ).rowcount
        if changed != 1:
            raise CandidateRecommendationGenerationRecoveryRequired(
                "recommendation generation STARTED checkpoint unavailable"
            )

    def _verify_ready(self, outcome, plan):
        response = outcome.response
        recommendation = outcome.recommendation
        try:
            response.require_projection(plan.projection)
        except ValueError as exc:
            raise CandidateRecommendationGenerationRecoveryRequired(
                "recommendation generation response drifted"
            ) from exc
        projection = plan.projection
        signal_ids = tuple(item.signal_id for item in projection.signals)
        selected = tuple(projection.locations[index] for index in response.cited_location_indexes)
        cited = recommendation.cited_locations
        if (
            recommendation.candidate_set_id != projection.candidate_set_id
            or recommendation.candidate_id != projection.candidate_id
            or recommendation.candidate_digest != projection.candidate_digest
            or recommendation.source_graph_id != projection.source_graph_id
            or recommendation.target_id != projection.target_id
            or recommendation.target_version_digest != projection.target_version_digest
            or recommendation.scope_id != projection.scope_id
            or recommendation.scope_version != projection.scope_version
            or recommendation.supporting_signal_ids != signal_ids
            or len(cited) != len(selected)
            or any(
                canonical_digest(location.path) != projected.path_digest
                or location.line != projected.line
                for location, projected in zip(cited, selected, strict=True)
            )
        ):
            raise CandidateRecommendationGenerationRecoveryRequired(
                "recommendation generation Candidate binding drifted"
            )

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()
