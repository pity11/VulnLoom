"""Transactional single-attempt review ledger; interrupted work is never retried."""

import sqlite3

from .models import CodeReviewOutcome


class ReviewRecoveryRequired(ValueError):
    pass


class CodeReviewStore:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS code_reviews (plan_id TEXT PRIMARY KEY, "
            "idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, "
            "approval_id TEXT NOT NULL UNIQUE, plan_json TEXT NOT NULL, "
            "state TEXT NOT NULL CHECK(state IN ('started','completed')), result_json TEXT)"
        )
        self.db.commit()

    def claim(self, plan, approval):
        grant = plan.config.registration.egress_grant_id
        rows = self.db.execute(
            "SELECT plan_json, approval_id, state, result_json FROM code_reviews "
            "WHERE plan_id=? OR idempotency_key=? OR grant_id=? OR approval_id=?",
            (plan.plan_id, plan.idempotency_key, grant, str(approval.approval_id)),
        ).fetchall()
        if rows:
            if len(rows) != 1 or rows[0][:2] != (plan.model_dump_json(), str(approval.approval_id)):
                raise ReviewRecoveryRequired("review ledger identity conflict")
            if rows[0][2] != "completed" or not rows[0][3]:
                raise ReviewRecoveryRequired("review interrupted; explicit recovery required")
            outcome = CodeReviewOutcome.model_validate_json(rows[0][3])
            if outcome.plan_id != plan.plan_id:
                raise ReviewRecoveryRequired("review ledger result binding mismatch")
            if outcome.review:
                outcome.review.require_references(plan.snippet)
            if outcome.status == "review_ready" and outcome.transport.completed_at >= plan.deadline:
                raise ReviewRecoveryRequired("review ledger completion outside deadline")
            if outcome.transport.completed_at < plan.created_at:
                raise ReviewRecoveryRequired("review ledger completion before creation")
            return outcome
        try:
            with self.db:
                self.db.execute(
                    "INSERT INTO code_reviews VALUES (?,?,?,?,?,'started',NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        grant,
                        str(approval.approval_id),
                        plan.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ReviewRecoveryRequired("review concurrent claim rejected") from exc
        return None

    def complete(self, outcome):
        outcome = CodeReviewOutcome.model_validate(outcome.model_dump())
        with self.db:
            changed = self.db.execute(
                "UPDATE code_reviews SET state='completed',result_json=? "
                "WHERE plan_id=? AND state='started'",
                (outcome.model_dump_json(), outcome.plan_id),
            ).rowcount
            if changed != 1:
                raise ReviewRecoveryRequired("review STARTED checkpoint unavailable")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()
