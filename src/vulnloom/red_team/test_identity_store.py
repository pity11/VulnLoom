"""Transactional registry and admission ledger for opaque test identities."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .test_identity_models import (
    TestIdentityAdmission,
    TestIdentityAdmissionOutcome,
    TestIdentityAdmissionPlan,
    TestIdentityAdmissionState,
    TestIdentityRecord,
    TestIdentityRecordState,
    TestIdentityRevocation,
)


class TestIdentityStoreRejected(ValueError):
    pass


class TestIdentityRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TestIdentityAdmissionClaim:
    created: bool
    attempt: int
    admission: TestIdentityAdmission | None = None
    outcome: TestIdentityAdmissionOutcome | None = None


class TestIdentityStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS red_team_test_identities (
                identity_ref TEXT PRIMARY KEY,
                record_id TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('active','revoked')),
                revocation_json TEXT
            );
            CREATE TABLE IF NOT EXISTS red_team_test_identity_admissions (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                admission_json TEXT,
                outcome_json TEXT
            );
            """
        )
        self.connection.commit()

    def register(self, record: TestIdentityRecord) -> TestIdentityRecord:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_test_identities VALUES (?,?,?,'active',NULL)",
                    (
                        record.reference.identity_ref,
                        record.record_id,
                        record.model_dump_json(),
                    ),
                )
            return record
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT record_json FROM red_team_test_identities "
                "WHERE identity_ref=? OR record_id=?",
                (record.reference.identity_ref, record.record_id),
            ).fetchone()
            if (
                row is None
                or TestIdentityRecord.model_validate_json(row["record_json"]) != record
            ):
                raise TestIdentityStoreRejected(
                    "Test Identity registry identity conflicted"
                ) from None
            return record

    def active_record(self, identity_ref: str) -> TestIdentityRecord:
        row = self.connection.execute(
            "SELECT record_json,state FROM red_team_test_identities WHERE identity_ref=?",
            (identity_ref,),
        ).fetchone()
        if row is None or row["state"] != TestIdentityRecordState.ACTIVE.value:
            raise TestIdentityStoreRejected("active Test Identity is unavailable")
        return TestIdentityRecord.model_validate_json(row["record_json"])

    def revoke(
        self,
        identity_ref: str,
        *,
        reason_digest: str,
        now: datetime,
    ) -> TestIdentityRevocation:
        with self.connection:
            row = self.connection.execute(
                "SELECT record_json,state,revocation_json "
                "FROM red_team_test_identities WHERE identity_ref=?",
                (identity_ref,),
            ).fetchone()
            if row is None:
                raise TestIdentityStoreRejected("Test Identity is unavailable")
            record = TestIdentityRecord.model_validate_json(row["record_json"])
            if now < record.issued_at:
                raise TestIdentityStoreRejected(
                    "Test Identity cannot be revoked before issuance"
                )
            revocation = TestIdentityRevocation.create(
                record_id=record.record_id,
                identity_ref=identity_ref,
                reason_digest=reason_digest,
                revoked_at=now,
            )
            if row["state"] == TestIdentityRecordState.REVOKED.value:
                existing = TestIdentityRevocation.model_validate_json(
                    row["revocation_json"]
                )
                if existing != revocation:
                    raise TestIdentityStoreRejected(
                        "Test Identity revocation conflicted"
                    )
                return existing
            changed = self.connection.execute(
                "UPDATE red_team_test_identities "
                "SET state='revoked',revocation_json=? "
                "WHERE identity_ref=? AND state='active'",
                (revocation.model_dump_json(), identity_ref),
            ).rowcount
            if changed != 1:
                raise TestIdentityStoreRejected("Test Identity revocation raced")
        return revocation

    def claim(
        self, plan: TestIdentityAdmissionPlan, *, now: datetime
    ) -> TestIdentityAdmissionClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO red_team_test_identity_admissions VALUES "
                    "(?,?,?,'started',1,?,NULL,NULL,NULL)",
                    (
                        plan.plan_id,
                        plan.idempotency_key,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return TestIdentityAdmissionClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] == TestIdentityAdmissionState.STARTED.value:
                raise TestIdentityRecoveryRequired(
                    "Test Identity Admission has an unfinished STARTED checkpoint"
                ) from None
            return TestIdentityAdmissionClaim(
                created=False,
                attempt=row["attempt"],
                admission=TestIdentityAdmission.model_validate_json(
                    row["admission_json"]
                ),
                outcome=TestIdentityAdmissionOutcome.model_validate_json(
                    row["outcome_json"]
                ),
            )

    def recover(
        self, plan: TestIdentityAdmissionPlan, *, now: datetime
    ) -> TestIdentityAdmissionClaim:
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if row["state"] != TestIdentityAdmissionState.STARTED.value:
                raise TestIdentityRecoveryRequired(
                    "Test Identity Admission is not awaiting recovery"
                )
            if row["attempt"] >= plan.limits.max_attempts:
                raise TestIdentityRecoveryRequired(
                    "Test Identity Admission recovery attempts are exhausted"
                )
            attempt = row["attempt"] + 1
            changed = self.connection.execute(
                "UPDATE red_team_test_identity_admissions SET attempt=?,started_at=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (attempt, now.isoformat(), plan.plan_id, row["attempt"]),
            ).rowcount
            if changed != 1:
                raise TestIdentityRecoveryRequired(
                    "Test Identity Admission recovery raced"
                )
        return TestIdentityAdmissionClaim(created=True, attempt=attempt)

    def complete(
        self,
        plan: TestIdentityAdmissionPlan,
        admission: TestIdentityAdmission,
        outcome: TestIdentityAdmissionOutcome,
    ) -> None:
        if (
            admission.plan_id != plan.plan_id
            or outcome.plan_id != plan.plan_id
            or outcome.admission_id != admission.admission_id
            or admission.record_id != plan.record_id
            or admission.identity_ref != plan.identity_ref
            or admission.credential_ref != plan.credential_ref
        ):
            raise TestIdentityStoreRejected(
                "Test Identity Admission completion binding is invalid"
            )
        with self.connection:
            row = self._by_identity(plan)
            self._same(row, plan)
            if (
                row["state"] != TestIdentityAdmissionState.STARTED.value
                or row["attempt"] != outcome.attempt
            ):
                raise TestIdentityRecoveryRequired(
                    "Test Identity Admission STARTED checkpoint is unavailable"
                )
            changed = self.connection.execute(
                "UPDATE red_team_test_identity_admissions "
                "SET state='completed',completed_at=?,admission_json=?,outcome_json=? "
                "WHERE plan_id=? AND state='started' AND attempt=?",
                (
                    outcome.completed_at.isoformat(),
                    admission.model_dump_json(),
                    outcome.model_dump_json(),
                    plan.plan_id,
                    outcome.attempt,
                ),
            ).rowcount
            if changed != 1:
                raise TestIdentityRecoveryRequired(
                    "Test Identity Admission completion raced"
                )

    def state(
        self, plan_id: str
    ) -> tuple[TestIdentityAdmissionState, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM red_team_test_identity_admissions WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return TestIdentityAdmissionState(row["state"]), row["attempt"]

    def admission(self, plan_id: str) -> TestIdentityAdmission:
        row = self.connection.execute(
            "SELECT state,admission_json FROM red_team_test_identity_admissions "
            "WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None or row["state"] != TestIdentityAdmissionState.COMPLETED.value:
            raise TestIdentityStoreRejected(
                "completed Test Identity Admission is unavailable"
            )
        return TestIdentityAdmission.model_validate_json(row["admission_json"])

    def plan(self, plan_id: str) -> TestIdentityAdmissionPlan:
        row = self.connection.execute(
            "SELECT plan_json FROM red_team_test_identity_admissions WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise TestIdentityStoreRejected(
                "Test Identity Admission Plan is unavailable"
            )
        return TestIdentityAdmissionPlan.model_validate_json(row["plan_json"])

    def admission_count(self) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM red_team_test_identity_admissions "
                "WHERE state='completed'"
            ).fetchone()[0]
        )

    def _by_identity(self, plan: TestIdentityAdmissionPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM red_team_test_identity_admissions "
            "WHERE plan_id=? OR idempotency_key=?",
            (plan.plan_id, plan.idempotency_key),
        ).fetchone()
        if row is None:
            raise TestIdentityRecoveryRequired(
                "Test Identity Admission checkpoint is unavailable"
            )
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: TestIdentityAdmissionPlan) -> None:
        if row["plan_id"] != plan.plan_id or row["plan_json"] != plan.model_dump_json():
            raise TestIdentityStoreRejected(
                "Test Identity Admission identity was reused for different content"
            )
