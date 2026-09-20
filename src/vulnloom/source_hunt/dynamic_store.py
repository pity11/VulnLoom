"""Transactional persistent Crash Signature catalog."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from .dynamic_models import (
    SourceCrashDisposition,
    SourceCrashRecord,
    SourceCrashRegistration,
    SourceCrashSignature,
)


class SourceCrashStoreRejected(ValueError):
    pass


class SourceCrashStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_crashes (
                fingerprint TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_crash_observations (
                idempotency_key TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                result_payload TEXT NOT NULL,
                UNIQUE(fingerprint, plan_id)
            )
            """
        )

    def register(
        self,
        *,
        signature: SourceCrashSignature,
        plan_id: str,
        input_digest: str,
        observed_at: datetime,
        idempotency_key: str,
    ) -> SourceCrashRegistration:
        with self.connection:
            replay = self.connection.execute(
                "SELECT fingerprint, plan_id, input_digest, result_payload "
                "FROM source_crash_observations WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if replay is not None:
                if replay[:3] != (signature.fingerprint, plan_id, input_digest):
                    raise SourceCrashStoreRejected("Crash registration idempotency collision")
                return SourceCrashRegistration.model_validate_json(replay[3])
            row = self.connection.execute(
                "SELECT payload FROM source_crashes WHERE fingerprint = ?",
                (signature.fingerprint,),
            ).fetchone()
            if row is None:
                record = SourceCrashRecord(
                    fingerprint=signature.fingerprint,
                    signature=signature,
                    canonical_input_digest=input_digest,
                    first_plan_id=plan_id,
                    last_plan_id=plan_id,
                    observation_count=1,
                    observed_plan_ids=(plan_id,),
                    first_observed_at=observed_at,
                    last_observed_at=observed_at,
                )
                disposition = SourceCrashDisposition.NEW
            else:
                prior = SourceCrashRecord.model_validate_json(row[0])
                if prior.signature != signature:
                    raise SourceCrashStoreRejected("Crash fingerprint collision")
                record = prior.model_copy(
                    update={
                        "last_plan_id": plan_id,
                        "observation_count": prior.observation_count + 1,
                        "observed_plan_ids": (*prior.observed_plan_ids, plan_id),
                        "last_observed_at": observed_at,
                    }
                )
                record = SourceCrashRecord.model_validate(record.model_dump(mode="python"))
                disposition = SourceCrashDisposition.DUPLICATE
            registration = SourceCrashRegistration(disposition=disposition, record=record)
            self.connection.execute(
                "INSERT INTO source_crashes VALUES (?, ?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET payload = excluded.payload",
                (signature.fingerprint, record.model_dump_json()),
            )
            try:
                self.connection.execute(
                    "INSERT INTO source_crash_observations VALUES (?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        signature.fingerprint,
                        plan_id,
                        input_digest,
                        registration.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SourceCrashStoreRejected(
                    "Crash plan was already registered under another key"
                ) from exc
        return registration

    def load(self, fingerprint: str) -> SourceCrashRecord:
        row = self.connection.execute(
            "SELECT payload FROM source_crashes WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            raise SourceCrashStoreRejected("Crash Signature is unavailable")
        return SourceCrashRecord.model_validate_json(row[0])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> SourceCrashStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
