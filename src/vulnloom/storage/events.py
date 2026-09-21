"""Transactional, idempotent SQLite event log."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, utc_now
from vulnloom.evidence.redaction import Redactor
from vulnloom.storage.audit_chain import (
    AuditAppendPlan,
    AuditCheckpoint,
    AuditIntegrityError,
    AuditOutcome,
    AuditRecord,
    AuditStateBindings,
    AuditVerificationStatus,
    AuthoritativeAuditStore,
)

CONTROL_PLANE_AUDIT_EVENT_TYPE = "control_plane.event_committed"


class Event(DomainModel):
    event_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    event_type: str = Field(min_length=1)
    aggregate_id: str = Field(min_length=1)
    payload: dict
    occurred_at: AwareDatetime = Field(default_factory=utc_now)
    idempotency_key: str = Field(min_length=1)


class IdempotencyConflict(ValueError):
    """An idempotency key was reused for a different event."""


class AtomicAuditRecoveryRequired(RuntimeError):
    """Only one side of an authoritative event/audit pair exists."""


def control_plane_audit_stream_id(engagement_id: UUID) -> str:
    return canonical_digest(
        {"audit_stream": "control-plane-events-v1", "engagement_id": engagement_id}
    )


def _event_idempotency_digest(event: Event) -> str:
    return canonical_digest(
        {
            "contract": "control-plane-event-idempotency-v1",
            "engagement_id": event.engagement_id,
            "idempotency_key": event.idempotency_key,
        }
    )


def _event_transition_digest(event: Event, idempotency_digest: str) -> str:
    return canonical_digest(
        {
            "contract": "control-plane-event-transition-v1",
            "event": event.model_dump(mode="python"),
            "idempotency_digest": idempotency_digest,
        }
    )


class EventStore:
    def __init__(self, path: Path, redactor: Redactor | None = None):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.redactor = redactor or Redactor()
        self._create_schema()
        self.audit = AuthoritativeAuditStore(path, connection=self.connection)

    def _create_schema(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                engagement_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE
            )
            """
        )
        self.connection.commit()

    def append(self, event: Event) -> tuple[Event, bool]:
        safe_payload = self.redactor.value(event.payload)
        safe_event = event.model_copy(update={"payload": safe_payload})
        encoded = json.dumps(safe_payload, sort_keys=True, separators=(",", ":"))
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO domain_events (
                        event_id, engagement_id, event_type, aggregate_id,
                        payload_json, occurred_at, idempotency_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(safe_event.event_id),
                        str(safe_event.engagement_id),
                        safe_event.event_type,
                        safe_event.aggregate_id,
                        encoded,
                        safe_event.occurred_at.isoformat(),
                        safe_event.idempotency_key,
                    ),
                )
            return safe_event, True
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM domain_events WHERE idempotency_key = ?",
                (event.idempotency_key,),
            ).fetchone()
            if row is None:
                raise
            existing = self._from_row(row)
            if (
                existing.engagement_id != safe_event.engagement_id
                or existing.event_type != safe_event.event_type
                or existing.aggregate_id != safe_event.aggregate_id
                or existing.payload != safe_event.payload
            ):
                raise IdempotencyConflict(
                    f"idempotency key reused with different event: {event.idempotency_key}"
                ) from None
            return existing, False

    def append_authoritative(
        self,
        event: Event,
        *,
        bindings: AuditStateBindings,
        trusted_checkpoint: AuditCheckpoint,
        deadline: datetime,
        now: datetime,
    ) -> tuple[Event, AuditRecord, bool]:
        """Atomically append a redacted event and its tamper-evident audit record."""

        event = Event.model_validate(event.model_dump(mode="python"))
        bindings = AuditStateBindings.model_validate(bindings.model_dump(mode="python"))
        if bindings.engagement_id != event.engagement_id:
            raise ValueError("audit bindings must match the event Engagement")
        safe_payload = self.redactor.value(event.payload)
        safe_event = event.model_copy(update={"payload": safe_payload})
        idempotency_digest = _event_idempotency_digest(safe_event)
        stream_id = control_plane_audit_stream_id(safe_event.engagement_id)
        transition_digest = _event_transition_digest(
            safe_event, idempotency_digest
        )
        audit_plan = AuditAppendPlan.create(
            stream_id=stream_id,
            event_type=CONTROL_PLANE_AUDIT_EVENT_TYPE,
            aggregate_id=canonical_digest(
                {
                    "engagement_id": safe_event.engagement_id,
                    "aggregate_id": safe_event.aggregate_id,
                }
            ),
            transition_digest=transition_digest,
            bindings=bindings,
            outcome=AuditOutcome.COMMITTED,
            cleanup_verified=True,
            occurred_at=safe_event.occurred_at,
            deadline=deadline,
            idempotency_digest=idempotency_digest,
        )

        self.connection.execute("BEGIN IMMEDIATE")
        try:
            verification = self.audit.verify_in_transaction(
                stream_id,
                now=now,
                trusted_checkpoint=trusted_checkpoint,
            )
            if verification.status is not AuditVerificationStatus.VERIFIED:
                raise AuditIntegrityError(
                    f"authoritative event refused: {verification.failure_code}"
                )
            self._assert_authoritative_pairs_locked(safe_event.engagement_id, stream_id)
            existing_row = self.connection.execute(
                "SELECT * FROM domain_events WHERE idempotency_key = ?",
                (safe_event.idempotency_key,),
            ).fetchone()
            audit_exists = self.audit.contains_idempotency(
                stream_id, idempotency_digest
            )
            event_exists = existing_row is not None
            if event_exists != audit_exists:
                raise AtomicAuditRecoveryRequired(
                    "authoritative event/audit pair is incomplete; restore a verified copy"
                )
            if existing_row is not None:
                existing = self._from_row(existing_row)
                self._assert_idempotent(existing, safe_event)
                record = self.audit.append_in_transaction(
                    audit_plan,
                    now=now,
                    trusted_checkpoint=trusted_checkpoint,
                )
                self.connection.execute("COMMIT")
                return existing, record, False

            encoded = json.dumps(safe_payload, sort_keys=True, separators=(",", ":"))
            self.connection.execute(
                """
                INSERT INTO domain_events (
                    event_id, engagement_id, event_type, aggregate_id,
                    payload_json, occurred_at, idempotency_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(safe_event.event_id),
                    str(safe_event.engagement_id),
                    safe_event.event_type,
                    safe_event.aggregate_id,
                    encoded,
                    safe_event.occurred_at.isoformat(),
                    safe_event.idempotency_key,
                ),
            )
            record = self.audit.append_in_transaction(
                audit_plan,
                now=now,
                trusted_checkpoint=trusted_checkpoint,
            )
            self.connection.execute("COMMIT")
            return safe_event, record, True
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def list_authoritative_for_engagement(
        self,
        engagement_id: UUID,
        *,
        trusted_checkpoint: AuditCheckpoint,
        now: datetime,
    ) -> tuple[Event, ...]:
        """Read state only after anchored chain and event-pair verification."""

        stream_id = control_plane_audit_stream_id(engagement_id)
        self.connection.execute("BEGIN")
        try:
            verification = self.audit.verify_in_transaction(
                stream_id,
                now=now,
                trusted_checkpoint=trusted_checkpoint,
            )
            if verification.status is not AuditVerificationStatus.VERIFIED:
                raise AuditIntegrityError(
                    f"authoritative event query refused: {verification.failure_code}"
                )
            events = self._assert_authoritative_pairs_locked(engagement_id, stream_id)
            self.connection.execute("COMMIT")
            return events
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _assert_authoritative_pairs_locked(
        self, engagement_id: UUID, stream_id: str
    ) -> tuple[Event, ...]:
        event_rows = self.connection.execute(
            "SELECT * FROM domain_events WHERE engagement_id = ? ORDER BY sequence",
            (str(engagement_id),),
        ).fetchall()
        audit_rows = self.connection.execute(
            "SELECT idempotency_digest, record_json "
            "FROM authoritative_audit_records WHERE stream_id = ? ORDER BY sequence",
            (stream_id,),
        ).fetchall()
        try:
            events = tuple(self._from_row(row) for row in event_rows)
            records = {
                row["idempotency_digest"]: AuditRecord.model_validate_json(
                    row["record_json"]
                )
                for row in audit_rows
            }
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise AtomicAuditRecoveryRequired(
                "authoritative event/audit pair cannot be decoded; restore a verified copy"
            ) from exc
        if len(events) != len(records):
            raise AtomicAuditRecoveryRequired(
                "authoritative event/audit pair count differs; restore a verified copy"
            )
        for event in events:
            idempotency_digest = _event_idempotency_digest(event)
            record = records.get(idempotency_digest)
            aggregate_digest = canonical_digest(
                {
                    "engagement_id": event.engagement_id,
                    "aggregate_id": event.aggregate_id,
                }
            )
            if (
                record is None
                or record.event_type != CONTROL_PLANE_AUDIT_EVENT_TYPE
                or record.bindings.engagement_id != engagement_id
                or record.aggregate_id != aggregate_digest
                or record.transition_digest
                != _event_transition_digest(event, idempotency_digest)
            ):
                raise AtomicAuditRecoveryRequired(
                    "authoritative event/audit binding differs; restore a verified copy"
                )
        return events

    @staticmethod
    def _assert_idempotent(existing: Event, requested: Event) -> None:
        if existing != requested:
            raise IdempotencyConflict(
                f"idempotency key reused with different authoritative event: "
                f"{requested.idempotency_key}"
            )

    def list_for_engagement(self, engagement_id: UUID) -> tuple[Event, ...]:
        rows = self.connection.execute(
            "SELECT * FROM domain_events WHERE engagement_id = ? ORDER BY sequence",
            (str(engagement_id),),
        ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Event:
        return Event(
            event_id=UUID(row["event_id"]),
            engagement_id=UUID(row["engagement_id"]),
            event_type=row["event_type"],
            aggregate_id=row["aggregate_id"],
            payload=json.loads(row["payload_json"]),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            idempotency_key=row["idempotency_key"],
        )

    def close(self) -> None:
        self.audit.close()
        self.connection.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
