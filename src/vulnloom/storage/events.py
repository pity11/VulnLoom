"""Transactional, idempotent SQLite event log."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field

from vulnloom.domain.models import DomainModel, utc_now
from vulnloom.evidence.redaction import Redactor


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


class EventStore:
    def __init__(self, path: Path, redactor: Redactor | None = None):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.redactor = redactor or Redactor()
        self._create_schema()

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
        self.connection.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
