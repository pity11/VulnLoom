from __future__ import annotations

import sqlite3
from uuid import uuid4

import pytest

from vulnloom.domain.models import EvidenceKind
from vulnloom.evidence.store import EvidenceStore
from vulnloom.storage.events import Event, EventStore, IdempotencyConflict


def test_evidence_is_redacted_content_addressed_and_integrity_checked(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    evidence = store.capture_text(
        "Authorization: Bearer top-secret-token\nowner=a@example.org\nsk-live-123456789012345",
        kind=EvidenceKind.HTTP,
        source_ref="validation-run:test",
        producer="http-validator",
        target_version="a" * 40,
        summary="response for a@example.org",
    )
    captured = store.read_text(evidence)
    assert "top-secret-token" not in captured
    assert "a@example.org" not in captured
    assert "sk-live" not in captured
    assert evidence.evidence_id not in evidence.summary

    path = tmp_path / "evidence" / evidence.content_ref
    path.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        store.read_text(evidence)


def test_evidence_redaction_covers_json_shaped_secrets(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    evidence = store.capture_text(
        '{"api_key":"json-secret","nested":{"password":"also-secret"}}',
        kind=EvidenceKind.HTTP,
        source_ref="fixture:json",
        producer="test",
        target_version="v1",
        summary="JSON response",
    )
    content = store.read_text(evidence)
    assert "json-secret" not in content
    assert "also-secret" not in content
    assert content.count("[REDACTED]") == 2


def test_event_store_is_idempotent_and_redacts_secrets(tmp_path, engagement_id):
    event = Event(
        engagement_id=engagement_id,
        event_type="WorkerReported",
        aggregate_id="task-1",
        payload={"api_key": "sk-should-not-persist", "nested": {"email": "me@example.org"}},
        idempotency_key="task-1:report",
    )
    with EventStore(tmp_path / "events.db") as store:
        first, created_first = store.append(event)
        second, created_second = store.append(event.model_copy(update={"event_id": uuid4()}))
        events = store.list_for_engagement(engagement_id)

    assert created_first is True
    assert created_second is False
    assert first.event_id == second.event_id
    assert len(events) == 1
    assert events[0].payload["api_key"] == "[REDACTED]"
    assert "me@example.org" not in str(events[0].payload)


def test_event_store_closes_connection_on_error(tmp_path):
    store = EventStore(tmp_path / "events.db")
    with pytest.raises(RuntimeError), store:
        raise RuntimeError("boom")
    with pytest.raises(sqlite3.ProgrammingError):
        store.connection.execute("SELECT 1")


def test_idempotency_key_collision_fails_closed(tmp_path, engagement_id):
    first = Event(
        engagement_id=engagement_id,
        event_type="CandidateProposed",
        aggregate_id="candidate-1",
        payload={"title": "first"},
        idempotency_key="candidate:1",
    )
    changed = first.model_copy(update={"event_id": uuid4(), "payload": {"title": "different"}})
    with EventStore(tmp_path / "events.db") as store:
        store.append(first)
        with pytest.raises(IdempotencyConflict, match="different event"):
            store.append(changed)
