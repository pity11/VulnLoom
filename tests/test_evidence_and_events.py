from __future__ import annotations

import base64
import sqlite3
from urllib.parse import quote
from uuid import uuid4

import pytest

from vulnloom.domain.models import EvidenceKind
from vulnloom.evidence import BoundedRedactionBuffer, Redactor, SensitiveDataRejected
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
    assert store.contains(evidence.evidence_id)
    assert "top-secret-token" not in captured
    assert "a@example.org" not in captured
    assert "sk-live" not in captured
    assert evidence.evidence_id not in evidence.summary

    path = tmp_path / "evidence" / evidence.content_ref
    path.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        store.read_text(evidence)
    assert not store.contains(evidence.evidence_id)


def test_evidence_store_rejects_oversize_and_symlink_objects(tmp_path):
    store = EvidenceStore(tmp_path / "evidence", max_evidence_bytes=8)
    with pytest.raises(ValueError, match="size limit"):
        store.capture_text(
            "x" * 9,
            kind=EvidenceKind.TEST,
            source_ref="fixture:oversize",
            producer="test",
            target_version="v1",
            summary="oversize",
        )

    evidence = store.capture_text(
        "12345678",
        kind=EvidenceKind.TEST,
        source_ref="fixture:symlink",
        producer="test",
        target_version="v1",
        summary="symlink",
    )
    path = tmp_path / "evidence" / evidence.content_ref
    moved = tmp_path / "outside-evidence"
    path.rename(moved)
    path.symlink_to(moved)
    assert not store.contains(evidence.evidence_id)
    with pytest.raises(ValueError, match="unavailable or unsafe"):
        store.read_text(evidence)


def test_evidence_size_limit_applies_before_secret_redaction_can_shrink_input(tmp_path):
    canary = "vl-canary-S1.3-raw-input-must-remain-bounded"
    store = EvidenceStore(
        tmp_path / "evidence",
        Redactor((canary,)),
        max_evidence_bytes=16,
    )

    with pytest.raises(ValueError, match="raw Evidence"):
        store.capture_text(
            canary,
            kind=EvidenceKind.TEST,
            source_ref="fixture:oversize-canary",
            producer="test",
            target_version="v1",
            summary="oversize",
        )

    assert tuple(store.objects.iterdir()) == ()


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


def test_known_canary_variants_are_redacted_across_fragmented_chunks(tmp_path):
    canary = "vl-canary-S1.3-credential"
    encoded = base64.urlsafe_b64encode(canary.encode()).decode().rstrip("=")
    content = (
        f"plain={canary}\nurl={quote(canary, safe='')}\n"
        f"b64={encoded}\nhex={canary.encode().hex()}"
    )
    chunks = tuple(
        content.encode()[index : index + 3] for index in range(0, len(content), 3)
    )
    redactor = Redactor((canary,))
    buffer = BoundedRedactionBuffer(redactor, max_input_bytes=4096)
    buffer.feed(chunks)

    redacted = buffer.finalize()

    assert canary not in redacted
    assert encoded not in redacted
    assert canary.encode().hex() not in redacted
    assert redacted.count("[REDACTED]") == 4
    assert buffer._buffer == bytearray()
    with pytest.raises(SensitiveDataRejected, match="finalized"):
        buffer.feed(b"late")

    store = EvidenceStore(tmp_path / "chunked-evidence", redactor, max_evidence_bytes=4096)
    evidence = store.capture_chunks(
        chunks,
        kind=EvidenceKind.TEST,
        source_ref="fixture:fragmented-canary",
        producer="test",
        target_version="v1",
        summary=f"captured {canary}",
    )
    persisted = store.read_text(evidence)
    assert canary not in persisted
    assert encoded not in persisted
    assert canary not in evidence.summary


@pytest.mark.parametrize("chunks", ((b"valid", b"\xff"), (b"x" * 9,)))
def test_bounded_redaction_buffer_rejects_malformed_or_oversized_input(chunks):
    buffer = BoundedRedactionBuffer(max_input_bytes=8)

    with pytest.raises(SensitiveDataRejected):
        buffer.feed(chunks)
        buffer.finalize()

    assert buffer._buffer == bytearray()
    with pytest.raises(SensitiveDataRejected, match="finalized"):
        buffer.feed(b"reuse")


def test_bounded_redaction_buffer_enforces_post_redaction_limit_and_clears():
    buffer = BoundedRedactionBuffer(
        Redactor(("12345678",)),
        max_input_bytes=8,
        max_output_bytes=8,
    )
    buffer.feed(b"12345678")

    with pytest.raises(SensitiveDataRejected, match="output exceeds"):
        buffer.finalize()

    assert buffer._buffer == bytearray()


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


def test_event_store_redacts_known_encoded_canary(tmp_path, engagement_id):
    canary = "vl-canary-S1.3-event-secret"
    encoded = base64.b64encode(canary.encode()).decode()
    event = Event(
        engagement_id=engagement_id,
        event_type="WorkerReported",
        aggregate_id="task-canary",
        payload={"message": f"fragment:{encoded}"},
        idempotency_key="task-canary:report",
    )
    with EventStore(tmp_path / "events.db", Redactor((canary,))) as store:
        store.append(event)
        raw_database = (tmp_path / "events.db").read_bytes()
        stored = store.list_for_engagement(engagement_id)[0]

    assert canary.encode() not in raw_database
    assert encoded.encode() not in raw_database
    assert stored.payload == {"message": "fragment:[REDACTED]"}


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
