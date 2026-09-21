from __future__ import annotations

import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.domain.digests import canonical_digest
from vulnloom.evidence.redaction import Redactor
from vulnloom.storage import (
    AtomicAuditRecoveryRequired,
    AuditAppendExpired,
    AuditIntegrityError,
    AuditStateBindings,
    AuditVerificationStatus,
    Event,
    EventStore,
    IdempotencyConflict,
    control_plane_audit_stream_id,
)


def _bindings(engagement_id, *, marker: str = "base") -> AuditStateBindings:
    return AuditStateBindings(
        engagement_id=engagement_id,
        scope_id=uuid4(),
        scope_version=4,
        policy_digest=canonical_digest({"policy": marker}),
        sandbox_profile_digest=canonical_digest({"profile": marker}),
        context_digest=canonical_digest({"context": marker}),
        tool_registry_digest=canonical_digest({"tools": marker}),
        provider_revision_digest=canonical_digest({"provider": marker}),
        input_digests=(canonical_digest({"input": marker}),),
    )


def _event(now, engagement_id, *, index: int = 1, payload=None) -> Event:
    return Event(
        engagement_id=engagement_id,
        event_type="ScopeApproved",
        aggregate_id=f"scope-{index}",
        payload=payload or {"scope_version": index},
        occurred_at=now + timedelta(seconds=index),
        idempotency_key=f"scope:{index}:approve",
    )


def _append(store, event, bindings, now, *, deadline=None, checkpoint=None):
    checkpoint = checkpoint or store.audit.checkpoint(
        control_plane_audit_stream_id(event.engagement_id),
        now=event.occurred_at,
    )
    return store.append_authoritative(
        event,
        bindings=bindings,
        trusted_checkpoint=checkpoint,
        deadline=deadline or event.occurred_at + timedelta(seconds=30),
        now=now,
    )


def test_authoritative_event_and_audit_commit_atomically_and_redacted(tmp_path, now):
    engagement_id = uuid4()
    stream_id = control_plane_audit_stream_id(engagement_id)
    canary = "vl-canary-S1.4-atomic-event"
    event = _event(
        now,
        engagement_id,
        payload={"scope_version": 1, "authorization": canary},
    )
    database = tmp_path / "control-plane.db"

    with EventStore(database, Redactor((canary,))) as store:
        stored, record, created = _append(
            store,
            event,
            _bindings(engagement_id),
            now + timedelta(seconds=2),
        )
        checkpoint = store.audit.checkpoint(stream_id, now=now + timedelta(seconds=3))
        verified = store.audit.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=4),
        )
        projection = store.audit.projections(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=5),
        )[0]
        events = store.list_authoritative_for_engagement(
            engagement_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=6),
        )

    assert created is True
    assert stored.payload["authorization"] == "[REDACTED]"
    assert events == (stored,)
    assert record.sequence == 1
    assert record.bindings.engagement_id == engagement_id
    assert verified.status is AuditVerificationStatus.VERIFIED
    assert projection.transition_digest == record.transition_digest
    assert canary.encode() not in database.read_bytes()
    assert event.idempotency_key not in record.model_dump_json()


def test_authoritative_replay_is_exact_and_idempotent_even_after_deadline(tmp_path, now):
    engagement_id = uuid4()
    event = _event(now, engagement_id)
    bindings = _bindings(engagement_id)
    deadline = event.occurred_at + timedelta(seconds=30)
    with EventStore(tmp_path / "control-plane.db") as store:
        first_event, first_record, first_created = _append(
            store,
            event,
            bindings,
            now + timedelta(seconds=2),
            deadline=deadline,
        )
        checkpoint = store.audit.checkpoint(
            control_plane_audit_stream_id(engagement_id),
            now=now + timedelta(seconds=3),
        )
        replay_event, replay_record, replay_created = _append(
            store,
            event,
            bindings,
            deadline,
            deadline=deadline,
            checkpoint=checkpoint,
        )

        changed = event.model_copy(update={"payload": {"scope_version": 99}})
        with pytest.raises(IdempotencyConflict, match="different authoritative event"):
            _append(store, changed, bindings, now + timedelta(seconds=3))

        assert len(store.list_for_engagement(engagement_id)) == 1

    assert first_created is True
    assert replay_created is False
    assert replay_event == first_event
    assert replay_record == first_record


def test_expired_audit_rolls_back_domain_event_and_head(tmp_path, now):
    engagement_id = uuid4()
    event = _event(now, engagement_id)
    stream_id = control_plane_audit_stream_id(engagement_id)
    with EventStore(tmp_path / "control-plane.db") as store:
        with pytest.raises(AuditAppendExpired, match="deadline"):
            _append(
                store,
                event,
                _bindings(engagement_id),
                event.occurred_at + timedelta(seconds=30),
            )

        assert store.list_for_engagement(engagement_id) == ()
        checkpoint = store.audit.checkpoint(
            stream_id, now=event.occurred_at + timedelta(seconds=31)
        )

    assert checkpoint.sequence == 0


def test_audit_insert_failure_rolls_back_domain_event_and_audit_head(tmp_path, now):
    engagement_id = uuid4()
    event = _event(now, engagement_id)
    with EventStore(tmp_path / "control-plane.db") as store:
        store.connection.execute(
            "CREATE TRIGGER deny_atomic_audit BEFORE INSERT "
            "ON authoritative_audit_records "
            "BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="fixture audit failure"):
            _append(
                store,
                event,
                _bindings(engagement_id),
                now + timedelta(seconds=2),
            )

        counts = tuple(
            store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "domain_events",
                "authoritative_audit_records",
                "authoritative_audit_heads",
            )
        )

    assert counts == (0, 0, 0)


@pytest.mark.parametrize("missing_side", ("event", "audit"))
def test_partial_pair_requires_external_recovery_without_backfill(
    tmp_path, now, missing_side
):
    engagement_id = uuid4()
    event = _event(now, engagement_id)
    bindings = _bindings(engagement_id)
    stream_id = control_plane_audit_stream_id(engagement_id)
    with EventStore(tmp_path / f"{missing_side}.db") as store:
        _append(store, event, bindings, now + timedelta(seconds=2))
        checkpoint = store.audit.checkpoint(
            stream_id, now=now + timedelta(seconds=3)
        )
        if missing_side == "event":
            store.connection.execute("DELETE FROM domain_events")
        else:
            store.connection.execute("DELETE FROM authoritative_audit_records")
            store.connection.execute("DELETE FROM authoritative_audit_heads")

        expected_error = (
            AtomicAuditRecoveryRequired
            if missing_side == "event"
            else AuditIntegrityError
        )
        with pytest.raises(expected_error):
            _append(
                store,
                event,
                bindings,
                now + timedelta(seconds=4),
                checkpoint=checkpoint,
            )
        with pytest.raises(expected_error):
            store.list_authoritative_for_engagement(
                engagement_id,
                trusted_checkpoint=checkpoint,
                now=now + timedelta(seconds=5),
            )

        event_count = store.connection.execute(
            "SELECT COUNT(*) FROM domain_events"
        ).fetchone()[0]
        audit_count = store.connection.execute(
            "SELECT COUNT(*) FROM authoritative_audit_records WHERE stream_id = ?",
            (stream_id,),
        ).fetchone()[0]

    assert (event_count, audit_count) in {(0, 1), (1, 0)}


def test_corrupt_chain_and_wrong_engagement_block_state_change(tmp_path, now):
    engagement_id = uuid4()
    bindings = _bindings(engagement_id)
    first = _event(now, engagement_id)
    second = _event(now, engagement_id, index=2)
    with EventStore(tmp_path / "control-plane.db") as store:
        with pytest.raises(ValueError, match="Engagement"):
            _append(
                store,
                first,
                _bindings(uuid4()),
                now + timedelta(seconds=2),
            )
        assert store.list_for_engagement(engagement_id) == ()

        _append(store, first, bindings, now + timedelta(seconds=2))
        checkpoint = store.audit.checkpoint(
            control_plane_audit_stream_id(engagement_id),
            now=now + timedelta(seconds=3),
        )
        store.connection.execute(
            "UPDATE authoritative_audit_records SET previous_digest = ?",
            ("f" * 64,),
        )
        with pytest.raises(AuditIntegrityError, match="authoritative event refused"):
            _append(
                store,
                second,
                bindings,
                now + timedelta(seconds=4),
                checkpoint=checkpoint,
            )

        events = store.list_for_engagement(engagement_id)

    assert len(events) == 1
    assert events[0].event_id == first.event_id


def test_external_checkpoint_blocks_complete_event_and_audit_rollback(tmp_path, now):
    engagement_id = uuid4()
    bindings = _bindings(engagement_id)
    stream_id = control_plane_audit_stream_id(engagement_id)
    first = _event(now, engagement_id)
    second = _event(now, engagement_id, index=2)
    with EventStore(tmp_path / "control-plane.db") as store:
        _append(store, first, bindings, now + timedelta(seconds=2))
        checkpoint = store.audit.checkpoint(stream_id, now=now + timedelta(seconds=3))
        store.connection.execute("DELETE FROM domain_events")
        store.connection.execute("DELETE FROM authoritative_audit_records")
        store.connection.execute("DELETE FROM authoritative_audit_heads")

        with pytest.raises(AuditIntegrityError, match="checkpoint_ahead_of_chain"):
            _append(
                store,
                second,
                bindings,
                now + timedelta(seconds=4),
                checkpoint=checkpoint,
            )

        assert store.list_for_engagement(engagement_id) == ()
        assert store.connection.execute(
            "SELECT COUNT(*) FROM authoritative_audit_records"
        ).fetchone()[0] == 0


def test_domain_event_tampering_blocks_authoritative_query_and_next_append(tmp_path, now):
    engagement_id = uuid4()
    bindings = _bindings(engagement_id)
    stream_id = control_plane_audit_stream_id(engagement_id)
    first = _event(now, engagement_id)
    second = _event(now, engagement_id, index=2)
    with EventStore(tmp_path / "control-plane.db") as store:
        _append(store, first, bindings, now + timedelta(seconds=2))
        checkpoint = store.audit.checkpoint(stream_id, now=now + timedelta(seconds=3))
        store.connection.execute(
            "UPDATE domain_events SET payload_json = ? WHERE event_id = ?",
            ('{"scope_version":999}', str(first.event_id)),
        )

        with pytest.raises(AtomicAuditRecoveryRequired, match="binding differs"):
            store.list_authoritative_for_engagement(
                engagement_id,
                trusted_checkpoint=checkpoint,
                now=now + timedelta(seconds=4),
            )
        with pytest.raises(AtomicAuditRecoveryRequired, match="binding differs"):
            _append(
                store,
                second,
                bindings,
                now + timedelta(seconds=5),
                checkpoint=checkpoint,
            )

        assert len(store.list_for_engagement(engagement_id)) == 1
        assert store.connection.execute(
            "SELECT COUNT(*) FROM authoritative_audit_records"
        ).fetchone()[0] == 1
