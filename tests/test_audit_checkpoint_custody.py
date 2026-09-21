from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.domain.digests import canonical_digest
from vulnloom.storage import (
    AUDIT_CHAIN_CONTRACT_DIGEST,
    AUDIT_GENESIS_DIGEST,
    AuditCheckpoint,
    AuditCheckpointCustodyError,
    AuditIntegrityError,
    AuditStateBindings,
    CheckpointedEventStore,
    Event,
    EventStore,
    FileAuditCheckpointStore,
    control_plane_audit_stream_id,
)


def _checkpoint(stream_id, sequence, head_digest, now):
    values = {
        "contract_digest": AUDIT_CHAIN_CONTRACT_DIGEST,
        "stream_id": stream_id,
        "sequence": sequence,
        "head_digest": head_digest,
        "issued_at": now,
    }
    return AuditCheckpoint(checkpoint_id=canonical_digest(values), **values)


def _event(now, engagement_id, *, index=1):
    return Event(
        engagement_id=engagement_id,
        event_type="ScopeApproved",
        aggregate_id=f"scope-{index}",
        payload={"scope_version": index},
        occurred_at=now + timedelta(seconds=index),
        idempotency_key=f"scope:{index}:approve",
    )


def _bindings(engagement_id):
    return AuditStateBindings(
        engagement_id=engagement_id,
        scope_id=uuid4(),
        scope_version=1,
        policy_digest=canonical_digest({"policy": "checkpoint"}),
        sandbox_profile_digest=canonical_digest({"profile": "checkpoint"}),
        context_digest=canonical_digest({"context": "checkpoint"}),
        tool_registry_digest=canonical_digest({"tools": "checkpoint"}),
        provider_revision_digest=canonical_digest({"provider": "checkpoint"}),
        input_digests=(canonical_digest({"input": "checkpoint"}),),
    )


def test_file_checkpoint_custody_is_private_monotonic_and_idempotent(tmp_path, now):
    stream_id = canonical_digest({"stream": "custody"})
    root = tmp_path / "checkpoints"
    store = FileAuditCheckpointStore(root)
    genesis = _checkpoint(stream_id, 0, AUDIT_GENESIS_DIGEST, now)
    first = _checkpoint(stream_id, 1, "a" * 64, now + timedelta(seconds=1))

    assert store.load(stream_id) is None
    assert store.initialize(genesis) == genesis
    assert store.initialize(genesis) == genesis
    assert store.advance(genesis, first) == first
    assert store.advance(genesis, first) == first
    assert store.load(stream_id) == first
    assert root.stat().st_mode & 0o077 == 0
    assert next(root.glob("*.checkpoint.json")).stat().st_mode & 0o077 == 0

    with pytest.raises(AuditCheckpointCustodyError, match="predecessor"):
        store.advance(genesis, _checkpoint(stream_id, 2, "b" * 64, now + timedelta(seconds=2)))
    with pytest.raises(AuditCheckpointCustodyError, match="empty stream"):
        FileAuditCheckpointStore(tmp_path / "other").initialize(first)


def test_checkpoint_write_failure_preserves_previous_anchor_and_cleans_temp(
    tmp_path, now, monkeypatch
):
    stream_id = canonical_digest({"stream": "atomic-custody"})
    root = tmp_path / "checkpoints"
    store = FileAuditCheckpointStore(root)
    genesis = store.initialize(_checkpoint(stream_id, 0, AUDIT_GENESIS_DIGEST, now))
    first = _checkpoint(stream_id, 1, "a" * 64, now + timedelta(seconds=1))

    def fail_replace(_source, _destination):
        raise OSError("fixture replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(AuditCheckpointCustodyError, match="atomic write failed"):
        store.advance(genesis, first)

    assert store.load(stream_id) == genesis
    assert list(root.glob("*.tmp")) == []


def test_checkpoint_custody_rejects_symlinks_permissions_and_oversize(tmp_path, now):
    target = tmp_path / "target"
    target.mkdir()
    symlink = tmp_path / "linked"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(AuditCheckpointCustodyError, match="symlink"):
        FileAuditCheckpointStore(symlink)

    stream_id = canonical_digest({"stream": "unsafe-file"})
    root = tmp_path / "checkpoints"
    store = FileAuditCheckpointStore(root)
    checkpoint = store.initialize(
        _checkpoint(stream_id, 0, AUDIT_GENESIS_DIGEST, now)
    )
    path = next(root.glob("*.checkpoint.json"))
    path.chmod(0o644)
    with pytest.raises(AuditCheckpointCustodyError, match="permissions"):
        store.load(stream_id)
    path.chmod(0o600)
    path.write_bytes(b"x" * (16 * 1024 + 1))
    with pytest.raises(AuditCheckpointCustodyError, match="size limit"):
        store.load(checkpoint.stream_id)


def test_checkpointed_event_store_survives_restart_and_detects_full_rollback(
    tmp_path, now
):
    database = tmp_path / "events.db"
    checkpoint_root = tmp_path / "checkpoints"
    engagement_id = uuid4()
    event = _event(now, engagement_id)
    bindings = _bindings(engagement_id)
    with CheckpointedEventStore(database, checkpoint_root) as store:
        stored, record, created = store.append(
            event,
            bindings=bindings,
            deadline=event.occurred_at + timedelta(seconds=30),
            now=now + timedelta(seconds=2),
        )

    with CheckpointedEventStore(database, checkpoint_root) as reopened:
        assert reopened.list_for_engagement(
            engagement_id, now=now + timedelta(seconds=3)
        ) == (stored,)

    connection = sqlite3.connect(database)
    connection.execute("DELETE FROM domain_events")
    connection.execute("DELETE FROM authoritative_audit_records")
    connection.execute("DELETE FROM authoritative_audit_heads")
    connection.commit()
    connection.close()

    with (
        CheckpointedEventStore(database, checkpoint_root) as rolled_back,
        pytest.raises(AuditIntegrityError, match="checkpoint_ahead_of_chain"),
    ):
        rolled_back.list_for_engagement(
            engagement_id, now=now + timedelta(seconds=4)
        )

    assert created is True
    assert record.sequence == 1


def test_missing_checkpoint_refuses_nonempty_legacy_or_authoritative_state(tmp_path, now):
    database = tmp_path / "events.db"
    engagement_id = uuid4()
    event = _event(now, engagement_id)
    with EventStore(database) as legacy:
        legacy.append(event)

    with (
        CheckpointedEventStore(database, tmp_path / "checkpoints") as store,
        pytest.raises(AuditCheckpointCustodyError, match="migrate or restore"),
    ):
        store.list_for_engagement(engagement_id, now=now + timedelta(seconds=2))


def test_checkpoint_advance_failure_recovers_by_exact_retry(tmp_path, now, monkeypatch):
    database = tmp_path / "events.db"
    checkpoint_root = tmp_path / "checkpoints"
    engagement_id = uuid4()
    event = _event(now, engagement_id)
    bindings = _bindings(engagement_id)
    with CheckpointedEventStore(database, checkpoint_root) as store:
        original_advance = store.checkpoints.advance

        def fail_advance(_expected, _checkpoint):
            raise AuditCheckpointCustodyError("fixture custody failure")

        monkeypatch.setattr(store.checkpoints, "advance", fail_advance)
        with pytest.raises(AuditCheckpointCustodyError, match="fixture"):
            store.append(
                event,
                bindings=bindings,
                deadline=event.occurred_at + timedelta(seconds=30),
                now=now + timedelta(seconds=2),
            )
        monkeypatch.setattr(store.checkpoints, "advance", original_advance)
        stored, record, created = store.append(
            event,
            bindings=bindings,
            deadline=event.occurred_at + timedelta(seconds=30),
            now=now + timedelta(seconds=3),
        )

        checkpoint = store.checkpoints.load(
            control_plane_audit_stream_id(engagement_id)
        )

    assert created is False
    assert stored.event_id == event.event_id
    assert record.sequence == 1
    assert checkpoint is not None and checkpoint.sequence == 1
