from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.storage import (
    AUDIT_GENESIS_DIGEST,
    AuditAppendExpired,
    AuditAppendPlan,
    AuditIdempotencyConflict,
    AuditIntegrityError,
    AuditOutcome,
    AuditRecordProjection,
    AuditStateBindings,
    AuditVerificationStatus,
    AuthoritativeAuditStore,
)


def _bindings(*, marker: str = "base") -> AuditStateBindings:
    return AuditStateBindings(
        engagement_id=uuid4(),
        scope_id=uuid4(),
        scope_version=3,
        policy_digest=canonical_digest({"policy": marker}),
        sandbox_profile_digest=canonical_digest({"profile": marker}),
        context_digest=canonical_digest({"context": marker}),
        tool_registry_digest=canonical_digest({"tools": marker}),
        provider_revision_digest=canonical_digest({"provider": marker}),
        input_digests=tuple(
            sorted(
                (
                    canonical_digest({"input": marker, "index": 1}),
                    canonical_digest({"input": marker, "index": 2}),
                )
            )
        ),
    )


def _updated_bindings(bindings: AuditStateBindings, marker: str) -> AuditStateBindings:
    return bindings.model_copy(
        update={
            "policy_digest": canonical_digest({"policy": marker}),
            "context_digest": canonical_digest({"context": marker}),
            "input_digests": (
                canonical_digest({"input": marker}),
            ),
        }
    )


def _plan(
    now,
    stream_id: str,
    index: int,
    *,
    bindings: AuditStateBindings | None = None,
    outcome: AuditOutcome = AuditOutcome.COMMITTED,
    cleanup_verified: bool = True,
    key: str | None = None,
) -> AuditAppendPlan:
    return AuditAppendPlan.create(
        stream_id=stream_id,
        event_type="candidate.state_changed",
        aggregate_id=canonical_digest({"candidate": index}),
        transition_digest=canonical_digest({"transition": index}),
        bindings=bindings or _bindings(marker=str(index)),
        outcome=outcome,
        cleanup_verified=cleanup_verified,
        occurred_at=now + timedelta(seconds=index),
        deadline=now + timedelta(seconds=index + 30),
        idempotency_digest=canonical_digest({"idempotency": key or f"audit:{index}"}),
    )


def _append(store, now, stream_id, count=3, *, bindings=None):
    bindings = bindings or _bindings()
    return tuple(
        store.append(
            _plan(
                now,
                stream_id,
                index,
                bindings=_updated_bindings(bindings, str(index)),
            ),
            now=now + timedelta(seconds=index + 1),
        )
        for index in range(1, count + 1)
    )


def test_append_checkpoint_verify_and_digest_only_projection(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-success"})
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        records = _append(store, now, stream_id)
        checkpoint = store.checkpoint(stream_id, now=now + timedelta(seconds=4))
        fourth = store.append(
            _plan(
                now,
                stream_id,
                4,
                bindings=_updated_bindings(records[-1].bindings, "4"),
            ),
            now=now + timedelta(seconds=5),
        )
        verification = store.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=11),
        )
        projections = store.projections(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=12),
        )

    assert records[0].previous_digest == AUDIT_GENESIS_DIGEST
    assert records[1].previous_digest == records[0].record_digest
    assert records[2].previous_digest == records[1].record_digest
    assert checkpoint.sequence == 3
    assert checkpoint.head_digest == records[-1].record_digest
    assert fourth.previous_digest == checkpoint.head_digest
    assert verification.status is AuditVerificationStatus.VERIFIED
    assert tuple(item.sequence for item in projections) == (1, 2, 3, 4)
    projection_fields = AuditRecordProjection.model_json_schema()["properties"]
    assert not {
        "payload",
        "secret",
        "stdout",
        "stderr",
        "idempotency_digest",
        "input_digests",
        "engagement_id",
    } & set(projection_fields)
    plan_fields = AuditAppendPlan.model_json_schema()["properties"]
    assert not {"payload", "secret", "stdout", "stderr", "idempotency_key"} & set(
        plan_fields
    )
    raw_plan = _plan(now, stream_id, 5, bindings=records[0].bindings).model_dump(
        mode="python"
    )
    raw_plan["payload"] = {"token": "must-not-enter-audit"}
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AuditAppendPlan.model_validate(raw_plan)


def test_append_is_idempotent_and_binding_or_key_drift_is_rejected(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-idempotency"})
    plan = _plan(now, stream_id, 1)
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        first = store.append(plan, now=now + timedelta(seconds=2))
        assert store.append(plan, now=now + timedelta(seconds=3)) == first
        assert store.append(plan, now=plan.deadline) == first

        changed = _plan(now, stream_id, 2, key="audit:1")
        with pytest.raises(AuditIdempotencyConflict):
            store.append(changed, now=now + timedelta(seconds=4))

        assert store.checkpoint(stream_id, now=now + timedelta(seconds=5)).sequence == 1

    raw = plan.model_dump(mode="python")
    raw["bindings"]["policy_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="plan id"):
        AuditAppendPlan.model_validate(raw)


def test_expired_append_fails_before_mutation_and_cleanup_failure_is_auditable(
    tmp_path, now
):
    stream_id = canonical_digest({"engagement": "audit-timeout"})
    expired = _plan(now, stream_id, 1)
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        with pytest.raises(AuditAppendExpired, match="deadline"):
            store.append(expired, now=expired.deadline)
        empty = store.checkpoint(stream_id, now=expired.deadline)
        assert empty.sequence == 0
        assert empty.head_digest == AUDIT_GENESIS_DIGEST

        cleanup = _plan(
            now,
            stream_id,
            2,
            outcome=AuditOutcome.CLEANUP_FAILED,
            cleanup_verified=False,
        )
        record = store.append(cleanup, now=now + timedelta(seconds=3))
        checkpoint = store.checkpoint(stream_id, now=now + timedelta(seconds=4))
        projected = store.projections(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=5),
        )[0]

    assert record.outcome is AuditOutcome.CLEANUP_FAILED
    assert projected.cleanup_verified is False


def test_stream_cannot_cross_engagement_boundaries(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-boundary"})
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        first = _plan(now, stream_id, 1)
        store.append(first, now=now + timedelta(seconds=2))
        crossing = _plan(now, stream_id, 2)

        with pytest.raises(AuditIntegrityError, match="Engagement"):
            store.append(crossing, now=now + timedelta(seconds=3))

        assert store.checkpoint(stream_id, now=now + timedelta(seconds=4)).sequence == 1


def test_failed_transaction_leaves_no_partial_record_or_head(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-transaction"})
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        store.connection.execute(
            "CREATE TRIGGER deny_audit_head BEFORE INSERT ON authoritative_audit_heads "
            "BEGIN SELECT RAISE(ABORT, 'fixture failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="fixture failure"):
            store.append(_plan(now, stream_id, 1), now=now + timedelta(seconds=2))

        records = store.connection.execute(
            "SELECT COUNT(*) FROM authoritative_audit_records"
        ).fetchone()[0]
        heads = store.connection.execute(
            "SELECT COUNT(*) FROM authoritative_audit_heads"
        ).fetchone()[0]

    assert records == 0
    assert heads == 0


def test_oversized_tampered_record_is_rejected_before_deserialization(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-size-limit"})
    database = tmp_path / "audit.db"
    with AuthoritativeAuditStore(database) as store:
        store.append(_plan(now, stream_id, 1), now=now + timedelta(seconds=2))
        store.connection.execute(
            "UPDATE authoritative_audit_records SET record_json = ? "
            "WHERE stream_id = ? AND sequence = 1",
            ("x" * 4097, stream_id),
        )

    with AuthoritativeAuditStore(database, max_record_bytes=4096) as bounded:
        result = bounded.verify(stream_id, now=now + timedelta(seconds=3))
        assert result.status is AuditVerificationStatus.CORRUPTION_DETECTED
        assert result.failure_code == "local_chain_limits_exceeded"
        with pytest.raises(AuditIntegrityError, match="refused append"):
            bounded.append(_plan(now, stream_id, 2), now=now + timedelta(seconds=3))


def test_record_count_limit_and_invalid_limits_fail_closed(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-count-limit"})
    database = tmp_path / "audit.db"
    with AuthoritativeAuditStore(database) as store:
        _append(store, now, stream_id, count=2)

    with AuthoritativeAuditStore(database, max_records_per_stream=1) as bounded:
        result = bounded.verify(stream_id, now=now + timedelta(seconds=4))
        assert result.status is AuditVerificationStatus.CORRUPTION_DETECTED
        assert result.failure_code == "local_chain_limits_exceeded"

    with pytest.raises(ValueError, match="limits"):
        AuthoritativeAuditStore(database, max_record_bytes=0)


def test_caller_owned_audit_methods_require_an_active_transaction(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-outer-transaction"})
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        checkpoint = store.checkpoint(stream_id, now=now)
        with pytest.raises(AuditIntegrityError, match="active outer transaction"):
            store.append_in_transaction(_plan(now, stream_id, 1), now=now)
        with pytest.raises(AuditIntegrityError, match="active transaction"):
            store.verify_in_transaction(
                stream_id,
                trusted_checkpoint=checkpoint,
                now=now,
            )


@pytest.mark.parametrize("mutation", ("delete", "insert", "modify", "reorder"))
def test_local_deletion_insertion_modification_and_reordering_are_detected(
    tmp_path, now, mutation
):
    stream_id = canonical_digest({"engagement": f"audit-{mutation}"})
    with AuthoritativeAuditStore(tmp_path / f"{mutation}.db") as store:
        records = _append(store, now, stream_id)
        if mutation == "delete":
            store.connection.execute(
                "DELETE FROM authoritative_audit_records "
                "WHERE stream_id = ? AND sequence = 2",
                (stream_id,),
            )
        elif mutation == "insert":
            store.connection.execute(
                "INSERT INTO authoritative_audit_records "
                "(stream_id, sequence, record_digest, previous_digest, plan_id, "
                "idempotency_digest, record_json) VALUES (?, 4, ?, ?, ?, ?, ?)",
                (
                    stream_id,
                    "e" * 64,
                    records[-1].record_digest,
                    "d" * 64,
                    "forged:4",
                    records[-1].model_dump_json(),
                ),
            )
            store.connection.execute(
                "UPDATE authoritative_audit_heads SET sequence = 4, head_digest = ? "
                "WHERE stream_id = ?",
                ("e" * 64, stream_id),
            )
        elif mutation == "modify":
            payload = json.loads(records[1].model_dump_json())
            payload["cleanup_verified"] = False
            store.connection.execute(
                "UPDATE authoritative_audit_records SET record_json = ? "
                "WHERE stream_id = ? AND sequence = 2",
                (json.dumps(payload), stream_id),
            )
        else:
            store.connection.execute(
                "UPDATE authoritative_audit_records SET sequence = 20 "
                "WHERE stream_id = ? AND sequence = 2",
                (stream_id,),
            )

        result = store.verify(stream_id, now=now + timedelta(seconds=20))
        assert result.status is AuditVerificationStatus.CORRUPTION_DETECTED
        assert result.failure_code == "local_chain_corrupt"
        with pytest.raises(AuditIntegrityError, match="refused append"):
            store.append(_plan(now, stream_id, 4), now=now + timedelta(seconds=5))


def test_trusted_checkpoint_detects_complete_rollback(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-rollback"})
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        records = _append(store, now, stream_id)
        checkpoint = store.checkpoint(stream_id, now=now + timedelta(seconds=10))
        store.connection.execute(
            "DELETE FROM authoritative_audit_records WHERE stream_id = ? AND sequence = 3",
            (stream_id,),
        )
        store.connection.execute(
            "UPDATE authoritative_audit_heads SET sequence = 2, head_digest = ? "
            "WHERE stream_id = ?",
            (records[1].record_digest, stream_id),
        )

        local_only = store.verify(stream_id, now=now + timedelta(seconds=11))
        anchored = store.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=12),
        )

    assert local_only.status is AuditVerificationStatus.VERIFIED
    assert anchored.status is AuditVerificationStatus.ROLLBACK_DETECTED
    assert anchored.failure_code == "checkpoint_ahead_of_chain"


def test_trusted_checkpoint_detects_valid_alternative_fork(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-fork"})
    shared = _bindings(marker="shared")
    first = _plan(now, stream_id, 1, bindings=shared)
    with AuthoritativeAuditStore(tmp_path / "authoritative.db") as original:
        original.append(first, now=now + timedelta(seconds=2))
        original.append(
            _plan(
                now,
                stream_id,
                2,
                bindings=_updated_bindings(shared, "original"),
            ),
            now=now + timedelta(seconds=3),
        )
        checkpoint = original.checkpoint(stream_id, now=now + timedelta(seconds=4))

    with AuthoritativeAuditStore(tmp_path / "fork.db") as fork:
        fork.append(first, now=now + timedelta(seconds=2))
        alternate = _plan(
            now,
            stream_id,
            20,
            bindings=_updated_bindings(shared, "alternate"),
        ).model_copy(
            update={
                "occurred_at": now + timedelta(seconds=2),
                "deadline": now + timedelta(seconds=30),
                "idempotency_digest": canonical_digest(
                    {"idempotency": "audit:alternate"}
                ),
            }
        )
        values = alternate.model_dump(mode="python", exclude={"plan_id"})
        alternate = alternate.model_copy(update={"plan_id": canonical_digest(values)})
        fork.append(alternate, now=now + timedelta(seconds=3))

        local = fork.verify(stream_id, now=now + timedelta(seconds=5))
        anchored = fork.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=6),
        )
        with pytest.raises(AuditIntegrityError, match="projection refused"):
            fork.projections(
                stream_id,
                trusted_checkpoint=checkpoint,
                now=now + timedelta(seconds=7),
            )

    assert local.status is AuditVerificationStatus.VERIFIED
    assert anchored.status is AuditVerificationStatus.FORK_DETECTED
    assert anchored.failure_code == "checkpoint_head_mismatch"


def test_unvalidated_checkpoint_copy_is_revalidated_at_trust_boundary(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-checkpoint-validation"})
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        _append(store, now, stream_id, count=1)
        checkpoint = store.checkpoint(stream_id, now=now + timedelta(seconds=3))
        forged = checkpoint.model_copy(update={"head_digest": "f" * 64})

        with pytest.raises(ValidationError, match="checkpoint id"):
            store.verify(
                stream_id,
                trusted_checkpoint=forged,
                now=now + timedelta(seconds=4),
            )


def test_future_or_wrong_stream_checkpoint_is_rejected_without_projection(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-checkpoint-boundary"})
    with AuthoritativeAuditStore(tmp_path / "audit.db") as store:
        _append(store, now, stream_id, count=1)
        checkpoint = store.checkpoint(stream_id, now=now + timedelta(seconds=10))
        future = store.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=9),
        )
        wrong_stream = checkpoint.model_copy(
            update={"stream_id": canonical_digest({"engagement": "other"})}
        )
        raw = wrong_stream.model_dump(mode="python", exclude={"checkpoint_id"})
        wrong_stream = wrong_stream.model_copy(
            update={"checkpoint_id": canonical_digest(raw)}
        )
        fork = store.verify(
            stream_id,
            trusted_checkpoint=wrong_stream,
            now=now + timedelta(seconds=11),
        )

    assert future.status is AuditVerificationStatus.FORK_DETECTED
    assert future.failure_code == "checkpoint_from_future"
    assert fork.status is AuditVerificationStatus.FORK_DETECTED
    assert fork.failure_code == "checkpoint_stream_mismatch"


def test_recovery_requires_external_verified_copy_and_never_auto_repairs(tmp_path, now):
    stream_id = canonical_digest({"engagement": "audit-recovery"})
    database = tmp_path / "audit.db"
    backup = tmp_path / "audit.verified-backup.db"
    base_bindings = _bindings(marker="recovery")
    with AuthoritativeAuditStore(database) as store:
        _append(store, now, stream_id, count=2, bindings=base_bindings)
        checkpoint = store.checkpoint(stream_id, now=now + timedelta(seconds=5))
    shutil.copy2(database, backup)

    with AuthoritativeAuditStore(database) as store:
        store.connection.execute(
            "UPDATE authoritative_audit_records SET previous_digest = ? "
            "WHERE stream_id = ? AND sequence = 2",
            ("f" * 64, stream_id),
        )
        corrupted = store.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=6),
        )
        assert corrupted.status is AuditVerificationStatus.CORRUPTION_DETECTED
        with pytest.raises(AuditIntegrityError):
            store.append(
                _plan(
                    now,
                    stream_id,
                    3,
                    bindings=_updated_bindings(base_bindings, "3"),
                ),
                now=now + timedelta(seconds=4),
            )
        still_corrupted = store.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=7),
        )
        assert still_corrupted.status is AuditVerificationStatus.CORRUPTION_DETECTED

    shutil.copy2(backup, database)
    with AuthoritativeAuditStore(database) as restored:
        recovered = restored.verify(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=now + timedelta(seconds=8),
        )
        next_record = restored.append(
            _plan(
                now,
                stream_id,
                3,
                bindings=_updated_bindings(base_bindings, "3"),
            ),
            now=now + timedelta(seconds=4),
        )

    assert recovered.status is AuditVerificationStatus.VERIFIED
    assert next_record.sequence == 3
    assert next_record.previous_digest == checkpoint.head_digest
