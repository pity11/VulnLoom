"""Tamper-evident authoritative audit chain with fail-closed verification."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

AUDIT_CHAIN_CONTRACT_DIGEST = canonical_digest(
    {
        "contract": "vulnloom-authoritative-audit-chain-s1.4-v1",
        "hash": "sha256-canonical-json",
        "recovery": "fail-closed-restore-verified-copy",
        "projection": "digest-only",
    }
)
AUDIT_GENESIS_DIGEST = canonical_digest(
    {"contract": AUDIT_CHAIN_CONTRACT_DIGEST, "record": "genesis"}
)
DEFAULT_MAX_AUDIT_RECORDS_PER_STREAM = 100_000
DEFAULT_MAX_AUDIT_RECORD_BYTES = 64 * 1024


class AuditOutcome(StrEnum):
    COMMITTED = "committed"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    CLEANUP_FAILED = "cleanup_failed"


class AuditVerificationStatus(StrEnum):
    VERIFIED = "verified"
    CORRUPTION_DETECTED = "corruption_detected"
    ROLLBACK_DETECTED = "rollback_detected"
    FORK_DETECTED = "fork_detected"


class AuditStateBindings(DomainModel):
    """Exact authority and input identities for one state transition."""

    engagement_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    policy_digest: Digest
    sandbox_profile_digest: Digest
    context_digest: Digest
    tool_registry_digest: Digest
    provider_revision_digest: Digest
    input_digests: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def unique_sorted_inputs(self) -> Self:
        if self.input_digests != tuple(sorted(set(self.input_digests))):
            raise ValueError("audit input digests must be unique and sorted")
        return self


class AuditAppendPlan(DomainModel):
    plan_id: Digest
    contract_digest: Digest = AUDIT_CHAIN_CONTRACT_DIGEST
    stream_id: Digest
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    aggregate_id: Digest
    transition_digest: Digest
    bindings: AuditStateBindings
    outcome: AuditOutcome
    cleanup_verified: bool
    occurred_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_digest: Digest

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.contract_digest != AUDIT_CHAIN_CONTRACT_DIGEST:
            raise ValueError("audit chain contract is not admitted")
        if not self.occurred_at < self.deadline:
            raise ValueError("audit append deadline must follow occurrence")
        if (self.deadline - self.occurred_at).total_seconds() > 300:
            raise ValueError("audit append deadline exceeds five minutes")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        if self.plan_id != expected:
            raise ValueError("audit append plan id does not match its content")
        return self

    @classmethod
    def create(
        cls,
        *,
        stream_id: str,
        event_type: str,
        aggregate_id: str,
        transition_digest: str,
        bindings: AuditStateBindings,
        outcome: AuditOutcome,
        cleanup_verified: bool,
        occurred_at: datetime,
        deadline: datetime,
        idempotency_digest: str,
    ) -> AuditAppendPlan:
        values = {
            "contract_digest": AUDIT_CHAIN_CONTRACT_DIGEST,
            "stream_id": stream_id,
            "event_type": event_type,
            "aggregate_id": aggregate_id,
            "transition_digest": transition_digest,
            "bindings": bindings,
            "outcome": outcome,
            "cleanup_verified": cleanup_verified,
            "occurred_at": occurred_at,
            "deadline": deadline,
            "idempotency_digest": idempotency_digest,
        }
        digest_values = {
            **values,
            "bindings": bindings.model_dump(mode="python"),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


class AuditRecord(DomainModel):
    record_digest: Digest
    contract_digest: Digest = AUDIT_CHAIN_CONTRACT_DIGEST
    stream_id: Digest
    sequence: int = Field(ge=1)
    previous_digest: Digest
    plan_id: Digest
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    aggregate_id: Digest
    transition_digest: Digest
    bindings: AuditStateBindings
    outcome: AuditOutcome
    cleanup_verified: bool
    occurred_at: AwareDatetime
    sealed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_record(self) -> Self:
        if self.contract_digest != AUDIT_CHAIN_CONTRACT_DIGEST:
            raise ValueError("audit record contract is not admitted")
        if self.sealed_at < self.occurred_at:
            raise ValueError("audit record cannot be sealed before occurrence")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"record_digest"}))
        if self.record_digest != expected:
            raise ValueError("audit record digest does not match its content")
        return self


class AuditCheckpoint(DomainModel):
    checkpoint_id: Digest
    contract_digest: Digest = AUDIT_CHAIN_CONTRACT_DIGEST
    stream_id: Digest
    sequence: int = Field(ge=0)
    head_digest: Digest
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_checkpoint(self) -> Self:
        if self.contract_digest != AUDIT_CHAIN_CONTRACT_DIGEST:
            raise ValueError("audit checkpoint contract is not admitted")
        if self.sequence == 0 and self.head_digest != AUDIT_GENESIS_DIGEST:
            raise ValueError("empty audit checkpoint must bind the genesis digest")
        expected = canonical_digest(
            self.model_dump(mode="python", exclude={"checkpoint_id"})
        )
        if self.checkpoint_id != expected:
            raise ValueError("audit checkpoint id does not match its content")
        return self


class AuditVerificationResult(DomainModel):
    result_id: Digest
    stream_id: Digest
    status: AuditVerificationStatus
    record_count: int = Field(ge=0)
    head_digest: Digest
    trusted_checkpoint_id: Digest | None = None
    failure_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    checked_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_result(self) -> Self:
        if (self.status is AuditVerificationStatus.VERIFIED) == bool(self.failure_code):
            raise ValueError("verified audit result must be clean and failure must have a code")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"result_id"}))
        if self.result_id != expected:
            raise ValueError("audit verification result id does not match its content")
        return self


class AuditRecordProjection(DomainModel):
    """Secret-free query surface for CLI and future API adapters."""

    record_digest: Digest
    stream_id: Digest
    sequence: int = Field(ge=1)
    previous_digest: Digest
    event_type: str
    aggregate_id: Digest
    transition_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    policy_digest: Digest
    sandbox_profile_digest: Digest
    context_digest: Digest
    tool_registry_digest: Digest
    provider_revision_digest: Digest
    outcome: AuditOutcome
    cleanup_verified: bool
    occurred_at: AwareDatetime


class AuditIntegrityError(RuntimeError):
    """The authoritative chain cannot be trusted or safely extended."""


class AuditAppendExpired(AuditIntegrityError):
    """The bounded audit append window expired before mutation."""


class AuditIdempotencyConflict(AuditIntegrityError):
    """An audit idempotency key was reused for different sealed content."""


class AuthoritativeAuditStore:
    """SQLite-backed append-only hash chain with external checkpoint verification."""

    def __init__(
        self,
        path: Path,
        *,
        connection: sqlite3.Connection | None = None,
        max_records_per_stream: int = DEFAULT_MAX_AUDIT_RECORDS_PER_STREAM,
        max_record_bytes: int = DEFAULT_MAX_AUDIT_RECORD_BYTES,
    ):
        if max_records_per_stream < 1 or max_record_bytes < 1:
            raise ValueError("audit verification limits must be positive")
        self.path = path
        self.max_records_per_stream = max_records_per_stream
        self.max_record_bytes = max_record_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._owns_connection = connection is None
        self.connection = connection or sqlite3.connect(path, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS authoritative_audit_records (
                stream_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                record_digest TEXT NOT NULL UNIQUE,
                previous_digest TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                idempotency_digest TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (stream_id, sequence),
                UNIQUE (stream_id, idempotency_digest)
            );
            CREATE TABLE IF NOT EXISTS authoritative_audit_heads (
                stream_id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL,
                head_digest TEXT NOT NULL
            );
            """
        )

    def append(
        self,
        plan: AuditAppendPlan,
        *,
        now: datetime,
        trusted_checkpoint: AuditCheckpoint | None = None,
    ) -> AuditRecord:
        plan = AuditAppendPlan.model_validate(plan.model_dump(mode="python"))
        if trusted_checkpoint is not None:
            trusted_checkpoint = AuditCheckpoint.model_validate(
                trusted_checkpoint.model_dump(mode="python")
            )
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            record = self._append_locked(
                plan, now=now, trusted_checkpoint=trusted_checkpoint
            )
            self.connection.execute("COMMIT")
            return record
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def append_in_transaction(
        self,
        plan: AuditAppendPlan,
        *,
        now: datetime,
        trusted_checkpoint: AuditCheckpoint | None = None,
    ) -> AuditRecord:
        """Append under a caller-owned transaction for an atomic state change."""

        if not self.connection.in_transaction:
            raise AuditIntegrityError("audit append requires an active outer transaction")
        plan = AuditAppendPlan.model_validate(plan.model_dump(mode="python"))
        if trusted_checkpoint is not None:
            trusted_checkpoint = AuditCheckpoint.model_validate(
                trusted_checkpoint.model_dump(mode="python")
            )
        return self._append_locked(
            plan, now=now, trusted_checkpoint=trusted_checkpoint
        )

    def contains_idempotency(self, stream_id: str, idempotency_digest: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM authoritative_audit_records "
                "WHERE stream_id = ? AND idempotency_digest = ?",
                (stream_id, idempotency_digest),
            ).fetchone()
            is not None
        )

    def _append_locked(
        self,
        plan: AuditAppendPlan,
        *,
        now: datetime,
        trusted_checkpoint: AuditCheckpoint | None = None,
    ) -> AuditRecord:
        verification = self._verify_locked(
            plan.stream_id, now=now, trusted_checkpoint=trusted_checkpoint
        )
        if verification.status is not AuditVerificationStatus.VERIFIED:
            raise AuditIntegrityError(
                f"audit chain refused append: {verification.failure_code}"
            )
        existing = self.connection.execute(
            "SELECT plan_id, record_json FROM authoritative_audit_records "
            "WHERE stream_id = ? AND idempotency_digest = ?",
            (plan.stream_id, plan.idempotency_digest),
        ).fetchone()
        if existing is not None:
            record = AuditRecord.model_validate_json(existing["record_json"])
            if existing["plan_id"] != plan.plan_id and not (
                record.stream_id == plan.stream_id
                and record.event_type == plan.event_type
                and record.aggregate_id == plan.aggregate_id
                and record.transition_digest == plan.transition_digest
                and record.bindings == plan.bindings
                and record.outcome == plan.outcome
                and record.cleanup_verified == plan.cleanup_verified
                and record.occurred_at == plan.occurred_at
            ):
                raise AuditIdempotencyConflict(
                    "audit idempotency key was reused for different content"
                )
            return record
        if now >= plan.deadline:
            raise AuditAppendExpired("audit append deadline expired before mutation")
        if verification.record_count:
            previous_row = self.connection.execute(
                "SELECT record_json FROM authoritative_audit_records "
                "WHERE stream_id = ? AND sequence = ?",
                (plan.stream_id, verification.record_count),
            ).fetchone()
            if previous_row is None:
                raise AuditIntegrityError("audit predecessor became unavailable")
            previous_record = AuditRecord.model_validate_json(previous_row[0])
            if previous_record.bindings.engagement_id != plan.bindings.engagement_id:
                raise AuditIntegrityError("audit stream cannot cross Engagement boundaries")
        sequence = verification.record_count + 1
        values = {
            "contract_digest": AUDIT_CHAIN_CONTRACT_DIGEST,
            "stream_id": plan.stream_id,
            "sequence": sequence,
            "previous_digest": verification.head_digest,
            "plan_id": plan.plan_id,
            "event_type": plan.event_type,
            "aggregate_id": plan.aggregate_id,
            "transition_digest": plan.transition_digest,
            "bindings": plan.bindings,
            "outcome": plan.outcome,
            "cleanup_verified": plan.cleanup_verified,
            "occurred_at": plan.occurred_at,
            "sealed_at": now,
        }
        digest_values = {
            **values,
            "bindings": plan.bindings.model_dump(mode="python"),
        }
        record = AuditRecord(record_digest=canonical_digest(digest_values), **values)
        record_json = record.model_dump_json()
        if len(record_json.encode("utf-8")) > self.max_record_bytes:
            raise AuditIntegrityError("sealed audit record exceeds storage limit")
        self.connection.execute(
            "INSERT INTO authoritative_audit_records "
            "(stream_id, sequence, record_digest, previous_digest, plan_id, "
            "idempotency_digest, record_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.stream_id,
                record.sequence,
                record.record_digest,
                record.previous_digest,
                record.plan_id,
                plan.idempotency_digest,
                record_json,
            ),
        )
        self.connection.execute(
            "INSERT INTO authoritative_audit_heads (stream_id, sequence, head_digest) "
            "VALUES (?, ?, ?) ON CONFLICT(stream_id) DO UPDATE SET "
            "sequence = excluded.sequence, head_digest = excluded.head_digest",
            (record.stream_id, record.sequence, record.record_digest),
        )
        return record

    def checkpoint(self, stream_id: str, *, now: datetime) -> AuditCheckpoint:
        verification = self.verify(stream_id, now=now)
        if verification.status is not AuditVerificationStatus.VERIFIED:
            raise AuditIntegrityError(
                f"audit checkpoint refused: {verification.failure_code}"
            )
        values = {
            "contract_digest": AUDIT_CHAIN_CONTRACT_DIGEST,
            "stream_id": stream_id,
            "sequence": verification.record_count,
            "head_digest": verification.head_digest,
            "issued_at": now,
        }
        return AuditCheckpoint(checkpoint_id=canonical_digest(values), **values)

    def verify(
        self,
        stream_id: str,
        *,
        now: datetime,
        trusted_checkpoint: AuditCheckpoint | None = None,
    ) -> AuditVerificationResult:
        if trusted_checkpoint is not None:
            trusted_checkpoint = AuditCheckpoint.model_validate(
                trusted_checkpoint.model_dump(mode="python")
            )
        self.connection.execute("BEGIN")
        try:
            result = self._verify_locked(
                stream_id, now=now, trusted_checkpoint=trusted_checkpoint
            )
            self.connection.execute("COMMIT")
            return result
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def verify_in_transaction(
        self,
        stream_id: str,
        *,
        now: datetime,
        trusted_checkpoint: AuditCheckpoint,
    ) -> AuditVerificationResult:
        """Verify under a caller-owned transaction before authoritative state use."""

        if not self.connection.in_transaction:
            raise AuditIntegrityError("audit verification requires an active transaction")
        trusted_checkpoint = AuditCheckpoint.model_validate(
            trusted_checkpoint.model_dump(mode="python")
        )
        return self._verify_locked(
            stream_id, now=now, trusted_checkpoint=trusted_checkpoint
        )

    def projections(
        self,
        stream_id: str,
        *,
        trusted_checkpoint: AuditCheckpoint,
        now: datetime,
        start_sequence: int = 1,
        limit: int = 100,
    ) -> tuple[AuditRecordProjection, ...]:
        if start_sequence < 1 or not 1 <= limit <= 1000:
            raise ValueError("audit projection pagination is invalid")
        verification = self.verify(
            stream_id, now=now, trusted_checkpoint=trusted_checkpoint
        )
        if verification.status is not AuditVerificationStatus.VERIFIED:
            raise AuditIntegrityError(
                f"audit projection refused: {verification.failure_code}"
            )
        rows = self.connection.execute(
            "SELECT record_json FROM authoritative_audit_records "
            "WHERE stream_id = ? AND sequence >= ? ORDER BY sequence LIMIT ?",
            (stream_id, start_sequence, limit),
        ).fetchall()
        return tuple(self._project(AuditRecord.model_validate_json(row[0])) for row in rows)

    def _verify_locked(
        self,
        stream_id: str,
        *,
        now: datetime,
        trusted_checkpoint: AuditCheckpoint | None = None,
    ) -> AuditVerificationResult:
        stats = self.connection.execute(
            "SELECT COUNT(*) AS record_count, "
            "COALESCE(MAX(length(CAST(record_json AS BLOB))), 0) AS max_record_bytes "
            "FROM authoritative_audit_records WHERE stream_id = ?",
            (stream_id,),
        ).fetchone()
        if (
            stats["record_count"] > self.max_records_per_stream
            or stats["max_record_bytes"] > self.max_record_bytes
        ):
            values = {
                "stream_id": stream_id,
                "status": AuditVerificationStatus.CORRUPTION_DETECTED,
                "record_count": stats["record_count"],
                "head_digest": AUDIT_GENESIS_DIGEST,
                "trusted_checkpoint_id": (
                    trusted_checkpoint.checkpoint_id if trusted_checkpoint else None
                ),
                "failure_code": "local_chain_limits_exceeded",
                "checked_at": now,
            }
            return AuditVerificationResult(result_id=canonical_digest(values), **values)
        rows = self.connection.execute(
            "SELECT * FROM authoritative_audit_records "
            "WHERE stream_id = ? ORDER BY sequence",
            (stream_id,),
        ).fetchall()
        expected_previous = AUDIT_GENESIS_DIGEST
        records: list[AuditRecord] = []
        failure_code: str | None = None
        try:
            for expected_sequence, row in enumerate(rows, start=1):
                record = AuditRecord.model_validate_json(row["record_json"])
                if (
                    record.stream_id != stream_id
                    or record.sequence != expected_sequence
                    or record.record_digest != row["record_digest"]
                    or record.previous_digest != row["previous_digest"]
                    or record.plan_id != row["plan_id"]
                    or record.previous_digest != expected_previous
                ):
                    raise ValueError("record binding mismatch")
                records.append(record)
                expected_previous = record.record_digest
            head = self.connection.execute(
                "SELECT sequence, head_digest FROM authoritative_audit_heads WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            if records:
                if (
                    head is None
                    or head["sequence"] != len(records)
                    or head["head_digest"] != records[-1].record_digest
                ):
                    raise ValueError("head binding mismatch")
            elif head is not None:
                raise ValueError("empty chain has a head")
        except (ValueError, TypeError, json.JSONDecodeError):
            failure_code = "local_chain_corrupt"
        status = (
            AuditVerificationStatus.CORRUPTION_DETECTED
            if failure_code
            else AuditVerificationStatus.VERIFIED
        )
        if status is AuditVerificationStatus.VERIFIED and trusted_checkpoint is not None:
            if trusted_checkpoint.issued_at > now:
                status = AuditVerificationStatus.FORK_DETECTED
                failure_code = "checkpoint_from_future"
            elif trusted_checkpoint.stream_id != stream_id:
                status = AuditVerificationStatus.FORK_DETECTED
                failure_code = "checkpoint_stream_mismatch"
            elif len(records) < trusted_checkpoint.sequence:
                status = AuditVerificationStatus.ROLLBACK_DETECTED
                failure_code = "checkpoint_ahead_of_chain"
            else:
                anchored = (
                    AUDIT_GENESIS_DIGEST
                    if trusted_checkpoint.sequence == 0
                    else records[trusted_checkpoint.sequence - 1].record_digest
                )
                if anchored != trusted_checkpoint.head_digest:
                    status = AuditVerificationStatus.FORK_DETECTED
                    failure_code = "checkpoint_head_mismatch"
        head_digest = records[-1].record_digest if records else AUDIT_GENESIS_DIGEST
        values = {
            "stream_id": stream_id,
            "status": status,
            "record_count": len(records),
            "head_digest": head_digest,
            "trusted_checkpoint_id": (
                trusted_checkpoint.checkpoint_id if trusted_checkpoint else None
            ),
            "failure_code": failure_code,
            "checked_at": now,
        }
        return AuditVerificationResult(result_id=canonical_digest(values), **values)

    @staticmethod
    def _project(record: AuditRecord) -> AuditRecordProjection:
        return AuditRecordProjection(
            record_digest=record.record_digest,
            stream_id=record.stream_id,
            sequence=record.sequence,
            previous_digest=record.previous_digest,
            event_type=record.event_type,
            aggregate_id=record.aggregate_id,
            transition_digest=record.transition_digest,
            scope_id=record.bindings.scope_id,
            scope_version=record.bindings.scope_version,
            policy_digest=record.bindings.policy_digest,
            sandbox_profile_digest=record.bindings.sandbox_profile_digest,
            context_digest=record.bindings.context_digest,
            tool_registry_digest=record.bindings.tool_registry_digest,
            provider_revision_digest=record.bindings.provider_revision_digest,
            outcome=record.outcome,
            cleanup_verified=record.cleanup_verified,
            occurred_at=record.occurred_at,
        )

    def close(self) -> None:
        if self._owns_connection:
            self.connection.close()

    def __enter__(self) -> AuthoritativeAuditStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
