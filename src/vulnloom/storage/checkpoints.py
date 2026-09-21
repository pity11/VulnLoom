"""Trusted filesystem custody for authoritative audit checkpoints."""

from __future__ import annotations

import fcntl
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from vulnloom.evidence.redaction import Redactor
from vulnloom.storage.audit_chain import AuditCheckpoint, AuditRecord, AuditStateBindings
from vulnloom.storage.events import (
    Event,
    EventStore,
    control_plane_audit_stream_id,
)

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_CHECKPOINT_BYTES = 16 * 1024


class AuditCheckpointCustodyError(RuntimeError):
    """Checkpoint custody cannot safely establish or advance trust."""


class FileAuditCheckpointStore:
    """Atomic, monotonic checkpoint custody outside the authoritative database."""

    def __init__(self, root: Path):
        self.root = root
        if root.is_symlink():
            raise AuditCheckpointCustodyError("checkpoint root cannot be a symlink")
        try:
            root.mkdir(parents=True, mode=0o700, exist_ok=True)
            root_stat = root.stat()
        except OSError:
            raise AuditCheckpointCustodyError(
                "checkpoint root is unavailable"
            ) from None
        if not stat.S_ISDIR(root_stat.st_mode):
            raise AuditCheckpointCustodyError("checkpoint root must be a directory")
        if root_stat.st_mode & 0o077:
            raise AuditCheckpointCustodyError(
                "checkpoint root must not grant group or other permissions"
            )

    def load(self, stream_id: str) -> AuditCheckpoint | None:
        path = self._checkpoint_path(stream_id)
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(path_stat.st_mode) or path.is_symlink():
            raise AuditCheckpointCustodyError("checkpoint must be a regular file")
        if path_stat.st_mode & 0o077:
            raise AuditCheckpointCustodyError(
                "checkpoint file must not grant group or other permissions"
            )
        if path_stat.st_size > _MAX_CHECKPOINT_BYTES:
            raise AuditCheckpointCustodyError("checkpoint exceeds the custody size limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                payload = os.read(descriptor, _MAX_CHECKPOINT_BYTES + 1)
            finally:
                os.close(descriptor)
        except OSError:
            raise AuditCheckpointCustodyError("checkpoint read failed") from None
        if len(payload) > _MAX_CHECKPOINT_BYTES:
            raise AuditCheckpointCustodyError("checkpoint exceeds the custody size limit")
        try:
            checkpoint = AuditCheckpoint.model_validate_json(payload)
        except (ValueError, TypeError) as exc:
            raise AuditCheckpointCustodyError("checkpoint is malformed") from exc
        if checkpoint.stream_id != stream_id:
            raise AuditCheckpointCustodyError("checkpoint stream binding differs")
        return checkpoint

    def initialize(self, checkpoint: AuditCheckpoint) -> AuditCheckpoint:
        checkpoint = AuditCheckpoint.model_validate(
            checkpoint.model_dump(mode="python")
        )
        if checkpoint.sequence != 0:
            raise AuditCheckpointCustodyError(
                "checkpoint custody can initialize only an empty stream"
            )
        with self._locked(checkpoint.stream_id):
            existing = self.load(checkpoint.stream_id)
            if existing is not None:
                if (
                    existing.sequence == checkpoint.sequence
                    and existing.head_digest == checkpoint.head_digest
                ):
                    return existing
                raise AuditCheckpointCustodyError(
                    "checkpoint stream was initialized with different trust"
                )
            self._replace_locked(checkpoint)
            return checkpoint

    def advance(
        self,
        expected: AuditCheckpoint,
        checkpoint: AuditCheckpoint,
    ) -> AuditCheckpoint:
        expected = AuditCheckpoint.model_validate(expected.model_dump(mode="python"))
        checkpoint = AuditCheckpoint.model_validate(
            checkpoint.model_dump(mode="python")
        )
        if checkpoint.stream_id != expected.stream_id:
            raise AuditCheckpointCustodyError("checkpoint stream cannot change")
        with self._locked(checkpoint.stream_id):
            stored = self.load(checkpoint.stream_id)
            if stored is None:
                raise AuditCheckpointCustodyError("checkpoint trust is not initialized")
            if (
                stored.sequence == checkpoint.sequence
                and stored.head_digest == checkpoint.head_digest
            ):
                return stored
            if stored.checkpoint_id != expected.checkpoint_id:
                raise AuditCheckpointCustodyError(
                    "checkpoint compare-and-swap predecessor differs"
                )
            if checkpoint.sequence <= stored.sequence:
                raise AuditCheckpointCustodyError("checkpoint cannot roll back or fork")
            if checkpoint.issued_at < stored.issued_at:
                raise AuditCheckpointCustodyError("checkpoint time cannot move backwards")
            self._replace_locked(checkpoint)
            return checkpoint

    def _checkpoint_path(self, stream_id: str) -> Path:
        if not _DIGEST_PATTERN.fullmatch(stream_id):
            raise AuditCheckpointCustodyError("checkpoint stream id must be a digest")
        return self.root / f"{stream_id}.checkpoint.json"

    @contextmanager
    def _locked(self, stream_id: str) -> Iterator[None]:
        checkpoint_path = self._checkpoint_path(stream_id)
        lock_path = checkpoint_path.with_suffix(".lock")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError:
            raise AuditCheckpointCustodyError("checkpoint lock is unavailable") from None
        locked = False
        try:
            os.fchmod(descriptor, 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditCheckpointCustodyError("checkpoint lock must be regular")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except OSError:
                raise AuditCheckpointCustodyError(
                    "checkpoint lock could not be acquired"
                ) from None
            locked = True
            yield
        finally:
            if locked:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _replace_locked(self, checkpoint: AuditCheckpoint) -> None:
        destination = self._checkpoint_path(checkpoint.stream_id)
        temporary = self.root / f".{checkpoint.stream_id}.{uuid4().hex}.tmp"
        payload = checkpoint.model_dump_json().encode("utf-8")
        if len(payload) > _MAX_CHECKPOINT_BYTES:
            raise AuditCheckpointCustodyError("checkpoint exceeds the custody size limit")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600, follow_symlinks=False)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception as exc:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
            if isinstance(exc, AuditCheckpointCustodyError):
                raise
            raise AuditCheckpointCustodyError("checkpoint atomic write failed") from None


class CheckpointedEventStore:
    """Production-facing Control Plane adapter with external checkpoint custody."""

    def __init__(
        self,
        database: Path,
        checkpoint_root: Path,
        redactor: Redactor | None = None,
    ):
        self._events = EventStore(database, redactor)
        try:
            self.checkpoints = FileAuditCheckpointStore(checkpoint_root)
        except Exception:
            self._events.close()
            raise

    def append(
        self,
        event: Event,
        *,
        bindings: AuditStateBindings,
        deadline: datetime,
        now: datetime,
    ) -> tuple[Event, AuditRecord, bool]:
        checkpoint = self._trusted_checkpoint(event.engagement_id, now=now)
        result = self._events.append_authoritative(
            event,
            bindings=bindings,
            trusted_checkpoint=checkpoint,
            deadline=deadline,
            now=now,
        )
        latest = self._events.audit.checkpoint(
            control_plane_audit_stream_id(event.engagement_id), now=now
        )
        self.checkpoints.advance(checkpoint, latest)
        return result

    def list_for_engagement(
        self, engagement_id: UUID, *, now: datetime
    ) -> tuple[Event, ...]:
        checkpoint = self._trusted_checkpoint(engagement_id, now=now)
        events = self._events.list_authoritative_for_engagement(
            engagement_id,
            trusted_checkpoint=checkpoint,
            now=now,
        )
        latest = self._events.audit.checkpoint(
            control_plane_audit_stream_id(engagement_id), now=now
        )
        self.checkpoints.advance(checkpoint, latest)
        return events

    def _trusted_checkpoint(
        self, engagement_id: UUID, *, now: datetime
    ) -> AuditCheckpoint:
        stream_id = control_plane_audit_stream_id(engagement_id)
        checkpoint = self.checkpoints.load(stream_id)
        if checkpoint is not None:
            return checkpoint
        if not self._events.authoritative_state_is_empty(engagement_id):
            raise AuditCheckpointCustodyError(
                "checkpoint is missing for non-empty authoritative state; migrate or restore"
            )
        genesis = self._events.audit.checkpoint(stream_id, now=now)
        return self.checkpoints.initialize(genesis)

    def close(self) -> None:
        self._events.close()

    def __enter__(self) -> CheckpointedEventStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
