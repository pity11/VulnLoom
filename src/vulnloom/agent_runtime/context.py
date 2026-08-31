"""Sealed, redacted, bounded model-context assembly and storage."""

from __future__ import annotations

import os
import stat
import tempfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from time import monotonic
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskEnvelope
from vulnloom.evidence import Redactor
from vulnloom.runners.models import Digest


class AgentContextRejected(ValueError):
    pass


class AgentContextTimedOut(TimeoutError):
    pass


class AgentContextSourceKind(StrEnum):
    TASK_SUMMARY = "task_summary"
    EVIDENCE_SUMMARY = "evidence_summary"
    OBSERVATION_SUMMARY = "observation_summary"


@dataclass(frozen=True, slots=True)
class AgentContextSource:
    """Transient source text; deliberately not a serializable DomainModel."""

    source_ref: str
    kind: AgentContextSourceKind
    text: str


class AgentContextLimits(DomainModel):
    max_fragments: int = Field(default=64, ge=0, le=1024)
    max_source_bytes_per_fragment: int = Field(default=65_536, gt=0, le=1_048_576)
    max_fragment_bytes: int = Field(default=32_768, gt=0, le=1_048_576)
    max_total_bytes: int = Field(default=262_144, gt=0, le=4_194_304)
    timeout_seconds: float = Field(default=5.0, gt=0, le=60)


class AgentContextFragment(DomainModel):
    ordinal: int = Field(ge=0, le=1023)
    source_ref_digest: Digest
    kind: AgentContextSourceKind
    redacted_text: str
    text_digest: Digest
    byte_size: int = Field(ge=0, le=1_048_576)
    untrusted: bool = True

    @model_validator(mode="after")
    def sealed_redacted_fragment(self) -> Self:
        if _normalize_context_text(self.redacted_text) != self.redacted_text:
            raise ValueError("Agent context fragment text is not normalized")
        if Redactor().text(self.redacted_text) != self.redacted_text:
            raise ValueError("Agent context fragment contains unredacted sensitive text")
        encoded = self.redacted_text.encode("utf-8")
        if self.byte_size != len(encoded):
            raise ValueError("Agent context fragment byte size mismatch")
        if self.text_digest != canonical_digest(self.redacted_text):
            raise ValueError("Agent context fragment text digest mismatch")
        if not self.untrusted:
            raise ValueError("Agent context fragment must remain marked untrusted")
        return self


class AgentContextSnapshot(DomainModel):
    snapshot_id: Digest
    task_id: UUID
    task_digest: Digest
    target_id: UUID
    target_version: str = Field(min_length=1)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    input_refs_digest: Digest
    input_ref_digests: tuple[Digest, ...]
    redaction_policy: str = Field(min_length=1, max_length=128)
    redaction_policy_digest: Digest
    fragments: Annotated[tuple[AgentContextFragment, ...], Field(max_length=1024)]
    total_bytes: int = Field(ge=0, le=4_194_304)
    assembled_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_snapshot(self) -> Self:
        if self.redaction_policy != Redactor.policy_name:
            raise ValueError("Agent context redaction policy is not trusted")
        if tuple(item.ordinal for item in self.fragments) != tuple(
            range(len(self.fragments))
        ):
            raise ValueError("Agent context fragment ordinals are not contiguous")
        if tuple(item.source_ref_digest for item in self.fragments) != self.input_ref_digests:
            raise ValueError("Agent context fragments do not match the sealed input references")
        if self.total_bytes != sum(item.byte_size for item in self.fragments):
            raise ValueError("Agent context total byte size mismatch")
        if self.redaction_policy_digest != canonical_digest(
            {"policy": self.redaction_policy}
        ):
            raise ValueError("Agent context redaction policy digest mismatch")
        if self.snapshot_id != agent_context_snapshot_digest(self):
            raise ValueError("Agent context snapshot content digest mismatch")
        return self

    def assert_for_task(self, task: TaskEnvelope) -> None:
        if (
            self.task_id != task.task_id
            or self.task_digest != canonical_digest(task.model_dump(mode="python"))
            or self.target_id != task.target_id
            or self.target_version != task.target_version
            or self.scope_id != task.scope_id
            or self.scope_version != task.scope_version
            or self.input_refs_digest != canonical_digest(task.input_refs)
            or self.input_ref_digests
            != tuple(canonical_digest(item) for item in task.input_refs)
        ):
            raise AgentContextRejected("Agent context snapshot does not match the Task")


def agent_context_snapshot_digest(snapshot: AgentContextSnapshot) -> str:
    return canonical_digest(snapshot.model_dump(mode="python", exclude={"snapshot_id"}))


class AgentContextAssembler:
    def __init__(
        self,
        redactor: Redactor | None = None,
        *,
        clock: Callable[[], float] = monotonic,
    ):
        if redactor is not None and type(redactor) is not Redactor:
            raise AgentContextRejected("custom Agent context redactors are not allowed")
        self.redactor = redactor or Redactor()
        self.clock = clock

    def assemble(
        self,
        *,
        task: TaskEnvelope,
        sources: tuple[AgentContextSource, ...],
        limits: AgentContextLimits,
        now: datetime,
        deadline: datetime,
    ) -> AgentContextSnapshot:
        if now >= deadline or now >= task.deadline:
            raise AgentContextTimedOut("Agent context assembly deadline expired")
        if len(sources) > limits.max_fragments:
            raise AgentContextRejected("Agent context fragment count exceeds the limit")
        if tuple(item.source_ref for item in sources) != task.input_refs:
            raise AgentContextRejected(
                "Agent context sources must exactly match Task input references"
            )
        started = self.clock()
        fragments: list[AgentContextFragment] = []
        total_bytes = 0
        for ordinal, source in enumerate(sources):
            self._check_timeout(started, limits)
            raw = source.text.encode("utf-8")
            if len(raw) > limits.max_source_bytes_per_fragment:
                raise AgentContextRejected("Agent context source exceeds the byte limit")
            normalized = _normalize_context_text(source.text)
            redacted = self.redactor.text(normalized)
            encoded = redacted.encode("utf-8")
            if len(encoded) > limits.max_fragment_bytes:
                raise AgentContextRejected("Agent context fragment exceeds the byte limit")
            total_bytes += len(encoded)
            if total_bytes > limits.max_total_bytes:
                raise AgentContextRejected("Agent context total exceeds the byte limit")
            fragments.append(
                AgentContextFragment(
                    ordinal=ordinal,
                    source_ref_digest=canonical_digest(source.source_ref),
                    kind=source.kind,
                    redacted_text=redacted,
                    text_digest=canonical_digest(redacted),
                    byte_size=len(encoded),
                )
            )
        self._check_timeout(started, limits)
        values = {
            "task_id": task.task_id,
            "task_digest": canonical_digest(task.model_dump(mode="python")),
            "target_id": task.target_id,
            "target_version": task.target_version,
            "scope_id": task.scope_id,
            "scope_version": task.scope_version,
            "input_refs_digest": canonical_digest(task.input_refs),
            "input_ref_digests": tuple(canonical_digest(item) for item in task.input_refs),
            "redaction_policy": self.redactor.policy_name,
            "redaction_policy_digest": canonical_digest(
                {"policy": self.redactor.policy_name}
            ),
            "fragments": tuple(fragments),
            "total_bytes": total_bytes,
            "assembled_at": now,
        }
        digest_values = {
            **values,
            "fragments": tuple(item.model_dump(mode="python") for item in fragments),
        }
        return AgentContextSnapshot(
            snapshot_id=canonical_digest(digest_values), **values
        )

    def _check_timeout(self, started: float, limits: AgentContextLimits) -> None:
        if self.clock() - started > limits.timeout_seconds:
            raise AgentContextTimedOut("Agent context assembly exceeded the wall budget")


class AgentContextStore:
    def __init__(self, root: Path, *, max_snapshot_bytes: int = 4_194_304):
        if max_snapshot_bytes <= 0:
            raise ValueError("Agent context store size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_snapshot_bytes = max_snapshot_bytes

    def publish(self, snapshot: AgentContextSnapshot) -> Path:
        encoded = (snapshot.model_dump_json() + "\n").encode("utf-8")
        if len(encoded) > self.max_snapshot_bytes:
            raise AgentContextRejected("Agent context snapshot exceeds the store limit")
        destination = self.objects / snapshot.snapshot_id
        if os.path.lexists(destination):
            if self._read_bytes(snapshot.snapshot_id) != encoded:
                raise AgentContextRejected("Agent context object collision")
            return destination
        descriptor, temporary = tempfile.mkstemp(prefix="context-", dir=self.objects)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o400)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        if self._read_bytes(snapshot.snapshot_id) != encoded:
            raise AgentContextRejected("Agent context object integrity check failed")
        return destination

    def read(self, snapshot_id: str) -> AgentContextSnapshot:
        data = self._read_bytes(snapshot_id)
        try:
            snapshot = AgentContextSnapshot.model_validate_json(data)
        except ValueError as exc:
            raise AgentContextRejected("Agent context object is invalid") from exc
        if snapshot.snapshot_id != snapshot_id:
            raise AgentContextRejected("Agent context object identity mismatch")
        return snapshot

    def _read_bytes(self, snapshot_id: str) -> bytes:
        if len(snapshot_id) != 64 or any(
            character not in "0123456789abcdef" for character in snapshot_id
        ):
            raise AgentContextRejected("invalid Agent context reference")
        if not hasattr(os, "O_NOFOLLOW"):
            raise AgentContextRejected("platform cannot enforce no-follow context reads")
        path = self.objects / snapshot_id
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise AgentContextRejected("Agent context object is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o222
                or metadata.st_size > self.max_snapshot_bytes
            ):
                raise AgentContextRejected("Agent context object is unavailable or unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(self.max_snapshot_bytes + 1)
        finally:
            os.close(descriptor)
        if len(data) > self.max_snapshot_bytes:
            raise AgentContextRejected("Agent context object exceeds the store limit")
        return data


def _normalize_context_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    if any(ord(character) < 32 and character not in "\n\t" for character in normalized):
        raise AgentContextRejected("Agent context contains a forbidden control character")
    return normalized
