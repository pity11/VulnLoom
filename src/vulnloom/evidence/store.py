"""Content-addressed storage for already-redacted evidence."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path

from vulnloom.domain.models import Evidence, EvidenceKind

from .redaction import Redactor


class EvidenceStore:
    def __init__(
        self,
        root: Path,
        redactor: Redactor | None = None,
        *,
        max_evidence_bytes: int = 20 * 1024 * 1024,
    ):
        if max_evidence_bytes <= 0:
            raise ValueError("Evidence size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.redactor = redactor or Redactor()
        self.max_evidence_bytes = max_evidence_bytes

    def capture_text(
        self,
        content: str,
        *,
        kind: EvidenceKind,
        source_ref: str,
        producer: str,
        target_version: str,
        summary: str,
    ) -> Evidence:
        redacted = self.redactor.text(content)
        safe_summary = self.redactor.text(summary)
        encoded = redacted.encode("utf-8")
        if len(encoded) > self.max_evidence_bytes:
            raise ValueError("redacted Evidence exceeds the configured size limit")
        evidence_id = hashlib.sha256(encoded).hexdigest()
        destination = self.objects / evidence_id
        if not destination.exists():
            fd, temp_name = tempfile.mkstemp(prefix="capture-", dir=self.objects)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, destination)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
        if self._read_object(evidence_id) != encoded:
            raise ValueError("Evidence object content collision")
        return Evidence(
            evidence_id=evidence_id,
            kind=kind,
            source_ref=source_ref,
            producer=producer,
            target_version=target_version,
            redaction_policy=self.redactor.policy_name,
            content_ref=str(destination.relative_to(self.root)),
            summary=safe_summary,
        )

    def read_text(self, evidence: Evidence) -> str:
        if evidence.content_ref != f"objects/{evidence.evidence_id}":
            raise ValueError("Evidence content_ref does not match its object identity")
        return self._read_object(evidence.evidence_id).decode("utf-8")

    def read_text_ref(self, evidence_ref: str) -> str:
        """Read one content-addressed object without trusting caller metadata."""

        return self._read_object(evidence_ref).decode("utf-8")

    def contains(self, evidence_ref: str) -> bool:
        try:
            self._read_object(evidence_ref)
        except ValueError:
            return False
        return True

    def _read_object(self, evidence_ref: str) -> bytes:
        if len(evidence_ref) != 64 or any(
            character not in "0123456789abcdef" for character in evidence_ref
        ):
            raise ValueError("invalid Evidence reference")
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("platform cannot enforce no-follow Evidence reads")
        path = self.objects / evidence_ref
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ValueError("Evidence object is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_evidence_bytes:
                raise ValueError("Evidence object is unavailable or unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(self.max_evidence_bytes + 1)
        finally:
            os.close(descriptor)
        if len(data) > self.max_evidence_bytes or hashlib.sha256(data).hexdigest() != evidence_ref:
            raise ValueError("Evidence integrity check failed")
        return data
