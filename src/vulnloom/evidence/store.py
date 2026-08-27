"""Content-addressed storage for already-redacted evidence."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from vulnloom.domain.models import Evidence, EvidenceKind

from .redaction import Redactor


class EvidenceStore:
    def __init__(self, root: Path, redactor: Redactor | None = None):
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.redactor = redactor or Redactor()

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
        path = (self.root / evidence.content_ref).resolve()
        if self.root not in path.parents:
            raise ValueError("evidence content_ref escapes store root")
        data = path.read_text(encoding="utf-8")
        digest = hashlib.sha256(data.encode()).hexdigest()
        if digest != evidence.evidence_id:
            raise ValueError("evidence integrity check failed")
        return data
