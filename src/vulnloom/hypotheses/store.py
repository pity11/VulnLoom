"""Content-addressed, immutable CandidateSet persistence."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from .models import CandidateSet, candidate_set_digest


class CandidateSetStore:
    def __init__(self, root: Path, *, max_set_bytes: int = 20 * 1024 * 1024):
        if max_set_bytes <= 0:
            raise ValueError("CandidateSet size limit must be positive")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_set_bytes = max_set_bytes

    def put(self, candidate_set: CandidateSet) -> tuple[Path, bool]:
        if candidate_set_digest(candidate_set) != candidate_set.candidate_set_id:
            raise ValueError("CandidateSet content digest mismatch")
        destination = self.root / f"{candidate_set.candidate_set_id}.json"
        encoded = candidate_set.model_dump_json(indent=2).encode()
        if len(encoded) > self.max_set_bytes:
            raise ValueError("CandidateSet exceeds the configured size limit")
        if destination.exists():
            if self._read(destination) != candidate_set:
                raise ValueError("CandidateSet id collision")
            return destination, False
        descriptor, name = tempfile.mkstemp(prefix="candidates-", dir=self.root)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o400)
            try:
                os.link(temporary, destination)
                created = True
            except FileExistsError:
                created = False
            if not created and self._read(destination) != candidate_set:
                raise ValueError("CandidateSet id collision")
            return destination, created
        finally:
            temporary.unlink(missing_ok=True)

    def load(self, candidate_set_id: str) -> CandidateSet:
        if len(candidate_set_id) != 64 or any(
            character not in "0123456789abcdef" for character in candidate_set_id
        ):
            raise ValueError("invalid CandidateSet id")
        candidate_set = self._read(self.root / f"{candidate_set_id}.json")
        if (
            candidate_set.candidate_set_id != candidate_set_id
            or candidate_set_digest(candidate_set) != candidate_set_id
        ):
            raise ValueError("CandidateSet identity mismatch")
        return candidate_set

    def _read(self, path: Path) -> CandidateSet:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError("CandidateSet object is unavailable or unsafe") from exc
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o222
                or metadata.st_size > self.max_set_bytes
            ):
                raise ValueError("CandidateSet object is unavailable or unsafe")
            content = handle.read(self.max_set_bytes + 1)
        if len(content) > self.max_set_bytes:
            raise ValueError("CandidateSet exceeds the configured size limit")
        return CandidateSet.model_validate_json(content)
