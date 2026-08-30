"""Content-addressed, immutable SourceGraph persistence."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from .models import SourceGraph, source_graph_digest


class SourceGraphStore:
    def __init__(self, root: Path, *, max_graph_bytes: int = 50 * 1024 * 1024):
        if max_graph_bytes <= 0:
            raise ValueError("SourceGraph size limit must be positive")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_graph_bytes = max_graph_bytes

    def put(self, graph: SourceGraph) -> tuple[Path, bool]:
        if source_graph_digest(graph) != graph.graph_id:
            raise ValueError("SourceGraph content digest mismatch")
        destination = self.root / f"{graph.graph_id}.json"
        encoded = graph.model_dump_json(indent=2).encode("utf-8")
        if len(encoded) > self.max_graph_bytes:
            raise ValueError("SourceGraph exceeds the configured size limit")
        if destination.exists():
            existing = self._read(destination)
            if existing != graph:
                raise ValueError("SourceGraph id collision")
            return destination, False
        fd, temporary_name = tempfile.mkstemp(prefix="graph-", dir=self.root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o400)
            try:
                os.link(temporary, destination)
                created = True
            except FileExistsError:
                created = False
            if not created:
                existing = self._read(destination)
                if existing != graph:
                    raise ValueError("SourceGraph id collision")
            return destination, created
        finally:
            temporary.unlink(missing_ok=True)

    def load(self, graph_id: str) -> SourceGraph:
        if len(graph_id) != 64 or any(
            character not in "0123456789abcdef" for character in graph_id
        ):
            raise ValueError("invalid SourceGraph id")
        graph = self._read(self.root / f"{graph_id}.json")
        if graph.graph_id != graph_id or source_graph_digest(graph) != graph_id:
            raise ValueError("SourceGraph identity mismatch")
        return graph

    def _read(self, path: Path) -> SourceGraph:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError("SourceGraph object is unavailable or unsafe") from exc
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_graph_bytes:
                raise ValueError("SourceGraph object is unavailable or unsafe")
            content = handle.read(self.max_graph_bytes + 1)
        if len(content) > self.max_graph_bytes:
            raise ValueError("SourceGraph exceeds the configured size limit")
        return SourceGraph.model_validate_json(content)
