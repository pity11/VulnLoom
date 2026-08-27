"""Content-addressed, immutable SourceGraph persistence."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .models import SourceGraph, source_graph_digest


class SourceGraphStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def put(self, graph: SourceGraph) -> tuple[Path, bool]:
        if source_graph_digest(graph) != graph.graph_id:
            raise ValueError("SourceGraph content digest mismatch")
        destination = self.root / f"{graph.graph_id}.json"
        encoded = graph.model_dump_json(indent=2).encode("utf-8")
        if destination.exists():
            existing = SourceGraph.model_validate_json(destination.read_bytes())
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
                existing = SourceGraph.model_validate_json(destination.read_bytes())
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
        graph = SourceGraph.model_validate_json((self.root / f"{graph_id}.json").read_bytes())
        if graph.graph_id != graph_id or source_graph_digest(graph) != graph_id:
            raise ValueError("SourceGraph identity mismatch")
        return graph
