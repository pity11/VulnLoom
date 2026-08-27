"""Export the trusted protocol and domain contracts as JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

from vulnloom.analyzers import SourceGraph, SourceMapperLimits
from vulnloom.domain.models import (
    ApprovalRequest,
    Artifact,
    Candidate,
    DisclosureCase,
    Evidence,
    EvidenceBundle,
    Finding,
    Report,
    Scope,
    TargetManifest,
    TargetSnapshot,
    ValidationRun,
)
from vulnloom.domain.protocol import TaskEnvelope, WorkerResult
from vulnloom.ingestion import IngestionLimits

MODELS = (
    Scope,
    Artifact,
    TargetManifest,
    TargetSnapshot,
    IngestionLimits,
    SourceMapperLimits,
    SourceGraph,
    Candidate,
    ApprovalRequest,
    ValidationRun,
    Evidence,
    EvidenceBundle,
    Finding,
    Report,
    DisclosureCase,
    TaskEnvelope,
    WorkerResult,
)


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas"
    root.mkdir(parents=True, exist_ok=True)
    for model in MODELS:
        path = root / f"{model.__name__}.schema.json"
        path.write_text(
            json.dumps(model.model_json_schema(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
