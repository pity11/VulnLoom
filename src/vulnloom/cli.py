"""VulnLoom CLI for trusted workflow and offline source mapping."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import UUID

from vulnloom.analyzers import PythonWebSourceMapper, SourceGraphStore
from vulnloom.domain.models import (
    ArtifactKind,
    Engagement,
    EngagementState,
    Scope,
    ScopeState,
    TargetSnapshot,
    utc_now,
)
from vulnloom.ingestion import IngestionService
from vulnloom.storage.events import Event, EventStore


def _store(path: str) -> EventStore:
    return EventStore(Path(path))


def create_engagement(args: argparse.Namespace) -> int:
    engagement = Engagement(
        name=args.name,
        authority_reference=args.authority,
        state=EngagementState.ACTIVE,
    )
    event = Event(
        engagement_id=engagement.engagement_id,
        event_type="EngagementCreated",
        aggregate_id=str(engagement.engagement_id),
        payload=engagement.model_dump(mode="json"),
        idempotency_key=args.idempotency_key or f"engagement:create:{engagement.engagement_id}",
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(json.dumps({"created": created, "event": stored.model_dump(mode="json")}, indent=2))
    return 0


def approve_scope(args: argparse.Namespace) -> int:
    raw = json.loads(Path(args.file).read_text(encoding="utf-8"))
    scope = Scope.model_validate(raw)
    now = utc_now()
    if not scope.valid_from <= now < scope.valid_until:
        raise SystemExit("refusing to approve Scope outside its validity window")
    approved = scope.model_copy(
        update={"state": ScopeState.APPROVED, "approved_by": args.approver, "approved_at": now}
    )
    event = Event(
        engagement_id=approved.engagement_id,
        event_type="ScopeApproved",
        aggregate_id=str(approved.scope_id),
        payload=approved.model_dump(mode="json"),
        idempotency_key=args.idempotency_key
        or f"scope:approve:{approved.scope_id}:v{approved.version}",
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(json.dumps({"created": created, "event": stored.model_dump(mode="json")}, indent=2))
    return 0


def show_status(args: argparse.Namespace) -> int:
    engagement_id = UUID(args.engagement_id)
    with _store(args.db) as store:
        events = store.list_for_engagement(engagement_id)
    print(json.dumps([event.model_dump(mode="json") for event in events], indent=2))
    return 0


def _load_scope(path: str) -> Scope:
    return Scope.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _record_snapshot(args: argparse.Namespace, snapshot: TargetSnapshot) -> int:
    event = Event(
        engagement_id=snapshot.target.engagement_id,
        event_type="TargetIngested",
        aggregate_id=str(snapshot.target.target_id),
        payload=snapshot.model_dump(mode="json"),
        idempotency_key=(
            args.idempotency_key
            or f"target:ingest:{snapshot.target.target_id}:{snapshot.manifest.manifest_id}"
        ),
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(
        json.dumps(
            {"created": created, "event": stored.model_dump(mode="json")},
            indent=2,
        )
    )
    return 0


def ingest_archive(args: argparse.Namespace) -> int:
    snapshot = IngestionService(Path(args.store)).ingest_archive(
        Path(args.source),
        scope=_load_scope(args.scope_file),
        kind=ArtifactKind(args.kind),
    )
    return _record_snapshot(args, snapshot)


def quarantine_artifact(args: argparse.Namespace) -> int:
    artifact = IngestionService(Path(args.store)).quarantine_artifact(
        Path(args.source),
        engagement_id=UUID(args.engagement_id),
        kind=ArtifactKind(args.kind),
    )
    event = Event(
        engagement_id=artifact.engagement_id,
        event_type="ArtifactQuarantined",
        aggregate_id=artifact.artifact_id,
        payload=artifact.model_dump(mode="json", exclude={"captured_at"}),
        idempotency_key=(
            args.idempotency_key
            or f"artifact:quarantine:{artifact.engagement_id}:{artifact.artifact_id}"
        ),
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(json.dumps({"created": created, "event": stored.model_dump(mode="json")}, indent=2))
    return 0


def ingest_git(args: argparse.Namespace) -> int:
    snapshot = IngestionService(Path(args.store)).ingest_git(
        Path(args.source),
        repository_url=args.repository_url,
        commit=args.commit,
        scope=_load_scope(args.scope_file),
    )
    return _record_snapshot(args, snapshot)


def register_image(args: argparse.Namespace) -> int:
    snapshot = IngestionService(Path(args.store)).register_oci_image(
        args.image_ref,
        args.digest,
        scope=_load_scope(args.scope_file),
    )
    return _record_snapshot(args, snapshot)


def source_map(args: argparse.Namespace) -> int:
    service = IngestionService(Path(args.store))
    snapshot = service.load_snapshot(args.snapshot_id)
    graph = PythonWebSourceMapper().analyze(snapshot, service.root)
    graph_path, graph_created = SourceGraphStore(Path(args.analysis_store)).put(graph)
    summary = {
        "graph_id": graph.graph_id,
        "manifest_id": graph.manifest_id,
        "analyzer_version": graph.analyzer_version,
        "graph_ref": str(graph_path),
        "files_analyzed": len(graph.files_analyzed),
        "routes": len(graph.routes),
        "flows": len(graph.flows),
        "signals": len(graph.signals),
    }
    event = Event(
        engagement_id=snapshot.target.engagement_id,
        event_type="SourceGraphBuilt",
        aggregate_id=graph.graph_id,
        payload=summary,
        idempotency_key=args.idempotency_key or f"source-map:{graph.graph_id}",
    )
    with _store(args.db) as store:
        stored, event_created = store.append(event)
    print(
        json.dumps(
            {
                "graph_created": graph_created,
                "event_created": event_created,
                "graph": summary,
                "event_id": str(stored.event_id),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnloom")
    parser.add_argument("--db", default=".vulnloom/events.db")
    parser.add_argument("--store", default=".vulnloom/targets")
    sub = parser.add_subparsers(required=True)

    engagement = sub.add_parser("engagement-create")
    engagement.add_argument("--name", required=True)
    engagement.add_argument("--authority", required=True)
    engagement.add_argument("--idempotency-key")
    engagement.set_defaults(handler=create_engagement)

    scope = sub.add_parser("scope-approve")
    scope.add_argument("--file", required=True)
    scope.add_argument("--approver", required=True)
    scope.add_argument("--idempotency-key")
    scope.set_defaults(handler=approve_scope)

    status = sub.add_parser("status")
    status.add_argument("--engagement-id", required=True)
    status.set_defaults(handler=show_status)

    quarantine = sub.add_parser("artifact-quarantine")
    quarantine.add_argument("--engagement-id", required=True)
    quarantine.add_argument("--source", required=True)
    quarantine.add_argument(
        "--kind",
        choices=(ArtifactKind.SOURCE_ARCHIVE.value, ArtifactKind.IAC_BUNDLE.value),
        default=ArtifactKind.SOURCE_ARCHIVE.value,
    )
    quarantine.add_argument("--idempotency-key")
    quarantine.set_defaults(handler=quarantine_artifact)

    archive = sub.add_parser("target-ingest-archive")
    archive.add_argument("--scope-file", required=True)
    archive.add_argument("--source", required=True)
    archive.add_argument(
        "--kind",
        choices=(ArtifactKind.SOURCE_ARCHIVE.value, ArtifactKind.IAC_BUNDLE.value),
        default=ArtifactKind.SOURCE_ARCHIVE.value,
    )
    archive.add_argument("--idempotency-key")
    archive.set_defaults(handler=ingest_archive)

    git = sub.add_parser("target-ingest-git")
    git.add_argument("--scope-file", required=True)
    git.add_argument("--source", required=True)
    git.add_argument("--repository-url", required=True)
    git.add_argument("--commit", required=True)
    git.add_argument("--idempotency-key")
    git.set_defaults(handler=ingest_git)

    image = sub.add_parser("target-register-image")
    image.add_argument("--scope-file", required=True)
    image.add_argument("--image-ref", required=True)
    image.add_argument("--digest", required=True)
    image.add_argument("--idempotency-key")
    image.set_defaults(handler=register_image)

    mapping = sub.add_parser("source-map")
    mapping.add_argument("--snapshot-id", required=True)
    mapping.add_argument("--analysis-store", default=".vulnloom/analysis")
    mapping.add_argument("--idempotency-key")
    mapping.set_defaults(handler=source_map)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
