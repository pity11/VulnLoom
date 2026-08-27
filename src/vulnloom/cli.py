"""Phase 0 CLI: create engagements, approve Scope documents, inspect events."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import UUID

from vulnloom.domain.models import Engagement, EngagementState, Scope, ScopeState, utc_now
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnloom")
    parser.add_argument("--db", default=".vulnloom/events.db")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
