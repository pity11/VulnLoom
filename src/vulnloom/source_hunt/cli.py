"""Stable local CLI surface for the Source Hunt application service."""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from vulnloom.domain.models import Scope, utc_now
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.ingestion import IngestionService

from .adapters import SnapshotSourceContextReader
from .candidate import SourceCandidateProposal, SourceCandidateService
from .execution import SourceExecutionPlanningService
from .execution_models import source_execution_approval_digest
from .models import (
    InvestigationQuery,
    InvestigationQueryKind,
    InvestigationStatus,
    SourceHuntLimits,
)
from .service import SourceHuntService
from .store import SourceHuntStore


def _scope(path: str) -> Scope:
    return Scope.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _start(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    ingestion = IngestionService(Path(args.target_store))
    snapshot = ingestion.load_snapshot(args.snapshot_id)
    limits = SourceHuntLimits(
        max_files=args.max_files,
        max_total_bytes=args.max_total_bytes,
        max_single_file_bytes=args.max_single_file_bytes,
        max_files_per_partition=args.max_files_per_partition,
        max_queries=args.max_queries,
        max_observations=args.max_observations,
        timeout_seconds=args.timeout_seconds,
    )
    with SourceHuntStore(Path(args.hunt_db)) as store:
        service = SourceHuntService(store=store)
        index = service.index_repository(
            snapshot=snapshot,
            store_root=ingestion.root,
            scope=scope,
            limits=limits,
            now=now,
        )
        plan, checkpoint = service.start(
            index=index,
            scope=scope,
            limits=limits,
            now=now,
            deadline=now + timedelta(seconds=args.investigation_ttl_seconds),
            idempotency_key=args.idempotency_key,
        )
    print(
        json.dumps(
            {
                "plan": plan.model_dump(mode="json"),
                "checkpoint": checkpoint.model_dump(mode="json"),
                "index_summary": {
                    "index_id": index.index_id,
                    "files_indexed": len(index.files_indexed),
                    "symbols": len(index.symbols),
                    "references": len(index.references),
                    "partitions": len(index.partitions),
                    "languages": sorted(item.value for item in index.adapter_versions),
                    "build_systems": [item.value for item in index.build_systems],
                },
            },
            indent=2,
        )
    )
    return 0


def _query(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    with SourceHuntStore(Path(args.hunt_db)) as store:
        service = SourceHuntService(store=store)
        plan = store.plan(args.plan_id)
        index = store.index(plan.index_id)
        checkpoint = store.latest(plan.plan_id)
        ingestion = IngestionService(Path(args.target_store))
        snapshot = ingestion.load_snapshot(index.manifest_id)
        IngestionService.require_snapshot_scope(snapshot, scope, now)
        if snapshot.root_ref is None:
            raise ValueError("Source Hunt query requires a filesystem Snapshot")
        reader = SnapshotSourceContextReader(ingestion.root / snapshot.root_ref)
        checkpoint, observation = service.query(
            plan=plan,
            index=index,
            checkpoint=checkpoint,
            query=InvestigationQuery(
                kind=InvestigationQueryKind(args.kind),
                term=args.term,
                max_results=args.max_results,
            ),
            scope=scope,
            now=now,
            source_reader=reader,
        )
    print(
        json.dumps(
            {
                "checkpoint": checkpoint.model_dump(mode="json"),
                "observation": observation.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def _transition(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file) if args.action != "expire" else None
    with SourceHuntStore(Path(args.hunt_db)) as store:
        service = SourceHuntService(store=store)
        plan = store.plan(args.plan_id)
        checkpoint = store.latest(plan.plan_id)
        if args.action == "expire":
            checkpoint = service.expire(plan=plan, checkpoint=checkpoint, now=now)
        else:
            index = store.index(plan.index_id)
            if args.action == "complete":
                checkpoint = service.complete(
                    plan=plan,
                    index=index,
                    checkpoint=checkpoint,
                    conclusion_digest=args.conclusion_digest,
                    scope=scope,
                    now=now,
                )
            else:
                checkpoint = service.cancel(
                    plan=plan,
                    index=index,
                    checkpoint=checkpoint,
                    scope=scope,
                    now=now,
                )
    print(json.dumps({"checkpoint": checkpoint.model_dump(mode="json")}, indent=2))
    return 0


def _materialize_candidate(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    proposal = SourceCandidateProposal.model_validate_json(
        Path(args.proposal_file).read_text(encoding="utf-8")
    )
    with SourceHuntStore(Path(args.hunt_db)) as store:
        service = SourceHuntService(store=store)
        plan = store.plan(args.plan_id)
        index = store.index(plan.index_id)
        checkpoint = store.latest(plan.plan_id)
        if checkpoint.status is InvestigationStatus.ACTIVE:
            checkpoint = service.complete(
                plan=plan,
                index=index,
                checkpoint=checkpoint,
                conclusion_digest=proposal.proposal_id,
                scope=scope,
                now=now,
            )
        candidate_set = SourceCandidateService(
            investigation_store=store
        ).materialize(
            proposal=proposal,
            investigation=checkpoint,
            index=index,
            scope=scope,
            now=now,
        )
    path, created = CandidateSetStore(Path(args.candidate_store)).put(candidate_set)
    candidate = candidate_set.candidates[0]
    print(
        json.dumps(
            {
                "created": created,
                "candidate_set_id": candidate_set.candidate_set_id,
                "candidate_set_path": str(path),
                "candidate_id": str(candidate.candidate_id),
                "candidate_state": candidate.state.value,
                "cwe": candidate.cwe,
                "entry": candidate.entry_point.model_dump(mode="json"),
                "sink": candidate.sink.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def _status(args: argparse.Namespace) -> int:
    with SourceHuntStore(Path(args.hunt_db)) as store:
        plan = store.plan(args.plan_id)
        index = store.index(plan.index_id)
        checkpoint = store.latest(plan.plan_id)
    print(
        json.dumps(
            {
                "plan_id": plan.plan_id,
                "index_id": index.index_id,
                "target_id": str(index.target_id),
                "target_version": index.target_version,
                "status": checkpoint.status.value,
                "revision": checkpoint.revision,
                "queries_used": checkpoint.queries_used,
                "observation_count": len(checkpoint.observation_ids),
            },
            indent=2,
        )
    )
    return 0


def _prepare_execution(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    candidate_set = CandidateSetStore(Path(args.candidate_store)).load(
        args.candidate_set_id
    )
    candidate_id = UUID(args.candidate_id)
    matches = tuple(
        item for item in candidate_set.candidates if item.candidate_id == candidate_id
    )
    if len(matches) != 1:
        raise ValueError("Source Hunt Candidate is not in the sealed CandidateSet")
    with SourceHuntStore(Path(args.hunt_db)) as store:
        investigation_plan = store.plan(args.plan_id)
        index = store.index(investigation_plan.index_id)
        checkpoint = store.latest(investigation_plan.plan_id)
    plan = SourceExecutionPlanningService().prepare(
        index=index,
        investigation=checkpoint,
        candidate=matches[0],
        scope=scope,
        image_digest=args.image_digest,
        tool_registry_digest=args.tool_registry_digest,
        now=now,
        deadline=now + timedelta(seconds=args.execution_ttl_seconds),
        idempotency_key=args.idempotency_key,
        stage_wall_seconds=args.stage_wall_seconds,
    )
    print(
        json.dumps(
            {
                "plan": plan.model_dump(mode="json"),
                "required_approval": {
                    "action": "run_untrusted_build",
                    "action_digest": source_execution_approval_digest(plan),
                },
            },
            indent=2,
        )
    )
    return 0


def register_source_hunt_commands(subparsers) -> None:
    root = subparsers.add_parser("source-hunt")
    actions = root.add_subparsers(dest="action", required=True)

    start = actions.add_parser("start")
    start.add_argument("--snapshot-id", required=True)
    start.add_argument("--scope-file", required=True)
    start.add_argument("--target-store", default=".vulnloom/targets")
    start.add_argument("--hunt-db", default=".vulnloom/source-hunt.db")
    start.add_argument("--idempotency-key", required=True)
    start.add_argument("--max-files", type=int, default=20_000)
    start.add_argument("--max-total-bytes", type=int, default=200 * 1024 * 1024)
    start.add_argument("--max-single-file-bytes", type=int, default=2 * 1024 * 1024)
    start.add_argument("--max-files-per-partition", type=int, default=500)
    start.add_argument("--max-queries", type=int, default=64)
    start.add_argument("--max-observations", type=int, default=64)
    start.add_argument("--timeout-seconds", type=float, default=120.0)
    start.add_argument("--investigation-ttl-seconds", type=int, default=1_800)
    start.set_defaults(handler=_start)

    query = actions.add_parser("query")
    query.add_argument("--plan-id", required=True)
    query.add_argument("--scope-file", required=True)
    query.add_argument("--hunt-db", default=".vulnloom/source-hunt.db")
    query.add_argument("--target-store", default=".vulnloom/targets")
    query.add_argument(
        "--kind", choices=tuple(item.value for item in InvestigationQueryKind), required=True
    )
    query.add_argument("--term", required=True)
    query.add_argument("--max-results", type=int, default=32)
    query.set_defaults(handler=_query)

    status = actions.add_parser("status")
    status.add_argument("--plan-id", required=True)
    status.add_argument("--hunt-db", default=".vulnloom/source-hunt.db")
    status.set_defaults(handler=_status)

    candidate = actions.add_parser("materialize-candidate")
    candidate.add_argument("--plan-id", required=True)
    candidate.add_argument("--scope-file", required=True)
    candidate.add_argument("--proposal-file", required=True)
    candidate.add_argument("--hunt-db", default=".vulnloom/source-hunt.db")
    candidate.add_argument("--candidate-store", default=".vulnloom/candidates")
    candidate.set_defaults(handler=_materialize_candidate)

    execution = actions.add_parser("prepare-execution")
    execution.add_argument("--plan-id", required=True)
    execution.add_argument("--scope-file", required=True)
    execution.add_argument("--candidate-set-id", required=True)
    execution.add_argument("--candidate-id", required=True)
    execution.add_argument("--image-digest", required=True)
    execution.add_argument("--tool-registry-digest", required=True)
    execution.add_argument("--idempotency-key", required=True)
    execution.add_argument("--hunt-db", default=".vulnloom/source-hunt.db")
    execution.add_argument("--candidate-store", default=".vulnloom/candidates")
    execution.add_argument("--execution-ttl-seconds", type=int, default=1_800)
    execution.add_argument("--stage-wall-seconds", type=int, default=600)
    execution.set_defaults(handler=_prepare_execution)

    for name in ("complete", "cancel", "expire"):
        command = actions.add_parser(name)
        command.add_argument("--plan-id", required=True)
        command.add_argument("--hunt-db", default=".vulnloom/source-hunt.db")
        if name != "expire":
            command.add_argument("--scope-file", required=True)
        if name == "complete":
            command.add_argument("--conclusion-digest", required=True)
        command.set_defaults(handler=_transition)
