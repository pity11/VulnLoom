"""Stable local CLI over the Authorized Red Team application service."""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

from vulnloom.domain.models import Scope, utc_now
from vulnloom.evidence import EvidenceStore
from vulnloom.workflows import Visibility

from .models import (
    ReconOutcome,
    RedTeamActionKind,
    RedTeamReconCommand,
)
from .service import OfflineReconScenario, OfflineRedTeamReconAdapter, RedTeamService
from .store import RedTeamStore
from .surface_models import AttackSurfaceReductionLimits, AttackSurfaceReductionPlan
from .surface_service import AttackSurfaceReductionService
from .surface_store import AttackSurfaceReductionStore


def _scope(path: str) -> Scope:
    return Scope.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _start(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    with RedTeamStore(Path(args.red_team_db)) as store:
        service = RedTeamService(store=store)
        plan = service.prepare(
            scope=scope,
            target_url=args.target_url,
            visibility=Visibility(args.visibility),
            allowed_test_classes=tuple(args.test_class),
            max_actions=args.max_actions,
            max_consecutive_failures=args.max_consecutive_failures,
            emergency_contact_ref=args.emergency_contact_ref,
            now=now,
            deadline=now + timedelta(seconds=args.flow_ttl_seconds),
            idempotency_key=args.idempotency_key,
        )
        checkpoint = service.create_and_start(plan, scope=scope, now=now)
    print(
        json.dumps(
            {
                "plan": plan.model_dump(mode="json"),
                "checkpoint": checkpoint.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def _prepare_recon(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    with RedTeamStore(Path(args.red_team_db)) as store:
        service = RedTeamService(store=store)
        plan = store.plan(args.plan_id)
        checkpoint = store.latest(plan.plan_id)
        command = service.prepare_recon(
            plan=plan,
            checkpoint=checkpoint,
            scope=scope,
            kind=RedTeamActionKind(args.kind),
            test_class=args.test_class,
            now=now,
            ttl_seconds=args.action_ttl_seconds,
            idempotency_key=args.idempotency_key,
        )
    print(json.dumps({"command": command.model_dump(mode="json")}, indent=2))
    return 0


def _run_recon_offline(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    base = RedTeamReconCommand.model_validate_json(
        Path(args.command_file).read_text(encoding="utf-8")
    )
    command = RedTeamReconCommand.create(action=base.action, attempt=args.attempt)
    outcome = ReconOutcome(args.outcome)
    scenario = OfflineReconScenario(
        outcome=outcome,
        status_code=(args.status_code if outcome is ReconOutcome.SUCCEEDED else None),
        reason_code=f"offline_{outcome.value}",
        cleanup_complete=not args.cleanup_failed,
        interrupt=args.interrupt,
    )
    with RedTeamStore(Path(args.red_team_db)) as store:
        checkpoint, observation = RedTeamService(store=store).execute_recon(
            command=command,
            scope=scope,
            adapter=OfflineRedTeamReconAdapter(scenario),
            now=now,
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


def _status(args: argparse.Namespace) -> int:
    with RedTeamStore(Path(args.red_team_db)) as store:
        plan = store.plan(args.plan_id)
        checkpoint = store.latest(plan.plan_id)
    print(
        json.dumps(
            {
                "plan_id": plan.plan_id,
                "target_id": str(plan.target.target_id),
                "status": checkpoint.status.value,
                "revision": checkpoint.revision,
                "actions_used": checkpoint.actions_used,
                "observation_count": len(checkpoint.observation_ids),
                "stop_reason": checkpoint.stop_reason,
            },
            indent=2,
        )
    )
    return 0


def _prepare_surface(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    with (
        RedTeamStore(Path(args.red_team_db)) as red_store,
        AttackSurfaceReductionStore(Path(args.surface_db)) as surface_store,
    ):
        plan = red_store.plan(args.plan_id)
        checkpoint = red_store.latest(plan.plan_id)
        reduction = AttackSurfaceReductionService(
            red_team_store=red_store,
            reduction_store=surface_store,
            evidence_store=EvidenceStore(Path(args.evidence_root)),
        ).prepare(
            flow_plan=plan,
            checkpoint=checkpoint,
            scope=scope,
            limits=AttackSurfaceReductionLimits(
                max_observations=args.max_observations,
                max_endpoints=args.max_endpoints,
                max_evidence_refs=args.max_evidence_refs,
                timeout_seconds=args.timeout_seconds,
            ),
            now=now,
            deadline=now + timedelta(seconds=args.ttl_seconds),
            idempotency_key=args.idempotency_key,
        )
    print(json.dumps({"reduction": reduction.model_dump(mode="json")}, indent=2))
    return 0


def _run_surface(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    reduction = AttackSurfaceReductionPlan.model_validate_json(
        Path(args.reduction_file).read_text(encoding="utf-8")
    )
    with (
        RedTeamStore(Path(args.red_team_db)) as red_store,
        AttackSurfaceReductionStore(Path(args.surface_db)) as surface_store,
    ):
        service = AttackSurfaceReductionService(
            red_team_store=red_store,
            reduction_store=surface_store,
            evidence_store=EvidenceStore(Path(args.evidence_root)),
        )
        outcome = (
            service.recover(reduction, scope=scope, now=now)
            if args.recover
            else service.execute(reduction, scope=scope, now=now)
        )
    print(json.dumps({"outcome": outcome.model_dump(mode="json")}, indent=2))
    return 0


def _surface_status(args: argparse.Namespace) -> int:
    with AttackSurfaceReductionStore(Path(args.surface_db)) as store:
        state = store.state(args.reduction_id)
        if state is None:
            raise ValueError("Attack Surface reduction is unavailable")
        payload = {
            "reduction_id": args.reduction_id,
            "state": state[0].value,
            "attempt": state[1],
        }
        if state[0].value == "completed":
            outcome = store.outcome(args.reduction_id)
            payload.update(
                {
                    "inventory_id": outcome.inventory.inventory_id,
                    "endpoint_count": len(outcome.inventory.endpoints),
                    "observation_count": len(outcome.inventory.observation_ids),
                    "evidence_count": len(outcome.inventory.evidence_refs),
                    "cleanup_complete": outcome.cleanup_complete,
                }
            )
    print(json.dumps(payload, indent=2))
    return 0


def _transition(args: argparse.Namespace) -> int:
    now = utc_now()
    with RedTeamStore(Path(args.red_team_db)) as store:
        service = RedTeamService(store=store)
        plan = store.plan(args.plan_id)
        checkpoint = store.latest(plan.plan_id)
        if args.action == "expire":
            checkpoint = service.expire(plan, checkpoint, now=now)
        else:
            scope = _scope(args.scope_file)
            checkpoint = (
                service.kill(plan, checkpoint, scope=scope, now=now)
                if args.action == "kill"
                else service.cancel(plan, checkpoint, scope=scope, now=now)
            )
    print(json.dumps({"checkpoint": checkpoint.model_dump(mode="json")}, indent=2))
    return 0


def register_red_team_commands(subparsers) -> None:
    root = subparsers.add_parser("red-team")
    actions = root.add_subparsers(dest="action", required=True)

    start = actions.add_parser("start")
    start.add_argument("--scope-file", required=True)
    start.add_argument("--target-url", required=True)
    start.add_argument(
        "--visibility",
        choices=(Visibility.BLACK_BOX.value, Visibility.GREY_BOX.value),
        default=Visibility.BLACK_BOX.value,
    )
    start.add_argument("--test-class", action="append", required=True)
    start.add_argument("--max-actions", type=int, default=32)
    start.add_argument("--max-consecutive-failures", type=int, default=3)
    start.add_argument("--emergency-contact-ref", required=True)
    start.add_argument("--flow-ttl-seconds", type=int, default=1_800)
    start.add_argument("--idempotency-key", required=True)
    start.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    start.set_defaults(handler=_start)

    prepare = actions.add_parser("prepare-recon")
    prepare.add_argument("--plan-id", required=True)
    prepare.add_argument("--scope-file", required=True)
    prepare.add_argument(
        "--kind", choices=tuple(item.value for item in RedTeamActionKind), required=True
    )
    prepare.add_argument("--test-class", required=True)
    prepare.add_argument("--action-ttl-seconds", type=int, default=30)
    prepare.add_argument("--idempotency-key", required=True)
    prepare.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    prepare.set_defaults(handler=_prepare_recon)

    run = actions.add_parser("run-recon-offline")
    run.add_argument("--command-file", required=True)
    run.add_argument("--scope-file", required=True)
    run.add_argument("--attempt", type=int, default=1)
    run.add_argument(
        "--outcome", choices=tuple(item.value for item in ReconOutcome), required=True
    )
    run.add_argument("--status-code", type=int, default=204)
    run.add_argument("--cleanup-failed", action="store_true")
    run.add_argument("--interrupt", action="store_true")
    run.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    run.set_defaults(handler=_run_recon_offline)

    status = actions.add_parser("status")
    status.add_argument("--plan-id", required=True)
    status.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    status.set_defaults(handler=_status)

    prepare_surface = actions.add_parser("prepare-surface-reduction")
    prepare_surface.add_argument("--plan-id", required=True)
    prepare_surface.add_argument("--scope-file", required=True)
    prepare_surface.add_argument("--ttl-seconds", type=int, default=300)
    prepare_surface.add_argument("--max-observations", type=int, default=1_000)
    prepare_surface.add_argument("--max-endpoints", type=int, default=1_000)
    prepare_surface.add_argument("--max-evidence-refs", type=int, default=6_000)
    prepare_surface.add_argument("--timeout-seconds", type=float, default=30.0)
    prepare_surface.add_argument("--idempotency-key", required=True)
    prepare_surface.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    prepare_surface.add_argument(
        "--surface-db", default=".vulnloom/red-team-surface.db"
    )
    prepare_surface.add_argument("--evidence-root", default=".vulnloom/evidence")
    prepare_surface.set_defaults(handler=_prepare_surface)

    run_surface = actions.add_parser("run-surface-reduction-offline")
    run_surface.add_argument("--reduction-file", required=True)
    run_surface.add_argument("--scope-file", required=True)
    run_surface.add_argument("--recover", action="store_true")
    run_surface.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    run_surface.add_argument("--surface-db", default=".vulnloom/red-team-surface.db")
    run_surface.add_argument("--evidence-root", default=".vulnloom/evidence")
    run_surface.set_defaults(handler=_run_surface)

    surface_status = actions.add_parser("surface-status")
    surface_status.add_argument("--reduction-id", required=True)
    surface_status.add_argument("--surface-db", default=".vulnloom/red-team-surface.db")
    surface_status.set_defaults(handler=_surface_status)

    for name in ("cancel", "kill", "expire"):
        command = actions.add_parser(name)
        command.add_argument("--plan-id", required=True)
        command.add_argument("--red-team-db", default=".vulnloom/red-team.db")
        if name != "expire":
            command.add_argument("--scope-file", required=True)
        command.set_defaults(handler=_transition)
