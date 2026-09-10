"""Stable local CLI over the Authorized Red Team application service."""

from __future__ import annotations

import argparse
import json
import os
import stat
from datetime import timedelta
from pathlib import Path

from vulnloom.domain.models import Scope, utc_now
from vulnloom.evidence import EvidenceStore
from vulnloom.workflows import Visibility

from .drift_models import AttackSurfaceDriftLimits, AttackSurfaceDriftPlan
from .drift_service import AttackSurfaceDriftService
from .drift_store import AttackSurfaceDriftStore
from .models import (
    ReconOutcome,
    RedTeamActionKind,
    RedTeamReconCommand,
)
from .seed_models import EndpointReconLimits, EndpointReconOutcomeKind
from .seed_service import (
    EndpointReconService,
    OfflineEndpointReconAdapter,
    OfflineEndpointReconScenario,
)
from .seed_store import EndpointReconStore
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


def _seed_paths(path: str) -> tuple[str, ...]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("platform cannot enforce no-follow seed reads")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024:
            raise ValueError("Endpoint Seed Set input is unavailable or unsafe")
        with os.fdopen(descriptor, encoding="utf-8", closefd=False) as handle:
            value = json.load(handle)
    finally:
        os.close(descriptor)
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 1_000
        or any(not isinstance(item, str) for item in value)
    ):
        raise ValueError("Endpoint Seed Set input must be a bounded JSON string array")
    return tuple(value)


def _endpoint_service(args):
    red_store = RedTeamStore(Path(args.red_team_db))
    recon_store = EndpointReconStore(Path(args.endpoint_recon_db))
    service = EndpointReconService(
        red_team_store=red_store,
        recon_store=recon_store,
        evidence_store=EvidenceStore(Path(args.evidence_root)),
    )
    return service, red_store, recon_store


def _seal_endpoint_seeds(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    service, red_store, recon_store = _endpoint_service(args)
    try:
        flow = red_store.plan(args.plan_id)
        checkpoint = red_store.latest(flow.plan_id)
        seed_set = service.seal_seed_set(
            flow_plan=flow,
            checkpoint=checkpoint,
            scope=scope,
            operator_ref=args.operator_ref,
            paths=_seed_paths(args.paths_file),
            now=now,
            expires_at=now + timedelta(seconds=args.ttl_seconds),
            idempotency_key=args.idempotency_key,
        )
    finally:
        red_store.close()
        recon_store.close()
    print(
        json.dumps(
            {
                "seed_set_id": seed_set.seed_set_id,
                "seed_count": len(seed_set.seeds),
                "path_digests": [seed.path_digest for seed in seed_set.seeds],
            },
            indent=2,
        )
    )
    return 0


def _prepare_endpoint_recon(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    service, red_store, recon_store = _endpoint_service(args)
    try:
        plan = service.prepare(
            seed_set_id=args.seed_set_id,
            scope=scope,
            test_class=args.test_class,
            limits=EndpointReconLimits(
                max_steps=args.max_steps,
                max_requests=args.max_requests,
                per_request_seconds=args.per_request_seconds,
                total_seconds=args.total_seconds,
                max_attempts=args.max_attempts,
            ),
            now=now,
            deadline=now + timedelta(seconds=args.total_seconds),
            idempotency_key=args.idempotency_key,
        )
    finally:
        red_store.close()
        recon_store.close()
    print(
        json.dumps(
            {
                "endpoint_recon_plan_id": plan.endpoint_recon_plan_id,
                "seed_set_id": plan.seed_set_id,
                "step_count": len(plan.steps),
                "max_requests": plan.limits.max_requests,
                "deadline": plan.deadline.isoformat(),
            },
            indent=2,
        )
    )
    return 0


def _run_endpoint_recon_offline(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    service, red_store, recon_store = _endpoint_service(args)
    try:
        plan = recon_store.plan(args.endpoint_recon_plan_id)
        kind = EndpointReconOutcomeKind(args.outcome)
        adapter = OfflineEndpointReconAdapter(
            OfflineEndpointReconScenario(
                outcome=kind,
                status_code=args.status_code
                if kind is EndpointReconOutcomeKind.SUCCEEDED
                else None,
                reason_code=f"offline_{kind.value}",
                cleanup_complete=not args.cleanup_failed,
                interrupt=args.interrupt,
            )
        )
        outcome = (
            service.recover(plan, scope=scope, adapter=adapter, now=now)
            if args.recover
            else service.execute(plan, scope=scope, adapter=adapter, now=now)
        )
    finally:
        red_store.close()
        recon_store.close()
    print(json.dumps({"outcome": outcome.model_dump(mode="json")}, indent=2))
    return 0


def _endpoint_recon_status(args: argparse.Namespace) -> int:
    with EndpointReconStore(Path(args.endpoint_recon_db)) as store:
        state = store.state(args.endpoint_recon_plan_id)
        if state is None:
            raise ValueError("Endpoint Recon is unavailable")
        payload = {
            "endpoint_recon_plan_id": args.endpoint_recon_plan_id,
            "state": state[0].value,
            "attempt": state[1],
        }
        if state[0].value == "completed":
            outcome = store.outcome(args.endpoint_recon_plan_id)
            payload.update(
                {
                    "outcome": outcome.outcome.value,
                    "requests_used": outcome.requests_used,
                    "cleanup_complete": outcome.cleanup_complete,
                }
            )
    print(json.dumps(payload, indent=2))
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


def _prepare_drift(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    with (
        AttackSurfaceReductionStore(Path(args.surface_db)) as surface_store,
        AttackSurfaceDriftStore(Path(args.drift_db)) as drift_store,
    ):
        plan = AttackSurfaceDriftService(
            inventory_source=surface_store,
            drift_store=drift_store,
            evidence_store=EvidenceStore(Path(args.evidence_root)),
        ).prepare(
            baseline_reduction_id=args.baseline_reduction_id,
            current_reduction_id=args.current_reduction_id,
            scope=scope,
            limits=AttackSurfaceDriftLimits(
                max_surfaces=args.max_surfaces,
                max_evidence_refs=args.max_evidence_refs,
                timeout_seconds=args.timeout_seconds,
            ),
            now=now,
            deadline=now + timedelta(seconds=args.ttl_seconds),
            idempotency_key=args.idempotency_key,
        )
    print(json.dumps({"comparison": plan.model_dump(mode="json")}, indent=2))
    return 0


def _run_drift(args: argparse.Namespace) -> int:
    now = utc_now()
    scope = _scope(args.scope_file)
    plan = AttackSurfaceDriftPlan.model_validate_json(
        Path(args.comparison_file).read_text(encoding="utf-8")
    )
    with (
        AttackSurfaceReductionStore(Path(args.surface_db)) as surface_store,
        AttackSurfaceDriftStore(Path(args.drift_db)) as drift_store,
    ):
        service = AttackSurfaceDriftService(
            inventory_source=surface_store,
            drift_store=drift_store,
            evidence_store=EvidenceStore(Path(args.evidence_root)),
        )
        outcome = (
            service.recover(plan, scope=scope, now=now)
            if args.recover
            else service.execute(plan, scope=scope, now=now)
        )
    print(json.dumps({"outcome": outcome.model_dump(mode="json")}, indent=2))
    return 0


def _drift_status(args: argparse.Namespace) -> int:
    with AttackSurfaceDriftStore(Path(args.drift_db)) as store:
        state = store.state(args.comparison_id)
        if state is None:
            raise ValueError("Attack Surface drift is unavailable")
        payload = {
            "comparison_id": args.comparison_id,
            "state": state[0].value,
            "attempt": state[1],
        }
        if state[0].value == "completed":
            outcome = store.outcome(args.comparison_id)
            payload.update(
                {
                    "report_id": outcome.report.report_id,
                    "compared_surface_count": outcome.report.compared_surface_count,
                    "changed_surface_count": len(outcome.report.changes),
                    "evidence_count": len(outcome.report.evidence_refs),
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
    run.add_argument("--outcome", choices=tuple(item.value for item in ReconOutcome), required=True)
    run.add_argument("--status-code", type=int, default=204)
    run.add_argument("--cleanup-failed", action="store_true")
    run.add_argument("--interrupt", action="store_true")
    run.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    run.set_defaults(handler=_run_recon_offline)

    status = actions.add_parser("status")
    status.add_argument("--plan-id", required=True)
    status.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    status.set_defaults(handler=_status)

    seal_seeds = actions.add_parser("seal-endpoint-seeds")
    seal_seeds.add_argument("--plan-id", required=True)
    seal_seeds.add_argument("--scope-file", required=True)
    seal_seeds.add_argument("--paths-file", required=True)
    seal_seeds.add_argument("--operator-ref", required=True)
    seal_seeds.add_argument("--ttl-seconds", type=int, default=300)
    seal_seeds.add_argument("--idempotency-key", required=True)
    seal_seeds.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    seal_seeds.add_argument("--endpoint-recon-db", default=".vulnloom/endpoint-recon.db")
    seal_seeds.add_argument("--evidence-root", default=".vulnloom/evidence")
    seal_seeds.set_defaults(handler=_seal_endpoint_seeds)

    prepare_endpoint = actions.add_parser("prepare-endpoint-recon")
    prepare_endpoint.add_argument("--seed-set-id", required=True)
    prepare_endpoint.add_argument("--scope-file", required=True)
    prepare_endpoint.add_argument("--test-class", required=True)
    prepare_endpoint.add_argument("--max-steps", type=int, default=100)
    prepare_endpoint.add_argument("--max-requests", type=int, default=100)
    prepare_endpoint.add_argument("--per-request-seconds", type=float, default=5.0)
    prepare_endpoint.add_argument("--total-seconds", type=float, default=60.0)
    prepare_endpoint.add_argument("--max-attempts", type=int, default=3)
    prepare_endpoint.add_argument("--idempotency-key", required=True)
    prepare_endpoint.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    prepare_endpoint.add_argument("--endpoint-recon-db", default=".vulnloom/endpoint-recon.db")
    prepare_endpoint.add_argument("--evidence-root", default=".vulnloom/evidence")
    prepare_endpoint.set_defaults(handler=_prepare_endpoint_recon)

    run_endpoint = actions.add_parser("run-endpoint-recon-offline")
    run_endpoint.add_argument("--endpoint-recon-plan-id", required=True)
    run_endpoint.add_argument("--scope-file", required=True)
    run_endpoint.add_argument(
        "--outcome",
        choices=tuple(item.value for item in EndpointReconOutcomeKind),
        default=EndpointReconOutcomeKind.SUCCEEDED.value,
    )
    run_endpoint.add_argument("--status-code", type=int, default=204)
    run_endpoint.add_argument("--cleanup-failed", action="store_true")
    run_endpoint.add_argument("--interrupt", action="store_true")
    run_endpoint.add_argument("--recover", action="store_true")
    run_endpoint.add_argument("--red-team-db", default=".vulnloom/red-team.db")
    run_endpoint.add_argument("--endpoint-recon-db", default=".vulnloom/endpoint-recon.db")
    run_endpoint.add_argument("--evidence-root", default=".vulnloom/evidence")
    run_endpoint.set_defaults(handler=_run_endpoint_recon_offline)

    endpoint_status = actions.add_parser("endpoint-recon-status")
    endpoint_status.add_argument("--endpoint-recon-plan-id", required=True)
    endpoint_status.add_argument("--endpoint-recon-db", default=".vulnloom/endpoint-recon.db")
    endpoint_status.set_defaults(handler=_endpoint_recon_status)

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
    prepare_surface.add_argument("--surface-db", default=".vulnloom/red-team-surface.db")
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

    prepare_drift = actions.add_parser("prepare-surface-drift")
    prepare_drift.add_argument("--baseline-reduction-id", required=True)
    prepare_drift.add_argument("--current-reduction-id", required=True)
    prepare_drift.add_argument("--scope-file", required=True)
    prepare_drift.add_argument("--ttl-seconds", type=int, default=300)
    prepare_drift.add_argument("--max-surfaces", type=int, default=10_000)
    prepare_drift.add_argument("--max-evidence-refs", type=int, default=60_000)
    prepare_drift.add_argument("--timeout-seconds", type=float, default=30.0)
    prepare_drift.add_argument("--idempotency-key", required=True)
    prepare_drift.add_argument("--surface-db", default=".vulnloom/red-team-surface.db")
    prepare_drift.add_argument("--drift-db", default=".vulnloom/red-team-drift.db")
    prepare_drift.add_argument("--evidence-root", default=".vulnloom/evidence")
    prepare_drift.set_defaults(handler=_prepare_drift)

    run_drift = actions.add_parser("run-surface-drift-offline")
    run_drift.add_argument("--comparison-file", required=True)
    run_drift.add_argument("--scope-file", required=True)
    run_drift.add_argument("--recover", action="store_true")
    run_drift.add_argument("--surface-db", default=".vulnloom/red-team-surface.db")
    run_drift.add_argument("--drift-db", default=".vulnloom/red-team-drift.db")
    run_drift.add_argument("--evidence-root", default=".vulnloom/evidence")
    run_drift.set_defaults(handler=_run_drift)

    drift_status = actions.add_parser("surface-drift-status")
    drift_status.add_argument("--comparison-id", required=True)
    drift_status.add_argument("--drift-db", default=".vulnloom/red-team-drift.db")
    drift_status.set_defaults(handler=_drift_status)

    for name in ("cancel", "kill", "expire"):
        command = actions.add_parser(name)
        command.add_argument("--plan-id", required=True)
        command.add_argument("--red-team-db", default=".vulnloom/red-team.db")
        if name != "expire":
            command.add_argument("--scope-file", required=True)
        command.set_defaults(handler=_transition)
