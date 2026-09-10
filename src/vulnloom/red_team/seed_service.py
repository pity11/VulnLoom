"""Trusted application service for exact, operator-sealed Endpoint Recon."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import ActionRequest, DecisionEffect, PolicyEngine

from .models import (
    ImpactClass,
    RedTeamCheckpoint,
    RedTeamFlowPlan,
    RedTeamFlowStatus,
    RedTeamPhase,
)
from .seed_models import (
    EndpointReconLimits,
    EndpointReconOutcome,
    EndpointReconOutcomeKind,
    EndpointReconPlan,
    EndpointReconStep,
    EndpointReconStepResult,
    EndpointSeed,
    EndpointSeedSet,
)
from .seed_store import EndpointReconStore, EndpointSeedIdempotencyConflict
from .store import RedTeamStore


class EndpointReconRejected(ValueError):
    pass


class EndpointReconTimedOut(TimeoutError):
    pass


class EndpointReconAdapterInterrupted(RuntimeError):
    pass


class EndpointReconAdapter(Protocol):
    """A future live adapter must enforce each step's exact URL digest allowlist."""

    def execute(
        self, step: EndpointReconStep, *, now: datetime, deadline: datetime
    ) -> EndpointReconStepResult: ...


@dataclass(frozen=True, slots=True)
class OfflineEndpointReconScenario:
    outcome: EndpointReconOutcomeKind = EndpointReconOutcomeKind.SUCCEEDED
    status_code: int | None = 204
    reason_code: str = "offline_endpoint_recon_succeeded"
    cleanup_complete: bool = True
    interrupt: bool = False


class OfflineEndpointReconAdapter:
    """Deterministic fake. It performs no DNS, socket, HTTP, or other network work."""

    def __init__(self, scenario: OfflineEndpointReconScenario | None = None):
        self.scenario = scenario or OfflineEndpointReconScenario()
        self.calls = 0

    def execute(self, step, *, now, deadline):
        del deadline
        self.calls += 1
        if self.scenario.interrupt:
            raise EndpointReconAdapterInterrupted("Offline Endpoint Recon interrupted")
        succeeded = self.scenario.outcome is EndpointReconOutcomeKind.SUCCEEDED
        return EndpointReconStepResult(
            step_id=step.step_id,
            target_url_digest=step.target_url_digest,
            outcome=self.scenario.outcome,
            status_code=self.scenario.status_code if succeeded else None,
            reason_code=self.scenario.reason_code,
            cleanup_complete=self.scenario.cleanup_complete,
            completed_at=now,
        )


class EndpointReconService:
    def __init__(
        self,
        *,
        red_team_store: RedTeamStore,
        recon_store: EndpointReconStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.red_team_store = red_team_store
        self.recon_store = recon_store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def seal_seed_set(
        self,
        *,
        flow_plan: RedTeamFlowPlan,
        checkpoint: RedTeamCheckpoint,
        scope: Scope,
        operator_ref: str,
        paths: tuple[str, ...],
        now: datetime,
        expires_at: datetime,
        idempotency_key: str,
    ) -> EndpointSeedSet:
        self._running(flow_plan, checkpoint, scope, now)
        if len(paths) != len(set(paths)):
            raise EndpointReconRejected("Endpoint Seed Set contains duplicate paths")
        seeds = tuple(
            sorted(
                (EndpointSeed.create(path=path) for path in paths),
                key=lambda item: item.path,
            )
        )
        if expires_at > min(flow_plan.deadline, scope.valid_until):
            raise EndpointReconRejected("Endpoint Seed Set exceeds its authorization lifetime")
        for seed in seeds:
            self._authorize_exact(flow_plan, scope, seed.path, now)
        seed_set = EndpointSeedSet.create(
            flow_plan_id=flow_plan.plan_id,
            source_checkpoint_id=checkpoint.checkpoint_id,
            target_id=flow_plan.target.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            operator_ref=operator_ref,
            seeds=seeds,
            sealed_at=now,
            expires_at=expires_at,
            idempotency_key=idempotency_key,
        )
        try:
            return self.recon_store.seal(seed_set)
        except EndpointSeedIdempotencyConflict as exc:
            raise EndpointReconRejected(str(exc)) from exc

    def prepare(
        self,
        *,
        seed_set_id: str,
        scope: Scope,
        test_class: str,
        limits: EndpointReconLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> EndpointReconPlan:
        seed_set = self.recon_store.seed_set(seed_set_id)
        flow = self.red_team_store.plan(seed_set.flow_plan_id)
        checkpoint = self.red_team_store.latest(flow.plan_id)
        self._seed_binding(seed_set, flow, checkpoint, scope, now)
        if test_class not in flow.rules.allowed_test_classes:
            raise EndpointReconRejected("Endpoint Recon test class is not authorized")
        remaining = flow.rules.stop_conditions.max_actions - checkpoint.actions_used
        if len(seed_set.seeds) > min(limits.max_steps, limits.max_requests, remaining):
            raise EndpointReconRejected("Endpoint Recon exceeds the remaining action budget")
        stop_at = min(
            deadline,
            now + timedelta(seconds=limits.total_seconds),
            seed_set.expires_at,
            flow.deadline,
            scope.valid_until,
        )
        if stop_at <= now:
            raise EndpointReconRejected("Endpoint Recon deadline is exhausted")
        steps = tuple(
            EndpointReconStep.create(
                seed_id=seed.seed_id,
                ordinal=ordinal,
                target_url=self._authorize_exact(
                    flow, scope, seed.path, now, test_class=test_class
                ),
            )
            for ordinal, seed in enumerate(seed_set.seeds, 1)
        )
        plan = EndpointReconPlan.create(
            seed_set_id=seed_set.seed_set_id,
            flow_plan_id=flow.plan_id,
            source_checkpoint_id=checkpoint.checkpoint_id,
            target_id=flow.target.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            test_class=test_class,
            steps=steps,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )
        try:
            return self.recon_store.reserve(plan, remaining_actions=remaining)
        except EndpointSeedIdempotencyConflict as exc:
            raise EndpointReconRejected(str(exc)) from exc

    def execute(
        self,
        plan: EndpointReconPlan,
        *,
        scope: Scope,
        adapter: EndpointReconAdapter,
        now: datetime,
    ) -> EndpointReconOutcome:
        claim = self._claim(plan, scope, now, recover=False)
        if claim.outcome is not None:
            return claim.outcome
        return self._run(plan, scope, adapter, now, claim.attempt)

    def recover(
        self,
        plan: EndpointReconPlan,
        *,
        scope: Scope,
        adapter: EndpointReconAdapter,
        now: datetime,
    ) -> EndpointReconOutcome:
        claim = self._claim(plan, scope, now, recover=True)
        return self._run(plan, scope, adapter, now, claim.attempt)

    def _claim(self, plan, scope, now, *, recover):
        self._plan_binding(plan, scope, now)
        return (
            self.recon_store.recover(plan, now=now)
            if recover
            else self.recon_store.claim(plan, now=now)
        )

    def _run(self, plan, scope, adapter, now, attempt):
        results: list[EndpointReconStepResult] = []
        started = self.monotonic()
        for step in plan.steps:
            if (
                len(results) >= plan.limits.max_requests
                or now >= plan.deadline
                or self.monotonic() - started >= plan.limits.total_seconds
            ):
                raise EndpointReconTimedOut("Endpoint Recon budget expired before dispatch")
            request_started = self.monotonic()
            try:
                result = adapter.execute(
                    step,
                    now=now,
                    deadline=min(
                        plan.deadline,
                        now + timedelta(seconds=plan.limits.per_request_seconds),
                    ),
                )
            except EndpointReconAdapterInterrupted:
                if attempt < plan.limits.max_attempts:
                    raise
                result = EndpointReconStepResult(
                    step_id=step.step_id,
                    target_url_digest=step.target_url_digest,
                    outcome=EndpointReconOutcomeKind.FAILED,
                    reason_code="adapter_attempts_exhausted",
                    cleanup_complete=False,
                    completed_at=now,
                )
            if self.monotonic() - request_started >= plan.limits.per_request_seconds:
                result = EndpointReconStepResult(
                    step_id=step.step_id,
                    target_url_digest=step.target_url_digest,
                    outcome=EndpointReconOutcomeKind.TIMED_OUT,
                    reason_code="per_request_deadline_exceeded",
                    cleanup_complete=result.cleanup_complete,
                    completed_at=result.completed_at,
                )
            if (
                result.step_id != step.step_id
                or result.target_url_digest != step.target_url_digest
                or not plan.created_at <= result.completed_at < plan.deadline
                or any(not self.evidence_store.contains(ref) for ref in result.evidence_refs)
            ):
                raise EndpointReconRejected("Endpoint Recon result provenance is invalid")
            results.append(result)
            if result.outcome is not EndpointReconOutcomeKind.SUCCEEDED:
                break
        outcome = EndpointReconOutcome(
            endpoint_recon_plan_id=plan.endpoint_recon_plan_id,
            seed_set_id=plan.seed_set_id,
            outcome=results[-1].outcome,
            results=tuple(results),
            requests_used=len(results),
            attempt=attempt,
            cleanup_complete=all(item.cleanup_complete for item in results),
            completed_at=results[-1].completed_at,
        )
        self._plan_binding(plan, scope, outcome.completed_at)
        self.recon_store.complete(outcome)
        return outcome

    def _plan_binding(self, plan: EndpointReconPlan, scope: Scope, now: datetime) -> None:
        seed_set = self.recon_store.seed_set(plan.seed_set_id)
        flow = self.red_team_store.plan(plan.flow_plan_id)
        checkpoint = self.red_team_store.latest(flow.plan_id)
        self._seed_binding(seed_set, flow, checkpoint, scope, now)
        expected = tuple(seed.seed_id for seed in seed_set.seeds)
        if (
            plan.source_checkpoint_id != checkpoint.checkpoint_id
            or plan.target_id != flow.target.target_id
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.test_class not in flow.rules.allowed_test_classes
            or tuple(step.seed_id for step in plan.steps) != expected
            or plan.deadline > min(seed_set.expires_at, flow.deadline, scope.valid_until)
            or not plan.created_at <= now < plan.deadline
        ):
            raise EndpointReconRejected("Endpoint Recon plan binding is invalid")
        for seed, step in zip(seed_set.seeds, plan.steps, strict=True):
            if step.target_url != self._authorize_exact(
                flow, scope, seed.path, now, test_class=plan.test_class
            ):
                raise EndpointReconRejected("Endpoint Recon exact target binding is invalid")

    def _seed_binding(self, seed_set, flow, checkpoint, scope, now):
        self._running(flow, checkpoint, scope, now)
        if (
            seed_set.flow_plan_id != flow.plan_id
            or seed_set.source_checkpoint_id != checkpoint.checkpoint_id
            or seed_set.target_id != flow.target.target_id
            or seed_set.scope_id != scope.scope_id
            or seed_set.scope_version != scope.version
            or now >= seed_set.expires_at
        ):
            raise EndpointReconRejected("Endpoint Seed Set binding is stale")

    def _running(self, flow, checkpoint, scope, now):
        expected_prohibited = {item for item in ImpactClass if item is not ImpactClass.READ_ONLY}
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise EndpointReconRejected("Endpoint Recon requires a current approved Scope")
        if (
            self.red_team_store.plan(flow.plan_id) != flow
            or self.red_team_store.latest(flow.plan_id) != checkpoint
            or checkpoint.status is not RedTeamFlowStatus.RUNNING
            or flow.rules.scope_id != scope.scope_id
            or flow.rules.scope_version != scope.version
            or flow.deadline > scope.valid_until
            or flow.rules.stop_conditions.stop_at > scope.valid_until
            or flow.rules.phases != (RedTeamPhase.RECON,)
            or flow.rules.allowed_impacts != (ImpactClass.READ_ONLY,)
            or flow.rules.approval_required_impacts
            or set(flow.rules.prohibited_impacts) != expected_prohibited
            or not set(flow.rules.allowed_test_classes) <= set(scope.allowed_test_classes)
            or now >= flow.deadline
        ):
            raise EndpointReconRejected("Endpoint Recon requires the current running Flow")

    @staticmethod
    def _authorize_exact(flow, scope, path, now, *, test_class=None) -> str:
        base = urlsplit(flow.target.url)
        base_path = base.path.rstrip("/")
        if base_path and path != base_path and not path.startswith(f"{base_path}/"):
            raise EndpointReconRejected("Endpoint seed escapes the Flow target base path")
        url = urlunsplit((base.scheme, base.netloc, path, "", ""))
        decision = PolicyEngine(scope).decide(
            ActionRequest(
                engagement_id=scope.engagement_id,
                target_id=flow.target.target_id,
                action="red_team.recon.http_head",
                requested_at=now,
                url=url,
                test_class=test_class or flow.rules.allowed_test_classes[0],
            )
        )
        if decision.effect is not DecisionEffect.ALLOW:
            raise EndpointReconRejected("Endpoint seed is outside approved Scope")
        return url
