"""Trusted offline reducer from authoritative Recon observations to Attack Surface."""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .models import (
    AttackSurfaceSnapshot,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamCheckpoint,
    RedTeamFlowPlan,
    RedTeamReconObservation,
)
from .store import RedTeamStore
from .surface_models import (
    AttackSurfaceEndpoint,
    AttackSurfaceInventory,
    AttackSurfaceReductionLimits,
    AttackSurfaceReductionOutcome,
    AttackSurfaceReductionPlan,
)
from .surface_store import AttackSurfaceReductionStore


class AttackSurfaceReductionRejected(ValueError):
    pass


class AttackSurfaceReductionTimedOut(TimeoutError):
    pass


class _ReductionDeadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise AttackSurfaceReductionTimedOut("Attack Surface reduction timed out")


class AttackSurfaceReductionService:
    def __init__(
        self,
        *,
        red_team_store: RedTeamStore,
        reduction_store: AttackSurfaceReductionStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.red_team_store = red_team_store
        self.reduction_store = reduction_store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        flow_plan: RedTeamFlowPlan,
        checkpoint: RedTeamCheckpoint,
        scope: Scope,
        limits: AttackSurfaceReductionLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AttackSurfaceReductionPlan:
        self._flow_binding(flow_plan, checkpoint, scope, now)
        observations = tuple(
            self.red_team_store.observation(item) for item in checkpoint.observation_ids
        )
        admitted = tuple(item for item in observations if item.attack_surface is not None)
        if not admitted:
            raise AttackSurfaceReductionRejected(
                "Attack Surface reduction requires trusted live Recon observations"
            )
        if len(admitted) > limits.max_observations:
            raise AttackSurfaceReductionRejected("Attack Surface observation budget exceeded")
        stop_at = min(deadline, scope.valid_until)
        if stop_at <= now:
            raise AttackSurfaceReductionRejected("Attack Surface reduction deadline is invalid")
        return AttackSurfaceReductionPlan.create(
            flow_plan_id=flow_plan.plan_id,
            source_checkpoint_id=checkpoint.checkpoint_id,
            target_id=flow_plan.target.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            observation_ids=tuple(sorted(item.observation_id for item in admitted)),
            snapshot_ids=tuple(
                sorted(item.attack_surface.snapshot_id for item in admitted if item.attack_surface)
            ),
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        reduction: AttackSurfaceReductionPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> AttackSurfaceReductionOutcome:
        plan = AttackSurfaceReductionPlan.model_validate(
            reduction.model_dump(mode="python")
        )
        inventory = self._reduce(plan, scope=scope, now=now)
        claim = self.reduction_store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise AttackSurfaceReductionRejected(
                    "completed Attack Surface reduction has no outcome"
                )
            if claim.outcome.inventory != inventory:
                raise AttackSurfaceReductionRejected(
                    "completed Attack Surface reduction outcome drifted"
                )
            return claim.outcome
        return self._complete(plan, inventory, attempt=claim.attempt, scope=scope, now=now)

    def recover(
        self,
        reduction: AttackSurfaceReductionPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> AttackSurfaceReductionOutcome:
        plan = AttackSurfaceReductionPlan.model_validate(
            reduction.model_dump(mode="python")
        )
        inventory = self._reduce(plan, scope=scope, now=now)
        claim = self.reduction_store.recover(plan, now=now)
        return self._complete(plan, inventory, attempt=claim.attempt, scope=scope, now=now)

    def _complete(self, plan, inventory, *, attempt, scope, now):
        self._current_binding(plan, scope=scope, now=now)
        if not all(
            self.evidence_store.contains(item) for item in inventory.evidence_refs
        ):
            raise AttackSurfaceReductionRejected(
                "Attack Surface Evidence changed before completion"
            )
        outcome = AttackSurfaceReductionOutcome(
            reduction_id=plan.reduction_id,
            inventory=inventory,
            attempt=attempt,
            cleanup_complete=True,
        )
        self.reduction_store.complete(outcome, completed_at=now)
        return outcome

    def _reduce(self, plan, *, scope, now):
        self._current_binding(plan, scope=scope, now=now)
        deadline = _ReductionDeadline(plan.limits.timeout_seconds, self.monotonic)
        observations: list[RedTeamReconObservation] = []
        surfaces: list[AttackSurfaceSnapshot] = []
        evidence_refs: set[str] = set()
        for observation_id in plan.observation_ids:
            deadline.check()
            observation = self.red_team_store.observation(observation_id)
            action = self.red_team_store.action(observation.action_id)
            surface = observation.attack_surface
            if (
                surface is None
                or observation.outcome is not ReconOutcome.SUCCEEDED
                or not observation.cleanup_complete
                or not observation.sensitive_data_redacted
                or action.kind is not RedTeamActionKind.HTTP_HEAD
                or action.plan_id != plan.flow_plan_id
                or surface.plan_id != plan.flow_plan_id
                or surface.action_id != action.action_id
                or surface.target_id != plan.target_id
                or surface.scope_id != plan.scope_id
                or surface.scope_version != plan.scope_version
                or surface.requested_url_digest
                != hashlib.sha256(action.target_url.encode()).hexdigest()
                or surface.captured_at != observation.observed_at
            ):
                raise AttackSurfaceReductionRejected(
                    "Attack Surface observation provenance is invalid"
                )
            observations.append(observation)
            surfaces.append(surface)
            evidence_refs.update(surface.evidence_refs)
        if tuple(sorted(item.snapshot_id for item in surfaces)) != plan.snapshot_ids:
            raise AttackSurfaceReductionRejected("Attack Surface snapshot binding mismatch")
        if len(evidence_refs) > plan.limits.max_evidence_refs:
            raise AttackSurfaceReductionRejected("Attack Surface Evidence budget exceeded")
        if not all(self.evidence_store.contains(item) for item in evidence_refs):
            raise AttackSurfaceReductionRejected("Attack Surface Evidence integrity failed")
        grouped: dict[
            tuple[str, str, str],
            list[tuple[RedTeamReconObservation, AttackSurfaceSnapshot]],
        ]
        grouped = defaultdict(list)
        for observation, surface in zip(observations, surfaces, strict=True):
            grouped[
                (
                    surface.requested_url_digest,
                    surface.final_url_digest,
                    surface.peer_ip,
                )
            ].append((observation, surface))
        if len(grouped) > plan.limits.max_endpoints:
            raise AttackSurfaceReductionRejected("Attack Surface endpoint budget exceeded")
        endpoints = []
        for key, records in grouped.items():
            deadline.check()
            endpoints.append(
                AttackSurfaceEndpoint.create(
                    requested_url_digest=key[0],
                    final_url_digest=key[1],
                    peer_ip=key[2],
                    status_codes=tuple(sorted({surface.status_code for _, surface in records})),
                    redirect_counts=tuple(
                        sorted({surface.redirect_count for _, surface in records})
                    ),
                    observation_ids=tuple(
                        sorted(observation.observation_id for observation, _ in records)
                    ),
                    snapshot_ids=tuple(
                        sorted(surface.snapshot_id for _, surface in records)
                    ),
                    evidence_refs=tuple(
                        sorted(
                            {
                                item
                                for _, surface in records
                                for item in surface.evidence_refs
                            }
                        )
                    ),
                    first_observed_at=min(
                        observation.observed_at for observation, _ in records
                    ),
                    last_observed_at=max(
                        observation.observed_at for observation, _ in records
                    ),
                )
            )
        deadline.check()
        return AttackSurfaceInventory.create(
            reduction_id=plan.reduction_id,
            flow_plan_id=plan.flow_plan_id,
            source_checkpoint_id=plan.source_checkpoint_id,
            target_id=plan.target_id,
            scope_id=plan.scope_id,
            scope_version=plan.scope_version,
            observation_ids=plan.observation_ids,
            snapshot_ids=plan.snapshot_ids,
            evidence_refs=tuple(sorted(evidence_refs)),
            endpoints=tuple(sorted(endpoints, key=lambda item: item.endpoint_id)),
            reduced_at=plan.created_at,
        )

    def _current_binding(self, reduction, *, scope, now):
        if not reduction.created_at <= now < reduction.deadline:
            raise AttackSurfaceReductionRejected("Attack Surface reduction plan is not active")
        flow_plan = self.red_team_store.plan(reduction.flow_plan_id)
        checkpoint = self.red_team_store.latest(flow_plan.plan_id)
        self._flow_binding(flow_plan, checkpoint, scope, now)
        if (
            checkpoint.checkpoint_id != reduction.source_checkpoint_id
            or flow_plan.target.target_id != reduction.target_id
            or scope.scope_id != reduction.scope_id
            or scope.version != reduction.scope_version
        ):
            raise AttackSurfaceReductionRejected("Attack Surface reduction binding drifted")

    def _flow_binding(self, flow_plan, checkpoint, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or flow_plan != self.red_team_store.plan(flow_plan.plan_id)
            or checkpoint != self.red_team_store.latest(flow_plan.plan_id)
            or flow_plan.rules.scope_id != scope.scope_id
            or flow_plan.rules.scope_version != scope.version
            or flow_plan.rules.target_id != flow_plan.target.target_id
        ):
            raise AttackSurfaceReductionRejected(
                "Attack Surface reduction requires current Flow and approved Scope"
            )
