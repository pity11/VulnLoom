"""Trusted review gate from OpenAPI discoveries to sealed Endpoint Seeds."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import datetime

from vulnloom.domain.models import Scope, ScopeState

from .openapi_models import OpenApiHttpMethod
from .openapi_promotion_models import (
    OpenApiDiscoveryPromotionLimits,
    OpenApiDiscoveryPromotionOutcome,
    OpenApiDiscoveryPromotionPlan,
    OpenApiDiscoverySelection,
)
from .openapi_promotion_store import OpenApiDiscoveryPromotionStore
from .openapi_store import OpenApiObservationStore
from .seed_models import EndpointSeedSet
from .seed_service import EndpointReconRejected, EndpointReconService
from .store import RedTeamStore


class OpenApiDiscoveryPromotionRejected(ValueError):
    pass


class OpenApiDiscoveryPromotionTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise OpenApiDiscoveryPromotionTimedOut(
                "OpenAPI discovery promotion timed out"
            )


class OpenApiDiscoveryPromotionService:
    _PARAMETER = re.compile(r"^\{[A-Za-z0-9._-]{1,128}\}$")
    _READ_ONLY_METHODS = frozenset({OpenApiHttpMethod.GET, OpenApiHttpMethod.HEAD})

    def __init__(
        self,
        *,
        red_team_store: RedTeamStore,
        endpoint_recon_service: EndpointReconService,
        observation_store: OpenApiObservationStore,
        promotion_store: OpenApiDiscoveryPromotionStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.red_team_store = red_team_store
        self.endpoint_recon_service = endpoint_recon_service
        self.observation_store = observation_store
        self.promotion_store = promotion_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        openapi_observation_plan_id: str,
        scope: Scope,
        operator_ref: str,
        selections: tuple[tuple[str, str], ...],
        limits: OpenApiDiscoveryPromotionLimits,
        now: datetime,
        deadline: datetime,
        seed_set_expires_at: datetime,
        idempotency_key: str,
    ) -> OpenApiDiscoveryPromotionPlan:
        source = self._source(
            openapi_observation_plan_id, scope=scope, now=now
        )
        selected = self._validate_selections(selections, source["outcome"].observation)
        expires_at = min(
            seed_set_expires_at,
            scope.valid_until,
            source["flow"].deadline,
        )
        stop_at = min(deadline, expires_at)
        if stop_at <= now or expires_at <= now:
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion lifetime is exhausted"
            )
        try:
            return OpenApiDiscoveryPromotionPlan.create(
                openapi_observation_plan_id=openapi_observation_plan_id,
                openapi_observation_id=source["outcome"].observation.observation_id,
                flow_plan_id=source["flow"].plan_id,
                source_checkpoint_id=source["checkpoint"].checkpoint_id,
                target_id=source["flow"].target.target_id,
                scope_id=scope.scope_id,
                scope_version=scope.version,
                operator_ref=operator_ref,
                selections=selected,
                limits=limits,
                created_at=now,
                deadline=stop_at,
                seed_set_expires_at=expires_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion plan could not be sealed"
            ) from exc

    def execute(
        self,
        plan: OpenApiDiscoveryPromotionPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> OpenApiDiscoveryPromotionOutcome:
        authoritative = OpenApiDiscoveryPromotionPlan.model_validate(
            plan.model_dump(mode="python")
        )
        source, seed_set = self._execution_inputs(
            authoritative, scope=scope, now=now
        )
        del source
        deadline = _Deadline(authoritative.limits.timeout_seconds, self.monotonic)
        deadline.check()
        claim = self.promotion_store.claim(authoritative, now=now)
        if not claim.created:
            self._completed_binding(authoritative, claim.outcome, seed_set)
            assert claim.outcome is not None
            return claim.outcome
        deadline.check()
        return self._complete(
            authoritative,
            seed_set,
            attempt=claim.attempt,
            scope=scope,
            now=now,
            deadline=deadline,
        )

    def recover(
        self,
        plan: OpenApiDiscoveryPromotionPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> OpenApiDiscoveryPromotionOutcome:
        authoritative = OpenApiDiscoveryPromotionPlan.model_validate(
            plan.model_dump(mode="python")
        )
        _, seed_set = self._execution_inputs(authoritative, scope=scope, now=now)
        deadline = _Deadline(authoritative.limits.timeout_seconds, self.monotonic)
        deadline.check()
        claim = self.promotion_store.recover(authoritative, now=now)
        deadline.check()
        return self._complete(
            authoritative,
            seed_set,
            attempt=claim.attempt,
            scope=scope,
            now=now,
            deadline=deadline,
        )

    def _complete(self, plan, seed_set, *, attempt, scope, now, deadline):
        source, expected_seed_set = self._execution_inputs(plan, scope=scope, now=now)
        del source
        if expected_seed_set != seed_set:
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion Seed Set drifted"
            )
        deadline.check()
        outcome = OpenApiDiscoveryPromotionOutcome.create(
            promotion_plan_id=plan.promotion_plan_id,
            openapi_observation_id=plan.openapi_observation_id,
            seed_set_id=seed_set.seed_set_id,
            selection_ids=tuple(item.selection_id for item in plan.selections),
            attempt=attempt,
            completed_at=now,
        )
        self.promotion_store.complete(plan, outcome, seed_set)
        return outcome

    def _execution_inputs(self, plan, *, scope, now):
        if not plan.created_at <= now < plan.deadline:
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion plan is not active"
            )
        source = self._source(
            plan.openapi_observation_plan_id, scope=scope, now=now
        )
        self._plan_binding(plan, source, scope)
        selected = self._validate_selections(
            tuple(
                (item.discovery_id, item.concrete_path)
                for item in plan.selections
            ),
            source["outcome"].observation,
        )
        if selected != plan.selections:
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion selections drifted"
            )
        try:
            seed_set = self.endpoint_recon_service.build_seed_set(
                flow_plan=source["flow"],
                checkpoint=source["checkpoint"],
                scope=scope,
                operator_ref=plan.operator_ref,
                paths=tuple(item.concrete_path for item in plan.selections),
                now=plan.created_at,
                expires_at=plan.seed_set_expires_at,
                idempotency_key=f"openapi-promotion:{plan.promotion_plan_id}",
            )
        except EndpointReconRejected as exc:
            raise OpenApiDiscoveryPromotionRejected(str(exc)) from exc
        return source, seed_set

    def _source(self, observation_plan_id, *, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion requires a current approved Scope"
            )
        observation_plan = self.observation_store.plan(observation_plan_id)
        outcome = self.observation_store.outcome(observation_plan_id)
        flow = self.red_team_store.plan(observation_plan.flow_plan_id)
        checkpoint = self.red_team_store.latest(flow.plan_id)
        if (
            outcome.plan_id != observation_plan.plan_id
            or not outcome.cleanup_complete
            or outcome.observation.plan_id != observation_plan.plan_id
            or outcome.observation.endpoint_recon_plan_id
            != observation_plan.endpoint_recon_plan_id
            or outcome.observation.source_observation_id
            != observation_plan.source_observation_id
            or outcome.observation.web_response_snapshot_id
            != observation_plan.web_response_snapshot_id
            or outcome.observation.evidence_ref != observation_plan.evidence_ref
            or outcome.observation.document_body_sha256
            != observation_plan.document_body_sha256
            or observation_plan.target_id != flow.target.target_id
            or observation_plan.scope_id != scope.scope_id
            or observation_plan.scope_version != scope.version
            or flow.rules.scope_id != scope.scope_id
            or flow.rules.scope_version != scope.version
            or flow.deadline > scope.valid_until
        ):
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion source provenance is invalid"
            )
        return {
            "observation_plan": observation_plan,
            "outcome": outcome,
            "flow": flow,
            "checkpoint": checkpoint,
        }

    @staticmethod
    def _plan_binding(plan, source, scope):
        if (
            source["outcome"].observation.observation_id
            != plan.openapi_observation_id
            or source["flow"].plan_id != plan.flow_plan_id
            or source["checkpoint"].checkpoint_id != plan.source_checkpoint_id
            or source["flow"].target.target_id != plan.target_id
            or scope.scope_id != plan.scope_id
            or scope.version != plan.scope_version
            or plan.seed_set_expires_at
            > min(scope.valid_until, source["flow"].deadline)
        ):
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion binding drifted"
            )

    def _validate_selections(self, selections, observation):
        discoveries = {item.discovery_id: item for item in observation.paths}
        result = []
        for discovery_id, concrete_path in selections:
            discovery = discoveries.get(discovery_id)
            if discovery is None:
                raise OpenApiDiscoveryPromotionRejected(
                    "OpenAPI discovery selection is not authoritative"
                )
            if not self._READ_ONLY_METHODS.intersection(discovery.methods):
                raise OpenApiDiscoveryPromotionRejected(
                    "OpenAPI discovery has no read-only method"
                )
            if not self._matches_template(discovery.path_template, concrete_path):
                raise OpenApiDiscoveryPromotionRejected(
                    "OpenAPI discovery concrete path does not match its template"
                )
            try:
                result.append(
                    OpenApiDiscoverySelection.create(
                        discovery_id=discovery_id,
                        concrete_path=concrete_path,
                    )
                )
            except ValueError as exc:
                raise OpenApiDiscoveryPromotionRejected(
                    "OpenAPI discovery concrete path is not canonical"
                ) from exc
        ordered = tuple(sorted(result, key=lambda item: item.selection_id))
        if not ordered:
            raise OpenApiDiscoveryPromotionRejected(
                "OpenAPI discovery promotion requires an explicit selection"
            )
        return ordered

    @classmethod
    def _matches_template(cls, template: str, concrete: str) -> bool:
        template_segments = template.split("/")
        concrete_segments = concrete.split("/")
        if len(template_segments) != len(concrete_segments):
            return False
        for expected, actual in zip(template_segments, concrete_segments, strict=True):
            if cls._PARAMETER.fullmatch(expected):
                if not actual or "{" in actual or "}" in actual:
                    return False
            elif expected != actual:
                return False
        return True

    def _completed_binding(self, plan, outcome, expected_seed_set: EndpointSeedSet):
        if (
            outcome is None
            or outcome.promotion_plan_id != plan.promotion_plan_id
            or outcome.openapi_observation_id != plan.openapi_observation_id
            or outcome.seed_set_id != expected_seed_set.seed_set_id
            or outcome.selection_ids
            != tuple(item.selection_id for item in plan.selections)
            or self.endpoint_recon_service.recon_store.seed_set(
                outcome.seed_set_id
            )
            != expected_seed_set
        ):
            raise OpenApiDiscoveryPromotionRejected(
                "completed OpenAPI discovery promotion drifted"
            )
