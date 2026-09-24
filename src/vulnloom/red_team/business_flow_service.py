"""Materialize an invariant observation only after compensated local state change."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope

from .business_flow_models import (
    BusinessInvariantLimits,
    BusinessInvariantOutcome,
    BusinessInvariantPlan,
    LocalBusinessFlowExecution,
    OfflinePublicationFixture,
)
from .business_flow_store import BusinessInvariantStore
from .credential_session_models import CredentialSessionPlan
from .credential_session_store import CredentialSessionStore
from .models import AuthorizedWebTarget
from .test_identity_models import TestIdentityPurpose
from .test_identity_service import TestIdentityAdmissionService


class LocalBusinessFlowExecutionSource(Protocol):
    def result(self, session_plan_id: str) -> LocalBusinessFlowExecution: ...


class BusinessInvariantRejected(ValueError):
    pass


class BusinessInvariantTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise BusinessInvariantTimedOut("Business Invariant materialization timed out")


class BusinessInvariantService:
    def __init__(
        self,
        *,
        identity_service: TestIdentityAdmissionService,
        session_store: CredentialSessionStore,
        execution_source: LocalBusinessFlowExecutionSource,
        store: BusinessInvariantStore,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.identity_service = identity_service
        self.session_store = session_store
        self.execution_source = execution_source
        self.store = store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        session_plan: CredentialSessionPlan,
        fixture: OfflinePublicationFixture,
        scope: Scope,
        target: AuthorizedWebTarget,
        limits: BusinessInvariantLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> BusinessInvariantPlan:
        self._session_plan(session_plan, scope=scope, target=target, now=now)
        stop_at = min(deadline, session_plan.deadline, scope.valid_until)
        if not now < stop_at:
            raise BusinessInvariantRejected("Business Invariant deadline is invalid")
        try:
            return BusinessInvariantPlan.create(
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_id=target.target_id,
                target_digest=canonical_digest(target.model_dump(mode="python")),
                session_plan_id=session_plan.plan_id,
                fixture_id=fixture.fixture_id,
                resource_ref=fixture.resource_ref,
                actor_identity_ref=session_plan.identity_ref,
                actor_role_ref=session_plan.role_ref,
                action_intent_digest=session_plan.action_intent_digest,
                limits=limits,
                created_at=now,
                deadline=stop_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise BusinessInvariantRejected("Business Invariant Plan could not be sealed") from exc

    def execute(
        self,
        plan: BusinessInvariantPlan,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        now: datetime,
    ) -> BusinessInvariantOutcome:
        authoritative = BusinessInvariantPlan.model_validate(plan.model_dump(mode="python"))
        bound = self._binding(authoritative, scope=scope, target=target, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            if claim.outcome.plan_id != authoritative.plan_id:
                raise BusinessInvariantRejected("completed Business Invariant binding drifted")
            return claim.outcome
        return self._complete(
            authoritative,
            bound=bound,
            scope=scope,
            target=target,
            now=now,
            attempt=claim.attempt,
        )

    def recover(self, plan, *, scope, target, now):
        authoritative = BusinessInvariantPlan.model_validate(plan.model_dump(mode="python"))
        bound = self._binding(authoritative, scope=scope, target=target, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            bound=bound,
            scope=scope,
            target=target,
            now=now,
            attempt=claim.attempt,
        )

    def _complete(self, plan, *, bound, scope, target, now, attempt):
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        _, session_outcome, execution = bound
        outcome = BusinessInvariantOutcome.create(
            plan_id=plan.plan_id,
            session_outcome_id=session_outcome.outcome_id,
            execution=execution,
            attempt=attempt,
            completed_at=now,
        )
        deadline.check()
        self._binding(plan, scope=scope, target=target, now=now)
        self.store.complete(plan, outcome)
        return outcome

    def _binding(self, plan, *, scope, target, now):
        if not plan.created_at <= now < plan.deadline:
            raise BusinessInvariantRejected("Business Invariant Plan is not active")
        try:
            session_plan = self.session_store.plan(plan.session_plan_id)
            session_outcome = self.session_store.outcome(plan.session_plan_id)
            execution = self.execution_source.result(plan.session_plan_id)
        except (ValueError, RuntimeError) as exc:
            raise BusinessInvariantRejected(
                "completed compensated state-change Session is unavailable"
            ) from exc
        self._session_plan(session_plan, scope=scope, target=target, now=now)
        observation = execution.observation
        if (
            plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.target_id != target.target_id
            or plan.target_digest != canonical_digest(target.model_dump(mode="python"))
            or plan.fixture_id != observation.fixture_id
            or plan.resource_ref != observation.resource_ref
            or plan.actor_identity_ref != session_plan.identity_ref
            or plan.actor_role_ref != session_plan.role_ref
            or plan.action_intent_digest != session_plan.action_intent_digest
            or observation.session_plan_id != session_plan.plan_id
            or observation.actor_identity_ref != session_plan.identity_ref
            or observation.actor_role_ref != session_plan.role_ref
            or observation.action_intent_digest != session_plan.action_intent_digest
            or session_outcome.plan_id != session_plan.plan_id
            or not session_outcome.cleanup_complete
            or not session_outcome.lease.zeroed
            or not session_outcome.session.zeroed
            or session_outcome.session.network_performed
            or not session_outcome.session.authentication_performed
            or not session_outcome.session.state_changed
            or not session_outcome.session.state_restored
            or not execution.cleanup_complete
            or not execution.restoration.restoration_verified
        ):
            raise BusinessInvariantRejected("Business Invariant binding drifted")
        return session_plan, session_outcome, execution

    def _session_plan(self, plan, *, scope, target, now):
        try:
            admission = self.identity_service.active_admission(
                plan.admission_plan_id, scope=scope, target=target, now=now
            )
        except (ValueError, RuntimeError) as exc:
            raise BusinessInvariantRejected("active Test Identity is unavailable") from exc
        if (
            plan.purpose is not TestIdentityPurpose.STATE_CHANGE_VALIDATION
            or not plan.mutates_state
            or plan.admission_id != admission.admission_id
            or plan.identity_ref != admission.identity_ref
            or plan.role_ref not in admission.role_refs
            or plan.engagement_id != scope.engagement_id
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.target_id != target.target_id
            or plan.target_digest != canonical_digest(target.model_dump(mode="python"))
        ):
            raise BusinessInvariantRejected("state-change Session Plan binding drifted")
