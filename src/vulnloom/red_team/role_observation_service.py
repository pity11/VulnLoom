"""Materialize a role differential from two cleaned local auth Sessions."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope

from .credential_session_store import CredentialSessionStore
from .models import AuthorizedWebTarget
from .role_observation_models import (
    LocalAuthenticationExecution,
    RoleDifferentialLimits,
    RoleDifferentialObservation,
    RoleDifferentialOutcome,
    RoleDifferentialPlan,
    RoleDifferentialVerdict,
)
from .role_observation_store import RoleDifferentialStore
from .test_identity_models import TestIdentityPurpose
from .test_identity_service import TestIdentityAdmissionService


class LocalAuthenticationExecutionSource(Protocol):
    def result(self, session_plan_id: str) -> LocalAuthenticationExecution: ...


class RoleDifferentialRejected(ValueError):
    pass


class RoleDifferentialTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise RoleDifferentialTimedOut("Role Differential timed out")


class RoleDifferentialService:
    def __init__(
        self,
        *,
        identity_service: TestIdentityAdmissionService,
        session_store: CredentialSessionStore,
        execution_source: LocalAuthenticationExecutionSource,
        store: RoleDifferentialStore,
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
        baseline_session_plan_id: str,
        comparison_session_plan_id: str,
        scope: Scope,
        target: AuthorizedWebTarget,
        limits: RoleDifferentialLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> RoleDifferentialPlan:
        baseline = self._session(baseline_session_plan_id, scope=scope, target=target, now=now)
        comparison = self._session(comparison_session_plan_id, scope=scope, target=target, now=now)
        self._pair(baseline, comparison)
        stop_at = min(deadline, scope.valid_until)
        if not now < stop_at:
            raise RoleDifferentialRejected("Role Differential deadline is invalid")
        baseline_plan, baseline_outcome, baseline_execution = baseline
        comparison_plan, comparison_outcome, comparison_execution = comparison
        try:
            return RoleDifferentialPlan.create(
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_id=target.target_id,
                target_digest=canonical_digest(target.model_dump(mode="python")),
                fixture_id=baseline_execution.observation.fixture_id,
                action_intent_digest=baseline_plan.action_intent_digest,
                baseline_session_plan_id=baseline_plan.plan_id,
                baseline_session_outcome_id=baseline_outcome.outcome_id,
                baseline_execution_id=baseline_execution.execution_id,
                baseline_identity_ref=baseline_plan.identity_ref,
                baseline_role_ref=baseline_plan.role_ref,
                comparison_session_plan_id=comparison_plan.plan_id,
                comparison_session_outcome_id=comparison_outcome.outcome_id,
                comparison_execution_id=comparison_execution.execution_id,
                comparison_identity_ref=comparison_plan.identity_ref,
                comparison_role_ref=comparison_plan.role_ref,
                limits=limits,
                created_at=now,
                deadline=stop_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise RoleDifferentialRejected("Role Differential Plan could not be sealed") from exc

    def execute(
        self,
        plan: RoleDifferentialPlan,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        now: datetime,
    ) -> RoleDifferentialOutcome:
        authoritative = RoleDifferentialPlan.model_validate(plan.model_dump(mode="python"))
        pair = self._binding(authoritative, scope=scope, target=target, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            if claim.outcome.plan_id != authoritative.plan_id:
                raise RoleDifferentialRejected("completed Role Differential binding drifted")
            return claim.outcome
        return self._complete(
            authoritative,
            pair=pair,
            scope=scope,
            target=target,
            now=now,
            attempt=claim.attempt,
        )

    def recover(
        self,
        plan: RoleDifferentialPlan,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        now: datetime,
    ) -> RoleDifferentialOutcome:
        authoritative = RoleDifferentialPlan.model_validate(plan.model_dump(mode="python"))
        pair = self._binding(authoritative, scope=scope, target=target, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            pair=pair,
            scope=scope,
            target=target,
            now=now,
            attempt=claim.attempt,
        )

    def _complete(self, plan, *, pair, scope, target, now, attempt):
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        baseline = pair[0][2]
        comparison = pair[1][2]
        verdict = (
            RoleDifferentialVerdict.SAME
            if baseline.observation.access_decision is comparison.observation.access_decision
            else RoleDifferentialVerdict.DIFFERENT
        )
        observation = RoleDifferentialObservation.create(
            plan_id=plan.plan_id,
            action_intent_digest=plan.action_intent_digest,
            baseline_authentication_observation_id=baseline.observation.observation_id,
            baseline_role_ref=baseline.observation.role_ref,
            baseline_decision=baseline.observation.access_decision,
            comparison_authentication_observation_id=(comparison.observation.observation_id),
            comparison_role_ref=comparison.observation.role_ref,
            comparison_decision=comparison.observation.access_decision,
            verdict=verdict,
            observed_at=now,
        )
        outcome = RoleDifferentialOutcome.create(
            plan_id=plan.plan_id,
            observation=observation,
            baseline_logout_proof_id=baseline.logout.proof_id,
            comparison_logout_proof_id=comparison.logout.proof_id,
            attempt=attempt,
            completed_at=now,
        )
        deadline.check()
        self._binding(plan, scope=scope, target=target, now=now)
        self.store.complete(plan, outcome)
        return outcome

    def _binding(self, plan, *, scope, target, now):
        if not plan.created_at <= now < plan.deadline:
            raise RoleDifferentialRejected("Role Differential Plan is not active")
        baseline = self._session(plan.baseline_session_plan_id, scope=scope, target=target, now=now)
        comparison = self._session(
            plan.comparison_session_plan_id, scope=scope, target=target, now=now
        )
        self._pair(baseline, comparison)
        baseline_plan, baseline_outcome, baseline_execution = baseline
        comparison_plan, comparison_outcome, comparison_execution = comparison
        if (
            plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.target_id != target.target_id
            or plan.target_digest != canonical_digest(target.model_dump(mode="python"))
            or plan.fixture_id != baseline_execution.observation.fixture_id
            or plan.action_intent_digest != baseline_plan.action_intent_digest
            or plan.baseline_session_outcome_id != baseline_outcome.outcome_id
            or plan.baseline_execution_id != baseline_execution.execution_id
            or plan.baseline_identity_ref != baseline_plan.identity_ref
            or plan.baseline_role_ref != baseline_plan.role_ref
            or plan.comparison_session_outcome_id != comparison_outcome.outcome_id
            or plan.comparison_execution_id != comparison_execution.execution_id
            or plan.comparison_identity_ref != comparison_plan.identity_ref
            or plan.comparison_role_ref != comparison_plan.role_ref
        ):
            raise RoleDifferentialRejected("Role Differential binding drifted")
        return baseline, comparison

    def _session(self, plan_id, *, scope, target, now):
        try:
            plan = self.session_store.plan(plan_id)
            outcome = self.session_store.outcome(plan_id)
            execution = self.execution_source.result(plan_id)
            admission = self.identity_service.active_admission(
                plan.admission_plan_id, scope=scope, target=target, now=now
            )
        except (ValueError, RuntimeError) as exc:
            raise RoleDifferentialRejected(
                "completed local authentication Session is unavailable"
            ) from exc
        if (
            plan.purpose is not TestIdentityPurpose.READ_ONLY_ROLE_OBSERVATION
            or plan.mutates_state
            or plan.admission_id != admission.admission_id
            or plan.identity_ref != admission.identity_ref
            or plan.role_ref not in admission.role_refs
            or outcome.plan_id != plan.plan_id
            or not outcome.cleanup_complete
            or not outcome.lease.zeroed
            or not outcome.session.zeroed
            or outcome.session.network_performed
            or not outcome.session.authentication_performed
            or outcome.session.state_changed
            or execution.observation.session_plan_id != plan.plan_id
            or execution.observation.identity_ref != plan.identity_ref
            or execution.observation.role_ref != plan.role_ref
            or execution.observation.action_intent_digest != plan.action_intent_digest
            or execution.logout.session_plan_id != plan.plan_id
            or not execution.cleanup_complete
        ):
            raise RoleDifferentialRejected("local authentication Session binding drifted")
        return plan, outcome, execution

    @staticmethod
    def _pair(baseline, comparison):
        baseline_plan, _, baseline_execution = baseline
        comparison_plan, _, comparison_execution = comparison
        if (
            baseline_plan.plan_id == comparison_plan.plan_id
            or baseline_plan.identity_ref == comparison_plan.identity_ref
            or baseline_plan.role_ref == comparison_plan.role_ref
            or baseline_plan.action_intent_digest != comparison_plan.action_intent_digest
            or baseline_execution.observation.fixture_id
            != comparison_execution.observation.fixture_id
        ):
            raise RoleDifferentialRejected(
                "Role Differential requires two distinct roles on one exact fixture action"
            )
