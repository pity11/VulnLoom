"""Approval-gated, offline credential lease and isolated Session lifecycle."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timedelta

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalRequest, Scope
from vulnloom.policy.engine import ActionRequest, DecisionEffect, PolicyEngine

from .credential_session_adapters import CredentialVault, IsolatedSessionAdapter
from .credential_session_models import (
    CredentialLeaseReceipt,
    CredentialSessionLimits,
    CredentialSessionOutcome,
    CredentialSessionPlan,
    IsolatedSessionReceipt,
    credential_authorization_context_digest,
)
from .credential_session_store import CredentialSessionStore
from .models import AuthorizedWebTarget
from .test_identity_models import TestIdentityPurpose
from .test_identity_service import TestIdentityAdmissionService


class CredentialSessionRejected(ValueError):
    pass


class CredentialSessionTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CredentialSessionTimedOut("Credential Session timed out")


class CredentialSessionService:
    def __init__(
        self,
        *,
        identity_service: TestIdentityAdmissionService,
        store: CredentialSessionStore,
        vault: CredentialVault,
        session_adapter: IsolatedSessionAdapter,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.identity_service = identity_service
        self.store = store
        self.vault = vault
        self.session_adapter = session_adapter
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        admission_plan_id: str,
        scope: Scope,
        target: AuthorizedWebTarget,
        purpose: TestIdentityPurpose,
        role_ref: str,
        action: ActionRequest,
        limits: CredentialSessionLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CredentialSessionPlan:
        admission = self.identity_service.active_admission(
            admission_plan_id, scope=scope, target=target, now=now
        )
        self._action(action, admission=admission, purpose=purpose, role_ref=role_ref)
        if action.requested_at != now:
            raise CredentialSessionRejected("Action request time must equal plan creation time")
        lease_expires_at = min(
            now + timedelta(seconds=limits.lease_ttl_seconds),
            admission.expires_at,
            scope.valid_until,
        )
        stop_at = min(deadline, lease_expires_at)
        if not now < stop_at <= lease_expires_at:
            raise CredentialSessionRejected("Credential Session deadline is invalid")
        try:
            return CredentialSessionPlan.create(
                admission_plan_id=admission.plan_id,
                admission_id=admission.admission_id,
                record_id=admission.record_id,
                identity_ref=admission.identity_ref,
                credential_ref=admission.credential_ref,
                engagement_id=scope.engagement_id,
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_id=target.target_id,
                target_digest=canonical_digest(target.model_dump(mode="python")),
                purpose=purpose,
                role_ref=role_ref,
                action_digest=action.digest(),
                action_intent_digest=action.intent_digest(),
                action_name=action.action,
                mutates_state=action.mutates_state,
                required_approvals=admission.required_approvals,
                limits=limits,
                created_at=now,
                deadline=stop_at,
                lease_expires_at=lease_expires_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise CredentialSessionRejected("Credential Session Plan could not be sealed") from exc

    def execute(
        self,
        plan: CredentialSessionPlan,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        action: ActionRequest,
        approvals: tuple[ApprovalRequest, ...],
        now: datetime,
    ) -> CredentialSessionOutcome:
        authoritative = CredentialSessionPlan.model_validate(plan.model_dump(mode="python"))
        self._binding(authoritative, scope=scope, target=target, action=action, now=now)
        approval_ids = self._approvals(
            authoritative, scope=scope, action=action, approvals=approvals, now=now
        )
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            self._completed_binding(authoritative, claim.outcome, approval_ids)
            return claim.outcome
        return self._complete(
            authoritative,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            approval_ids=approval_ids,
            now=now,
            attempt=claim.attempt,
        )

    def recover(
        self,
        plan: CredentialSessionPlan,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        action: ActionRequest,
        approvals: tuple[ApprovalRequest, ...],
        now: datetime,
    ) -> CredentialSessionOutcome:
        authoritative = CredentialSessionPlan.model_validate(plan.model_dump(mode="python"))
        self._binding(authoritative, scope=scope, target=target, action=action, now=now)
        approval_ids = self._approvals(
            authoritative, scope=scope, action=action, approvals=approvals, now=now
        )
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            approval_ids=approval_ids,
            now=now,
            attempt=claim.attempt,
        )

    def _complete(self, plan, *, scope, target, action, approvals, approval_ids, now, attempt):
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        lease = None
        handle = None
        try:
            deadline.check()
            self._binding(plan, scope=scope, target=target, action=action, now=now)
            self._approvals(plan, scope=scope, action=action, approvals=approvals, now=now)
            lease = self.vault.acquire(plan, now=now)
            if (
                lease.credential_ref != plan.credential_ref
                or lease.expires_at != plan.lease_expires_at
            ):
                raise CredentialSessionRejected("credential Lease binding drifted")
            deadline.check()
            credential = lease.view(now=now)
            handle = self.session_adapter.open(plan, credential=credential, now=now)
            deadline.check()
            expected_binding = canonical_digest(
                {"plan_id": plan.plan_id, "use": 1, "offline": True}
            )
            if handle.session_binding != expected_binding:
                raise CredentialSessionRejected("isolated Session binding drifted")
        finally:
            cleanup_error = None
            try:
                if handle is not None:
                    handle.close()
            except Exception as exc:  # cleanup must not strand the credential Lease
                cleanup_error = exc
            finally:
                if lease is not None:
                    lease.close()
            if cleanup_error is not None:
                raise CredentialSessionRejected(
                    "isolated Session cleanup failed closed"
                ) from cleanup_error
        if lease is None or handle is None or not lease.zeroed or not handle.zeroed:
            raise CredentialSessionRejected("Credential Session cleanup was not proven")
        lease_receipt = CredentialLeaseReceipt.create(
            plan_id=plan.plan_id,
            credential_ref=plan.credential_ref,
            issued_at=now,
            expires_at=plan.lease_expires_at,
        )
        session_receipt = IsolatedSessionReceipt.create(
            plan_id=plan.plan_id,
            lease_id=lease_receipt.lease_id,
            target_id=plan.target_id,
            identity_ref=plan.identity_ref,
            role_ref=plan.role_ref,
            opened_at=now,
            closed_at=now,
            authentication_performed=handle.authentication_performed,
            state_changed=getattr(handle, "state_changed", False),
            state_restored=getattr(handle, "state_restored", True),
        )
        outcome = CredentialSessionOutcome.create(
            plan_id=plan.plan_id,
            attempt=attempt,
            approval_ids=approval_ids,
            lease=lease_receipt,
            session=session_receipt,
            completed_at=now,
        )
        deadline.check()
        self._binding(plan, scope=scope, target=target, action=action, now=now)
        self._approvals(plan, scope=scope, action=action, approvals=approvals, now=now)
        self.store.complete(plan, outcome)
        return outcome

    def _binding(self, plan, *, scope, target, action, now):
        if not plan.created_at <= now < plan.deadline or now >= plan.lease_expires_at:
            raise CredentialSessionRejected("Credential Session Plan is not active")
        admission = self.identity_service.active_admission(
            plan.admission_plan_id, scope=scope, target=target, now=now
        )
        self._action(action, admission=admission, purpose=plan.purpose, role_ref=plan.role_ref)
        if (
            admission.admission_id != plan.admission_id
            or admission.record_id != plan.record_id
            or admission.identity_ref != plan.identity_ref
            or admission.credential_ref != plan.credential_ref
            or admission.required_approvals != plan.required_approvals
            or plan.engagement_id != scope.engagement_id
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.target_id != target.target_id
            or plan.target_digest != canonical_digest(target.model_dump(mode="python"))
            or action.engagement_id != scope.engagement_id
            or plan.action_digest != action.digest()
            or plan.action_intent_digest != action.intent_digest()
            or plan.action_name != action.action
            or plan.mutates_state != action.mutates_state
        ):
            raise CredentialSessionRejected("Credential Session binding drifted")

    @staticmethod
    def _action(action, *, admission, purpose, role_ref):
        expected_context = credential_authorization_context_digest(
            admission_id=admission.admission_id,
            identity_ref=admission.identity_ref,
            purpose=purpose,
            role_ref=role_ref,
        )
        if (
            action.target_id != admission.target_id
            or action.authorization_context_digest != expected_context
            or not action.uses_real_credentials
            or purpose not in admission.purposes
            or role_ref not in admission.role_refs
            or action.external_callback
            or action.submits_report
            or action.runs_untrusted_build
            or action.mutates_state != (purpose is TestIdentityPurpose.STATE_CHANGE_VALIDATION)
        ):
            raise CredentialSessionRejected("Action is not admitted for this Test Identity")

    @staticmethod
    def _approvals(plan, *, scope, action, approvals, now):
        current_action = action.model_copy(update={"requested_at": now})
        decision = PolicyEngine(scope).decide(current_action, approvals)
        if decision.effect is not DecisionEffect.ALLOW:
            raise CredentialSessionRejected("exact Action Approval binding was not satisfied")
        matching = []
        for required in plan.required_approvals:
            match = next(
                (
                    approval.approval_id
                    for approval in approvals
                    if approval.engagement_id == plan.engagement_id
                    and approval.target_id == plan.target_id
                    and approval.policy_version == plan.scope_version
                    and approval.is_valid_for(action=required, digest=plan.action_digest, now=now)
                ),
                None,
            )
            if match is None:
                raise CredentialSessionRejected("required exact Action Approvals are missing")
            matching.append(match)
        return tuple(sorted(matching, key=str))

    @staticmethod
    def _completed_binding(plan, outcome, approval_ids):
        if outcome.plan_id != plan.plan_id or outcome.approval_ids != approval_ids:
            raise CredentialSessionRejected("completed Credential Session drifted")
