"""Trusted admission service for controlled, opaque test identities."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlsplit

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, Scope, ScopeState

from .models import AuthorizedWebTarget
from .test_identity_models import (
    TestIdentityAdmission,
    TestIdentityAdmissionLimits,
    TestIdentityAdmissionOutcome,
    TestIdentityAdmissionPlan,
    TestIdentityPurpose,
    TestIdentityRecord,
    TestIdentityReference,
)
from .test_identity_store import TestIdentityStore


class TestIdentityAdmissionRejected(ValueError):
    pass


class TestIdentityAdmissionTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise TestIdentityAdmissionTimedOut(
                "Test Identity Admission timed out"
            )


_PURPOSE_TEST_CLASS = {
    TestIdentityPurpose.AUTHENTICATION: "authentication",
    TestIdentityPurpose.READ_ONLY_ROLE_OBSERVATION: "read_only",
    TestIdentityPurpose.STATE_CHANGE_VALIDATION: "state_change",
}


class TestIdentityAdmissionService:
    def __init__(
        self,
        *,
        store: TestIdentityStore,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.monotonic = monotonic

    def issue_record(
        self,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        identity_ref: str,
        credential_ref: str,
        custody_proof_digest: str,
        issuer_ref: str,
        allowed_purposes: tuple[TestIdentityPurpose, ...],
        role_refs: tuple[str, ...],
        valid_from: datetime,
        valid_until: datetime,
        now: datetime,
    ) -> TestIdentityRecord:
        self._scope(scope, now=now)
        self._target(scope, target)
        if identity_ref not in scope.allowed_identities:
            raise TestIdentityAdmissionRejected(
                "Test Identity reference is not allowed by Scope"
            )
        if identity_ref == credential_ref:
            raise TestIdentityAdmissionRejected(
                "identity and credential references must remain distinct"
            )
        self._purposes(scope, allowed_purposes)
        if not scope.valid_from <= valid_from <= now < valid_until <= scope.valid_until:
            raise TestIdentityAdmissionRejected(
                "Test Identity validity must be contained by Scope"
            )
        try:
            record = TestIdentityRecord.create(
                reference=TestIdentityReference(
                    identity_ref=identity_ref,
                    credential_ref=credential_ref,
                ),
                custody_proof_digest=custody_proof_digest,
                issuer_ref=issuer_ref,
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_id=target.target_id,
                target_digest=self._target_digest(target),
                allowed_purposes=allowed_purposes,
                role_refs=role_refs,
                valid_from=valid_from,
                valid_until=valid_until,
                issued_at=now,
            )
        except ValueError as exc:
            raise TestIdentityAdmissionRejected(
                "Test Identity Record could not be sealed"
            ) from exc
        return self.store.register(record)

    def prepare(
        self,
        *,
        identity_ref: str,
        scope: Scope,
        target: AuthorizedWebTarget,
        purposes: tuple[TestIdentityPurpose, ...],
        role_refs: tuple[str, ...],
        limits: TestIdentityAdmissionLimits,
        now: datetime,
        deadline: datetime,
        admission_expires_at: datetime,
        idempotency_key: str,
    ) -> TestIdentityAdmissionPlan:
        record = self._record(
            identity_ref, scope=scope, target=target, now=now
        )
        selected_purposes = tuple(
            sorted(set(purposes), key=lambda item: item.value)
        )
        selected_roles = tuple(sorted(set(role_refs)))
        if not set(selected_purposes) <= set(record.allowed_purposes):
            raise TestIdentityAdmissionRejected(
                "Test Identity purpose is not admitted by its Record"
            )
        if not set(selected_roles) <= set(record.role_refs):
            raise TestIdentityAdmissionRejected(
                "Test Identity role is not admitted by its Record"
            )
        self._purposes(scope, selected_purposes)
        expires_at = min(admission_expires_at, record.valid_until, scope.valid_until)
        stop_at = min(deadline, expires_at)
        if not now < stop_at <= expires_at:
            raise TestIdentityAdmissionRejected(
                "Test Identity Admission deadline is invalid"
            )
        try:
            return TestIdentityAdmissionPlan.create(
                record_id=record.record_id,
                identity_ref=record.reference.identity_ref,
                credential_ref=record.reference.credential_ref,
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_id=target.target_id,
                target_digest=self._target_digest(target),
                purposes=selected_purposes,
                role_refs=selected_roles,
                limits=limits,
                created_at=now,
                deadline=stop_at,
                admission_expires_at=expires_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise TestIdentityAdmissionRejected(
                "Test Identity Admission Plan could not be sealed"
            ) from exc

    def execute(
        self,
        plan: TestIdentityAdmissionPlan,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        now: datetime,
    ) -> TestIdentityAdmissionOutcome:
        authoritative = TestIdentityAdmissionPlan.model_validate(
            plan.model_dump(mode="python")
        )
        self._binding(authoritative, scope=scope, target=target, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            self._completed_binding(authoritative, claim.admission, claim.outcome)
            assert claim.outcome is not None
            return claim.outcome
        return self._complete(
            authoritative,
            scope=scope,
            target=target,
            now=now,
            attempt=claim.attempt,
        )

    def recover(
        self,
        plan: TestIdentityAdmissionPlan,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        now: datetime,
    ) -> TestIdentityAdmissionOutcome:
        authoritative = TestIdentityAdmissionPlan.model_validate(
            plan.model_dump(mode="python")
        )
        self._binding(authoritative, scope=scope, target=target, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            scope=scope,
            target=target,
            now=now,
            attempt=claim.attempt,
        )

    def active_admission(
        self,
        plan_id: str,
        *,
        scope: Scope,
        target: AuthorizedWebTarget,
        now: datetime,
    ) -> TestIdentityAdmission:
        plan = self.store.plan(plan_id)
        admission = self.store.admission(plan_id)
        self._scope(scope, now=now)
        record = self._record(
            plan.identity_ref, scope=scope, target=target, now=now
        )
        if (
            record.record_id != plan.record_id
            or admission.plan_id != plan.plan_id
            or admission.record_id != record.record_id
            or admission.identity_ref != record.reference.identity_ref
            or admission.credential_ref != record.reference.credential_ref
            or admission.scope_id != scope.scope_id
            or admission.scope_version != scope.version
            or admission.target_id != target.target_id
            or admission.target_digest != self._target_digest(target)
            or admission.purposes != plan.purposes
            or admission.role_refs != plan.role_refs
            or not admission.admitted_at <= now < admission.expires_at
        ):
            raise TestIdentityAdmissionRejected(
                "active Test Identity Admission binding drifted"
            )
        return admission

    def _complete(self, plan, *, scope, target, now, attempt):
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        record = self._binding(plan, scope=scope, target=target, now=now)
        required_approvals = {ApprovalAction.USE_REAL_CREDENTIALS}
        if TestIdentityPurpose.STATE_CHANGE_VALIDATION in plan.purposes:
            required_approvals.add(ApprovalAction.MUTATE_TARGET_STATE)
        admission = TestIdentityAdmission.create(
            plan_id=plan.plan_id,
            record_id=record.record_id,
            identity_ref=record.reference.identity_ref,
            credential_ref=record.reference.credential_ref,
            scope_id=plan.scope_id,
            scope_version=plan.scope_version,
            target_id=plan.target_id,
            target_digest=plan.target_digest,
            purposes=plan.purposes,
            role_refs=plan.role_refs,
            required_approvals=tuple(required_approvals),
            admitted_at=now,
            expires_at=plan.admission_expires_at,
        )
        outcome = TestIdentityAdmissionOutcome.create(
            plan_id=plan.plan_id,
            admission_id=admission.admission_id,
            attempt=attempt,
            completed_at=now,
        )
        deadline.check()
        self._binding(plan, scope=scope, target=target, now=now)
        self.store.complete(plan, admission, outcome)
        return outcome

    def _record(self, identity_ref, *, scope, target, now):
        self._scope(scope, now=now)
        self._target(scope, target)
        try:
            record = self.store.active_record(identity_ref)
        except ValueError as exc:
            raise TestIdentityAdmissionRejected(
                "active Test Identity is unavailable"
            ) from exc
        if (
            record.reference.identity_ref not in scope.allowed_identities
            or record.scope_id != scope.scope_id
            or record.scope_version != scope.version
            or record.target_id != target.target_id
            or record.target_digest != self._target_digest(target)
            or not record.valid_from <= now < record.valid_until
        ):
            raise TestIdentityAdmissionRejected(
                "Test Identity Record binding drifted"
            )
        self._purposes(scope, record.allowed_purposes)
        return record

    def _binding(self, plan, *, scope, target, now):
        if not plan.created_at <= now < plan.deadline:
            raise TestIdentityAdmissionRejected(
                "Test Identity Admission Plan is not active"
            )
        record = self._record(
            plan.identity_ref, scope=scope, target=target, now=now
        )
        if (
            record.record_id != plan.record_id
            or record.reference.credential_ref != plan.credential_ref
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.target_id != target.target_id
            or plan.target_digest != self._target_digest(target)
            or not set(plan.purposes) <= set(record.allowed_purposes)
            or not set(plan.role_refs) <= set(record.role_refs)
            or plan.admission_expires_at > record.valid_until
        ):
            raise TestIdentityAdmissionRejected(
                "Test Identity Admission binding drifted"
            )
        return record

    @staticmethod
    def _completed_binding(plan, admission, outcome):
        if (
            admission is None
            or outcome is None
            or admission.plan_id != plan.plan_id
            or admission.record_id != plan.record_id
            or admission.identity_ref != plan.identity_ref
            or admission.credential_ref != plan.credential_ref
            or admission.scope_id != plan.scope_id
            or admission.scope_version != plan.scope_version
            or admission.target_id != plan.target_id
            or admission.target_digest != plan.target_digest
            or admission.purposes != plan.purposes
            or admission.role_refs != plan.role_refs
            or outcome.plan_id != plan.plan_id
            or outcome.admission_id != admission.admission_id
        ):
            raise TestIdentityAdmissionRejected(
                "completed Test Identity Admission drifted"
            )

    @staticmethod
    def _scope(scope: Scope, *, now: datetime) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise TestIdentityAdmissionRejected(
                "Test Identity Admission requires a current approved Scope"
            )

    @staticmethod
    def _purposes(
        scope: Scope, purposes: tuple[TestIdentityPurpose, ...]
    ) -> None:
        if not purposes or any(
            _PURPOSE_TEST_CLASS[item] not in scope.allowed_test_classes
            for item in purposes
        ):
            raise TestIdentityAdmissionRejected(
                "Test Identity purpose is not allowed by Scope"
            )

    @staticmethod
    def _target(scope: Scope, target: AuthorizedWebTarget) -> None:
        parsed = urlsplit(target.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not any(
            item.host.lower() == parsed.hostname
            and parsed.scheme in item.schemes
            and port in item.ports
            for item in scope.network_targets
        ):
            raise TestIdentityAdmissionRejected(
                "Test Identity Target is outside Scope"
            )

    @staticmethod
    def _target_digest(target: AuthorizedWebTarget) -> str:
        return canonical_digest(target.model_dump(mode="python"))
