from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus
from vulnloom.policy.engine import ActionRequest
from vulnloom.red_team.credential_session_adapters import (
    CredentialSessionAdapterRejected as AdapterRejected,
)
from vulnloom.red_team.credential_session_adapters import (
    OfflineCredentialVault as OfflineVault,
)
from vulnloom.red_team.credential_session_adapters import (
    OfflineIsolatedSessionAdapter as OfflineSessionAdapter,
)
from vulnloom.red_team.credential_session_models import (
    CredentialSessionLimits as SessionLimits,
)
from vulnloom.red_team.credential_session_models import (
    CredentialSessionPlan as SessionPlan,
)
from vulnloom.red_team.credential_session_models import (
    CredentialSessionState as SessionState,
)
from vulnloom.red_team.credential_session_models import (
    credential_authorization_context_digest,
)
from vulnloom.red_team.credential_session_service import (
    CredentialSessionRejected as SessionRejected,
)
from vulnloom.red_team.credential_session_service import (
    CredentialSessionService as SessionService,
)
from vulnloom.red_team.credential_session_service import (
    CredentialSessionTimedOut as SessionTimedOut,
)
from vulnloom.red_team.credential_session_store import (
    CredentialSessionRecoveryRequired as SessionRecoveryRequired,
)
from vulnloom.red_team.credential_session_store import (
    CredentialSessionStore as SessionStore,
)
from vulnloom.red_team.credential_session_store import (
    CredentialSessionStoreRejected as SessionStoreRejected,
)
from vulnloom.red_team.models import AuthorizedWebTarget
from vulnloom.red_team.test_identity_models import (
    TestIdentityAdmissionLimits as IdentityLimits,
)
from vulnloom.red_team.test_identity_models import TestIdentityPurpose as Purpose
from vulnloom.red_team.test_identity_service import (
    TestIdentityAdmissionService as IdentityService,
)
from vulnloom.red_team.test_identity_store import TestIdentityStore as IdentityStore

IDENTITY_REF = "1" * 64
CREDENTIAL_REF = "2" * 64
ROLE_READER = "role:reader-fixture"
ROLE_EDITOR = "role:editor-fixture"
_CONNECTIONS: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while _CONNECTIONS:
        _CONNECTIONS.pop().close()


def _scope(approved_scope):
    return approved_scope.model_copy(
        update={
            "allowed_identities": frozenset({IDENTITY_REF}),
            "allowed_test_classes": frozenset({"authentication", "read_only", "state_change"}),
        }
    )


def _identity(scope, target, now, *, selected_purpose):
    connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(connection)
    service = IdentityService(store=IdentityStore(connection))
    service.issue_record(
        scope=scope,
        target=target,
        identity_ref=IDENTITY_REF,
        credential_ref=CREDENTIAL_REF,
        custody_proof_digest="3" * 64,
        issuer_ref="operator:security-owner",
        allowed_purposes=(
            Purpose.AUTHENTICATION,
            Purpose.READ_ONLY_ROLE_OBSERVATION,
            Purpose.STATE_CHANGE_VALIDATION,
        ),
        role_refs=(ROLE_EDITOR, ROLE_READER),
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        now=now,
    )
    plan = service.prepare(
        identity_ref=IDENTITY_REF,
        scope=scope,
        target=target,
        purposes=(selected_purpose,),
        role_refs=(
            ROLE_EDITOR if selected_purpose is Purpose.STATE_CHANGE_VALIDATION else ROLE_READER,
        ),
        limits=IdentityLimits(),
        now=now,
        deadline=now + timedelta(minutes=2),
        admission_expires_at=now + timedelta(minutes=30),
        idempotency_key="identity-admission",
    )
    service.execute(plan, scope=scope, target=target, now=now)
    return service, plan


def _action(scope, target, now, *, admission, purpose, role, mutate=False):
    return ActionRequest(
        engagement_id=scope.engagement_id,
        target_id=target.target_id,
        action="fixture_role_observation" if not mutate else "fixture_state_change",
        requested_at=now,
        url=target.url,
        test_class="read_only" if not mutate else "state_change",
        mutates_state=mutate,
        uses_real_credentials=True,
        authorization_context_digest=credential_authorization_context_digest(
            admission_id=admission.admission_id,
            identity_ref=admission.identity_ref,
            purpose=purpose,
            role_ref=role,
        ),
    )


def _approval(scope, target, action, now, approval_action):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=target.target_id,
        action=approval_action,
        action_digest=action.digest(),
        expected_side_effects=("offline_fixture_session_only",),
        evidence_summary="Operator approved the exact fixture action digest",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=10),
        status=ApprovalStatus.GRANTED,
        decided_by="security-owner",
        decided_at=now,
    )


def _runtime(approved_scope, now, *, mutate=False, monotonic=None, interrupt=False):
    scope = _scope(approved_scope)
    target = AuthorizedWebTarget(target_id=uuid4(), url="https://app.example.test/")
    purpose = Purpose.STATE_CHANGE_VALIDATION if mutate else Purpose.READ_ONLY_ROLE_OBSERVATION
    identity_service, admission_plan = _identity(scope, target, now, selected_purpose=purpose)
    vault = OfflineVault({CREDENTIAL_REF: b"fixture:opaque-material"})
    adapter = OfflineSessionAdapter(interrupt=interrupt)
    session_connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(session_connection)
    kwargs = {
        "identity_service": identity_service,
        "store": SessionStore(session_connection),
        "vault": vault,
        "session_adapter": adapter,
    }
    if monotonic is not None:
        kwargs["monotonic"] = monotonic
    service = SessionService(**kwargs)
    role = ROLE_EDITOR if mutate else ROLE_READER
    admission = identity_service.store.admission(admission_plan.plan_id)
    action = _action(
        scope,
        target,
        now,
        admission=admission,
        purpose=purpose,
        role=role,
        mutate=mutate,
    )
    plan = service.prepare(
        admission_plan_id=admission_plan.plan_id,
        scope=scope,
        target=target,
        purpose=purpose,
        role_ref=role,
        action=action,
        limits=SessionLimits(),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="credential-session",
    )
    approvals = [_approval(scope, target, action, now, ApprovalAction.USE_REAL_CREDENTIALS)]
    if mutate:
        approvals.append(_approval(scope, target, action, now, ApprovalAction.MUTATE_TARGET_STATE))
    return scope, target, identity_service, service, vault, adapter, action, plan, tuple(approvals)


def test_exact_approval_issues_one_offline_lease_and_zeroes_all_material(approved_scope, now):
    scope, target, _, service, vault, adapter, action, plan, approvals = _runtime(
        approved_scope, now
    )

    outcome = service.execute(
        plan,
        scope=scope,
        target=target,
        action=action,
        approvals=approvals,
        now=now + timedelta(seconds=1),
    )
    replay = service.execute(
        plan,
        scope=scope,
        target=target,
        action=action,
        approvals=approvals,
        now=now + timedelta(seconds=2),
    )

    assert replay == outcome
    assert vault.acquisitions == 1
    assert adapter.opens == 1
    assert vault.last_lease is not None and vault.last_lease.zeroed
    assert adapter.last_handle is not None and adapter.last_handle.zeroed
    assert outcome.lease.released and outcome.lease.zeroed
    assert outcome.session.isolated and outcome.session.zeroed
    assert outcome.session.network_performed is False
    assert outcome.session.authentication_performed is False
    assert outcome.session.state_changed is False
    assert service.store.state(plan.plan_id) == (SessionState.COMPLETED, 1)

    persisted = service.store.connection.execute(
        "SELECT plan_json,outcome_json FROM red_team_credential_sessions"
    ).fetchone()
    serialized = "".join(persisted)
    assert "opaque-material" not in serialized
    assert "password" not in serialized.lower()
    assert "cookie" not in serialized.lower()
    assert "token" not in serialized.lower()


def test_missing_wrong_or_expired_approval_fails_before_vault(approved_scope, now):
    scope, target, _, service, vault, _, action, plan, approvals = _runtime(approved_scope, now)
    wrong = approvals[0].model_copy(update={"action_digest": "9" * 64})
    expired = approvals[0].model_copy(update={"expires_at": now + timedelta(milliseconds=500)})

    for supplied, at in (
        ((), now + timedelta(seconds=1)),
        ((wrong,), now + timedelta(seconds=1)),
        ((expired,), now + timedelta(seconds=1)),
    ):
        with pytest.raises(SessionRejected, match="Approval"):
            service.execute(
                plan,
                scope=scope,
                target=target,
                action=action,
                approvals=supplied,
                now=at,
            )
    assert vault.acquisitions == 0
    assert service.store.state(plan.plan_id) is None


def test_action_target_role_and_state_change_bindings_fail_closed(approved_scope, now):
    scope, target, _, service, vault, _, action, plan, approvals = _runtime(approved_scope, now)
    drifted = action.model_copy(update={"action": "different_action"})
    with pytest.raises(SessionRejected, match="binding drifted"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=drifted,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    with pytest.raises(SessionRejected, match="not admitted"):
        service.prepare(
            admission_plan_id=plan.admission_plan_id,
            scope=scope,
            target=target,
            purpose=Purpose.READ_ONLY_ROLE_OBSERVATION,
            role_ref=ROLE_READER,
            action=action.model_copy(update={"mutates_state": True}),
            limits=SessionLimits(),
            now=now,
            deadline=now + timedelta(seconds=10),
            idempotency_key="bad-state",
        )
    with pytest.raises(SessionRejected, match="not admitted"):
        service.prepare(
            admission_plan_id=plan.admission_plan_id,
            scope=scope,
            target=target,
            purpose=plan.purpose,
            role_ref=plan.role_ref,
            action=action.model_copy(update={"authorization_context_digest": None}),
            limits=SessionLimits(),
            now=now,
            deadline=now + timedelta(seconds=10),
            idempotency_key="missing-auth-context",
        )
    assert vault.acquisitions == 0


def test_one_admission_cannot_fund_a_second_session(approved_scope, now):
    scope, target, _, service, vault, _, action, plan, approvals = _runtime(approved_scope, now)
    service.execute(
        plan,
        scope=scope,
        target=target,
        action=action,
        approvals=approvals,
        now=now + timedelta(seconds=1),
    )
    second = service.prepare(
        admission_plan_id=plan.admission_plan_id,
        scope=scope,
        target=target,
        purpose=plan.purpose,
        role_ref=plan.role_ref,
        action=action,
        limits=SessionLimits(),
        now=now,
        deadline=now + timedelta(seconds=20),
        idempotency_key="second-session",
    )
    with pytest.raises(SessionStoreRejected, match="reused"):
        service.execute(
            second,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=2),
        )
    assert vault.acquisitions == 1


def test_state_change_requires_two_exact_approvals_but_performs_no_change(approved_scope, now):
    scope, target, _, service, _, _, action, plan, approvals = _runtime(
        approved_scope, now, mutate=True
    )
    with pytest.raises(SessionRejected, match="Approval"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals[:1],
            now=now + timedelta(seconds=1),
        )
    outcome = service.execute(
        plan,
        scope=scope,
        target=target,
        action=action,
        approvals=approvals,
        now=now + timedelta(seconds=1),
    )
    assert len(outcome.approval_ids) == 2
    assert outcome.session.state_changed is False


def test_revoked_identity_blocks_lease_after_plan(approved_scope, now):
    scope, target, identity_service, service, vault, _, action, plan, approvals = _runtime(
        approved_scope, now
    )
    identity_service.store.revoke(
        IDENTITY_REF, reason_digest="8" * 64, now=now + timedelta(milliseconds=1)
    )
    with pytest.raises(ValueError, match="active Test Identity"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert vault.acquisitions == 0


def test_adapter_interruption_zeroes_lease_and_recovery_is_bounded(approved_scope, now):
    scope, target, _, service, vault, _, action, plan, approvals = _runtime(
        approved_scope, now, interrupt=True
    )
    with pytest.raises(AdapterRejected, match="interrupted"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert vault.last_lease is not None and vault.last_lease.zeroed
    assert service.store.state(plan.plan_id) == (SessionState.STARTED, 1)

    service.session_adapter = OfflineSessionAdapter()
    outcome = service.recover(
        plan,
        scope=scope,
        target=target,
        action=action,
        approvals=approvals,
        now=now + timedelta(seconds=2),
    )
    assert outcome.attempt == 2
    with pytest.raises(SessionRecoveryRequired, match="not awaiting"):
        service.recover(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=3),
        )


def test_vault_lease_binding_drift_is_zeroed_and_not_published(approved_scope, now):
    scope, target, _, service, vault, _, action, plan, approvals = _runtime(approved_scope, now)
    original_acquire = vault.acquire

    def drifted_acquire(session_plan, *, now):
        lease = original_acquire(session_plan, now=now)
        lease.credential_ref = "9" * 64
        return lease

    vault.acquire = drifted_acquire
    with pytest.raises(SessionRejected, match="Lease binding drifted"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert vault.last_lease is not None and vault.last_lease.zeroed
    assert service.store.state(plan.plan_id) == (SessionState.STARTED, 1)


def test_timeout_after_lease_acquisition_zeroes_and_publishes_nothing(approved_scope, now):
    ticks = iter((0.0, 0.0, 100.0))
    scope, target, _, service, vault, _, action, plan, approvals = _runtime(
        approved_scope, now, monotonic=lambda: next(ticks)
    )
    with pytest.raises(SessionTimedOut):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert vault.last_lease is not None and vault.last_lease.zeroed
    assert service.store.state(plan.plan_id) == (SessionState.STARTED, 1)


def test_schema_rejects_permission_escalation_and_contains_no_secret_fields(approved_scope, now):
    *_, plan, _ = _runtime(approved_scope, now)
    payload = plan.model_dump(mode="python")
    payload["network_execution_authorized"] = True
    payload["plan_id"] = "0" * 64
    with pytest.raises(ValidationError):
        SessionPlan.model_validate(payload)

    schema = json.dumps(SessionPlan.model_json_schema()).lower()
    for forbidden in ("password", "cookie", "username", "vault_path", "secret_value"):
        assert forbidden not in schema
