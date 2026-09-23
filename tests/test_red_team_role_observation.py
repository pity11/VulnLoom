from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus
from vulnloom.policy.engine import ActionRequest
from vulnloom.red_team.credential_session_adapters import (
    CredentialSessionAdapterRejected,
    OfflineCredentialVault,
)
from vulnloom.red_team.credential_session_models import (
    CredentialSessionLimits,
    credential_authorization_context_digest,
)
from vulnloom.red_team.credential_session_service import CredentialSessionService
from vulnloom.red_team.credential_session_store import CredentialSessionStore
from vulnloom.red_team.models import AuthorizedWebTarget
from vulnloom.red_team.role_observation_adapters import (
    OfflineRoleAuthenticationAdapter,
)
from vulnloom.red_team.role_observation_models import (
    LocalAuthenticationObservation,
    OfflineRoleFixture,
    RoleAccessDecision,
    RoleDifferentialLimits,
    RoleDifferentialPlan,
    RoleDifferentialState,
    RoleDifferentialVerdict,
    RoleFixtureDecision,
)
from vulnloom.red_team.role_observation_service import (
    RoleDifferentialRejected,
    RoleDifferentialService,
    RoleDifferentialTimedOut,
)
from vulnloom.red_team.role_observation_store import (
    RoleDifferentialRecoveryRequired,
    RoleDifferentialStore,
)
from vulnloom.red_team.test_identity_models import (
    TestIdentityAdmissionLimits as IdentityAdmissionLimits,
)
from vulnloom.red_team.test_identity_models import TestIdentityPurpose as IdentityPurpose
from vulnloom.red_team.test_identity_service import (
    TestIdentityAdmissionService as IdentityService,
)
from vulnloom.red_team.test_identity_store import TestIdentityStore as IdentityStore

READER_IDENTITY = "1" * 64
EDITOR_IDENTITY = "2" * 64
READER_CREDENTIAL = "3" * 64
EDITOR_CREDENTIAL = "4" * 64
READER_ROLE = "role:reader-fixture"
EDITOR_ROLE = "role:editor-fixture"
_CONNECTIONS: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while _CONNECTIONS:
        _CONNECTIONS.pop().close()


def _connection():
    connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(connection)
    return connection


def _scope(approved_scope):
    return approved_scope.model_copy(
        update={
            "allowed_identities": frozenset({READER_IDENTITY, EDITOR_IDENTITY}),
            "allowed_test_classes": frozenset({"read_only"}),
        }
    )


def _approval(scope, target, action, now):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=target.target_id,
        action=ApprovalAction.USE_REAL_CREDENTIALS,
        action_digest=action.digest(),
        expected_side_effects=("local_fixture_authentication_only",),
        evidence_summary="Exact local fixture identity and role context approved",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=10),
        status=ApprovalStatus.GRANTED,
        decided_by="security-owner",
        decided_at=now,
    )


def _admit(identity_service, scope, target, now, *, identity_ref, credential_ref, role):
    identity_service.issue_record(
        scope=scope,
        target=target,
        identity_ref=identity_ref,
        credential_ref=credential_ref,
        custody_proof_digest="5" * 64,
        issuer_ref="operator:security-owner",
        allowed_purposes=(IdentityPurpose.READ_ONLY_ROLE_OBSERVATION,),
        role_refs=(role,),
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        now=now,
    )
    plan = identity_service.prepare(
        identity_ref=identity_ref,
        scope=scope,
        target=target,
        purposes=(IdentityPurpose.READ_ONLY_ROLE_OBSERVATION,),
        role_refs=(role,),
        limits=IdentityAdmissionLimits(),
        now=now,
        deadline=now + timedelta(minutes=2),
        admission_expires_at=now + timedelta(minutes=30),
        idempotency_key=f"admit-{identity_ref}",
    )
    identity_service.execute(plan, scope=scope, target=target, now=now)
    return plan


def _session(
    session_service,
    identity_service,
    admission_plan,
    scope,
    target,
    now,
    *,
    role,
    key,
):
    admission = identity_service.store.admission(admission_plan.plan_id)
    action = ActionRequest(
        engagement_id=scope.engagement_id,
        target_id=target.target_id,
        action="fixture_view_same_record",
        requested_at=now,
        url="https://app.example.test/fixture/record",
        test_class="read_only",
        uses_real_credentials=True,
        authorization_context_digest=credential_authorization_context_digest(
            admission_id=admission.admission_id,
            identity_ref=admission.identity_ref,
            purpose=IdentityPurpose.READ_ONLY_ROLE_OBSERVATION,
            role_ref=role,
        ),
    )
    plan = session_service.prepare(
        admission_plan_id=admission_plan.plan_id,
        scope=scope,
        target=target,
        purpose=IdentityPurpose.READ_ONLY_ROLE_OBSERVATION,
        role_ref=role,
        action=action,
        limits=CredentialSessionLimits(),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key=key,
    )
    outcome = session_service.execute(
        plan,
        scope=scope,
        target=target,
        action=action,
        approvals=(_approval(scope, target, action, now),),
        now=now + timedelta(seconds=1),
    )
    return plan, outcome


def _runtime(
    approved_scope,
    now,
    *,
    comparison_decision=RoleAccessDecision.ALLOWED,
    valid_editor_credential=True,
):
    scope = _scope(approved_scope)
    target = AuthorizedWebTarget(target_id=uuid4(), url="https://app.example.test/")
    identity_service = IdentityService(store=IdentityStore(_connection()))
    reader_admission = _admit(
        identity_service,
        scope,
        target,
        now,
        identity_ref=READER_IDENTITY,
        credential_ref=READER_CREDENTIAL,
        role=READER_ROLE,
    )
    editor_admission = _admit(
        identity_service,
        scope,
        target,
        now,
        identity_ref=EDITOR_IDENTITY,
        credential_ref=EDITOR_CREDENTIAL,
        role=EDITOR_ROLE,
    )
    fixture = OfflineRoleFixture.create(
        decisions=(
            RoleFixtureDecision(role_ref=READER_ROLE, decision=RoleAccessDecision.DENIED),
            RoleFixtureDecision(role_ref=EDITOR_ROLE, decision=comparison_decision),
        )
    )
    reader_material = b"fixture:reader-material"
    editor_material = b"fixture:editor-material"
    adapter = OfflineRoleAuthenticationAdapter(
        fixture,
        credential_proofs={
            READER_CREDENTIAL: hashlib.sha256(reader_material).digest(),
            EDITOR_CREDENTIAL: (
                hashlib.sha256(editor_material).digest()
                if valid_editor_credential
                else b"\x00" * 32
            ),
        },
    )
    session_store = CredentialSessionStore(_connection())
    session_service = CredentialSessionService(
        identity_service=identity_service,
        store=session_store,
        vault=OfflineCredentialVault(
            {
                READER_CREDENTIAL: reader_material,
                EDITOR_CREDENTIAL: editor_material,
            }
        ),
        session_adapter=adapter,
    )
    reader_session = _session(
        session_service,
        identity_service,
        reader_admission,
        scope,
        target,
        now,
        role=READER_ROLE,
        key="reader-session",
    )
    editor_session = _session(
        session_service,
        identity_service,
        editor_admission,
        scope,
        target,
        now,
        role=EDITOR_ROLE,
        key="editor-session",
    )
    service = RoleDifferentialService(
        identity_service=identity_service,
        session_store=session_store,
        execution_source=adapter,
        store=RoleDifferentialStore(_connection()),
    )
    plan = service.prepare(
        baseline_session_plan_id=reader_session[0].plan_id,
        comparison_session_plan_id=editor_session[0].plan_id,
        scope=scope,
        target=target,
        limits=RoleDifferentialLimits(),
        now=now + timedelta(seconds=2),
        deadline=now + timedelta(minutes=2),
        idempotency_key="role-differential",
    )
    return (
        scope,
        target,
        identity_service,
        adapter,
        service,
        reader_session,
        editor_session,
        plan,
    )


def test_two_cleaned_local_auth_sessions_materialize_role_difference(approved_scope, now):
    scope, target, _, adapter, service, reader, editor, plan = _runtime(approved_scope, now)

    outcome = service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=3))
    replay = service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=4))

    assert replay == outcome
    assert outcome.observation.verdict is RoleDifferentialVerdict.DIFFERENT
    assert outcome.observation.baseline_decision is RoleAccessDecision.DENIED
    assert outcome.observation.comparison_decision is RoleAccessDecision.ALLOWED
    assert outcome.observation.candidate_created is False
    assert outcome.observation.finding_created is False
    assert outcome.observation.vulnerability_claimed is False
    assert reader[1].session.authentication_performed is True
    assert editor[1].session.authentication_performed is True
    assert adapter.result(reader[0].plan_id).logout.post_logout_reuse_rejected
    assert adapter.result(editor[0].plan_id).logout.post_logout_reuse_rejected
    assert service.store.state(plan.plan_id) == (RoleDifferentialState.COMPLETED, 1)

    row = service.store.connection.execute(
        "SELECT plan_json,outcome_json FROM red_team_role_differentials"
    ).fetchone()
    serialized = "".join(row)
    assert "reader-material" not in serialized
    assert "editor-material" not in serialized
    assert "password" not in serialized.lower()
    assert "cookie" not in serialized.lower()


def test_equal_role_decisions_remain_observation_not_vulnerability(approved_scope, now):
    scope, target, _, _, service, _, _, plan = _runtime(
        approved_scope, now, comparison_decision=RoleAccessDecision.DENIED
    )
    outcome = service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=3))
    assert outcome.observation.verdict is RoleDifferentialVerdict.SAME
    assert outcome.observation.vulnerability_claimed is False


def test_wrong_fixture_credential_is_rejected_during_local_authentication(approved_scope, now):
    with pytest.raises(CredentialSessionAdapterRejected, match="fixture credential"):
        _runtime(approved_scope, now, valid_editor_credential=False)


def test_same_session_cannot_be_compared_with_itself(approved_scope, now):
    scope, target, _, _, service, reader, _, _ = _runtime(approved_scope, now)
    with pytest.raises(RoleDifferentialRejected, match="distinct roles"):
        service.prepare(
            baseline_session_plan_id=reader[0].plan_id,
            comparison_session_plan_id=reader[0].plan_id,
            scope=scope,
            target=target,
            limits=RoleDifferentialLimits(),
            now=now + timedelta(seconds=2),
            deadline=now + timedelta(minutes=1),
            idempotency_key="same-session",
        )


def test_identity_revocation_after_plan_blocks_materialization(approved_scope, now):
    scope, target, identity_service, _, service, _, _, plan = _runtime(approved_scope, now)
    identity_service.store.revoke(
        READER_IDENTITY,
        reason_digest="9" * 64,
        now=now + timedelta(milliseconds=1),
    )
    with pytest.raises(RoleDifferentialRejected, match="unavailable"):
        service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=3))
    assert service.store.state(plan.plan_id) is None


def test_missing_auth_execution_fails_closed(approved_scope, now):
    scope, target, _, adapter, service, reader, _, _ = _runtime(approved_scope, now)
    adapter._runs.pop(reader[0].plan_id)
    with pytest.raises(RoleDifferentialRejected, match="unavailable"):
        service.prepare(
            baseline_session_plan_id=reader[0].plan_id,
            comparison_session_plan_id="f" * 64,
            scope=scope,
            target=target,
            limits=RoleDifferentialLimits(),
            now=now + timedelta(seconds=2),
            deadline=now + timedelta(minutes=1),
            idempotency_key="missing-execution",
        )


def test_authentication_execution_drift_after_plan_is_rejected(approved_scope, now):
    scope, target, _, adapter, service, reader, _, plan = _runtime(approved_scope, now)
    observation, handle = adapter._runs[reader[0].plan_id]
    adapter._runs[reader[0].plan_id] = (
        LocalAuthenticationObservation.create(
            fixture_id="a" * 64,
            session_plan_id=observation.session_plan_id,
            identity_ref=observation.identity_ref,
            role_ref=observation.role_ref,
            action_intent_digest=observation.action_intent_digest,
            access_decision=observation.access_decision,
            observed_at=observation.observed_at,
        ),
        handle,
    )
    with pytest.raises(RoleDifferentialRejected, match="exact fixture action"):
        service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=3))
    assert service.store.state(plan.plan_id) is None


def test_timeout_keeps_started_and_explicit_recovery_completes(approved_scope, now):
    scope, target, _, _, service, _, _, plan = _runtime(approved_scope, now)
    ticks = iter((0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(RoleDifferentialTimedOut):
        service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=3))
    assert service.store.state(plan.plan_id) == (RoleDifferentialState.STARTED, 1)

    service.monotonic = time.monotonic
    outcome = service.recover(plan, scope=scope, target=target, now=now + timedelta(seconds=4))
    assert outcome.attempt == 2


def test_timeout_recovery_is_capped_at_three_attempts(approved_scope, now):
    scope, target, _, _, service, _, _, plan = _runtime(approved_scope, now)
    ticks = iter((0.0, 100.0, 0.0, 100.0, 0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(RoleDifferentialTimedOut):
        service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=3))
    with pytest.raises(RoleDifferentialTimedOut):
        service.recover(plan, scope=scope, target=target, now=now + timedelta(seconds=4))
    with pytest.raises(RoleDifferentialTimedOut):
        service.recover(plan, scope=scope, target=target, now=now + timedelta(seconds=5))
    with pytest.raises(RoleDifferentialRecoveryRequired, match="exhausted"):
        service.recover(plan, scope=scope, target=target, now=now + timedelta(seconds=6))
    assert service.store.state(plan.plan_id) == (RoleDifferentialState.STARTED, 3)


def test_schema_rejects_promotion_and_secret_fields_are_absent(approved_scope, now):
    *_, plan = _runtime(approved_scope, now)
    payload = plan.model_dump(mode="python")
    payload["candidate_authorized"] = True
    payload["plan_id"] = "0" * 64
    with pytest.raises(ValidationError):
        RoleDifferentialPlan.model_validate(payload)

    schema = json.dumps(RoleDifferentialPlan.model_json_schema()).lower()
    for forbidden in ("password", "cookie", "username", "credential_value", "session_token"):
        assert forbidden not in schema
