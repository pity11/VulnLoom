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
from vulnloom.red_team.business_flow_adapters import OfflinePublicationFlowAdapter
from vulnloom.red_team.business_flow_models import (
    BusinessInvariantLimits,
    BusinessInvariantPlan,
    BusinessInvariantState,
    BusinessInvariantVerdict,
    OfflinePublicationFixture,
    PublicationState,
)
from vulnloom.red_team.business_flow_service import (
    BusinessInvariantRejected,
    BusinessInvariantService,
    BusinessInvariantTimedOut,
)
from vulnloom.red_team.business_flow_store import (
    BusinessInvariantRecoveryRequired,
    BusinessInvariantStore,
)
from vulnloom.red_team.credential_session_adapters import OfflineCredentialVault
from vulnloom.red_team.credential_session_models import (
    CredentialSessionLimits,
    CredentialSessionState,
    credential_authorization_context_digest,
)
from vulnloom.red_team.credential_session_service import (
    CredentialSessionRejected,
    CredentialSessionService,
    CredentialSessionTimedOut,
)
from vulnloom.red_team.credential_session_store import CredentialSessionStore
from vulnloom.red_team.models import AuthorizedWebTarget
from vulnloom.red_team.test_identity_models import (
    TestIdentityAdmissionLimits as IdentityLimits,
)
from vulnloom.red_team.test_identity_models import (
    TestIdentityPurpose as IdentityPurpose,
)
from vulnloom.red_team.test_identity_service import (
    TestIdentityAdmissionService as IdentityService,
)
from vulnloom.red_team.test_identity_store import TestIdentityStore as IdentityStore

IDENTITY_REF = "1" * 64
CREDENTIAL_REF = "2" * 64
RESOURCE_REF = "3" * 64
EDITOR_ROLE = "role:editor-fixture"
READER_ROLE = "role:reader-fixture"
MATERIAL = b"fixture:business-flow-material"
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
            "allowed_identities": frozenset({IDENTITY_REF}),
            "allowed_test_classes": frozenset({"state_change"}),
        }
    )


def _approval(scope, target, action, now, approval_action):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=target.target_id,
        action=approval_action,
        action_digest=action.digest(),
        expected_side_effects=("local_fixture_publish_then_restore",),
        evidence_summary="Exact offline fixture mutation and identity context approved",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=10),
        status=ApprovalStatus.GRANTED,
        decided_by="security-owner",
        decided_at=now,
    )


def _runtime(
    approved_scope,
    now,
    *,
    role=EDITOR_ROLE,
    enforces_role_policy=True,
    valid_credential=True,
    session_clock=None,
    fail_after_restoration=False,
):
    scope = _scope(approved_scope)
    target = AuthorizedWebTarget(target_id=uuid4(), url="https://app.example.test/")
    identity_service = IdentityService(store=IdentityStore(_connection()))
    identity_service.issue_record(
        scope=scope,
        target=target,
        identity_ref=IDENTITY_REF,
        credential_ref=CREDENTIAL_REF,
        custody_proof_digest="4" * 64,
        issuer_ref="operator:security-owner",
        allowed_purposes=(IdentityPurpose.STATE_CHANGE_VALIDATION,),
        role_refs=(role,),
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        now=now,
    )
    admission_plan = identity_service.prepare(
        identity_ref=IDENTITY_REF,
        scope=scope,
        target=target,
        purposes=(IdentityPurpose.STATE_CHANGE_VALIDATION,),
        role_refs=(role,),
        limits=IdentityLimits(),
        now=now,
        deadline=now + timedelta(minutes=2),
        admission_expires_at=now + timedelta(minutes=30),
        idempotency_key="business-identity-admission",
    )
    identity_service.execute(admission_plan, scope=scope, target=target, now=now)
    admission = identity_service.store.admission(admission_plan.plan_id)
    action = ActionRequest(
        engagement_id=scope.engagement_id,
        target_id=target.target_id,
        action=OfflinePublicationFlowAdapter.ACTION_NAME,
        requested_at=now,
        url="https://app.example.test/fixture/draft",
        test_class="state_change",
        mutates_state=True,
        uses_real_credentials=True,
        authorization_context_digest=credential_authorization_context_digest(
            admission_id=admission.admission_id,
            identity_ref=admission.identity_ref,
            purpose=IdentityPurpose.STATE_CHANGE_VALIDATION,
            role_ref=role,
        ),
    )
    fixture = OfflinePublicationFixture.create(
        resource_ref=RESOURCE_REF,
        publisher_roles=(EDITOR_ROLE,),
        enforces_role_policy=enforces_role_policy,
    )
    adapter = OfflinePublicationFlowAdapter(
        fixture,
        credential_proofs={
            CREDENTIAL_REF: (
                hashlib.sha256(MATERIAL).digest()
                if valid_credential
                else b"\x00" * hashlib.sha256().digest_size
            )
        },
        fail_after_restoration=fail_after_restoration,
    )
    session_store = CredentialSessionStore(_connection())
    vault = OfflineCredentialVault({CREDENTIAL_REF: MATERIAL})
    session_service = CredentialSessionService(
        identity_service=identity_service,
        store=session_store,
        vault=vault,
        session_adapter=adapter,
        monotonic=session_clock or time.monotonic,
    )
    session_plan = session_service.prepare(
        admission_plan_id=admission_plan.plan_id,
        scope=scope,
        target=target,
        purpose=IdentityPurpose.STATE_CHANGE_VALIDATION,
        role_ref=role,
        action=action,
        limits=CredentialSessionLimits(),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="business-state-change-session",
    )
    approvals = tuple(
        _approval(scope, target, action, now, item)
        for item in (
            ApprovalAction.MUTATE_TARGET_STATE,
            ApprovalAction.USE_REAL_CREDENTIALS,
        )
    )
    business_service = BusinessInvariantService(
        identity_service=identity_service,
        session_store=session_store,
        execution_source=adapter,
        store=BusinessInvariantStore(_connection()),
    )
    business_plan = business_service.prepare(
        session_plan=session_plan,
        fixture=fixture,
        scope=scope,
        target=target,
        limits=BusinessInvariantLimits(),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="business-invariant-materialization",
    )
    return (
        scope,
        target,
        identity_service,
        session_service,
        vault,
        adapter,
        action,
        session_plan,
        approvals,
        business_service,
        business_plan,
    )


def _run_session(runtime, now):
    scope, target, _, service, _, _, action, plan, approvals, _, _ = runtime
    return service.execute(
        plan,
        scope=scope,
        target=target,
        action=action,
        approvals=approvals,
        now=now + timedelta(seconds=1),
    )


def test_authorized_mutation_is_observed_restored_and_materialized(approved_scope, now):
    runtime = _runtime(approved_scope, now)
    scope, target, _, _, _, adapter, _, session_plan, _, service, plan = runtime

    session_outcome = _run_session(runtime, now)
    outcome = service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=2))
    replay = service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=3))

    assert replay == outcome
    assert session_outcome.session.state_changed is True
    assert session_outcome.session.state_restored is True
    assert outcome.execution.observation.verdict is BusinessInvariantVerdict.UPHELD
    assert outcome.execution.before.state is PublicationState.DRAFT
    assert outcome.execution.mutated.state is PublicationState.PUBLISHED
    assert outcome.execution.restored.state is PublicationState.DRAFT
    assert (
        outcome.execution.before.semantic_digest
        == outcome.execution.restored.semantic_digest
    )
    assert outcome.execution.before.revision < outcome.execution.mutated.revision
    assert outcome.execution.mutated.revision < outcome.execution.restored.revision
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT
    assert adapter.result(session_plan.plan_id).restoration.restoration_verified
    assert service.store.state(plan.plan_id) == (BusinessInvariantState.COMPLETED, 1)
    serialized = "".join(
        service.store.connection.execute(
            "SELECT plan_json,outcome_json FROM red_team_business_invariants"
        ).fetchone()
    ).lower()
    assert "business-flow-material" not in serialized
    assert "password" not in serialized
    assert "cookie" not in serialized


def test_unenforced_role_policy_is_only_an_invariant_signal_and_is_restored(
    approved_scope, now
):
    runtime = _runtime(
        approved_scope,
        now,
        role=READER_ROLE,
        enforces_role_policy=False,
    )
    scope, target, _, _, _, adapter, _, _, _, service, plan = runtime
    _run_session(runtime, now)
    outcome = service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=2))

    observation = outcome.execution.observation
    assert observation.verdict is BusinessInvariantVerdict.VIOLATED
    assert observation.expected_authorized is False
    assert observation.candidate_created is False
    assert observation.finding_created is False
    assert observation.vulnerability_claimed is False
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT


def test_enforced_role_policy_refuses_mutation_and_publishes_nothing(approved_scope, now):
    runtime = _runtime(approved_scope, now, role=READER_ROLE, enforces_role_policy=True)
    scope, target, _, session_service, _, adapter, action, plan, approvals, service, _ = runtime

    with pytest.raises(Exception, match="enforced its role policy"):
        session_service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT
    assert session_service.store.state(plan.plan_id) == (CredentialSessionState.STARTED, 1)
    assert service.store.connection.execute(
        "SELECT COUNT(*) FROM red_team_business_invariants"
    ).fetchone()[0] == 0


def test_missing_mutation_approval_refuses_before_vault_or_state_change(approved_scope, now):
    runtime = _runtime(approved_scope, now)
    scope, target, _, service, vault, adapter, action, plan, approvals, _, _ = runtime

    with pytest.raises(CredentialSessionRejected, match="Approval"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=tuple(
                item for item in approvals if item.action is ApprovalAction.USE_REAL_CREDENTIALS
            ),
            now=now + timedelta(seconds=1),
        )
    assert vault.acquisitions == 0
    assert adapter.opens == 0
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT
    assert service.store.state(plan.plan_id) is None


def test_wrong_fixture_credential_refuses_before_mutation(approved_scope, now):
    runtime = _runtime(approved_scope, now, valid_credential=False)
    scope, target, _, service, vault, adapter, action, plan, approvals, _, _ = runtime

    with pytest.raises(Exception, match="fixture credential"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert vault.last_lease is not None and vault.last_lease.zeroed
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT


def test_timeout_after_mutation_compensates_and_leaves_started_checkpoint(
    approved_scope, now
):
    ticks = iter((0.0, 0.0, 0.0, 100.0))
    runtime = _runtime(approved_scope, now, session_clock=lambda: next(ticks))
    scope, target, _, service, vault, adapter, action, plan, approvals, _, _ = runtime

    with pytest.raises(CredentialSessionTimedOut):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT
    assert adapter.result(plan.plan_id).restoration.restoration_verified
    assert vault.last_lease is not None and vault.last_lease.zeroed
    assert service.store.state(plan.plan_id) == (CredentialSessionState.STARTED, 1)


def test_restoration_proof_interruption_still_zeroes_lease_and_restores_state(
    approved_scope, now
):
    runtime = _runtime(approved_scope, now, fail_after_restoration=True)
    scope, target, _, service, vault, adapter, action, plan, approvals, _, _ = runtime

    with pytest.raises(CredentialSessionRejected, match="cleanup failed closed"):
        service.execute(
            plan,
            scope=scope,
            target=target,
            action=action,
            approvals=approvals,
            now=now + timedelta(seconds=1),
        )
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT
    assert vault.last_lease is not None and vault.last_lease.zeroed
    assert service.store.state(plan.plan_id) == (CredentialSessionState.STARTED, 1)


def test_identity_revocation_blocks_materialization_after_clean_restoration(
    approved_scope, now
):
    runtime = _runtime(approved_scope, now)
    scope, target, identity_service, _, _, adapter, _, _, _, service, plan = runtime
    _run_session(runtime, now)
    identity_service.store.revoke(
        IDENTITY_REF,
        reason_digest="9" * 64,
        now=now + timedelta(milliseconds=1),
    )

    with pytest.raises(BusinessInvariantRejected, match="active Test Identity"):
        service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=2))
    assert adapter.current_snapshot(now=now).state is PublicationState.DRAFT
    assert service.store.state(plan.plan_id) is None


def test_materialization_timeout_and_bounded_recovery(approved_scope, now):
    runtime = _runtime(approved_scope, now)
    scope, target, _, _, _, _, _, _, _, service, plan = runtime
    _run_session(runtime, now)
    ticks = iter((0.0, 100.0, 0.0, 100.0, 0.0, 100.0))
    service.monotonic = lambda: next(ticks)

    with pytest.raises(BusinessInvariantTimedOut):
        service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=2))
    with pytest.raises(BusinessInvariantTimedOut):
        service.recover(plan, scope=scope, target=target, now=now + timedelta(seconds=3))
    with pytest.raises(BusinessInvariantTimedOut):
        service.recover(plan, scope=scope, target=target, now=now + timedelta(seconds=4))
    with pytest.raises(BusinessInvariantRecoveryRequired, match="exhausted"):
        service.recover(plan, scope=scope, target=target, now=now + timedelta(seconds=5))
    assert service.store.state(plan.plan_id) == (BusinessInvariantState.STARTED, 3)


def test_schema_cannot_promote_signal_or_carry_secrets(approved_scope, now):
    *_, plan = _runtime(approved_scope, now)
    payload = plan.model_dump(mode="python")
    payload["candidate_authorized"] = True
    payload["plan_id"] = "0" * 64
    with pytest.raises(ValidationError):
        BusinessInvariantPlan.model_validate(payload)

    schemas = json.dumps(
        {
            "plan": BusinessInvariantPlan.model_json_schema(),
            "fixture": OfflinePublicationFixture.model_json_schema(),
        }
    ).lower()
    for forbidden in (
        "password",
        "cookie",
        "username",
        "credential_value",
        "session_token",
        "model_token",
    ):
        assert forbidden not in schemas
