from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ScopeState
from vulnloom.red_team.models import AuthorizedWebTarget
from vulnloom.red_team.test_identity_models import (
    TestIdentityAdmission as IdentityAdmission,
)
from vulnloom.red_team.test_identity_models import (
    TestIdentityAdmissionLimits as IdentityAdmissionLimits,
)
from vulnloom.red_team.test_identity_models import (
    TestIdentityAdmissionPlan as IdentityAdmissionPlan,
)
from vulnloom.red_team.test_identity_models import (
    TestIdentityAdmissionState as IdentityAdmissionState,
)
from vulnloom.red_team.test_identity_models import (
    TestIdentityPurpose as IdentityPurpose,
)
from vulnloom.red_team.test_identity_models import (
    TestIdentityRecord as IdentityRecord,
)
from vulnloom.red_team.test_identity_service import (
    TestIdentityAdmissionRejected as IdentityAdmissionRejected,
)
from vulnloom.red_team.test_identity_service import (
    TestIdentityAdmissionService as IdentityAdmissionService,
)
from vulnloom.red_team.test_identity_service import (
    TestIdentityAdmissionTimedOut as IdentityAdmissionTimedOut,
)
from vulnloom.red_team.test_identity_store import (
    TestIdentityRecoveryRequired as IdentityRecoveryRequired,
)
from vulnloom.red_team.test_identity_store import (
    TestIdentityStore as IdentityStore,
)
from vulnloom.red_team.test_identity_store import (
    TestIdentityStoreRejected as IdentityStoreRejected,
)

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


def _scope(approved_scope, *, identity_ref=IDENTITY_REF):
    return approved_scope.model_copy(
        update={
            "allowed_identities": frozenset({identity_ref}),
            "allowed_test_classes": frozenset(
                {"authentication", "read_only", "state_change"}
            ),
        }
    )


def _target(*, target_id=None, url="https://app.example.test/"):
    return AuthorizedWebTarget(target_id=target_id or uuid4(), url=url)


def _service(*, monotonic=None):
    connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(connection)
    kwargs = {"store": IdentityStore(connection)}
    if monotonic is not None:
        kwargs["monotonic"] = monotonic
    return IdentityAdmissionService(**kwargs)


def _record(service, scope, target, now, *, purposes=None, roles=None):
    return service.issue_record(
        scope=scope,
        target=target,
        identity_ref=IDENTITY_REF,
        credential_ref=CREDENTIAL_REF,
        custody_proof_digest="3" * 64,
        issuer_ref="operator:security-owner",
        allowed_purposes=purposes
        or (
            IdentityPurpose.AUTHENTICATION,
            IdentityPurpose.READ_ONLY_ROLE_OBSERVATION,
            IdentityPurpose.STATE_CHANGE_VALIDATION,
        ),
        role_refs=roles or (ROLE_READER, ROLE_EDITOR),
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        now=now,
    )


def _plan(service, scope, target, now, *, purposes=None, roles=None, key="identity-1"):
    return service.prepare(
        identity_ref=IDENTITY_REF,
        scope=scope,
        target=target,
        purposes=purposes
        or (
            IdentityPurpose.AUTHENTICATION,
            IdentityPurpose.READ_ONLY_ROLE_OBSERVATION,
        ),
        role_refs=roles or (ROLE_READER,),
        limits=IdentityAdmissionLimits(),
        now=now,
        deadline=now + timedelta(minutes=2),
        admission_expires_at=now + timedelta(minutes=30),
        idempotency_key=key,
    )


def test_controlled_identity_admission_is_opaque_non_executable_and_idempotent(
    approved_scope, now
):
    scope = _scope(approved_scope)
    target = _target()
    service = _service()
    record = _record(service, scope, target, now)
    plan = _plan(service, scope, target, now)

    outcome = service.execute(plan, scope=scope, target=target, now=now)
    replay = service.execute(plan, scope=scope, target=target, now=now)
    admission = service.store.admission(plan.plan_id)
    active = service.active_admission(
        plan.plan_id,
        scope=scope,
        target=target,
        now=now + timedelta(minutes=3),
    )

    assert replay == outcome
    assert active == admission
    with pytest.raises(IdentityAdmissionRejected, match="binding drifted"):
        service.active_admission(
            plan.plan_id,
            scope=scope,
            target=target,
            now=now + timedelta(minutes=31),
        )
    assert admission.record_id == record.record_id
    assert admission.identity_ref == IDENTITY_REF
    assert admission.credential_ref == CREDENTIAL_REF
    assert admission.required_approvals == (ApprovalAction.USE_REAL_CREDENTIALS,)
    assert admission.credential_access_authorized is False
    assert admission.authentication_authorized is False
    assert admission.session_authorized is False
    assert admission.state_change_authorized is False
    assert admission.third_party_account_authorized is False
    assert outcome.credential_material_acquired is False
    assert outcome.secret_material_persisted is False
    assert outcome.session_created is False
    assert outcome.cleanup_complete is True
    assert service.store.admission_count() == 1

    serialized = record.model_dump_json() + plan.model_dump_json() + admission.model_dump_json()
    assert "password" not in serialized.lower()
    assert "cookie" not in serialized.lower()
    assert "token" not in serialized.lower()
    assert "username" not in serialized.lower()
    assert "vault" not in serialized.lower()


def test_state_change_purpose_only_declares_both_future_approvals(
    approved_scope, now
):
    scope = _scope(approved_scope)
    target = _target()
    service = _service()
    _record(service, scope, target, now)
    plan = _plan(
        service,
        scope,
        target,
        now,
        purposes=(IdentityPurpose.STATE_CHANGE_VALIDATION,),
        roles=(ROLE_EDITOR,),
    )

    service.execute(plan, scope=scope, target=target, now=now)
    admission = service.store.admission(plan.plan_id)

    assert admission.required_approvals == (
        ApprovalAction.MUTATE_TARGET_STATE,
        ApprovalAction.USE_REAL_CREDENTIALS,
    )
    assert admission.state_change_authorized is False


def test_scope_target_purpose_and_role_are_fail_closed(approved_scope, now):
    scope = _scope(approved_scope)
    target = _target()
    service = _service()
    _record(service, scope, target, now)

    with pytest.raises(IdentityAdmissionRejected, match="role"):
        _plan(service, scope, target, now, roles=("role:unknown",))
    with pytest.raises(IdentityAdmissionRejected, match="purpose"):
        _plan(
            service,
            scope.model_copy(
                update={"allowed_test_classes": frozenset({"read_only"})}
            ),
            target,
            now,
            purposes=(IdentityPurpose.AUTHENTICATION,),
        )
    with pytest.raises(IdentityAdmissionRejected, match="outside Scope"):
        service.issue_record(
            scope=scope,
            target=_target(url="https://outside.example.test/"),
            identity_ref=IDENTITY_REF,
            credential_ref=CREDENTIAL_REF,
            custody_proof_digest="3" * 64,
            issuer_ref="operator:security-owner",
            allowed_purposes=(IdentityPurpose.AUTHENTICATION,),
            role_refs=(ROLE_READER,),
            valid_from=now,
            valid_until=now + timedelta(minutes=5),
            now=now,
        )
    with pytest.raises(IdentityAdmissionRejected, match="not allowed by Scope"):
        service.issue_record(
            scope=scope,
            target=target,
            identity_ref="4" * 64,
            credential_ref="5" * 64,
            custody_proof_digest="6" * 64,
            issuer_ref="operator:security-owner",
            allowed_purposes=(IdentityPurpose.AUTHENTICATION,),
            role_refs=(ROLE_READER,),
            valid_from=now,
            valid_until=now + timedelta(minutes=5),
            now=now,
        )


def test_revocation_and_scope_drift_block_pending_admission(approved_scope, now):
    scope = _scope(approved_scope)
    target = _target()
    service = _service()
    record = _record(service, scope, target, now)
    plan = _plan(service, scope, target, now)
    revocation = service.store.revoke(
        IDENTITY_REF,
        reason_digest=canonical_digest("operator revoked fixture identity"),
        now=now + timedelta(seconds=1),
    )

    assert revocation.record_id == record.record_id
    assert revocation.credential_material_accessed is False
    with pytest.raises(IdentityAdmissionRejected, match="unavailable"):
        service.execute(plan, scope=scope, target=target, now=now + timedelta(seconds=1))
    assert service.store.admission_count() == 0

    second = _service()
    second_record = _record(second, scope, target, now)
    second_plan = _plan(second, scope, target, now)
    assert second_record.scope_version == scope.version
    with pytest.raises(IdentityAdmissionRejected, match="drifted"):
        second.execute(
            second_plan,
            scope=scope.model_copy(update={"version": scope.version + 1}),
            target=target,
            now=now,
        )
    with pytest.raises(IdentityAdmissionRejected, match="approved Scope"):
        second.execute(
            second_plan,
            scope=scope.model_copy(update={"state": ScopeState.REVOKED}),
            target=target,
            now=now,
        )


def test_revocation_immediately_invalidates_completed_admission(
    approved_scope, now
):
    scope = _scope(approved_scope)
    target = _target()
    service = _service()
    _record(service, scope, target, now)
    plan = _plan(service, scope, target, now)
    service.execute(plan, scope=scope, target=target, now=now)
    service.store.revoke(
        IDENTITY_REF,
        reason_digest=canonical_digest("fixture compromise response"),
        now=now + timedelta(seconds=1),
    )

    with pytest.raises(IdentityAdmissionRejected, match="unavailable"):
        service.active_admission(
            plan.plan_id,
            scope=scope,
            target=target,
            now=now + timedelta(seconds=1),
        )


def test_timeout_leaves_no_admission_and_explicit_recovery_completes(
    approved_scope, now
):
    ticks = iter((0.0, 11.0, 0.0, 0.0, 0.0))
    scope = _scope(approved_scope)
    target = _target()
    service = _service(monotonic=lambda: next(ticks))
    _record(service, scope, target, now)
    plan = _plan(service, scope, target, now)

    with pytest.raises(IdentityAdmissionTimedOut):
        service.execute(plan, scope=scope, target=target, now=now)
    assert service.store.state(plan.plan_id) == (
        IdentityAdmissionState.STARTED,
        1,
    )
    assert service.store.admission_count() == 0

    outcome = service.recover(plan, scope=scope, target=target, now=now)

    assert outcome.attempt == 2
    assert outcome.cleanup_complete is True
    assert service.store.admission_count() == 1


def test_recovery_attempts_are_bounded_and_never_publish_partial_admission(
    approved_scope, now
):
    ticks = iter((0.0, 11.0, 0.0, 11.0, 0.0, 11.0))
    scope = _scope(approved_scope)
    target = _target()
    service = _service(monotonic=lambda: next(ticks))
    _record(service, scope, target, now)
    plan = _plan(service, scope, target, now)

    with pytest.raises(IdentityAdmissionTimedOut):
        service.execute(plan, scope=scope, target=target, now=now)
    with pytest.raises(IdentityAdmissionTimedOut):
        service.recover(plan, scope=scope, target=target, now=now)
    with pytest.raises(IdentityAdmissionTimedOut):
        service.recover(plan, scope=scope, target=target, now=now)
    with pytest.raises(IdentityRecoveryRequired, match="exhausted"):
        service.recover(plan, scope=scope, target=target, now=now)
    assert service.store.admission_count() == 0


def test_schema_forbids_third_party_secret_and_execution_escalation(
    approved_scope, now
):
    scope = _scope(approved_scope)
    target = _target()
    service = _service()
    record = _record(service, scope, target, now)
    plan = _plan(service, scope, target, now)
    service.execute(plan, scope=scope, target=target, now=now)
    admission = service.store.admission(plan.plan_id)

    for model, field, value in (
        (record, "third_party_account", True),
        (record, "secret_material_absent", False),
        (plan, "credential_material_present", True),
        (plan, "authentication_authorized", True),
        (admission, "credential_access_authorized", True),
        (admission, "session_authorized", True),
        (admission, "state_change_authorized", True),
        (admission, "third_party_account_authorized", True),
    ):
        with pytest.raises(ValidationError):
            type(model).model_validate(model.model_dump(mode="python") | {field: value})

    schemas = json.dumps(
        {
            "record": IdentityRecord.model_json_schema(),
            "plan": IdentityAdmissionPlan.model_json_schema(),
            "admission": IdentityAdmission.model_json_schema(),
        }
    ).lower()
    for forbidden in ("password", "username", "cookie", "vault_path", "secret_value"):
        assert forbidden not in schemas


def test_registry_and_completion_identity_conflicts_are_rejected(
    approved_scope, now
):
    scope = _scope(approved_scope)
    target = _target()
    service = _service()
    record = _record(service, scope, target, now)
    conflicting = record.model_copy(update={"custody_proof_digest": "9" * 64})
    with pytest.raises(IdentityStoreRejected, match="conflicted"):
        service.store.register(conflicting)

    plan = _plan(service, scope, target, now)
    outcome = service.execute(plan, scope=scope, target=target, now=now)
    admission = service.store.admission(plan.plan_id)
    forged = admission.model_copy(update={"record_id": "8" * 64})
    with pytest.raises(IdentityStoreRejected, match="binding"):
        service.store.complete(plan, forged, outcome)
