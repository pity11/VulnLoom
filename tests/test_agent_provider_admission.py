from __future__ import annotations

import os
import stat
from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import (
    SUBPROCESS_HTTPS_ADAPTER_DIGEST,
    AgentProviderEgressAuthority,
    AgentProviderEgressConflict,
    AgentProviderEgressGrant,
    AgentProviderEgressIssuerPolicy,
    AgentProviderEgressPurpose,
    AgentProviderEgressRecoveryRequired,
    AgentProviderEgressRejected,
    AgentProviderEgressRevocation,
    AgentProviderEgressStatus,
    AgentProviderEgressStore,
    AgentProviderEgressTimedOut,
    AgentProviderTransportAdmission,
    AgentProviderTransportLimits,
    AgentProviderTransportMode,
)
from vulnloom.domain.digests import canonical_digest


def _admission():
    return AgentProviderTransportAdmission.create_live_https(
        provider_id="provider",
        hostname="api.provider.example",
        request_path="/v1/responses",
        credential_reference_id="a" * 64,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        limits=AgentProviderTransportLimits(),
    )


def _policy(*, providers=("provider",), lifetime=3600):
    return AgentProviderEgressIssuerPolicy.create(
        issuer_id="security-operator",
        allowed_provider_ids=providers,
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=lifetime,
    )


def _issue(tmp_path, now, *, policy=None, store=None, clock=None):
    policy = policy or _policy()
    store = store or AgentProviderEgressStore(tmp_path / "egress")
    authority = AgentProviderEgressAuthority(
        store=store,
        issuer_policies=(policy,),
        **({} if clock is None else {"clock": clock}),
    )
    admission = _admission()
    grant = authority.issue(
        admission=admission,
        issuer_policy_id=policy.policy_id,
        purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
        now=now,
        expires_at=now + timedelta(minutes=30),
        deadline=now + timedelta(seconds=10),
        idempotency_key="provider-egress:issue:1",
    )
    return admission, policy, store, authority, grant


def test_issued_grant_is_content_addressed_read_only_and_idempotent(tmp_path, now):
    admission, policy, store, authority, grant = _issue(tmp_path, now)

    path = store.objects / grant.grant_id
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert store.read_grant(grant.grant_id) == grant
    assert store.require_active(
        grant.grant_id, admission=admission, now=now + timedelta(seconds=1)
    ) == grant
    assert store.status_at(
        grant.grant_id, now=now + timedelta(seconds=1)
    )[0] is AgentProviderEgressStatus.ACTIVE
    replay = authority.issue(
        admission=admission,
        issuer_policy_id=policy.policy_id,
        purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
        now=now,
        expires_at=now + timedelta(minutes=30),
        deadline=now + timedelta(seconds=10),
        idempotency_key="provider-egress:issue:1",
    )
    assert replay == grant
    assert admission.hostname not in (tmp_path / "egress" / "ledger.sqlite3").read_text(
        encoding="latin-1"
    )
    store.close()


def test_issuance_policy_and_deadline_reject_before_checkpoint(tmp_path, now):
    policy = _policy(providers=("other",))
    store = AgentProviderEgressStore(tmp_path / "egress")
    authority = AgentProviderEgressAuthority(
        store=store, issuer_policies=(policy,)
    )

    with pytest.raises(AgentProviderEgressRejected, match="policy rejected"):
        authority.issue(
            admission=_admission(),
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(minutes=5),
            deadline=now + timedelta(seconds=1),
            idempotency_key="provider-egress:denied",
        )
    with pytest.raises(AgentProviderEgressTimedOut, match="deadline expired"):
        authority.issue(
            admission=_admission(),
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(minutes=5),
            deadline=now,
            idempotency_key="provider-egress:expired",
        )

    assert store.connection.execute(
        "SELECT count(*) FROM provider_egress_issuances"
    ).fetchone()[0] == 0
    store.close()


def test_revocation_is_content_addressed_and_immediately_fail_closed(tmp_path, now):
    admission, policy, store, authority, grant = _issue(tmp_path, now)
    revocation = authority.revoke(
        grant_id=grant.grant_id,
        issuer_policy_id=policy.policy_id,
        reason_digest=canonical_digest("operator-revoked"),
        now=now + timedelta(seconds=1),
        deadline=now + timedelta(seconds=5),
        idempotency_key="provider-egress:revoke:1",
    )

    assert store.read_revocation(revocation.revocation_id) == revocation
    assert stat.S_IMODE((store.objects / revocation.revocation_id).stat().st_mode) == 0o400
    with pytest.raises(AgentProviderEgressRejected, match="revoked"):
        store.require_active(
            grant.grant_id, admission=admission, now=now + timedelta(seconds=2)
        )
    assert store.status_at(
        grant.grant_id, now=now + timedelta(seconds=2)
    )[0] is AgentProviderEgressStatus.REVOKED
    assert authority.revoke(
        grant_id=grant.grant_id,
        issuer_policy_id=policy.policy_id,
        reason_digest=canonical_digest("operator-revoked"),
        now=now + timedelta(seconds=1),
        deadline=now + timedelta(seconds=5),
        idempotency_key="provider-egress:revoke:1",
    ) == revocation
    store.close()


def test_expired_or_tampered_grant_is_rejected_on_every_read(tmp_path, now):
    admission, _, store, _, grant = _issue(tmp_path, now)
    with pytest.raises(AgentProviderEgressRejected, match="expired"):
        store.require_active(
            grant.grant_id,
            admission=admission,
            now=grant.expires_at,
        )
    assert store.status_at(
        grant.grant_id, now=grant.expires_at
    )[0] is AgentProviderEgressStatus.EXPIRED

    path = store.objects / grant.grant_id
    path.chmod(0o600)
    with pytest.raises(AgentProviderEgressRejected, match="unsafe"):
        store.require_active(
            grant.grant_id, admission=admission, now=now + timedelta(seconds=1)
        )
    store.close()


def test_symlink_grant_and_binding_drift_are_rejected(tmp_path, now):
    admission, _, store, _, grant = _issue(tmp_path, now)
    drifted = AgentProviderTransportAdmission.create_live_https(
        provider_id="provider",
        hostname="different.provider.example",
        request_path="/v1/responses",
        credential_reference_id="a" * 64,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        limits=AgentProviderTransportLimits(),
    )
    with pytest.raises(AgentProviderEgressRejected, match="binding mismatch"):
        store.require_active(
            grant.grant_id, admission=drifted, now=now + timedelta(seconds=1)
        )

    path = store.objects / grant.grant_id
    safe_copy = tmp_path / "grant-copy"
    safe_copy.write_bytes(path.read_bytes())
    path.unlink()
    os.symlink(safe_copy, path)
    with pytest.raises(AgentProviderEgressRejected, match="unsafe"):
        store.require_active(
            grant.grant_id, admission=admission, now=now + timedelta(seconds=1)
        )
    store.close()


def test_idempotency_conflict_and_unfinished_issuance_require_recovery(tmp_path, now):
    admission, policy, store, authority, _ = _issue(tmp_path, now)
    with pytest.raises(AgentProviderEgressConflict, match="idempotency key"):
        authority.issue(
            admission=admission,
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(minutes=20),
            deadline=now + timedelta(seconds=5),
            idempotency_key="provider-egress:issue:1",
        )

    clock_values = iter((0.0, 2.0))
    timed_authority = AgentProviderEgressAuthority(
        store=store,
        issuer_policies=(policy,),
        clock=lambda: next(clock_values),
    )
    with pytest.raises(AgentProviderEgressTimedOut, match="timed out"):
        timed_authority.issue(
            admission=admission,
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(minutes=10),
            deadline=now + timedelta(seconds=1),
            idempotency_key="provider-egress:unfinished",
        )
    with pytest.raises(AgentProviderEgressRecoveryRequired, match="unfinished STARTED"):
        AgentProviderEgressAuthority(
            store=store, issuer_policies=(policy,), clock=lambda: 0.0
        ).issue(
            admission=admission,
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(minutes=10),
            deadline=now + timedelta(seconds=1),
            idempotency_key="provider-egress:unfinished",
        )
    store.close()


def test_unfinished_revocation_blocks_active_reads(tmp_path, now):
    admission, policy, store, _, grant = _issue(tmp_path, now)
    values = {
        "grant_id": grant.grant_id,
        "issuer_policy_id": policy.policy_id,
        "issuer_id": policy.issuer_id,
        "reason_digest": canonical_digest("pending revocation"),
        "revoked_at": now + timedelta(seconds=1),
        "idempotency_key": "provider-egress:pending-revocation:1",
    }
    revocation = AgentProviderEgressRevocation(
        revocation_id=canonical_digest(values), **values
    )
    assert store.claim_revoke(revocation).created

    with pytest.raises(AgentProviderEgressRecoveryRequired, match="unfinished STARTED"):
        store.require_active(
            grant.grant_id, admission=admission, now=now + timedelta(seconds=2)
        )
    store.close()


def test_publication_failure_cleans_temporary_object_and_requires_recovery(
    tmp_path, now, monkeypatch
):
    policy = _policy()
    store = AgentProviderEgressStore(tmp_path / "egress")
    authority = AgentProviderEgressAuthority(
        store=store, issuer_policies=(policy,)
    )

    def fail_replace(source, destination):
        raise OSError("sealed object publication failed")

    monkeypatch.setattr(
        "vulnloom.agent_runtime.provider_admission.os.replace", fail_replace
    )
    with pytest.raises(AgentProviderEgressRejected, match="publication failed"):
        authority.issue(
            admission=_admission(),
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(minutes=10),
            deadline=now + timedelta(seconds=5),
            idempotency_key="provider-egress:publication-failure:1",
        )

    assert not tuple(store.objects.glob("egress-*"))
    assert store.connection.execute(
        "SELECT state FROM provider_egress_issuances"
    ).fetchone()[0] == "started"
    store.close()


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"mode": AgentProviderTransportMode.ADMISSION_FAKE}, "no-network"),
        ({"expires_at": "issued"}, "lifetime"),
        (
            {"purpose": AgentProviderEgressPurpose.LOOPBACK_ADMISSION_PROBE},
            "purpose and mode",
        ),
        ({"idempotency_key": "bad\x00key"}, "contains NUL"),
        ({"grant_id": "0" * 64}, "digest mismatch"),
    ],
)
def test_grant_schema_rejects_permission_and_integrity_drift(
    tmp_path, now, updates, message
):
    _, _, store, _, grant = _issue(tmp_path, now)
    values = grant.model_dump(mode="python")
    if updates.get("expires_at") == "issued":
        updates = {**updates, "expires_at": grant.issued_at}
    values.update(updates)
    if "grant_id" not in updates:
        values["grant_id"] = canonical_digest(
            {key: value for key, value in values.items() if key != "grant_id"}
        )

    with pytest.raises(ValidationError, match=message):
        AgentProviderEgressGrant.model_validate(values)
    store.close()
