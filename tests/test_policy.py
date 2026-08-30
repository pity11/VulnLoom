from __future__ import annotations

from datetime import timedelta

from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus, Scope
from vulnloom.policy.engine import ActionRequest, DecisionEffect, PolicyEngine


def _request(approved_scope, now, **updates):
    values = {
        "engagement_id": approved_scope.engagement_id,
        "target_id": None,
        "action": "http.request",
        "requested_at": now,
        "url": "https://app.example.test/invoices/42",
        "test_class": "read_only",
    }
    values.update(updates)
    return ActionRequest(**values)


def test_allows_exact_scoped_network_target(approved_scope, now):
    decision = PolicyEngine(approved_scope).decide(_request(approved_scope, now))
    assert decision.effect is DecisionEffect.ALLOW
    assert "resolve_and_pin_ip" in decision.obligations


def test_policy_digest_survives_scope_boundary_reparse(approved_scope):
    reparsed = Scope.model_validate(approved_scope.model_dump(mode="python"))
    assert PolicyEngine(reparsed).policy_digest == PolicyEngine(approved_scope).policy_digest


def test_fails_closed_for_unknown_host(approved_scope, now):
    request = _request(approved_scope, now, url="https://public.example/invoices/42")
    decision = PolicyEngine(approved_scope).decide(request)
    assert decision.effect is DecisionEffect.DENY
    assert "network_target_out_of_scope" in decision.reasons


def test_expired_scope_is_denied(approved_scope, now):
    request = _request(approved_scope, now + timedelta(days=1))
    assert PolicyEngine(approved_scope).decide(request).effect is DecisionEffect.DENY


def test_state_change_requires_action_bound_approval(approved_scope, now):
    request = _request(approved_scope, now, mutates_state=True)
    engine = PolicyEngine(approved_scope)
    assert engine.decide(request).effect is DecisionEffect.APPROVAL_REQUIRED

    approval = ApprovalRequest(
        engagement_id=approved_scope.engagement_id,
        action=ApprovalAction.MUTATE_TARGET_STATE,
        action_digest=request.digest(),
        expected_side_effects=("create test invoice",),
        evidence_summary="Validation plan reviewed",
        policy_version=approved_scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="reviewer",
        decided_at=now,
    )
    assert engine.decide(request, (approval,)).effect is DecisionEffect.ALLOW


def test_approval_cannot_be_reused_for_changed_action(approved_scope, now):
    original = _request(approved_scope, now, mutates_state=True)
    changed = _request(
        approved_scope, now, mutates_state=True, url="https://app.example.test/other"
    )
    approval = ApprovalRequest(
        engagement_id=approved_scope.engagement_id,
        action=ApprovalAction.MUTATE_TARGET_STATE,
        action_digest=original.digest(),
        expected_side_effects=("one scoped write",),
        evidence_summary="Reviewed original action",
        policy_version=approved_scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
    )
    assert (
        PolicyEngine(approved_scope).decide(changed, (approval,)).effect
        is DecisionEffect.APPROVAL_REQUIRED
    )


def test_repository_commit_is_pinned(approved_scope, now):
    allowed = ActionRequest(
        engagement_id=approved_scope.engagement_id,
        action="source.read",
        requested_at=now,
        repository_url="https://example.test/app.git",
        repository_commit="a" * 40,
        test_class="read_only",
    )
    assert PolicyEngine(approved_scope).decide(allowed).effect is DecisionEffect.ALLOW
    changed = allowed.model_copy(update={"repository_commit": "b" * 40})
    assert PolicyEngine(approved_scope).decide(changed).effect is DecisionEffect.DENY


def test_credentialed_and_unbounded_requests_are_denied(approved_scope, now):
    engine = PolicyEngine(approved_scope)
    credentialed = _request(
        approved_scope,
        now,
        url="https://user:password@app.example.test/invoices/42",
    )
    unbounded = ActionRequest(
        engagement_id=approved_scope.engagement_id,
        action="sandbox.exec",
        requested_at=now,
    )
    assert engine.decide(credentialed).effect is DecisionEffect.DENY
    assert engine.decide(unbounded).effect is DecisionEffect.DENY
