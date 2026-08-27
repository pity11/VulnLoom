"""Offline-testable Scope policy engine.

This layer performs preflight checks. Network adapters must additionally pin
resolved IPs and re-evaluate every redirect at connection time.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AwareDatetime

from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    DomainModel,
    Scope,
    ScopeState,
)


class DecisionEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class ActionRequest(DomainModel):
    engagement_id: UUID
    target_id: UUID | None = None
    action: str
    requested_at: AwareDatetime
    repository_url: str | None = None
    repository_commit: str | None = None
    url: str | None = None
    test_class: str | None = None
    mutates_state: bool = False
    uses_real_credentials: bool = False
    external_callback: bool = False
    submits_report: bool = False
    runs_untrusted_build: bool = False

    def digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"requested_at"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


class Decision(DomainModel):
    effect: DecisionEffect
    reasons: tuple[str, ...]
    obligations: tuple[str, ...] = ()
    policy_digest: str


class PolicyEngine:
    def __init__(self, scope: Scope):
        self.scope = scope
        encoded = scope.model_dump_json(exclude_none=False).encode()
        self.policy_digest = hashlib.sha256(encoded).hexdigest()

    def decide(
        self,
        request: ActionRequest,
        approvals: tuple[ApprovalRequest, ...] = (),
    ) -> Decision:
        reasons: list[str] = []
        obligations: list[str] = []
        now = request.requested_at

        if self.scope.state is not ScopeState.APPROVED:
            reasons.append("scope_not_approved")
        if request.engagement_id != self.scope.engagement_id:
            reasons.append("engagement_mismatch")
        if not self.scope.valid_from <= now < self.scope.valid_until:
            reasons.append("scope_outside_validity_window")
        if request.action in self.scope.denied_actions:
            reasons.append("action_explicitly_denied")
        if request.test_class and request.test_class not in self.scope.allowed_test_classes:
            reasons.append("test_class_not_allowed")

        if request.repository_url is not None:
            matched = any(
                repo.url == request.repository_url and repo.commit == request.repository_commit
                for repo in self.scope.repositories
            )
            if not matched:
                reasons.append("repository_or_commit_out_of_scope")

        if request.url is not None:
            parsed = urlsplit(request.url)
            if parsed.username or parsed.password or not parsed.hostname:
                reasons.append("invalid_or_credentialed_url")
            else:
                scheme = parsed.scheme.lower()
                port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else 0)
                matched_network = any(
                    parsed.hostname.lower() == target.host.lower()
                    and scheme in target.schemes
                    and port in target.ports
                    for target in self.scope.network_targets
                )
                if not matched_network:
                    reasons.append("network_target_out_of_scope")
                else:
                    obligations.extend(("resolve_and_pin_ip", "recheck_each_redirect"))

        if request.repository_url is None and request.url is None:
            reasons.append("target_boundary_not_supplied")

        if reasons:
            return Decision(
                effect=DecisionEffect.DENY,
                reasons=tuple(reasons),
                obligations=tuple(obligations),
                policy_digest=self.policy_digest,
            )

        required = self._required_approvals(request)
        missing = tuple(
            action.value
            for action in required
            if not any(
                approval.engagement_id == request.engagement_id
                and approval.target_id == request.target_id
                and approval.policy_version == self.scope.version
                and approval.is_valid_for(action=action, digest=request.digest(), now=now)
                for approval in approvals
            )
        )
        if missing:
            return Decision(
                effect=DecisionEffect.APPROVAL_REQUIRED,
                reasons=tuple(f"missing_approval:{item}" for item in missing),
                obligations=tuple(obligations),
                policy_digest=self.policy_digest,
            )

        return Decision(
            effect=DecisionEffect.ALLOW,
            reasons=("scope_policy_satisfied",),
            obligations=tuple(obligations),
            policy_digest=self.policy_digest,
        )

    def _required_approvals(self, request: ActionRequest) -> frozenset[ApprovalAction]:
        required: set[ApprovalAction] = set()
        flags = {
            ApprovalAction.MUTATE_TARGET_STATE: request.mutates_state,
            ApprovalAction.USE_REAL_CREDENTIALS: request.uses_real_credentials,
            ApprovalAction.EXTERNAL_CALLBACK: request.external_callback,
            ApprovalAction.SUBMIT_REPORT: request.submits_report,
            ApprovalAction.RUN_UNTRUSTED_BUILD: request.runs_untrusted_build,
        }
        required.update(action for action, enabled in flags.items() if enabled)
        required.update(self.scope.approval_requirements)
        return frozenset(required)
