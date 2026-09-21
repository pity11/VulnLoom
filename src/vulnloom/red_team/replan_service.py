"""Control-plane admission for observation-driven bounded replanning."""

from __future__ import annotations

from datetime import datetime, timedelta

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, Scope
from vulnloom.policy import ActionRequest, DecisionEffect, PolicyEngine

from .models import RedTeamActionKind, RedTeamReconAction, RedTeamReconCommand
from .replan_models import (
    RedTeamReplanAdmission,
    RedTeamReplanProposal,
    RedTeamReplanToolView,
)
from .service import RedTeamReconAdapter, RedTeamRejected, RedTeamService
from .store import RedTeamStore


class RedTeamReplanRejected(ValueError):
    pass


class RedTeamReplanningService:
    def __init__(self, *, store: RedTeamStore):
        self.store = store
        self.flow_service = RedTeamService(store=store)

    def issue_tool_view(
        self,
        *,
        flow_plan_id: str,
        scope: Scope,
        now: datetime,
        ttl_seconds: int = 300,
    ) -> RedTeamReplanToolView:
        if not 0 < ttl_seconds <= 300:
            raise RedTeamReplanRejected("Red Team replan Tool View TTL is invalid")
        plan = self.store.plan(flow_plan_id)
        checkpoint = self.store.latest(flow_plan_id)
        self.flow_service._preflight_running(plan, checkpoint, scope, now)
        if not checkpoint.observation_ids:
            raise RedTeamReplanRejected("Red Team replanning requires an Observation")
        self._verify_observations(plan.plan_id, checkpoint.observation_ids)
        remaining = self.store.remaining_action_budget(plan.plan_id)
        if remaining < 1:
            raise RedTeamReplanRejected("Red Team replan action budget is exhausted")
        kinds = [RedTeamActionKind.HTTP_HEAD]
        if plan.target.url.startswith("https://"):
            kinds.append(RedTeamActionKind.TLS_INSPECT)
        view = RedTeamReplanToolView.create(
            flow_plan_id=plan.plan_id,
            checkpoint_id=checkpoint.checkpoint_id,
            target_id=plan.target.target_id,
            target_url_digest=canonical_digest(plan.target.url),
            scope_id=scope.scope_id,
            scope_version=scope.version,
            observation_ids=tuple(sorted(checkpoint.observation_ids)),
            allowed_action_kinds=tuple(sorted(kinds, key=str)),
            allowed_test_classes=plan.rules.allowed_test_classes,
            remaining_actions=remaining,
            issued_at=now,
            expires_at=min(now + timedelta(seconds=ttl_seconds), plan.deadline),
        )
        return self.store.put_replan_tool_view(view)

    def admit(
        self,
        *,
        proposal: RedTeamReplanProposal,
        scope: Scope,
        now: datetime,
    ) -> RedTeamReplanAdmission:
        try:
            existing = self.store.replan_admission_for_proposal(proposal)
            if existing is not None:
                plan = self.store.plan(existing.flow_plan_id)
                self.flow_service._scope_binding(plan, scope)
                return existing
            view = self.store.replan_tool_view(proposal.tool_view_id)
            plan = self.store.plan(view.flow_plan_id)
            checkpoint = self.store.latest(plan.plan_id)
        except ValueError as exc:
            raise RedTeamReplanRejected("Red Team replan authority is unavailable") from exc
        self.flow_service._preflight_running(plan, checkpoint, scope, now)
        if (
            checkpoint.checkpoint_id != view.checkpoint_id
            or not view.issued_at <= proposal.proposed_at <= now < view.expires_at
            or proposal.source_observation_ids != view.observation_ids
            or proposal.action_kind not in view.allowed_action_kinds
            or proposal.test_class not in view.allowed_test_classes
            or view.target_id != plan.target.target_id
            or view.target_url_digest != canonical_digest(plan.target.url)
            or view.scope_id != scope.scope_id
            or view.scope_version != scope.version
        ):
            raise RedTeamReplanRejected("Red Team replan proposal exceeds its Tool View")
        self._verify_observations(plan.plan_id, proposal.source_observation_ids)
        action = RedTeamReconAction.create(
            plan_id=plan.plan_id,
            expected_checkpoint_id=checkpoint.checkpoint_id,
            kind=proposal.action_kind,
            target_url=plan.target.url,
            test_class=proposal.test_class,
            created_at=now,
            deadline=min(now + timedelta(seconds=proposal.ttl_seconds), view.expires_at),
            idempotency_key=f"red-team:replan:{proposal.idempotency_key}",
        )
        policy_request = ActionRequest(
            engagement_id=scope.engagement_id,
            target_id=plan.target.target_id,
            action=f"red_team.replan.{action.kind.value}",
            requested_at=now,
            url=action.target_url,
            test_class=action.test_class,
        )
        if PolicyEngine(scope).decide(policy_request).effect is not DecisionEffect.ALLOW:
            raise RedTeamReplanRejected("Red Team replanned action was denied by policy")
        command = RedTeamReconCommand.create(action=action, attempt=1)
        admission = RedTeamReplanAdmission.create(
            proposal_id=proposal.proposal_id,
            tool_view_id=view.tool_view_id,
            flow_plan_id=plan.plan_id,
            source_checkpoint_id=checkpoint.checkpoint_id,
            source_observation_ids=proposal.source_observation_ids,
            command=command,
            policy_request_digest=policy_request.digest(),
            required_approval_digest=action.action_id,
            admitted_at=now,
        )
        try:
            return self.store.admit_replan(proposal, admission)
        except ValueError as exc:
            raise RedTeamReplanRejected("Red Team replan admission was rejected") from exc

    def execute(
        self,
        *,
        admission: RedTeamReplanAdmission,
        command: RedTeamReconCommand,
        approval: ApprovalRequest,
        scope: Scope,
        adapter: RedTeamReconAdapter,
        now: datetime,
    ):
        try:
            authoritative = self.store.replan_admission(admission.admission_id)
        except ValueError as exc:
            raise RedTeamReplanRejected("Red Team replan admission is unavailable") from exc
        if (
            authoritative != admission
            or command.action != admission.command.action
            or command.attempt < admission.command.attempt
            or approval.engagement_id != scope.engagement_id
        ):
            raise RedTeamReplanRejected("Red Team replanned execution binding is invalid")
        plan = self.store.plan(admission.flow_plan_id)
        if approval.target_id != plan.target.target_id or not approval.is_valid_for(
            action=ApprovalAction.EXECUTE_RED_TEAM_ACTION,
            digest=admission.required_approval_digest,
            now=now,
        ) or (
            approval.policy_version != scope.version
            or approval.decided_by is None
            or approval.decided_at is None
        ):
            raise RedTeamReplanRejected("Red Team replanned action lacks exact Approval")
        policy_request = ActionRequest(
            engagement_id=scope.engagement_id,
            target_id=plan.target.target_id,
            action=f"red_team.replan.{command.action.kind.value}",
            requested_at=admission.admitted_at,
            url=command.action.target_url,
            test_class=command.action.test_class,
        )
        if (
            policy_request.digest() != admission.policy_request_digest
            or PolicyEngine(scope).decide(policy_request, (approval,)).effect
            is not DecisionEffect.ALLOW
            or self.store.replan_admission_state(admission.admission_id)
            not in {"reserved", "consumed"}
        ):
            raise RedTeamReplanRejected("Red Team replanned policy binding drifted")
        try:
            return self.flow_service.execute_recon(
                command=command, scope=scope, adapter=adapter, now=now
            )
        except RedTeamRejected as exc:
            raise RedTeamReplanRejected(str(exc)) from exc

    def cancel(
        self,
        *,
        admission: RedTeamReplanAdmission,
        scope: Scope,
        now: datetime,
    ) -> None:
        self._release(admission=admission, scope=scope, now=now, state="cancelled")

    def expire(
        self,
        *,
        admission: RedTeamReplanAdmission,
        scope: Scope,
        now: datetime,
    ) -> None:
        if now < admission.command.action.deadline:
            raise RedTeamReplanRejected("Red Team replan admission has not expired")
        self._release(admission=admission, scope=scope, now=now, state="expired")

    def _release(
        self,
        *,
        admission: RedTeamReplanAdmission,
        scope: Scope,
        now: datetime,
        state: str,
    ) -> None:
        try:
            authoritative = self.store.replan_admission(admission.admission_id)
            plan = self.store.plan(admission.flow_plan_id)
        except ValueError as exc:
            raise RedTeamReplanRejected("Red Team replan admission is unavailable") from exc
        self.flow_service._scope_binding(plan, scope)
        if authoritative != admission or now < admission.admitted_at:
            raise RedTeamReplanRejected("Red Team replan release binding is invalid")
        try:
            self.store.release_replan_admission(admission.admission_id, state=state)
        except ValueError as exc:
            raise RedTeamReplanRejected("Red Team replan admission is not releasable") from exc

    def _verify_observations(self, plan_id: str, observation_ids: tuple[str, ...]) -> None:
        for observation_id in observation_ids:
            observation = self.store.observation(observation_id)
            action = self.store.action(observation.action_id)
            if action.plan_id != plan_id or action.action_id != observation.action_id:
                raise RedTeamReplanRejected("Red Team replan Observation provenance drifted")
