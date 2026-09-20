"""Fail-closed promotion from authoritative Hybrid evidence to a Finding."""

from __future__ import annotations

from datetime import datetime

from vulnloom.critic import CriticStore, domain_object_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    CriticVerdict,
    Scope,
    ScopeState,
)
from vulnloom.domain.state_machine import TransitionRejected, promote_candidate
from vulnloom.evidence import EvidenceStore
from vulnloom.findings import DuplicateCheckResult, FindingDuplicateCheck
from vulnloom.validation import ValidationStore

from .finding_models import (
    HYBRID_FINDING_SIDE_EFFECTS,
    HybridFindingPromotionOutcome,
    HybridFindingPromotionPlan,
    HybridFindingState,
    hybrid_finding_approval_digest,
)
from .finding_store import HybridFindingPromotionStore
from .models import HybridCheckKind, HybridConclusion, HybridRunState
from .store import HybridValidationStore


class HybridFindingPromotionRejected(ValueError):
    pass


class HybridFindingPromotionService:
    def __init__(
        self,
        *,
        scope: Scope,
        hybrid_store: HybridValidationStore,
        validation_store: ValidationStore,
        critic_store: CriticStore,
        evidence_store: EvidenceStore,
        store: HybridFindingPromotionStore,
    ):
        self.scope = scope
        self.hybrid_store = hybrid_store
        self.validation_store = validation_store
        self.critic_store = critic_store
        self.evidence_store = evidence_store
        self.store = store

    def execute(
        self,
        *,
        plan: HybridFindingPromotionPlan,
        duplicate_check: FindingDuplicateCheck,
        approval: ApprovalRequest,
        now: datetime,
        recover: bool = False,
    ) -> HybridFindingPromotionOutcome:
        chain, candidate, run, review = self._preflight(
            plan=plan,
            duplicate_check=duplicate_check,
            approval=approval,
            now=now,
        )
        approval_digest = domain_object_digest(approval)
        claim_args = {
            "approval_id": approval.approval_id,
            "approval_digest": approval_digest,
            "now": now,
        }
        claim = (
            self.store.recover(plan, **claim_args)
            if recover
            else self.store.claim(plan, **claim_args)
        )
        if not claim.created:
            assert claim.outcome is not None
            if (
                claim.outcome.approval_id != approval.approval_id
                or claim.outcome.approval_digest != approval_digest
            ):
                raise HybridFindingPromotionRejected(
                    "Hybrid Finding Approval receipt drifted"
                )
            if claim.outcome.state is HybridFindingState.COMPLETED:
                self._verify_evidence(chain.evidence_bundle.evidence_refs)
            return claim.outcome
        if now >= plan.deadline:
            return self._terminal(
                plan,
                attempt=claim.attempt,
                state=HybridFindingState.TIMED_OUT,
                reason_code="hybrid_finding_deadline_elapsed",
                now=now,
                approval=approval,
            )
        try:
            promoted, finding = promote_candidate(
                candidate,
                scope=self.scope,
                now=now,
                root_cause=plan.root_cause,
                affected_versions=plan.affected_versions,
                impact=plan.impact,
                severity_assessment=plan.severity_assessment,
                validation_runs=(run,),
                evidence_bundle=chain.evidence_bundle,
                critic_review=review,
                duplicate_checked=True,
                finding_id=plan.finding_id,
            )
        except TransitionRejected:
            return self._terminal(
                plan,
                attempt=claim.attempt,
                state=HybridFindingState.FAILED,
                reason_code="hybrid_finding_transition_rejected",
                now=now,
                approval=approval,
            )
        return self._terminal(
            plan,
            attempt=claim.attempt,
            state=HybridFindingState.COMPLETED,
            reason_code="hybrid_finding_promoted",
            now=now,
            approval=approval,
            source_candidate_digest=domain_object_digest(candidate),
            promoted_candidate=promoted,
            finding=finding,
        )

    def _preflight(self, *, plan, duplicate_check, approval, now):
        try:
            authoritative = self.hybrid_store.outcome_by_chain(plan.hybrid_chain_id)
            assert authoritative.chain is not None
            chain = authoritative.chain
            _validation_plan, validation = self.validation_store.load_completed(
                chain.validation_plan_id
            )
            critic_plan, critic = self.critic_store.load_completed(plan.critic_plan_id)
        except (AssertionError, ValueError, RuntimeError) as exc:
            raise HybridFindingPromotionRejected(
                "Hybrid Finding authoritative checkpoint is unavailable"
            ) from exc
        candidate = critic.candidate
        run = validation.validation_run
        review = critic.review
        self._verify_evidence(chain.evidence_bundle.evidence_refs)
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or now < plan.created_at
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
            or authoritative.state is not HybridRunState.COMPLETED
            or chain.check_kind is not HybridCheckKind.INITIAL
            or chain.conclusion is not HybridConclusion.CONFIRMED
            or plan.hybrid_chain_digest != domain_object_digest(chain)
            or chain.scope_id != self.scope.scope_id
            or chain.scope_version != self.scope.version
            or chain.candidate_id != candidate.candidate_id
            or chain.source_target_id != candidate.target_id
            or chain.source_target_version != candidate.target_version
            or chain.validation_run_id != run.run_id
            or critic_plan.plan_id != plan.critic_plan_id
            or plan.critic_outcome_digest != domain_object_digest(critic)
            or critic.plan_id != critic_plan.plan_id
            or critic_plan.candidate_id != candidate.candidate_id
            or critic_plan.candidate_digest != domain_object_digest(
                validation.candidate
            )
            or critic_plan.validation_run_id != run.run_id
            or critic_plan.validation_run_digest != domain_object_digest(run)
            or critic_plan.evidence_bundle_id != chain.evidence_bundle.bundle_id
            or critic_plan.evidence_bundle_digest != domain_object_digest(chain.evidence_bundle)
            or validation.candidate.candidate_id != candidate.candidate_id
            or validation.candidate.target_id != candidate.target_id
            or validation.candidate.target_version != candidate.target_version
            or run.candidate_id != candidate.candidate_id
            or not set(run.evidence_refs) <= set(chain.evidence_bundle.evidence_refs)
            or review.plan_id != critic_plan.plan_id
            or review.candidate_id != candidate.candidate_id
            or review.evidence_bundle_id != chain.evidence_bundle.bundle_id
            or review.validation_run_id != run.run_id
            or review.verdict is not CriticVerdict.ACCEPTED
            or candidate.state is not CandidateState.CRITIC_REVIEWED
            or plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != domain_object_digest(candidate)
            or plan.duplicate_check_id != duplicate_check.check_id
            or plan.duplicate_check_digest != domain_object_digest(duplicate_check)
            or duplicate_check.result is not DuplicateCheckResult.CLEAR
            or duplicate_check.candidate_id != candidate.candidate_id
            or duplicate_check.candidate_digest != domain_object_digest(candidate)
            or duplicate_check.target_version_digest
            != canonical_digest(candidate.target_version)
            or duplicate_check.scope_id != self.scope.scope_id
            or duplicate_check.scope_version != self.scope.version
            or not duplicate_check.checked_at <= now < duplicate_check.expires_at
            or candidate.target_version not in plan.affected_versions
        ):
            raise HybridFindingPromotionRejected("Hybrid Finding promotion provenance failed")
        if (
            approval.status is not ApprovalStatus.GRANTED
            or approval.action is not ApprovalAction.MUTATE_TARGET_STATE
            or approval.action_digest != hybrid_finding_approval_digest(plan)
            or approval.engagement_id != self.scope.engagement_id
            or approval.target_id != candidate.target_id
            or approval.policy_version != self.scope.version
            or approval.expected_side_effects != HYBRID_FINDING_SIDE_EFFECTS
            or approval.decided_by is None
            or approval.decided_at is None
            or not plan.created_at <= approval.decided_at <= now < approval.expires_at
        ):
            raise HybridFindingPromotionRejected("Hybrid Finding promotion Approval failed")
        return chain, candidate, run, review

    def _verify_evidence(self, refs: tuple[str, ...]) -> None:
        if not refs or any(not self.evidence_store.contains(ref) for ref in refs):
            raise HybridFindingPromotionRejected("Hybrid Finding Evidence integrity failed")

    def _terminal(
        self,
        plan,
        *,
        attempt,
        state,
        reason_code,
        now,
        approval,
        source_candidate_digest=None,
        promoted_candidate=None,
        finding=None,
    ):
        outcome = HybridFindingPromotionOutcome(
            plan_id=plan.plan_id,
            state=state,
            attempt=attempt,
            hybrid_chain_id=plan.hybrid_chain_id,
            approval_id=approval.approval_id,
            approval_digest=domain_object_digest(approval),
            source_candidate_digest=source_candidate_digest,
            promoted_candidate=promoted_candidate,
            finding=finding,
            reason_code=reason_code,
            cleanup_complete=True,
            completed_at=now,
        )
        self.store.finish(outcome)
        return outcome
