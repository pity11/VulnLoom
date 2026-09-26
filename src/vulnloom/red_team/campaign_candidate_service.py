"""Human-gated B5.6 materializer for proposed Campaign Candidates."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, Scope, ScopeState

from .campaign_candidate_models import (
    CampaignCandidate,
    CampaignCandidateIntakeLimits,
    CampaignCandidateIntakeOutcome,
    CampaignCandidateIntakePlan,
)
from .campaign_candidate_store import CampaignCandidateIntakeStore
from .campaign_orchestration_models import (
    CampaignEvidenceClosureDisposition,
    CampaignOrchestrationOutcome,
    CampaignOrchestrationPlan,
)
from .evidence_requirement_models import (
    EvidenceAssessmentOutcome,
    EvidenceAssessmentPlan,
    EvidenceAssessmentVerdict,
)


class CampaignOrchestrationOutcomeSource(Protocol):
    def plan(self, plan_id: str) -> CampaignOrchestrationPlan: ...

    def outcome(self, plan_id: str) -> CampaignOrchestrationOutcome: ...


class CampaignCandidateEvidenceSource(Protocol):
    def plan(self, plan_id: str) -> EvidenceAssessmentPlan: ...

    def outcome(self, plan_id: str) -> EvidenceAssessmentOutcome: ...


class CampaignCandidateIntakeRejected(ValueError):
    pass


class CampaignCandidateIntakeTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CampaignCandidateIntakeTimedOut("Campaign Candidate Intake timed out")


class CampaignCandidateIntakeService:
    def __init__(
        self,
        *,
        orchestration_source: CampaignOrchestrationOutcomeSource,
        evidence_source: CampaignCandidateEvidenceSource,
        store: CampaignCandidateIntakeStore,
        monotonic: Callable[[], float] = time.monotonic,
        after_claim: Callable[[], None] | None = None,
    ) -> None:
        self.orchestration_source = orchestration_source
        self.evidence_source = evidence_source
        self.store = store
        self.monotonic = monotonic
        self.after_claim = after_claim

    def prepare(
        self,
        *,
        orchestration_plan_id: str,
        scope: Scope,
        limits: CampaignCandidateIntakeLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CampaignCandidateIntakePlan:
        orchestration_plan, orchestration_outcome, assessment_plan, assessment_outcome = self._read(
            orchestration_plan_id
        )
        self._validate_sources(
            orchestration_plan,
            orchestration_outcome,
            assessment_plan,
            assessment_outcome,
            scope=scope,
            now=now,
        )
        stop_at = min(deadline, scope.valid_until)
        if not now < stop_at:
            raise CampaignCandidateIntakeRejected("Campaign Candidate Intake deadline is invalid")
        closure = orchestration_outcome.closure
        requirement = assessment_plan.requirement
        target_id = orchestration_plan.evidence_target_id
        target_version = orchestration_plan.evidence_target_version
        return CampaignCandidateIntakePlan.create(
            orchestration_plan_id=orchestration_plan.orchestration_plan_id,
            orchestration_plan_digest=canonical_digest(
                orchestration_plan.model_dump(mode="python")
            ),
            orchestration_outcome_digest=canonical_digest(
                orchestration_outcome.model_dump(mode="python")
            ),
            closure_id=closure.closure_id,
            assessment_plan_id=assessment_plan.plan_id,
            assessment_plan_digest=canonical_digest(assessment_plan.model_dump(mode="python")),
            assessment_id=assessment_outcome.assessment.assessment_id,
            assessment_outcome_digest=canonical_digest(
                assessment_outcome.model_dump(mode="python")
            ),
            candidate_id=uuid5(NAMESPACE_URL, f"vulnloom:campaign-candidate:{closure.closure_id}"),
            target_id=target_id,
            target_version=target_version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            vulnerability_class=requirement.vulnerability_class,
            cwe=requirement.cwe,
            hypothesis_digest=orchestration_plan.goal_id,
            evidence_refs=closure.evidence_refs,
            duplicate_fingerprint=canonical_digest(
                {
                    "target_id": target_id,
                    "target_version": target_version,
                    "vulnerability_class": requirement.vulnerability_class,
                    "cwe": requirement.cwe,
                }
            ),
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: CampaignCandidateIntakePlan,
        *,
        approval: ApprovalRequest,
        scope: Scope,
        now: datetime,
    ) -> CampaignCandidateIntakeOutcome:
        authoritative = CampaignCandidateIntakePlan.model_validate(plan.model_dump(mode="python"))
        sources = self._read(authoritative.orchestration_plan_id)
        self._validate_sources(*sources, scope=scope, now=now)
        self._validate_plan(authoritative, *sources)
        if not authoritative.created_at <= now < authoritative.deadline:
            raise CampaignCandidateIntakeTimedOut("Campaign Candidate Intake Plan is not active")
        if (
            approval.engagement_id != scope.engagement_id
            or approval.target_id != authoritative.target_id
            or approval.policy_version != scope.version
            or approval.expected_side_effects != ("create proposed campaign candidate",)
            or approval.decided_at is None
            or not authoritative.created_at <= approval.decided_at <= now < approval.expires_at
            or not approval.is_valid_for(
                action=ApprovalAction.CREATE_CAMPAIGN_CANDIDATE,
                digest=authoritative.intake_plan_id,
                now=now,
            )
        ):
            raise CampaignCandidateIntakeRejected("Campaign Candidate Intake Approval is invalid")
        deadline = _Deadline(authoritative.limits.timeout_seconds, self.monotonic)
        deadline.check()
        claim = self.store.claim(authoritative, now=now)
        if claim.outcome is not None:
            return claim.outcome
        if self.after_claim is not None:
            self.after_claim()
        candidate = CampaignCandidate.create(
            candidate_id=authoritative.candidate_id,
            target_id=authoritative.target_id,
            target_version=authoritative.target_version,
            scope_id=authoritative.scope_id,
            scope_version=authoritative.scope_version,
            vulnerability_class=authoritative.vulnerability_class,
            cwe=authoritative.cwe,
            hypothesis_digest=authoritative.hypothesis_digest,
            duplicate_fingerprint=authoritative.duplicate_fingerprint,
            orchestration_plan_id=authoritative.orchestration_plan_id,
            closure_id=authoritative.closure_id,
            assessment_id=authoritative.assessment_id,
            evidence_refs=authoritative.evidence_refs,
            created_at=approval.decided_at,
        )
        deadline.check()
        outcome = CampaignCandidateIntakeOutcome.create(
            intake_plan_id=authoritative.intake_plan_id,
            approval_id=approval.approval_id,
            candidate=candidate,
            attempt=claim.attempt,
            completed_at=now,
        )
        deadline.check()
        self.store.complete(authoritative, outcome)
        return outcome

    def _read(self, orchestration_plan_id):
        try:
            plan = self.orchestration_source.plan(orchestration_plan_id)
            outcome = self.orchestration_source.outcome(orchestration_plan_id)
            assessment_plan = self.evidence_source.plan(plan.evidence_assessment_plan_id)
            assessment_outcome = self.evidence_source.outcome(plan.evidence_assessment_plan_id)
            return plan, outcome, assessment_plan, assessment_outcome
        except (KeyError, LookupError) as exc:
            raise CampaignCandidateIntakeRejected(
                "Campaign Candidate Intake authoritative source is unavailable"
            ) from exc

    @staticmethod
    def _validate_sources(
        orchestration_plan,
        orchestration_outcome,
        assessment_plan,
        assessment_outcome,
        *,
        scope,
        now,
    ):
        closure = orchestration_outcome.closure
        assessment = assessment_outcome.assessment
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
            or orchestration_plan.scope_id != scope.scope_id
            or orchestration_plan.scope_version != scope.version
        ):
            raise CampaignCandidateIntakeRejected(
                "Campaign Candidate Intake requires a current approved Scope"
            )
        if (
            orchestration_outcome.orchestration_plan_id != orchestration_plan.orchestration_plan_id
            or closure.orchestration_plan_id != orchestration_plan.orchestration_plan_id
            or closure.disposition is not CampaignEvidenceClosureDisposition.UNRESOLVED_CANDIDATE
            or closure.assessment_verdict is not EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
            or not closure.unresolved_candidate_recorded
            or closure.candidate_created
            or closure.finding_created
            or not closure.cleanup_complete
            or not orchestration_outcome.campaign_completed
            or not orchestration_outcome.cleanup_complete
            or assessment_plan.plan_id != orchestration_plan.evidence_assessment_plan_id
            or canonical_digest(assessment_plan.model_dump(mode="python"))
            != orchestration_plan.evidence_assessment_plan_digest
            or assessment_outcome.plan_id != assessment_plan.plan_id
            or assessment.assessment_id != orchestration_plan.evidence_assessment_id
            or canonical_digest(assessment_outcome.model_dump(mode="python"))
            != orchestration_plan.evidence_assessment_outcome_digest
            or assessment.verdict is not EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
            or not assessment.candidate_proposal_eligible
            or not assessment.cleanup_requirement_satisfied
            or assessment.finding_authorized
            or assessment.test_execution_authorized
            or closure.evidence_assessment_id != assessment.assessment_id
            or closure.evidence_requirement_id != assessment.requirement_id
            or closure.evidence_refs != assessment.evidence_refs
            or assessment_plan.target_id != orchestration_plan.evidence_target_id
            or assessment_plan.target_version != orchestration_plan.evidence_target_version
        ):
            raise CampaignCandidateIntakeRejected(
                "Campaign Candidate Intake source binding is invalid"
            )

    @staticmethod
    def _validate_plan(
        plan,
        orchestration_plan,
        orchestration_outcome,
        assessment_plan,
        assessment_outcome,
    ):
        expected = {
            "orchestration_plan_id": orchestration_plan.orchestration_plan_id,
            "orchestration_plan_digest": canonical_digest(
                orchestration_plan.model_dump(mode="python")
            ),
            "orchestration_outcome_digest": canonical_digest(
                orchestration_outcome.model_dump(mode="python")
            ),
            "closure_id": orchestration_outcome.closure.closure_id,
            "assessment_plan_id": assessment_plan.plan_id,
            "assessment_plan_digest": canonical_digest(assessment_plan.model_dump(mode="python")),
            "assessment_id": assessment_outcome.assessment.assessment_id,
            "assessment_outcome_digest": canonical_digest(
                assessment_outcome.model_dump(mode="python")
            ),
            "target_id": orchestration_plan.evidence_target_id,
            "target_version": orchestration_plan.evidence_target_version,
            "scope_id": orchestration_plan.scope_id,
            "scope_version": orchestration_plan.scope_version,
            "vulnerability_class": assessment_plan.requirement.vulnerability_class,
            "cwe": assessment_plan.requirement.cwe,
            "hypothesis_digest": orchestration_plan.goal_id,
            "evidence_refs": orchestration_outcome.closure.evidence_refs,
            "duplicate_fingerprint": canonical_digest(
                {
                    "target_id": orchestration_plan.evidence_target_id,
                    "target_version": orchestration_plan.evidence_target_version,
                    "vulnerability_class": (assessment_plan.requirement.vulnerability_class),
                    "cwe": assessment_plan.requirement.cwe,
                }
            ),
        }
        if any(getattr(plan, key) != value for key, value in expected.items()):
            raise CampaignCandidateIntakeRejected(
                "Campaign Candidate Intake Plan source binding drifted"
            )
