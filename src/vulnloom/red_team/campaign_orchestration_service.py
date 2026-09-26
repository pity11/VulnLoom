"""Fail-closed B5.5 Campaign orchestration over authoritative typed facts."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, Scope, ScopeState

from .campaign_models import (
    CampaignGoalKind,
    CampaignPhaseKind,
    GoalDrivenCampaignPlan,
    GoalDrivenCampaignQualificationOutcome,
)
from .campaign_orchestration_models import (
    CampaignEvidenceClosure,
    CampaignEvidenceClosureDisposition,
    CampaignOrchestrationLimits,
    CampaignOrchestrationOutcome,
    CampaignOrchestrationPlan,
    CampaignPhaseCheckpoint,
    campaign_phase_admission_digest,
)
from .campaign_orchestration_store import CampaignOrchestrationStore
from .campaign_runtime_models import (
    CampaignRuntimeQualificationOutcome,
    CampaignRuntimeQualificationPlan,
)
from .evidence_requirement_models import (
    EvidenceAssessmentOutcome,
    EvidenceAssessmentPlan,
    EvidenceAssessmentVerdict,
    EvidenceRequirementStage,
)


class CampaignQualificationSource(Protocol):
    def plan(self, plan_id: str) -> GoalDrivenCampaignPlan: ...

    def outcome(self, plan_id: str) -> GoalDrivenCampaignQualificationOutcome: ...


class CampaignRuntimeSource(Protocol):
    def plan(self, plan_id: str) -> CampaignRuntimeQualificationPlan: ...

    def outcome(self, plan_id: str) -> CampaignRuntimeQualificationOutcome: ...


class CampaignEvidenceAssessmentSource(Protocol):
    def plan(self, plan_id: str) -> EvidenceAssessmentPlan: ...

    def outcome(self, plan_id: str) -> EvidenceAssessmentOutcome: ...


class CampaignOrchestrationRejected(ValueError):
    pass


class CampaignOrchestrationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CampaignOrchestrationTimedOut("Campaign Orchestration timed out")


class CampaignOrchestrationService:
    def __init__(
        self,
        *,
        campaign_source: CampaignQualificationSource,
        runtime_source: CampaignRuntimeSource,
        assessment_source: CampaignEvidenceAssessmentSource,
        store: CampaignOrchestrationStore,
        monotonic: Callable[[], float] = time.monotonic,
        after_phase: Callable[[CampaignPhaseCheckpoint], None] | None = None,
    ) -> None:
        self.campaign_source = campaign_source
        self.runtime_source = runtime_source
        self.assessment_source = assessment_source
        self.store = store
        self.monotonic = monotonic
        self.after_phase = after_phase

    def prepare(
        self,
        *,
        campaign_plan_id: str,
        runtime_plan_id: str,
        evidence_assessment_plan_id: str,
        scope: Scope,
        limits: CampaignOrchestrationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CampaignOrchestrationPlan:
        (
            campaign_plan,
            campaign_outcome,
            runtime_plan,
            runtime_outcome,
            assessment_plan,
            assessment_outcome,
        ) = self._read(campaign_plan_id, runtime_plan_id, evidence_assessment_plan_id)
        self._validate_sources(
            campaign_plan,
            campaign_outcome,
            runtime_plan,
            runtime_outcome,
            assessment_plan,
            assessment_outcome,
            scope=scope,
            now=now,
        )
        stop_at = min(deadline, campaign_plan.deadline, scope.valid_until)
        if not now < stop_at:
            raise CampaignOrchestrationRejected("Campaign Orchestration deadline is invalid")
        return CampaignOrchestrationPlan.create(
            campaign_plan_id=campaign_plan.campaign_plan_id,
            campaign_plan_digest=canonical_digest(campaign_plan.model_dump(mode="python")),
            campaign_outcome_id=campaign_outcome.outcome_id,
            campaign_outcome_digest=canonical_digest(campaign_outcome.model_dump(mode="python")),
            runtime_plan_id=runtime_plan.runtime_plan_id,
            runtime_plan_digest=canonical_digest(runtime_plan.model_dump(mode="python")),
            runtime_outcome_id=runtime_outcome.outcome_id,
            runtime_outcome_digest=canonical_digest(runtime_outcome.model_dump(mode="python")),
            goal_id=campaign_plan.goal.goal_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            target_ids=campaign_plan.target_ids,
            target_set_digest=canonical_digest(campaign_plan.target_ids),
            phase_ids=tuple(item.phase_id for item in campaign_plan.phases),
            phase_graph_digest=canonical_digest(
                tuple(item.model_dump(mode="python") for item in campaign_plan.phases)
            ),
            evidence_assessment_plan_id=assessment_plan.plan_id,
            evidence_assessment_plan_digest=canonical_digest(
                assessment_plan.model_dump(mode="python")
            ),
            evidence_assessment_id=assessment_outcome.assessment.assessment_id,
            evidence_assessment_outcome_digest=canonical_digest(
                assessment_outcome.model_dump(mode="python")
            ),
            evidence_requirement_id=assessment_outcome.assessment.requirement_id,
            evidence_target_id=assessment_plan.target_id,
            evidence_target_version=assessment_plan.target_version,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: CampaignOrchestrationPlan,
        *,
        approvals: tuple[ApprovalRequest, ...],
        scope: Scope,
        now: datetime,
    ) -> CampaignOrchestrationOutcome:
        authoritative = CampaignOrchestrationPlan.model_validate(plan.model_dump(mode="python"))
        sources = self._read(
            authoritative.campaign_plan_id,
            authoritative.runtime_plan_id,
            authoritative.evidence_assessment_plan_id,
        )
        self._validate_sources(*sources, scope=scope, now=now)
        self._validate_plan(authoritative, *sources)
        if not authoritative.created_at <= now < authoritative.deadline:
            raise CampaignOrchestrationRejected("Campaign Orchestration Plan is not active")
        ordered_approvals = self._approvals(authoritative, approvals, scope=scope, now=now)
        deadline = _Deadline(authoritative.limits.timeout_seconds, self.monotonic)
        deadline.check()
        claim = self.store.claim(authoritative, now=now)
        if claim.outcome is not None:
            return claim.outcome

        campaign_plan, _, _, runtime_outcome, assessment_plan, assessment_outcome = sources
        expected = self._checkpoints(
            authoritative,
            campaign_plan=campaign_plan,
            assessment_plan=assessment_plan,
            assessment_outcome=assessment_outcome,
            approvals=ordered_approvals,
            now=now,
        )
        if claim.checkpoints != expected[: len(claim.checkpoints)]:
            raise CampaignOrchestrationRejected("persisted Campaign Phase checkpoints drifted")
        for checkpoint in expected[len(claim.checkpoints) :]:
            deadline.check()
            self.store.record(authoritative, checkpoint)
            if self.after_phase is not None:
                self.after_phase(checkpoint)
        deadline.check()
        assessment = assessment_outcome.assessment
        disposition = {
            EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE: (
                CampaignEvidenceClosureDisposition.UNRESOLVED_CANDIDATE
            ),
            EvidenceAssessmentVerdict.NEGATIVE: CampaignEvidenceClosureDisposition.REFUTED,
            EvidenceAssessmentVerdict.INCONCLUSIVE: CampaignEvidenceClosureDisposition.INCONCLUSIVE,
        }[assessment.verdict]
        closure = CampaignEvidenceClosure.create(
            orchestration_plan_id=authoritative.orchestration_plan_id,
            campaign_plan_id=campaign_plan.campaign_plan_id,
            runtime_outcome_id=runtime_outcome.outcome_id,
            evidence_assessment_id=assessment.assessment_id,
            evidence_requirement_id=assessment.requirement_id,
            disposition=disposition,
            assessment_verdict=assessment.verdict,
            phase_checkpoint_ids=tuple(item.checkpoint_id for item in expected),
            evidence_refs=assessment.evidence_refs,
            unresolved_candidate_recorded=(
                assessment.verdict is EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
            ),
            closed_at=now,
        )
        outcome = CampaignOrchestrationOutcome(
            orchestration_plan_id=authoritative.orchestration_plan_id,
            closure=closure,
            attempt=claim.attempt,
        )
        deadline.check()
        self.store.complete(authoritative, outcome, now=now)
        return outcome

    def _read(self, campaign_plan_id, runtime_plan_id, assessment_plan_id):
        try:
            return (
                self.campaign_source.plan(campaign_plan_id),
                self.campaign_source.outcome(campaign_plan_id),
                self.runtime_source.plan(runtime_plan_id),
                self.runtime_source.outcome(runtime_plan_id),
                self.assessment_source.plan(assessment_plan_id),
                self.assessment_source.outcome(assessment_plan_id),
            )
        except (KeyError, LookupError) as exc:
            raise CampaignOrchestrationRejected(
                "Campaign Orchestration authoritative source is unavailable"
            ) from exc

    @staticmethod
    def _validate_sources(
        campaign_plan,
        campaign_outcome,
        runtime_plan,
        runtime_outcome,
        assessment_plan,
        assessment_outcome,
        *,
        scope,
        now,
    ):
        if (
            scope.state is not ScopeState.APPROVED
            or scope.scope_id != campaign_plan.scope_id
            or scope.version != campaign_plan.scope_version
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
        ):
            raise CampaignOrchestrationRejected(
                "Campaign Orchestration requires a current approved Scope"
            )
        if (
            campaign_plan.goal.kind is not CampaignGoalKind.EVIDENCE_REQUIREMENT_SATISFACTION
            or campaign_outcome.campaign_plan_id != campaign_plan.campaign_plan_id
            or campaign_outcome.goal_id != campaign_plan.goal.goal_id
            or not campaign_outcome.qualified
            or runtime_plan.campaign_plan_id != campaign_plan.campaign_plan_id
            or runtime_plan.campaign_outcome_id != campaign_outcome.outcome_id
            or runtime_plan.scope_id != scope.scope_id
            or runtime_plan.scope_version != scope.version
            or runtime_plan.target_set_digest != canonical_digest(campaign_plan.target_ids)
            or runtime_plan.required_phase_ids
            != tuple(item.phase_id for item in campaign_plan.phases)
            or runtime_plan.phase_graph_digest
            != canonical_digest(
                tuple(item.model_dump(mode="python") for item in campaign_plan.phases)
            )
            or runtime_plan.campaign_plan_digest
            != canonical_digest(campaign_plan.model_dump(mode="python"))
            or runtime_plan.campaign_outcome_digest
            != canonical_digest(campaign_outcome.model_dump(mode="python"))
            or runtime_outcome.runtime_plan_id != runtime_plan.runtime_plan_id
            or runtime_outcome.campaign_plan_id != campaign_plan.campaign_plan_id
            or runtime_outcome.campaign_outcome_id != campaign_outcome.outcome_id
            or not runtime_outcome.isolated_runtime_qualified
            or assessment_outcome.plan_id != assessment_plan.plan_id
            or assessment_outcome.assessment.plan_id != assessment_plan.plan_id
            or assessment_outcome.assessment.requirement_id
            != assessment_plan.requirement.requirement_id
            or assessment_plan.scope_id != scope.scope_id
            or assessment_plan.scope_version != scope.version
            or assessment_plan.target_id not in campaign_plan.target_ids
            or not assessment_outcome.cleanup_complete
            or not assessment_outcome.assessment.cleanup_requirement_satisfied
        ):
            raise CampaignOrchestrationRejected("Campaign Orchestration source binding is invalid")

    @staticmethod
    def _validate_plan(
        plan,
        campaign_plan,
        campaign_outcome,
        runtime_plan,
        runtime_outcome,
        assessment_plan,
        assessment_outcome,
    ):
        expected = {
            "campaign_plan_id": campaign_plan.campaign_plan_id,
            "campaign_plan_digest": canonical_digest(campaign_plan.model_dump(mode="python")),
            "campaign_outcome_id": campaign_outcome.outcome_id,
            "campaign_outcome_digest": canonical_digest(campaign_outcome.model_dump(mode="python")),
            "runtime_plan_id": runtime_plan.runtime_plan_id,
            "runtime_plan_digest": canonical_digest(runtime_plan.model_dump(mode="python")),
            "runtime_outcome_id": runtime_outcome.outcome_id,
            "runtime_outcome_digest": canonical_digest(runtime_outcome.model_dump(mode="python")),
            "goal_id": campaign_plan.goal.goal_id,
            "target_ids": campaign_plan.target_ids,
            "target_set_digest": canonical_digest(campaign_plan.target_ids),
            "phase_ids": tuple(item.phase_id for item in campaign_plan.phases),
            "evidence_requirement_id": assessment_plan.requirement.requirement_id,
            "evidence_target_id": assessment_plan.target_id,
            "evidence_target_version": assessment_plan.target_version,
            "evidence_assessment_plan_digest": canonical_digest(
                assessment_plan.model_dump(mode="python")
            ),
            "evidence_assessment_id": assessment_outcome.assessment.assessment_id,
            "evidence_assessment_outcome_digest": canonical_digest(
                assessment_outcome.model_dump(mode="python")
            ),
            "phase_graph_digest": canonical_digest(
                tuple(item.model_dump(mode="python") for item in campaign_plan.phases)
            ),
        }
        if any(getattr(plan, key) != value for key, value in expected.items()):
            raise CampaignOrchestrationRejected(
                "Campaign Orchestration Plan source binding drifted"
            )

    @staticmethod
    def _approvals(plan, approvals, *, scope, now):
        by_digest = {item.action_digest: item for item in approvals}
        if len(by_digest) != 6 or len(approvals) != 6:
            raise CampaignOrchestrationRejected(
                "Campaign Orchestration requires six distinct phase Approvals"
            )
        ordered = []
        for ordinal, phase_id in enumerate(plan.phase_ids, start=1):
            digest = campaign_phase_admission_digest(plan.orchestration_plan_id, phase_id, ordinal)
            approval = by_digest.get(digest)
            if (
                approval is None
                or approval.engagement_id != scope.engagement_id
                or approval.target_id not in (None, plan.evidence_target_id)
                or approval.policy_version != scope.version
                or not approval.is_valid_for(
                    action=ApprovalAction.ADVANCE_CAMPAIGN_PHASE,
                    digest=digest,
                    now=now,
                )
            ):
                raise CampaignOrchestrationRejected("Campaign Phase Approval is invalid")
            ordered.append(approval)
        decided = [item.decided_at for item in ordered]
        if (
            any(item is None or item > now for item in decided)
            or decided != sorted(decided)
            or len(set(decided)) != 6
        ):
            raise CampaignOrchestrationRejected(
                "Campaign Phase Approvals are not temporally ordered"
            )
        return tuple(ordered)

    @staticmethod
    def _checkpoints(
        plan,
        *,
        campaign_plan,
        assessment_plan,
        assessment_outcome,
        approvals,
        now,
    ):
        assertions = assessment_plan.assertions
        refs = {
            stage: tuple(sorted(item.assertion_id for item in assertions if item.stage is stage))
            for stage in EvidenceRequirementStage
        }
        phase_refs = {
            CampaignPhaseKind.SCOPE_CONFIRMATION: (
                canonical_digest(
                    {
                        "scope_id": plan.scope_id,
                        "scope_version": plan.scope_version,
                        "target_set_digest": plan.target_set_digest,
                    }
                ),
            ),
            CampaignPhaseKind.OBSERVATION: refs[EvidenceRequirementStage.OBSERVATION],
            CampaignPhaseKind.HYPOTHESIS: (plan.evidence_requirement_id,),
            CampaignPhaseKind.VALIDATION: refs[EvidenceRequirementStage.VALIDATION],
            CampaignPhaseKind.CRITIC_REVIEW: refs[EvidenceRequirementStage.CRITIC],
            CampaignPhaseKind.CLEANUP_CONFIRMATION: tuple(
                sorted(
                    (
                        *refs[EvidenceRequirementStage.CLEANUP],
                        assessment_outcome.assessment.assessment_id,
                    )
                )
            ),
        }
        return tuple(
            CampaignPhaseCheckpoint.create(
                orchestration_plan_id=plan.orchestration_plan_id,
                phase_id=phase.phase_id,
                phase_kind=phase.kind,
                ordinal=phase.ordinal,
                approval_id=approval.approval_id,
                approval_digest=approval.action_digest,
                evidence_refs=phase_refs[phase.kind],
                recorded_at=now,
            )
            for phase, approval in zip(campaign_plan.phases, approvals, strict=True)
        )
