"""Approval-gated deterministic review of an M8.9-selected local Report."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    Evidence,
    EvidenceBundle,
    ScopeState,
)

from .execution_models import AgentReportDraftExecutionPlan
from .models import domain_object_digest
from .review import HumanReportReviewService, ReportReviewRejected
from .review_execution_models import (
    REPORT_REVIEW_EFFECTS,
    AgentReportReviewExecutionPlan,
    AgentReportReviewOutcomeBinding,
    ReportReviewApprovalAction,
    agent_report_review_execution_plan_digest,
)
from .review_execution_store import AgentReportReviewExecutionStore
from .review_intake import AgentReportReviewIntakeRejected, AgentReportReviewIntakeService
from .review_intake_models import (
    AgentReportReviewIntakeDecision,
    AgentReportReviewIntakePlan,
    AgentReportReviewIntakeReason,
    agent_report_review_intake_record_digest,
)
from .review_models import ReportReviewCommand, ReportReviewPlan


class AgentReportReviewExecutionRejected(ValueError):
    pass


class AgentReportReviewExecutionTimedOut(TimeoutError):
    pass


class AgentReportReviewExecutionService:
    """Consumes accepted Intake plus exact human command and Approval."""

    def __init__(
        self,
        *,
        intake_service: AgentReportReviewIntakeService,
        review_service: HumanReportReviewService,
        store: AgentReportReviewExecutionStore,
    ):
        if review_service.scope != intake_service.scope:
            raise ValueError("Report review execution services use different Scope objects")
        if review_service.evidence_store.root != intake_service.evidence_store.root:
            raise ValueError("Report review execution services use different Evidence stores")
        if review_service.artifact_store.root != intake_service.artifact_store.root:
            raise ValueError("Report review execution services use different artifact stores")
        self.intake_service = intake_service
        self.review_service = review_service
        self.store = store
        self.scope = intake_service.scope

    def prepare(
        self,
        *,
        review_intake_plan: AgentReportReviewIntakePlan,
        draft_execution_plan: AgentReportDraftExecutionPlan,
        report_review_plan: ReportReviewPlan,
        report_review_command: ReportReviewCommand,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        approval: ApprovalRequest,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AgentReportReviewExecutionPlan:
        record, binding, outcome, action = self._load(
            review_intake_plan=review_intake_plan,
            draft_execution_plan=draft_execution_plan,
            report_review_plan=report_review_plan,
            report_review_command=report_review_command,
            evidence_bundle=evidence_bundle,
            evidence=evidence,
            approval=approval,
            now=now,
        )
        if (
            not now
            < deadline
            <= min(
                self.scope.valid_until,
                record.expires_at,
                report_review_plan.deadline,
                report_review_plan.approval_expires_at,
                approval.expires_at,
            )
        ):
            raise AgentReportReviewExecutionRejected(
                "Report review execution deadline exceeds active authority"
            )
        values = {
            "approval_action_id": action.action_id,
            "approval_id": approval.approval_id,
            "approval_digest": domain_object_digest(approval),
            "review_intake_plan_id": review_intake_plan.intake_plan_id,
            "review_intake_record_id": record.record_id,
            "review_intake_record_digest": agent_report_review_intake_record_digest(record),
            "draft_execution_plan_id": draft_execution_plan.execution_plan_id,
            "draft_outcome_binding_id": binding.binding_id,
            "report_review_plan_id": report_review_plan.plan_id,
            "report_review_plan_digest": domain_object_digest(report_review_plan),
            "report_review_command_id": report_review_command.command_id,
            "report_review_command_digest": domain_object_digest(report_review_command),
            "report_id": outcome.report.report_id,
            "report_digest": domain_object_digest(outcome.report),
            "artifact_digest": domain_object_digest(outcome.artifact),
            "decision": report_review_command.decision,
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentReportReviewExecutionPlan.create(**values)

    def execute(
        self,
        plan: AgentReportReviewExecutionPlan,
        *,
        review_intake_plan: AgentReportReviewIntakePlan,
        draft_execution_plan: AgentReportDraftExecutionPlan,
        report_review_plan: ReportReviewPlan,
        report_review_command: ReportReviewCommand,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        approval: ApprovalRequest,
        now: datetime,
    ) -> AgentReportReviewOutcomeBinding:
        try:
            AgentReportReviewExecutionPlan.model_validate(plan)
        except ValidationError as exc:
            raise AgentReportReviewExecutionRejected(
                "Report review execution plan drifted"
            ) from exc
        if now < plan.created_at or now >= plan.deadline:
            raise AgentReportReviewExecutionTimedOut(
                "Report review execution is outside its window"
            )
        record, _draft_binding, draft_outcome, _action = self._load(
            review_intake_plan=review_intake_plan,
            draft_execution_plan=draft_execution_plan,
            report_review_plan=report_review_plan,
            report_review_command=report_review_command,
            evidence_bundle=evidence_bundle,
            evidence=evidence,
            approval=approval,
            now=now,
        )
        expected = self.prepare(
            review_intake_plan=review_intake_plan,
            draft_execution_plan=draft_execution_plan,
            report_review_plan=report_review_plan,
            report_review_command=report_review_command,
            evidence_bundle=evidence_bundle,
            evidence=evidence,
            approval=approval,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan or plan.execution_plan_id != agent_report_review_execution_plan_digest(
            plan
        ):
            raise AgentReportReviewExecutionRejected("Report review execution plan drifted")
        if not self.store.has_checkpoint(
            plan.execution_plan_id
        ) and self.review_service.store.has_checkpoint(report_review_plan.plan_id):
            raise AgentReportReviewExecutionRejected(
                "Report review checkpoint predates accepted execution"
            )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            return claim.binding
        if self.review_service.store.has_checkpoint(report_review_plan.plan_id):
            raise AgentReportReviewExecutionRejected(
                "Report review checkpoint predates accepted execution"
            )
        try:
            outcome = self.review_service.review(
                draft_outcome.report,
                draft_outcome.artifact,
                evidence_bundle,
                evidence,
                report_review_plan,
                report_review_command,
                now=now,
            )
        except (ReportReviewRejected, ValueError, RuntimeError) as exc:
            raise AgentReportReviewExecutionRejected(
                "Deterministic Report review execution failed"
            ) from exc
        persisted = self.review_service.store.load_completed(report_review_plan.plan_id)
        if (
            persisted != outcome
            or self.review_service.artifact_store.read_report(outcome.artifact) != outcome.report
            or outcome.review.command_id != report_review_command.command_id
            or outcome.review.decision is not report_review_command.decision
        ):
            raise AgentReportReviewExecutionRejected("Report review outcome drifted")
        values = {
            "execution_plan_id": plan.execution_plan_id,
            "approval_action_id": plan.approval_action_id,
            "approval_id": plan.approval_id,
            "approval_digest": plan.approval_digest,
            "review_intake_record_id": record.record_id,
            "report_review_plan_id": report_review_plan.plan_id,
            "report_review_command_id": report_review_command.command_id,
            "report_review_outcome_digest": domain_object_digest(outcome),
            "report_id": outcome.report.report_id,
            "source_report_digest": domain_object_digest(draft_outcome.report),
            "resulting_report_digest": domain_object_digest(outcome.report),
            "resulting_artifact_digest": domain_object_digest(outcome.artifact),
            "review_id": outcome.review.review_id,
            "review_digest": domain_object_digest(outcome.review),
            "decision": outcome.review.decision,
            "resulting_status": outcome.report.review_status,
            "completed_at": now,
        }
        binding = AgentReportReviewOutcomeBinding(binding_id=canonical_digest(values), **values)
        self.store.complete(binding)
        return binding

    def approval_action(
        self,
        *,
        record,
        report_review_plan: ReportReviewPlan,
        report_review_command: ReportReviewCommand,
    ) -> ReportReviewApprovalAction:
        return ReportReviewApprovalAction.create(
            engagement_id=self.scope.engagement_id,
            review_intake_record_id=record.record_id,
            review_intake_record_digest=agent_report_review_intake_record_digest(record),
            report_review_plan_id=report_review_plan.plan_id,
            report_review_plan_digest=domain_object_digest(report_review_plan),
            report_review_command_id=report_review_command.command_id,
            report_review_command_digest=domain_object_digest(report_review_command),
            report_id=report_review_command.report_id,
            report_digest=report_review_command.report_digest,
            artifact_digest=record.artifact_digest,
            decision=report_review_command.decision,
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            expected_side_effects=REPORT_REVIEW_EFFECTS[report_review_command.decision],
        )

    def _load(
        self,
        *,
        review_intake_plan,
        draft_execution_plan,
        report_review_plan,
        report_review_command,
        evidence_bundle,
        evidence,
        approval,
        now,
    ):
        try:
            AgentReportReviewIntakePlan.model_validate(review_intake_plan)
            ReportReviewCommand.model_validate(report_review_command)
            ApprovalRequest.model_validate(approval)
            record = self.intake_service.store.load_completed(review_intake_plan.intake_plan_id)
            binding, outcome = self.intake_service.load_authoritative(
                draft_execution_plan=draft_execution_plan,
                report_review_plan=report_review_plan,
                evidence_bundle=evidence_bundle,
                evidence=evidence,
                now=now,
            )
        except (
            ValueError,
            RuntimeError,
            ValidationError,
            AgentReportReviewIntakeRejected,
        ) as exc:
            raise AgentReportReviewExecutionRejected(
                "Report review authoritative input unavailable"
            ) from exc
        action = self.approval_action(
            record=record,
            report_review_plan=report_review_plan,
            report_review_command=report_review_command,
        )
        report = outcome.report
        if (
            self.scope.state is not ScopeState.APPROVED
            or record.decision is not AgentReportReviewIntakeDecision.ACCEPT
            or record.reason_code is not AgentReportReviewIntakeReason.HUMAN_ACCEPTED_EXACT_REVIEW
            or not record.decided_at <= now < record.expires_at
            or record.intake_plan_id != review_intake_plan.intake_plan_id
            or record.draft_execution_plan_id != draft_execution_plan.execution_plan_id
            or record.draft_outcome_binding_id != binding.binding_id
            or record.report_review_plan_id != report_review_plan.plan_id
            or record.report_review_plan_digest != domain_object_digest(report_review_plan)
            or record.report_id != report.report_id
            or record.report_digest != domain_object_digest(report)
            or record.artifact_digest != domain_object_digest(outcome.artifact)
            or report_review_command.plan_id != report_review_plan.plan_id
            or report_review_command.report_id != report.report_id
            or report_review_command.report_digest != domain_object_digest(report)
            or report_review_command.reviewer != report_review_plan.reviewer
            or not record.decided_at
            <= report_review_command.decided_at
            <= now
            < report_review_plan.deadline
            or approval.status is not ApprovalStatus.GRANTED
            or approval.action is not ApprovalAction.REVIEW_REPORT
            or approval.action_digest != action.action_id
            or approval.target_id is not None
            or approval.policy_version != self.scope.version
            or approval.expected_side_effects != action.expected_side_effects
            or not approval.decided_by
            or approval.decided_at is None
            or not record.decided_at <= approval.decided_at <= now < approval.expires_at
        ):
            raise AgentReportReviewExecutionRejected(
                "Report review Intake, command, or Approval drifted"
            )
        return record, binding, outcome, action
