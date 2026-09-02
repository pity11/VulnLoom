"""Approval-gated deterministic local export of an M8.11-selected Report."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus, ScopeState

from .export_execution_models import (
    REPORT_EXPORT_EFFECTS,
    AgentReportExportExecutionPlan,
    AgentReportExportOutcomeBinding,
    ReportExportApprovalAction,
    agent_report_export_execution_plan_digest,
)
from .export_execution_store import AgentReportExportExecutionStore
from .export_intake import AgentReportExportIntakeRejected, AgentReportExportIntakeService
from .export_intake_models import (
    AgentReportExportIntakeDecision,
    AgentReportExportIntakePlan,
    AgentReportExportIntakeReason,
    agent_report_export_intake_record_digest,
)
from .models import domain_object_digest
from .review import LocalReportExportService, ReportReviewRejected
from .review_execution_models import (
    AgentReportReviewExecutionPlan,
    agent_report_review_outcome_binding_digest,
)
from .review_models import ReportExportPlan


class AgentReportExportExecutionRejected(ValueError):
    pass


class AgentReportExportExecutionTimedOut(TimeoutError):
    pass


class AgentReportExportExecutionService:
    """Consumes accepted Intake and exact Approval for local export only."""

    def __init__(
        self,
        *,
        intake_service: AgentReportExportIntakeService,
        export_service: LocalReportExportService,
        store: AgentReportExportExecutionStore,
    ):
        if export_service.scope != intake_service.scope:
            raise ValueError("Report export execution services use different Scope objects")
        if export_service.artifact_store.root != intake_service.artifact_store.root:
            raise ValueError("Report export execution services use different artifact stores")
        self.intake_service = intake_service
        self.export_service = export_service
        self.store = store
        self.scope = intake_service.scope

    def prepare(
        self,
        *,
        export_intake_plan: AgentReportExportIntakePlan,
        review_execution_plan: AgentReportReviewExecutionPlan,
        report_export_plan: ReportExportPlan,
        approval: ApprovalRequest,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AgentReportExportExecutionPlan:
        record, binding, outcome, action = self._load(
            export_intake_plan=export_intake_plan,
            review_execution_plan=review_execution_plan,
            report_export_plan=report_export_plan,
            approval=approval,
            now=now,
        )
        if not now < deadline <= min(
            self.scope.valid_until,
            record.expires_at,
            outcome.review.expires_at,
            report_export_plan.deadline,
            approval.expires_at,
        ):
            raise AgentReportExportExecutionRejected(
                "Report export execution deadline exceeds active authority"
            )
        values = {
            "approval_action_id": action.action_id,
            "approval_id": approval.approval_id,
            "approval_digest": domain_object_digest(approval),
            "export_intake_plan_id": export_intake_plan.intake_plan_id,
            "export_intake_record_id": record.record_id,
            "export_intake_record_digest": agent_report_export_intake_record_digest(record),
            "review_execution_plan_id": review_execution_plan.execution_plan_id,
            "review_outcome_binding_id": binding.binding_id,
            "report_export_plan_id": report_export_plan.plan_id,
            "report_export_plan_digest": domain_object_digest(report_export_plan),
            "report_id": outcome.report.report_id,
            "report_digest": domain_object_digest(outcome.report),
            "artifact_digest": domain_object_digest(outcome.artifact),
            "review_id": outcome.review.review_id,
            "review_digest": domain_object_digest(outcome.review),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentReportExportExecutionPlan.create(**values)

    def execute(
        self,
        plan: AgentReportExportExecutionPlan,
        *,
        export_intake_plan: AgentReportExportIntakePlan,
        review_execution_plan: AgentReportReviewExecutionPlan,
        report_export_plan: ReportExportPlan,
        approval: ApprovalRequest,
        now: datetime,
    ) -> AgentReportExportOutcomeBinding:
        try:
            AgentReportExportExecutionPlan.model_validate(plan)
        except ValidationError as exc:
            raise AgentReportExportExecutionRejected(
                "Report export execution plan drifted"
            ) from exc
        if now < plan.created_at or now >= plan.deadline:
            raise AgentReportExportExecutionTimedOut(
                "Report export execution is outside its window"
            )
        record, _review_binding, review_outcome, _action = self._load(
            export_intake_plan=export_intake_plan,
            review_execution_plan=review_execution_plan,
            report_export_plan=report_export_plan,
            approval=approval,
            now=now,
        )
        expected = self.prepare(
            export_intake_plan=export_intake_plan,
            review_execution_plan=review_execution_plan,
            report_export_plan=report_export_plan,
            approval=approval,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan or plan.execution_plan_id != agent_report_export_execution_plan_digest(
            plan
        ):
            raise AgentReportExportExecutionRejected("Report export execution plan drifted")
        if not self.store.has_checkpoint(
            plan.execution_plan_id
        ) and self.export_service.store.has_checkpoint(report_export_plan.plan_id):
            raise AgentReportExportExecutionRejected(
                "Report export checkpoint predates accepted execution"
            )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            return claim.binding
        if self.export_service.store.has_checkpoint(report_export_plan.plan_id):
            raise AgentReportExportExecutionRejected(
                "Report export checkpoint predates accepted execution"
            )
        try:
            outcome = self.export_service.export(
                review_outcome.report,
                review_outcome.artifact,
                review_outcome.review,
                report_export_plan,
                now=now,
            )
        except (ReportReviewRejected, ValueError, RuntimeError) as exc:
            raise AgentReportExportExecutionRejected(
                "Deterministic local Report export failed"
            ) from exc
        persisted = self.export_service.store.load_completed(report_export_plan.plan_id)
        if (
            persisted != outcome
            or self.export_service.artifact_store.read_report(outcome.artifact)
            != outcome.report
            or outcome.review != review_outcome.review
        ):
            raise AgentReportExportExecutionRejected("Report export outcome drifted")
        values = {
            "execution_plan_id": plan.execution_plan_id,
            "approval_action_id": plan.approval_action_id,
            "approval_id": plan.approval_id,
            "approval_digest": plan.approval_digest,
            "export_intake_record_id": record.record_id,
            "report_export_plan_id": report_export_plan.plan_id,
            "report_export_outcome_digest": domain_object_digest(outcome),
            "report_id": outcome.report.report_id,
            "source_report_digest": domain_object_digest(review_outcome.report),
            "exported_report_digest": domain_object_digest(outcome.report),
            "exported_artifact_digest": domain_object_digest(outcome.artifact),
            "review_id": outcome.review.review_id,
            "review_digest": domain_object_digest(outcome.review),
            "resulting_status": outcome.report.review_status,
            "completed_at": now,
        }
        binding = AgentReportExportOutcomeBinding(
            binding_id=canonical_digest(values), **values
        )
        self.store.complete(binding)
        return binding

    def approval_action(
        self,
        *,
        record,
        report_export_plan: ReportExportPlan,
    ) -> ReportExportApprovalAction:
        return ReportExportApprovalAction.create(
            engagement_id=self.scope.engagement_id,
            export_intake_record_id=record.record_id,
            export_intake_record_digest=agent_report_export_intake_record_digest(record),
            review_execution_plan_id=record.review_execution_plan_id,
            review_outcome_binding_id=record.review_outcome_binding_id,
            report_export_plan_id=report_export_plan.plan_id,
            report_export_plan_digest=domain_object_digest(report_export_plan),
            report_id=record.report_id,
            report_digest=record.report_digest,
            artifact_digest=record.artifact_digest,
            review_id=record.review_id,
            review_digest=record.review_digest,
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            expected_side_effects=REPORT_EXPORT_EFFECTS,
        )

    def _load(
        self,
        *,
        export_intake_plan,
        review_execution_plan,
        report_export_plan,
        approval,
        now,
    ):
        try:
            AgentReportExportIntakePlan.model_validate(export_intake_plan)
            ReportExportPlan.model_validate(report_export_plan)
            ApprovalRequest.model_validate(approval)
            record = self.intake_service.store.load_completed(
                export_intake_plan.intake_plan_id
            )
            binding, outcome = self.intake_service.load_authoritative(
                review_execution_plan=review_execution_plan,
                report_export_plan=report_export_plan,
                now=now,
            )
        except (
            ValueError,
            RuntimeError,
            ValidationError,
            AgentReportExportIntakeRejected,
        ) as exc:
            raise AgentReportExportExecutionRejected(
                "Report export authoritative input unavailable"
            ) from exc
        action = self.approval_action(
            record=record,
            report_export_plan=report_export_plan,
        )
        if (
            self.scope.state is not ScopeState.APPROVED
            or record.decision is not AgentReportExportIntakeDecision.ACCEPT
            or record.reason_code
            is not AgentReportExportIntakeReason.HUMAN_ACCEPTED_EXACT_EXPORT
            or not record.decided_at <= now < record.expires_at
            or record.intake_plan_id != export_intake_plan.intake_plan_id
            or record.review_execution_plan_id != review_execution_plan.execution_plan_id
            or record.review_outcome_binding_id != binding.binding_id
            or record.review_outcome_binding_digest
            != agent_report_review_outcome_binding_digest(binding)
            or record.report_export_plan_id != report_export_plan.plan_id
            or record.report_export_plan_digest != domain_object_digest(report_export_plan)
            or record.report_id != outcome.report.report_id
            or record.report_digest != domain_object_digest(outcome.report)
            or record.artifact_digest != domain_object_digest(outcome.artifact)
            or record.review_id != outcome.review.review_id
            or record.review_digest != domain_object_digest(outcome.review)
            or record.scope_id != self.scope.scope_id
            or record.scope_version != self.scope.version
            or approval.engagement_id != self.scope.engagement_id
            or approval.status is not ApprovalStatus.GRANTED
            or approval.action is not ApprovalAction.EXPORT_REPORT
            or approval.action_digest != action.action_id
            or approval.target_id is not None
            or approval.policy_version != self.scope.version
            or approval.expected_side_effects != REPORT_EXPORT_EFFECTS
            or not approval.decided_by
            or approval.decided_at is None
            or not record.decided_at <= approval.decided_at <= now < approval.expires_at
        ):
            raise AgentReportExportExecutionRejected(
                "Report export Intake or Approval drifted"
            )
        return record, binding, outcome, action
