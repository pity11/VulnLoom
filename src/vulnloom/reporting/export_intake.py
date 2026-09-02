"""Human Intake for a local export of an M8.10 human-approved Report."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ReportReviewStatus, Scope, ScopeState

from .export_intake_models import (
    AgentReportExportIntakeCommand,
    AgentReportExportIntakePlan,
    AgentReportExportIntakeRecord,
    agent_report_export_intake_command_digest,
    agent_report_export_intake_plan_digest,
)
from .export_intake_store import AgentReportExportIntakeStore
from .models import domain_object_digest
from .review_execution_models import (
    AgentReportReviewExecutionPlan,
    agent_report_review_execution_plan_digest,
    agent_report_review_outcome_binding_digest,
)
from .review_execution_store import AgentReportReviewExecutionStore
from .review_models import ReportExportPlan
from .state_machine import ReviewDecisionKind
from .store import ReportArtifactStore
from .workflow_store import ReportReviewStore


class AgentReportExportIntakeRejected(ValueError):
    pass


class AgentReportExportIntakeTimedOut(TimeoutError):
    pass


class AgentReportExportIntakeService:
    """Records human selection without exporting or changing a Report."""

    def __init__(
        self,
        *,
        scope: Scope,
        review_execution_store: AgentReportReviewExecutionStore,
        review_store: ReportReviewStore,
        artifact_store: ReportArtifactStore,
        store: AgentReportExportIntakeStore,
    ):
        self.scope = scope
        self.review_execution_store = review_execution_store
        self.review_store = review_store
        self.artifact_store = artifact_store
        self.store = store

    def prepare(
        self,
        *,
        review_execution_plan: AgentReportReviewExecutionPlan,
        report_export_plan: ReportExportPlan,
        now: datetime,
        decision_deadline: datetime,
        idempotency_key: str,
    ) -> AgentReportExportIntakePlan:
        binding, outcome = self.load_authoritative(
            review_execution_plan=review_execution_plan,
            report_export_plan=report_export_plan,
            now=now,
        )
        if not now < decision_deadline <= min(
            self.scope.valid_until,
            outcome.review.expires_at,
            report_export_plan.deadline,
        ):
            raise AgentReportExportIntakeRejected(
                "Report export Intake deadline exceeds active authority"
            )
        report = outcome.report
        values = {
            "review_execution_plan_id": review_execution_plan.execution_plan_id,
            "review_execution_plan_digest": agent_report_review_execution_plan_digest(
                review_execution_plan
            ),
            "review_outcome_binding_id": binding.binding_id,
            "review_outcome_binding_digest": agent_report_review_outcome_binding_digest(
                binding
            ),
            "report_review_outcome_digest": domain_object_digest(outcome),
            "report_export_plan_id": report_export_plan.plan_id,
            "report_export_plan_digest": domain_object_digest(report_export_plan),
            "report_id": report.report_id,
            "report_digest": domain_object_digest(report),
            "artifact_digest": domain_object_digest(outcome.artifact),
            "review_id": outcome.review.review_id,
            "review_digest": domain_object_digest(outcome.review),
            "report_family_id": report.report_family_id,
            "report_version": report.version,
            "finding_id": report.finding_id,
            "candidate_id": report.candidate_id,
            "evidence_bundle_id": report.evidence_bundle_id,
            "channel": report.channel,
            "review_status": report.review_status,
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "decision_deadline": decision_deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentReportExportIntakePlan.create(**values)

    def decide(
        self,
        plan: AgentReportExportIntakePlan,
        command: AgentReportExportIntakeCommand,
        *,
        review_execution_plan: AgentReportReviewExecutionPlan,
        report_export_plan: ReportExportPlan,
        now: datetime,
    ) -> AgentReportExportIntakeRecord:
        try:
            AgentReportExportIntakePlan.model_validate(plan)
            AgentReportExportIntakeCommand.model_validate(command)
        except ValidationError as exc:
            raise AgentReportExportIntakeRejected(
                "Report export Intake boundary validation failed"
            ) from exc
        if now < plan.created_at or now >= plan.decision_deadline:
            raise AgentReportExportIntakeTimedOut(
                "Report export Intake decision is outside its window"
            )
        binding, _ = self.load_authoritative(
            review_execution_plan=review_execution_plan,
            report_export_plan=report_export_plan,
            now=now,
        )
        expected = self.prepare(
            review_execution_plan=review_execution_plan,
            report_export_plan=report_export_plan,
            now=plan.created_at,
            decision_deadline=plan.decision_deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentReportExportIntakeRejected("Report export Intake plan drifted")
        if (
            command.command_id != agent_report_export_intake_command_digest(command)
            or command.intake_plan_id != plan.intake_plan_id
            or command.intake_plan_digest != agent_report_export_intake_plan_digest(plan)
            or command.review_outcome_binding_id != binding.binding_id
            or command.report_export_plan_id != report_export_plan.plan_id
            or command.report_export_plan_digest != domain_object_digest(report_export_plan)
            or command.report_id != plan.report_id
            or command.report_digest != plan.report_digest
            or not plan.created_at <= command.decided_at < plan.decision_deadline
            or command.decided_at > now
        ):
            raise AgentReportExportIntakeRejected("Report export Intake command drifted")
        claim = self.store.claim(plan, command, now=now)
        if not claim.created:
            assert claim.record is not None
            return claim.record
        values = {
            "intake_plan_id": plan.intake_plan_id,
            "command_id": command.command_id,
            "review_execution_plan_id": plan.review_execution_plan_id,
            "review_outcome_binding_id": plan.review_outcome_binding_id,
            "review_outcome_binding_digest": plan.review_outcome_binding_digest,
            "report_export_plan_id": plan.report_export_plan_id,
            "report_export_plan_digest": plan.report_export_plan_digest,
            "report_id": plan.report_id,
            "report_digest": plan.report_digest,
            "artifact_digest": plan.artifact_digest,
            "review_id": plan.review_id,
            "review_digest": plan.review_digest,
            "report_family_id": plan.report_family_id,
            "report_version": plan.report_version,
            "finding_id": plan.finding_id,
            "candidate_id": plan.candidate_id,
            "evidence_bundle_id": plan.evidence_bundle_id,
            "channel": plan.channel,
            "scope_id": plan.scope_id,
            "scope_version": plan.scope_version,
            "decision": command.decision,
            "reason_code": command.reason_code,
            "reviewer": command.reviewer,
            "decided_at": command.decided_at,
            "expires_at": plan.decision_deadline,
        }
        record = AgentReportExportIntakeRecord(record_id=canonical_digest(values), **values)
        self.store.complete(record)
        return record

    def load_authoritative(
        self,
        *,
        review_execution_plan: AgentReportReviewExecutionPlan,
        report_export_plan: ReportExportPlan,
        now: datetime,
    ):
        try:
            AgentReportReviewExecutionPlan.model_validate(review_execution_plan)
            ReportExportPlan.model_validate(report_export_plan)
            binding = self.review_execution_store.load_completed(
                review_execution_plan.execution_plan_id
            )
            outcome = self.review_store.load_completed(binding.report_review_plan_id)
            persisted_report = self.artifact_store.read_report(outcome.artifact)
        except (ValueError, RuntimeError, ValidationError) as exc:
            raise AgentReportExportIntakeRejected(
                "Report export authoritative input unavailable"
            ) from exc
        report = outcome.report
        review = outcome.review
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or review_execution_plan.execution_plan_id
            != agent_report_review_execution_plan_digest(review_execution_plan)
            or binding.execution_plan_id != review_execution_plan.execution_plan_id
            or binding.binding_id != agent_report_review_outcome_binding_digest(binding)
            or not review_execution_plan.created_at
            <= binding.completed_at
            < review_execution_plan.deadline
            or review_execution_plan.scope_id != self.scope.scope_id
            or review_execution_plan.scope_version != self.scope.version
            or review_execution_plan.decision is not ReviewDecisionKind.APPROVE
            or binding.approval_action_id != review_execution_plan.approval_action_id
            or binding.approval_id != review_execution_plan.approval_id
            or binding.approval_digest != review_execution_plan.approval_digest
            or binding.review_intake_record_id
            != review_execution_plan.review_intake_record_id
            or binding.report_review_plan_id != review_execution_plan.report_review_plan_id
            or binding.report_review_command_id != review_execution_plan.report_review_command_id
            or binding.decision is not review_execution_plan.decision
            or binding.report_id != report.report_id
            or review_execution_plan.report_id != report.report_id
            or binding.report_review_outcome_digest != domain_object_digest(outcome)
            or binding.resulting_report_digest != domain_object_digest(report)
            or binding.resulting_artifact_digest != domain_object_digest(outcome.artifact)
            or binding.review_id != review.review_id
            or binding.review_digest != domain_object_digest(review)
            or binding.decision is not ReviewDecisionKind.APPROVE
            or binding.resulting_status is not ReportReviewStatus.HUMAN_APPROVED
            or report.review_status is not ReportReviewStatus.HUMAN_APPROVED
            or review.decision is not ReviewDecisionKind.APPROVE
            or review.resulting_status is not ReportReviewStatus.HUMAN_APPROVED
            or review.report_id != report.report_id
            or review.resulting_report_digest != domain_object_digest(report)
            or not binding.completed_at <= now < review.expires_at
            or persisted_report != report
            or report.scope_id != self.scope.scope_id
            or report.scope_version != self.scope.version
            or report_export_plan.created_at < binding.completed_at
            or not report_export_plan.created_at <= now < report_export_plan.deadline
            or report_export_plan.deadline > self.scope.valid_until
            or report_export_plan.deadline > review.expires_at
            or report_export_plan.report_id != report.report_id
            or report_export_plan.report_digest != domain_object_digest(report)
            or report_export_plan.artifact_digest != domain_object_digest(outcome.artifact)
            or report_export_plan.review_id != review.review_id
            or report_export_plan.review_digest != domain_object_digest(review)
            or report_export_plan.scope_id != self.scope.scope_id
            or report_export_plan.scope_version != self.scope.version
        ):
            raise AgentReportExportIntakeRejected("Report export provenance drifted")
        return binding, outcome
