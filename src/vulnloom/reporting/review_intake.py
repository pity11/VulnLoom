"""Human Report review Intake over a completed M8.8 local draft binding."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Evidence, EvidenceBundle, ReportReviewStatus, Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .execution import evidence_catalog_digest
from .execution_models import (
    AgentReportDraftExecutionPlan,
    agent_report_draft_execution_plan_digest,
    agent_report_draft_outcome_binding_digest,
)
from .execution_store import AgentReportDraftExecutionStore
from .models import domain_object_digest
from .review_intake_models import (
    AgentReportReviewIntakeCommand,
    AgentReportReviewIntakePlan,
    AgentReportReviewIntakeRecord,
    agent_report_review_intake_command_digest,
    agent_report_review_intake_plan_digest,
)
from .review_intake_store import AgentReportReviewIntakeStore
from .review_models import ReportReviewPlan
from .store import ReportArtifactStore, ReportDraftStore


class AgentReportReviewIntakeRejected(ValueError):
    pass


class AgentReportReviewIntakeTimedOut(TimeoutError):
    pass


class AgentReportReviewIntakeService:
    """Records human selection without reviewing or changing a Report."""

    def __init__(
        self,
        *,
        scope: Scope,
        draft_execution_store: AgentReportDraftExecutionStore,
        report_store: ReportDraftStore,
        artifact_store: ReportArtifactStore,
        evidence_store: EvidenceStore,
        store: AgentReportReviewIntakeStore,
    ):
        self.scope = scope
        self.draft_execution_store = draft_execution_store
        self.report_store = report_store
        self.artifact_store = artifact_store
        self.evidence_store = evidence_store
        self.store = store

    def prepare(
        self,
        *,
        draft_execution_plan: AgentReportDraftExecutionPlan,
        report_review_plan: ReportReviewPlan,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        now: datetime,
        decision_deadline: datetime,
        idempotency_key: str,
    ) -> AgentReportReviewIntakePlan:
        binding, outcome = self.load_authoritative(
            draft_execution_plan=draft_execution_plan,
            report_review_plan=report_review_plan,
            evidence_bundle=evidence_bundle,
            evidence=evidence,
            now=now,
        )
        if not now < decision_deadline <= min(self.scope.valid_until, report_review_plan.deadline):
            raise AgentReportReviewIntakeRejected(
                "Report review Intake deadline exceeds active authority"
            )
        values = {
            "draft_execution_plan_id": draft_execution_plan.execution_plan_id,
            "draft_execution_plan_digest": agent_report_draft_execution_plan_digest(
                draft_execution_plan
            ),
            "draft_outcome_binding_id": binding.binding_id,
            "draft_outcome_binding_digest": agent_report_draft_outcome_binding_digest(binding),
            "report_outcome_digest": domain_object_digest(outcome),
            "report_review_plan_id": report_review_plan.plan_id,
            "report_review_plan_digest": domain_object_digest(report_review_plan),
            "report_id": outcome.report.report_id,
            "report_digest": domain_object_digest(outcome.report),
            "artifact_digest": domain_object_digest(outcome.artifact),
            "report_family_id": outcome.report.report_family_id,
            "report_version": outcome.report.version,
            "finding_id": outcome.report.finding_id,
            "candidate_id": outcome.report.candidate_id,
            "evidence_bundle_id": evidence_bundle.bundle_id,
            "evidence_bundle_digest": domain_object_digest(evidence_bundle),
            "evidence_catalog_digest": evidence_catalog_digest(evidence),
            "channel": outcome.report.channel,
            "review_status": outcome.report.review_status,
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "decision_deadline": decision_deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentReportReviewIntakePlan.create(**values)

    def decide(
        self,
        plan: AgentReportReviewIntakePlan,
        command: AgentReportReviewIntakeCommand,
        *,
        draft_execution_plan: AgentReportDraftExecutionPlan,
        report_review_plan: ReportReviewPlan,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        now: datetime,
    ) -> AgentReportReviewIntakeRecord:
        try:
            AgentReportReviewIntakePlan.model_validate(plan)
            AgentReportReviewIntakeCommand.model_validate(command)
        except ValidationError as exc:
            raise AgentReportReviewIntakeRejected(
                "Report review Intake boundary validation failed"
            ) from exc
        if now < plan.created_at or now >= plan.decision_deadline:
            raise AgentReportReviewIntakeTimedOut(
                "Report review Intake decision is outside its window"
            )
        binding, _ = self.load_authoritative(
            draft_execution_plan=draft_execution_plan,
            report_review_plan=report_review_plan,
            evidence_bundle=evidence_bundle,
            evidence=evidence,
            now=now,
        )
        expected = self.prepare(
            draft_execution_plan=draft_execution_plan,
            report_review_plan=report_review_plan,
            evidence_bundle=evidence_bundle,
            evidence=evidence,
            now=plan.created_at,
            decision_deadline=plan.decision_deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentReportReviewIntakeRejected("Report review Intake plan drifted")
        if (
            command.command_id != agent_report_review_intake_command_digest(command)
            or command.intake_plan_id != plan.intake_plan_id
            or command.intake_plan_digest != agent_report_review_intake_plan_digest(plan)
            or command.draft_outcome_binding_id != binding.binding_id
            or command.report_review_plan_id != report_review_plan.plan_id
            or command.report_review_plan_digest != domain_object_digest(report_review_plan)
            or command.report_id != plan.report_id
            or command.report_digest != plan.report_digest
            or not plan.created_at <= command.decided_at < plan.decision_deadline
            or command.decided_at > now
        ):
            raise AgentReportReviewIntakeRejected("Report review Intake command drifted")
        claim = self.store.claim(plan, command, now=now)
        if not claim.created:
            assert claim.record is not None
            return claim.record
        values = {
            "intake_plan_id": plan.intake_plan_id,
            "command_id": command.command_id,
            "draft_execution_plan_id": plan.draft_execution_plan_id,
            "draft_outcome_binding_id": plan.draft_outcome_binding_id,
            "draft_outcome_binding_digest": plan.draft_outcome_binding_digest,
            "report_review_plan_id": plan.report_review_plan_id,
            "report_review_plan_digest": plan.report_review_plan_digest,
            "report_id": plan.report_id,
            "report_digest": plan.report_digest,
            "artifact_digest": plan.artifact_digest,
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
        record = AgentReportReviewIntakeRecord(record_id=canonical_digest(values), **values)
        self.store.complete(record)
        return record

    def load_authoritative(
        self,
        *,
        draft_execution_plan: AgentReportDraftExecutionPlan,
        report_review_plan: ReportReviewPlan,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        now: datetime,
    ):
        try:
            AgentReportDraftExecutionPlan.model_validate(draft_execution_plan)
            ReportReviewPlan.model_validate(report_review_plan)
            binding = self.draft_execution_store.load_completed(
                draft_execution_plan.execution_plan_id
            )
            outcome = self.report_store.load_completed(binding.report_draft_plan_id)
            persisted_report = self.artifact_store.read_report(outcome.artifact)
        except (ValueError, RuntimeError, ValidationError) as exc:
            raise AgentReportReviewIntakeRejected(
                "Report review authoritative input unavailable"
            ) from exc
        report = outcome.report
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or draft_execution_plan.execution_plan_id
            != agent_report_draft_execution_plan_digest(draft_execution_plan)
            or not draft_execution_plan.created_at
            <= binding.completed_at
            < draft_execution_plan.deadline
            or binding.execution_plan_id != draft_execution_plan.execution_plan_id
            or binding.binding_id != agent_report_draft_outcome_binding_digest(binding)
            or binding.report_intake_record_id != draft_execution_plan.report_intake_record_id
            or binding.report_draft_plan_id != draft_execution_plan.report_draft_plan_id
            or binding.report_draft_plan_digest != draft_execution_plan.report_draft_plan_digest
            or binding.report_outcome_digest != domain_object_digest(outcome)
            or binding.report_id != report.report_id
            or binding.report_digest != domain_object_digest(report)
            or binding.artifact_digest != domain_object_digest(outcome.artifact)
            or binding.report_family_id != report.report_family_id
            or binding.report_version != report.version
            or binding.finding_id != report.finding_id
            or binding.candidate_id != report.candidate_id
            or binding.evidence_bundle_id != evidence_bundle.bundle_id
            or binding.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or draft_execution_plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or binding.channel != report.channel
            or draft_execution_plan.report_family_id != report.report_family_id
            or draft_execution_plan.report_version != report.version
            or draft_execution_plan.finding_id != report.finding_id
            or draft_execution_plan.candidate_id != report.candidate_id
            or draft_execution_plan.evidence_bundle_id != evidence_bundle.bundle_id
            or draft_execution_plan.channel != report.channel
            or draft_execution_plan.scope_id != self.scope.scope_id
            or draft_execution_plan.scope_version != self.scope.version
            or binding.review_status is not ReportReviewStatus.DRAFT
            or persisted_report != report
            or report.review_status is not ReportReviewStatus.DRAFT
            or report.scope_id != self.scope.scope_id
            or report.scope_version != self.scope.version
            or evidence_bundle.candidate_id != report.candidate_id
            or evidence_bundle.bundle_id != report.evidence_bundle_id
            or tuple(item.evidence_id for item in evidence) != evidence_bundle.evidence_refs
            or len({item.evidence_id for item in evidence}) != len(evidence)
            or evidence_catalog_digest(evidence) != draft_execution_plan.evidence_catalog_digest
            or not set(report.evidence_refs) <= set(evidence_bundle.evidence_refs)
            or report_review_plan.created_at < binding.completed_at
            or not report_review_plan.created_at <= now < report_review_plan.deadline
            or report_review_plan.approval_expires_at > self.scope.valid_until
            or report_review_plan.report_id != report.report_id
            or report_review_plan.report_family_id != report.report_family_id
            or report_review_plan.report_version != report.version
            or report_review_plan.report_digest != domain_object_digest(report)
            or report_review_plan.artifact_digest != domain_object_digest(outcome.artifact)
            or report_review_plan.evidence_bundle_id != evidence_bundle.bundle_id
            or report_review_plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or report_review_plan.scope_id != self.scope.scope_id
            or report_review_plan.scope_version != self.scope.version
            or report_review_plan.diff_id is not None
        ):
            raise AgentReportReviewIntakeRejected("Report review provenance drifted")
        try:
            for item in evidence:
                if item.target_version != report.target_version:
                    raise ValueError("Evidence targets another version")
                self.evidence_store.read_text(item)
        except ValueError as exc:
            raise AgentReportReviewIntakeRejected(
                "Report review Evidence is unavailable or corrupt"
            ) from exc
        return binding, outcome
