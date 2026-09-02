"""Accepted Report Intake execution through the deterministic local drafting service."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.critic import AgentCriticOutcomeBindingPlan
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Evidence, ReportReviewStatus
from vulnloom.findings import FindingPromotionExecutionPlan

from .execution_models import AgentReportDraftExecutionPlan, AgentReportDraftOutcomeBinding
from .execution_store import AgentReportDraftExecutionStore
from .intake import AgentReportIntakeRejected, AgentReportIntakeService
from .intake_models import (
    AgentReportIntakeDecision,
    AgentReportIntakePlan,
    AgentReportIntakeReason,
    agent_report_intake_record_digest,
)
from .models import ReportDraftPlan, domain_object_digest, report_draft_plan_digest
from .service import DeterministicReportService, ReportRejected


class AgentReportDraftExecutionRejected(ValueError):
    pass


class AgentReportDraftExecutionTimedOut(TimeoutError):
    pass


def evidence_catalog_digest(evidence: tuple[Evidence, ...]) -> str:
    return canonical_digest(tuple(item.model_dump(mode="python") for item in evidence))


class AgentReportDraftExecutionService:
    """Drafts only an accepted exact plan and emits a prose-free outcome binding."""

    def __init__(
        self,
        *,
        intake_service: AgentReportIntakeService,
        report_service: DeterministicReportService,
        store: AgentReportDraftExecutionStore,
    ):
        if report_service.scope != intake_service.scope:
            raise ValueError("Report execution services use different Scope objects")
        if report_service.evidence_store.root != intake_service.evidence_store.root:
            raise ValueError("Report execution services use different Evidence stores")
        self.intake_service = intake_service
        self.report_service = report_service
        self.store = store
        self.scope = intake_service.scope

    def prepare(
        self,
        *,
        report_intake_plan: AgentReportIntakePlan,
        finding_execution_plan: FindingPromotionExecutionPlan,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        report_draft_plan: ReportDraftPlan,
        evidence: tuple[Evidence, ...],
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AgentReportDraftExecutionPlan:
        record, promotion_outcome, bundle = self._load(
            report_intake_plan=report_intake_plan,
            finding_execution_plan=finding_execution_plan,
            critic_binding_plan=critic_binding_plan,
            report_draft_plan=report_draft_plan,
            evidence=evidence,
            now=now,
        )
        if (
            not now
            < deadline
            <= min(
                self.scope.valid_until,
                record.expires_at,
                report_draft_plan.deadline,
            )
        ):
            raise AgentReportDraftExecutionRejected(
                "Report draft execution deadline exceeds active authority"
            )
        values = {
            "report_intake_plan_id": report_intake_plan.intake_plan_id,
            "report_intake_record_id": record.record_id,
            "report_intake_record_digest": agent_report_intake_record_digest(record),
            "finding_promotion_execution_plan_id": finding_execution_plan.execution_plan_id,
            "finding_promotion_outcome_id": promotion_outcome.outcome_id,
            "finding_promotion_outcome_digest": report_intake_plan.finding_promotion_outcome_digest,
            "report_draft_plan_id": report_draft_plan.plan_id,
            "report_draft_plan_digest": report_draft_plan_digest(report_draft_plan),
            "evidence_catalog_digest": evidence_catalog_digest(evidence),
            "report_family_id": report_draft_plan.report_family_id,
            "report_version": report_draft_plan.version,
            "finding_id": promotion_outcome.finding.finding_id,
            "candidate_id": promotion_outcome.promoted_candidate.candidate_id,
            "evidence_bundle_id": bundle.bundle_id,
            "channel": report_draft_plan.channel,
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentReportDraftExecutionPlan.create(**values)

    def execute(
        self,
        plan: AgentReportDraftExecutionPlan,
        *,
        report_intake_plan: AgentReportIntakePlan,
        finding_execution_plan: FindingPromotionExecutionPlan,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        report_draft_plan: ReportDraftPlan,
        evidence: tuple[Evidence, ...],
        now: datetime,
    ) -> AgentReportDraftOutcomeBinding:
        try:
            AgentReportDraftExecutionPlan.model_validate(plan)
        except ValidationError as exc:
            raise AgentReportDraftExecutionRejected("Report draft execution plan drifted") from exc
        if now < plan.created_at or now >= plan.deadline:
            raise AgentReportDraftExecutionTimedOut("Report draft execution is outside its window")
        record, promotion_outcome, bundle = self._load(
            report_intake_plan=report_intake_plan,
            finding_execution_plan=finding_execution_plan,
            critic_binding_plan=critic_binding_plan,
            report_draft_plan=report_draft_plan,
            evidence=evidence,
            now=now,
        )
        expected = self.prepare(
            report_intake_plan=report_intake_plan,
            finding_execution_plan=finding_execution_plan,
            critic_binding_plan=critic_binding_plan,
            report_draft_plan=report_draft_plan,
            evidence=evidence,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentReportDraftExecutionRejected("Report draft execution plan drifted")
        if not self.store.has_checkpoint(
            plan.execution_plan_id
        ) and self.report_service.store.has_checkpoint(report_draft_plan.plan_id):
            raise AgentReportDraftExecutionRejected(
                "Report draft checkpoint predates accepted execution"
            )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            return claim.binding
        if self.report_service.store.has_checkpoint(report_draft_plan.plan_id):
            raise AgentReportDraftExecutionRejected(
                "Report draft checkpoint predates accepted execution"
            )
        try:
            outcome = self.report_service.draft(
                promotion_outcome.finding,
                promotion_outcome.promoted_candidate,
                bundle,
                evidence,
                report_draft_plan,
                now=now,
            )
        except (ReportRejected, ValueError, RuntimeError) as exc:
            raise AgentReportDraftExecutionRejected(
                "Deterministic Report draft execution failed"
            ) from exc
        persisted = self.report_service.store.load_completed(report_draft_plan.plan_id)
        if (
            persisted != outcome
            or self.report_service.artifact_store.read_report(outcome.artifact) != outcome.report
            or outcome.report.review_status is not ReportReviewStatus.DRAFT
        ):
            raise AgentReportDraftExecutionRejected("Report draft outcome drifted")
        values = {
            "execution_plan_id": plan.execution_plan_id,
            "report_intake_record_id": record.record_id,
            "finding_promotion_outcome_id": promotion_outcome.outcome_id,
            "report_draft_plan_id": report_draft_plan.plan_id,
            "report_draft_plan_digest": report_draft_plan_digest(report_draft_plan),
            "report_outcome_digest": domain_object_digest(outcome),
            "report_id": outcome.report.report_id,
            "report_digest": domain_object_digest(outcome.report),
            "artifact_digest": domain_object_digest(outcome.artifact),
            "report_family_id": outcome.report.report_family_id,
            "report_version": outcome.report.version,
            "finding_id": outcome.report.finding_id,
            "candidate_id": outcome.report.candidate_id,
            "evidence_bundle_id": outcome.report.evidence_bundle_id,
            "channel": outcome.report.channel,
            "review_status": outcome.report.review_status,
            "completed_at": now,
        }
        binding = AgentReportDraftOutcomeBinding(binding_id=canonical_digest(values), **values)
        self.store.complete(binding)
        return binding

    def _load(
        self,
        *,
        report_intake_plan,
        finding_execution_plan,
        critic_binding_plan,
        report_draft_plan,
        evidence,
        now,
    ):
        try:
            AgentReportIntakePlan.model_validate(report_intake_plan)
            record = self.intake_service.store.load_completed(report_intake_plan.intake_plan_id)
            promotion_outcome, bundle = self.intake_service.load_authoritative(
                finding_execution_plan=finding_execution_plan,
                critic_binding_plan=critic_binding_plan,
                report_draft_plan=report_draft_plan,
                now=now,
            )
        except (ValueError, RuntimeError, ValidationError, AgentReportIntakeRejected) as exc:
            raise AgentReportDraftExecutionRejected(
                "Report draft authoritative input unavailable"
            ) from exc
        if (
            record.decision is not AgentReportIntakeDecision.ACCEPT
            or record.reason_code is not AgentReportIntakeReason.HUMAN_ACCEPTED_EXACT_DRAFT
            or not record.decided_at <= now < record.expires_at
            or record.intake_plan_id != report_intake_plan.intake_plan_id
            or record.finding_promotion_outcome_id != promotion_outcome.outcome_id
            or record.report_draft_plan_id != report_draft_plan.plan_id
            or record.report_draft_plan_digest != report_draft_plan_digest(report_draft_plan)
            or record.report_family_id != report_draft_plan.report_family_id
            or record.report_version != report_draft_plan.version
            or record.finding_id != promotion_outcome.finding.finding_id
            or record.candidate_id != promotion_outcome.promoted_candidate.candidate_id
            or record.evidence_bundle_id != bundle.bundle_id
            or tuple(item.evidence_id for item in evidence) != bundle.evidence_refs
            or len({item.evidence_id for item in evidence}) != len(evidence)
            or any(
                item.target_version != promotion_outcome.promoted_candidate.target_version
                for item in evidence
            )
        ):
            raise AgentReportDraftExecutionRejected(
                "Report draft Intake or Evidence catalog drifted"
            )
        try:
            for item in evidence:
                self.report_service.evidence_store.read_text(item)
        except ValueError as exc:
            raise AgentReportDraftExecutionRejected(
                "Report draft Evidence is unavailable or corrupt"
            ) from exc
        return record, promotion_outcome, bundle
