"""Human Report Intake over a sealed M8.6 Finding promotion outcome."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.critic import (
    AgentCriticOutcomeBindingPlan,
    AgentCriticOutcomeBindingStore,
    agent_critic_outcome_binding_plan_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    Scope,
    ScopeState,
    ValidationResult,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.findings import (
    FindingPromotionExecutionPlan,
    FindingPromotionStore,
    finding_promotion_execution_plan_digest,
    finding_promotion_outcome_digest,
)
from vulnloom.validation import AgentValidationOutcomeBindingStore, ValidationStore

from .intake_models import (
    AgentReportIntakeCommand,
    AgentReportIntakePlan,
    AgentReportIntakeRecord,
    agent_report_intake_command_digest,
    agent_report_intake_plan_digest,
)
from .intake_store import AgentReportIntakeStore
from .models import ReportDraftPlan, domain_object_digest, report_draft_plan_digest


class AgentReportIntakeRejected(ValueError):
    pass


class AgentReportIntakeTimedOut(TimeoutError):
    pass


class AgentReportIntakeService:
    """Records human selection without drafting, exporting, or submitting a Report."""

    def __init__(
        self,
        *,
        scope: Scope,
        finding_promotion_store: FindingPromotionStore,
        critic_binding_store: AgentCriticOutcomeBindingStore,
        validation_binding_store: AgentValidationOutcomeBindingStore,
        validation_store: ValidationStore,
        evidence_store: EvidenceStore,
        store: AgentReportIntakeStore,
    ):
        self.scope = scope
        self.finding_promotion_store = finding_promotion_store
        self.critic_binding_store = critic_binding_store
        self.validation_binding_store = validation_binding_store
        self.validation_store = validation_store
        self.evidence_store = evidence_store
        self.store = store

    def prepare(
        self,
        *,
        finding_execution_plan: FindingPromotionExecutionPlan,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        report_draft_plan: ReportDraftPlan,
        now: datetime,
        decision_deadline: datetime,
        idempotency_key: str,
    ) -> AgentReportIntakePlan:
        outcome, bundle = self._load(
            finding_execution_plan=finding_execution_plan,
            critic_binding_plan=critic_binding_plan,
            report_draft_plan=report_draft_plan,
            now=now,
        )
        if not now < decision_deadline <= min(self.scope.valid_until, report_draft_plan.deadline):
            raise AgentReportIntakeRejected("Report Intake deadline exceeds active authority")
        values = {
            "finding_promotion_execution_plan_id": finding_execution_plan.execution_plan_id,
            "finding_promotion_outcome_id": outcome.outcome_id,
            "finding_promotion_outcome_digest": finding_promotion_outcome_digest(outcome),
            "report_draft_plan_id": report_draft_plan.plan_id,
            "report_draft_plan_digest": report_draft_plan_digest(report_draft_plan),
            "report_family_id": report_draft_plan.report_family_id,
            "report_version": report_draft_plan.version,
            "finding_id": outcome.finding.finding_id,
            "finding_digest": domain_object_digest(outcome.finding),
            "candidate_id": outcome.promoted_candidate.candidate_id,
            "candidate_digest": domain_object_digest(outcome.promoted_candidate),
            "evidence_bundle_id": bundle.bundle_id,
            "evidence_bundle_digest": domain_object_digest(bundle),
            "channel": report_draft_plan.channel,
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "decision_deadline": decision_deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentReportIntakePlan.create(**values)

    def decide(
        self,
        plan: AgentReportIntakePlan,
        command: AgentReportIntakeCommand,
        *,
        finding_execution_plan: FindingPromotionExecutionPlan,
        critic_binding_plan: AgentCriticOutcomeBindingPlan,
        report_draft_plan: ReportDraftPlan,
        now: datetime,
    ) -> AgentReportIntakeRecord:
        try:
            AgentReportIntakePlan.model_validate(plan)
            AgentReportIntakeCommand.model_validate(command)
        except ValidationError as exc:
            raise AgentReportIntakeRejected("Report Intake boundary validation failed") from exc
        if now < plan.created_at or now >= plan.decision_deadline:
            raise AgentReportIntakeTimedOut("Report Intake decision is outside its window")
        self._load(
            finding_execution_plan=finding_execution_plan,
            critic_binding_plan=critic_binding_plan,
            report_draft_plan=report_draft_plan,
            now=now,
        )
        expected = self.prepare(
            finding_execution_plan=finding_execution_plan,
            critic_binding_plan=critic_binding_plan,
            report_draft_plan=report_draft_plan,
            now=plan.created_at,
            decision_deadline=plan.decision_deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentReportIntakeRejected("Report Intake plan drifted")
        if (
            command.command_id != agent_report_intake_command_digest(command)
            or command.intake_plan_id != plan.intake_plan_id
            or command.intake_plan_digest != agent_report_intake_plan_digest(plan)
            or command.finding_promotion_outcome_id != plan.finding_promotion_outcome_id
            or command.report_draft_plan_id != plan.report_draft_plan_id
            or command.report_draft_plan_digest != plan.report_draft_plan_digest
            or command.report_family_id != plan.report_family_id
            or command.report_version != plan.report_version
            or command.finding_id != plan.finding_id
            or not plan.created_at <= command.decided_at < plan.decision_deadline
            or command.decided_at > now
        ):
            raise AgentReportIntakeRejected("Report Intake command drifted")
        claim = self.store.claim(plan, command, now=now)
        if not claim.created:
            assert claim.record is not None
            return claim.record
        values = {
            "intake_plan_id": plan.intake_plan_id,
            "command_id": command.command_id,
            "finding_promotion_outcome_id": plan.finding_promotion_outcome_id,
            "finding_promotion_outcome_digest": plan.finding_promotion_outcome_digest,
            "report_draft_plan_id": plan.report_draft_plan_id,
            "report_draft_plan_digest": plan.report_draft_plan_digest,
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
        record = AgentReportIntakeRecord(record_id=canonical_digest(values), **values)
        self.store.complete(record)
        return record

    def _load(
        self,
        *,
        finding_execution_plan,
        critic_binding_plan,
        report_draft_plan,
        now,
    ):
        try:
            FindingPromotionExecutionPlan.model_validate(finding_execution_plan)
            AgentCriticOutcomeBindingPlan.model_validate(critic_binding_plan)
            ReportDraftPlan.model_validate(report_draft_plan)
            outcome = self.finding_promotion_store.load_completed(
                finding_execution_plan.execution_plan_id
            )
            critic_binding = self.critic_binding_store.load_completed(
                critic_binding_plan.binding_plan_id
            )
            validation_binding = self.validation_binding_store.load_completed_by_binding_id(
                critic_binding.outcome_binding_id
            )
            _, validation_outcome = self.validation_store.load_completed(
                validation_binding.validation_plan_id
            )
        except (ValueError, RuntimeError, ValidationError) as exc:
            raise AgentReportIntakeRejected(
                "Report Intake authoritative input unavailable"
            ) from exc
        bundle = validation_outcome.evidence_bundle
        run = validation_outcome.validation_run
        referenced = {
            ref for section in report_draft_plan.sections for ref in section.evidence_refs
        }
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or finding_execution_plan.execution_plan_id
            != finding_promotion_execution_plan_digest(finding_execution_plan)
            or outcome.execution_plan_id != finding_execution_plan.execution_plan_id
            or outcome.approval_id != finding_execution_plan.approval_id
            or outcome.approval_digest != finding_execution_plan.approval_digest
            or outcome.promotion_plan_id != finding_execution_plan.promotion_plan_id
            or outcome.finding.finding_id != finding_execution_plan.finding_id
            or outcome.completed_at > report_draft_plan.created_at
            or critic_binding_plan.binding_plan_id
            != agent_critic_outcome_binding_plan_digest(critic_binding_plan)
            or critic_binding.binding_plan_id != critic_binding_plan.binding_plan_id
            or critic_binding.verdict is not CriticVerdict.ACCEPTED
            or critic_binding.final_candidate_state is not CandidateState.CRITIC_REVIEWED
            or critic_binding.final_candidate_digest != outcome.source_candidate_digest
            or critic_binding.candidate_id != outcome.promoted_candidate.candidate_id
            or validation_binding.validation_outcome_digest
            != canonical_digest(validation_outcome.model_dump(mode="python"))
            or run.result is not ValidationResult.REPRODUCED
            or run.run_id not in outcome.finding.validation_run_ids
            or bundle is None
            or bundle.bundle_id != outcome.finding.evidence_bundle_id
            or bundle.candidate_id != outcome.promoted_candidate.candidate_id
            or not bundle.evidence_refs
            or any(not self.evidence_store.contains(ref) for ref in bundle.evidence_refs)
            or outcome.promoted_candidate.state is not CandidateState.PROMOTED
            or outcome.finding.state != "verified"
            or report_draft_plan.plan_id != report_draft_plan_digest(report_draft_plan)
            or not report_draft_plan.created_at <= now < report_draft_plan.deadline
            or report_draft_plan.version != 1
            or report_draft_plan.previous_report_digest is not None
            or report_draft_plan.finding_id != outcome.finding.finding_id
            or report_draft_plan.finding_digest != domain_object_digest(outcome.finding)
            or report_draft_plan.candidate_id != outcome.promoted_candidate.candidate_id
            or report_draft_plan.candidate_digest
            != domain_object_digest(outcome.promoted_candidate)
            or report_draft_plan.evidence_bundle_id != bundle.bundle_id
            or report_draft_plan.evidence_bundle_digest != domain_object_digest(bundle)
            or report_draft_plan.scope_id != self.scope.scope_id
            or report_draft_plan.scope_version != self.scope.version
            or not referenced
            or not referenced <= set(bundle.evidence_refs)
        ):
            raise AgentReportIntakeRejected("Report Intake provenance drifted")
        return outcome, bundle
