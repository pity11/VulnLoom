"""Hybrid Report admission over the shared deterministic report engine."""

from __future__ import annotations

from datetime import datetime

from vulnloom.domain.models import Evidence, ReportSectionKind, Scope, ScopeState
from vulnloom.reporting import (
    DeterministicReportService,
    ReportDraftPlan,
    domain_object_digest,
    report_draft_plan_digest,
)

from .finding_models import HybridFindingState
from .finding_store import HybridFindingPromotionStore
from .models import HybridCheckKind, HybridConclusion, HybridRunState
from .report_models import (
    HybridReportOutcome,
    HybridReportPlan,
    HybridReportState,
)
from .report_store import HybridReportStore
from .store import HybridValidationStore


class HybridReportRejected(ValueError):
    pass


class HybridReportService:
    def __init__(
        self,
        *,
        scope: Scope,
        hybrid_store: HybridValidationStore,
        finding_store: HybridFindingPromotionStore,
        report_service: DeterministicReportService,
        store: HybridReportStore,
    ):
        self.scope = scope
        self.hybrid_store = hybrid_store
        self.finding_store = finding_store
        self.report_service = report_service
        self.store = store

    def execute(
        self,
        *,
        plan: HybridReportPlan,
        report_plan: ReportDraftPlan,
        evidence: tuple[Evidence, ...],
        now: datetime,
        recover: bool = False,
    ) -> HybridReportOutcome:
        chain, finding_outcome = self._load(plan=plan, report_plan=report_plan, now=now)
        if now >= plan.deadline:
            claim = (
                self.store.recover(plan, now=now)
                if recover
                else self.store.claim(plan, now=now)
            )
            if not claim.created:
                assert claim.outcome is not None
                return claim.outcome
            return self._terminal(
                plan,
                attempt=claim.attempt,
                state=HybridReportState.TIMED_OUT,
                reason_code="hybrid_report_deadline_elapsed",
                now=now,
            )
        assert finding_outcome.finding is not None
        assert finding_outcome.promoted_candidate is not None
        self._citations(chain=chain, report_plan=report_plan)
        try:
            self.report_service.preflight(
                finding_outcome.finding,
                finding_outcome.promoted_candidate,
                chain.evidence_bundle,
                evidence,
                report_plan,
                now=now,
            )
            report_outcome = self.report_service.draft(
                finding_outcome.finding,
                finding_outcome.promoted_candidate,
                chain.evidence_bundle,
                evidence,
                report_plan,
                now=now,
            )
        except (ValueError, RuntimeError) as exc:
            raise HybridReportRejected("shared Report drafting rejected Hybrid inputs") from exc
        claim = self.store.recover(plan, now=now) if recover else self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            if claim.outcome.report_outcome != report_outcome:
                raise HybridReportRejected("Hybrid Report completed outcome drifted")
            return claim.outcome
        return self._terminal(
            plan,
            attempt=claim.attempt,
            state=HybridReportState.COMPLETED,
            reason_code="hybrid_report_drafted",
            now=now,
            report_outcome=report_outcome,
        )

    def _load(self, *, plan, report_plan, now):
        try:
            plan = HybridReportPlan.model_validate(plan.model_dump(mode="python"))
            report_plan = ReportDraftPlan.model_validate(report_plan.model_dump(mode="python"))
            finding_plan, finding_outcome = self.finding_store.load_completed(
                plan.hybrid_finding_plan_id
            )
            chain_outcome = self.hybrid_store.outcome_by_chain(plan.hybrid_chain_id)
            assert chain_outcome.chain is not None
            chain = chain_outcome.chain
        except (AssertionError, ValueError, RuntimeError) as exc:
            raise HybridReportRejected("Hybrid Report authoritative input unavailable") from exc
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or now < plan.created_at
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
            or finding_outcome.state is not HybridFindingState.COMPLETED
            or finding_outcome.hybrid_chain_id != chain.chain_id
            or plan.hybrid_finding_outcome_digest != domain_object_digest(finding_outcome)
            or finding_plan.plan_id != plan.hybrid_finding_plan_id
            or finding_plan.hybrid_chain_id != chain.chain_id
            or finding_plan.hybrid_chain_digest != domain_object_digest(chain)
            or chain_outcome.state is not HybridRunState.COMPLETED
            or chain.check_kind is not HybridCheckKind.INITIAL
            or chain.conclusion is not HybridConclusion.CONFIRMED
            or plan.hybrid_chain_digest != domain_object_digest(chain)
            or chain.scope_id != self.scope.scope_id
            or chain.scope_version != self.scope.version
            or plan.report_draft_plan_id != report_plan.plan_id
            or plan.report_draft_plan_digest != report_draft_plan_digest(report_plan)
            or report_plan.scope_id != self.scope.scope_id
            or report_plan.scope_version != self.scope.version
            or report_plan.version != 1
            or report_plan.deadline < plan.deadline
        ):
            raise HybridReportRejected("Hybrid Report provenance failed")
        if finding_outcome.finding is None or finding_outcome.promoted_candidate is None:
            raise HybridReportRejected("Hybrid Finding is unavailable")
        narrative = (report_plan.title, *(section.text for section in report_plan.sections))
        if any("http://" in text.lower() or "https://" in text.lower() for text in narrative):
            raise HybridReportRejected("Hybrid Report narrative cannot contain a full endpoint")
        if (
            report_plan.finding_id != finding_outcome.finding.finding_id
            or report_plan.finding_digest != domain_object_digest(finding_outcome.finding)
            or report_plan.candidate_id
            != finding_outcome.promoted_candidate.candidate_id
            or report_plan.candidate_digest
            != domain_object_digest(finding_outcome.promoted_candidate)
            or report_plan.evidence_bundle_id != chain.evidence_bundle.bundle_id
            or report_plan.evidence_bundle_digest != domain_object_digest(chain.evidence_bundle)
        ):
            raise HybridReportRejected("Hybrid Report draft binding failed")
        return chain, finding_outcome

    @staticmethod
    def _citations(*, chain, report_plan) -> None:
        by_kind = {section.kind: section for section in report_plan.sections}
        source_refs = set(chain.source_evidence_refs)
        deployment_refs = {chain.deployment_evidence_ref}
        http_refs = set(chain.http_evidence_refs)
        code_refs = set(by_kind[ReportSectionKind.CODE_LOCATION].evidence_refs)
        request_refs = set(by_kind[ReportSectionKind.REQUEST_RESPONSE].evidence_refs)
        reproduction_refs = set(
            ref
            for section in report_plan.sections
            if section.kind is ReportSectionKind.REPRODUCTION
            for ref in section.evidence_refs
        )
        impact_refs = set(by_kind[ReportSectionKind.IMPACT].evidence_refs)
        if (
            not code_refs & source_refs
            or not request_refs & http_refs
            or not reproduction_refs & deployment_refs
            or not reproduction_refs & http_refs
            or not impact_refs & http_refs
        ):
            raise HybridReportRejected(
                "Hybrid Report sections do not cover source, deployment, and HTTP Evidence"
            )

    def _terminal(
        self,
        plan,
        *,
        attempt,
        state,
        reason_code,
        now,
        report_outcome=None,
    ):
        outcome = HybridReportOutcome(
            plan_id=plan.plan_id,
            state=state,
            attempt=attempt,
            hybrid_finding_plan_id=plan.hybrid_finding_plan_id,
            hybrid_chain_id=plan.hybrid_chain_id,
            report_draft_plan_id=plan.report_draft_plan_id,
            report_outcome=report_outcome,
            reason_code=reason_code,
            cleanup_complete=True,
            completed_at=now,
        )
        self.store.finish(outcome)
        return outcome
