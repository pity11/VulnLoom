"""Trusted offline Report drafting and Evidence consistency checks."""

from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.models import (
    Candidate,
    CandidateState,
    Evidence,
    EvidenceBundle,
    Finding,
    RedactionStatus,
    Report,
    ReportReviewStatus,
    ReportSection,
    ReportSectionKind,
    Scope,
    ScopeState,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.evidence.redaction import Redactor

from .models import ReportDraftPlan, ReportOutcome, domain_object_digest
from .store import ReportArtifactStore, ReportDraftStore


class ReportRejected(ValueError):
    """The report request violated provenance, Scope, or Evidence invariants."""


class DeterministicReportService:
    def __init__(
        self,
        *,
        scope: Scope,
        evidence_store: EvidenceStore,
        store: ReportDraftStore,
        artifact_store: ReportArtifactStore,
        redactor: Redactor | None = None,
    ):
        self.scope = scope
        self.evidence_store = evidence_store
        self.store = store
        self.artifact_store = artifact_store
        self.redactor = redactor or Redactor()

    def draft(
        self,
        finding: Finding,
        candidate: Candidate,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        plan: ReportDraftPlan,
        *,
        now: datetime,
    ) -> ReportOutcome:
        catalog = self._preflight(
            finding, candidate, evidence_bundle, evidence, plan, now=now
        )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome

        for ref in dict.fromkeys(
            ref for section in plan.sections for ref in section.evidence_refs
        ):
            self.evidence_store.read_text(catalog[ref])
        sections = tuple(
            ReportSection(
                kind=section.kind,
                text=self.redactor.text(section.text),
                evidence_refs=section.evidence_refs,
            )
            for section in plan.sections
        )
        by_kind = {section.kind: section for section in sections}
        reproduction = tuple(
            section.text
            for section in sections
            if section.kind is ReportSectionKind.REPRODUCTION
        )
        evidence_refs = tuple(
            dict.fromkeys(ref for section in sections for ref in section.evidence_refs)
        )
        report = Report(
            report_id=uuid5(NAMESPACE_URL, f"vulnloom:report:{plan.plan_id}"),
            draft_plan_id=plan.plan_id,
            finding_id=finding.finding_id,
            candidate_id=candidate.candidate_id,
            evidence_bundle_id=evidence_bundle.bundle_id,
            target_version=candidate.target_version,
            scope_id=candidate.scope_id,
            scope_version=candidate.scope_version,
            channel=plan.channel,
            title=self.redactor.text(plan.title),
            summary=by_kind[ReportSectionKind.SUMMARY].text,
            reproduction=reproduction,
            impact=by_kind[ReportSectionKind.IMPACT].text,
            remediation=by_kind[ReportSectionKind.REMEDIATION].text,
            sections=sections,
            evidence_refs=evidence_refs,
            redaction_status=RedactionStatus.PASSED,
            review_status=ReportReviewStatus.DRAFT,
        )
        artifact = self.artifact_store.put(report)
        outcome = ReportOutcome(
            plan_id=plan.plan_id,
            report=report,
            artifact=artifact,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome

    def _preflight(
        self,
        finding: Finding,
        candidate: Candidate,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        plan: ReportDraftPlan,
        *,
        now: datetime,
    ) -> dict[str, Evidence]:
        if candidate.state is not CandidateState.PROMOTED or finding.state != "verified":
            raise ReportRejected("Report drafting requires a verified promoted Finding")
        if self.scope.state is not ScopeState.APPROVED:
            raise ReportRejected("Report drafting requires an approved Scope")
        if not self.scope.valid_from <= now < self.scope.valid_until:
            raise ReportRejected("Report drafting is outside the Scope validity window")
        if plan.created_at > now or now >= plan.deadline:
            raise ReportRejected("ReportDraftPlan is not currently valid")
        if evidence_bundle.sealed_at > plan.created_at:
            raise ReportRejected("ReportDraftPlan predates its EvidenceBundle")
        if (
            candidate.scope_id != self.scope.scope_id
            or candidate.scope_version != self.scope.version
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
        ):
            raise ReportRejected("Report inputs are bound to another Scope version")
        if (
            finding.candidate_id != candidate.candidate_id
            or finding.evidence_bundle_id != evidence_bundle.bundle_id
            or evidence_bundle.candidate_id != candidate.candidate_id
            or plan.finding_id != finding.finding_id
            or plan.finding_digest != domain_object_digest(finding)
            or plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != domain_object_digest(candidate)
            or plan.evidence_bundle_id != evidence_bundle.bundle_id
            or plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
        ):
            raise ReportRejected("ReportDraftPlan provenance does not match its sealed inputs")
        referenced = {ref for section in plan.sections for ref in section.evidence_refs}
        if not referenced or not referenced <= set(evidence_bundle.evidence_refs):
            raise ReportRejected("Report citations exceed the Finding EvidenceBundle")
        catalog = {item.evidence_id: item for item in evidence}
        if len(catalog) != len(evidence):
            raise ReportRejected("Report Evidence catalog contains duplicate identities")
        if not set(evidence_bundle.evidence_refs) <= set(catalog):
            raise ReportRejected("Report Evidence catalog does not cover the Finding bundle")
        for ref in evidence_bundle.evidence_refs:
            item = catalog[ref]
            if item.target_version != candidate.target_version:
                raise ReportRejected("Report Evidence is bound to another Target version")
            try:
                self.evidence_store.read_text(item)
            except ValueError as exc:
                raise ReportRejected("Report Evidence is unavailable or corrupt") from exc
        return catalog
