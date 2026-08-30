"""Trusted human review, digest-bound approval, and local export services."""

from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.models import (
    Evidence,
    EvidenceBundle,
    Report,
    ReportReviewStatus,
    Scope,
    ScopeState,
)
from vulnloom.evidence import EvidenceStore

from .diff import ReportDiff, diff_reports
from .models import ReportArtifact, domain_object_digest
from .review_models import (
    ReportExportOutcome,
    ReportExportPlan,
    ReportReviewCommand,
    ReportReviewOutcome,
    ReportReviewPlan,
    ReportReviewRecord,
)
from .state_machine import ReviewDecisionKind, apply_review_decision, mark_report_exported
from .store import ReportArtifactStore
from .workflow_store import ReportExportStore, ReportReviewStore


class ReportReviewRejected(ValueError):
    """A report review or export violated a trusted workflow invariant."""


class HumanReportReviewService:
    def __init__(
        self,
        *,
        scope: Scope,
        evidence_store: EvidenceStore,
        artifact_store: ReportArtifactStore,
        store: ReportReviewStore,
    ):
        self.scope = scope
        self.evidence_store = evidence_store
        self.artifact_store = artifact_store
        self.store = store

    def review(
        self,
        report: Report,
        artifact: ReportArtifact,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        plan: ReportReviewPlan,
        command: ReportReviewCommand,
        *,
        now: datetime,
        previous_report: Report | None = None,
        report_diff: ReportDiff | None = None,
    ) -> ReportReviewOutcome:
        self._preflight(
            report,
            artifact,
            evidence_bundle,
            evidence,
            plan,
            command,
            now=now,
            previous_report=previous_report,
            report_diff=report_diff,
        )
        claim = self.store.claim(plan, command, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome

        reviewed = apply_review_decision(report, command.decision)
        reviewed_artifact = self.artifact_store.put(reviewed)
        record = ReportReviewRecord(
            review_id=uuid5(
                NAMESPACE_URL, f"vulnloom:report-review:{command.command_id}"
            ),
            plan_id=plan.plan_id,
            command_id=command.command_id,
            report_id=report.report_id,
            report_family_id=report.report_family_id,
            report_version=report.version,
            reviewed_report_digest=domain_object_digest(report),
            resulting_report_digest=domain_object_digest(reviewed),
            reviewer=command.reviewer,
            decision=command.decision,
            rationale_code=command.rationale_code,
            diff_id=plan.diff_id,
            decided_at=command.decided_at,
            expires_at=plan.approval_expires_at,
            resulting_status=reviewed.review_status,
        )
        outcome = ReportReviewOutcome(
            plan_id=plan.plan_id,
            report=reviewed,
            artifact=reviewed_artifact,
            review=record,
            completed_at=now,
        )
        self.store.complete(outcome, command_id=command.command_id)
        return outcome

    def _preflight(
        self,
        report: Report,
        artifact: ReportArtifact,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        plan: ReportReviewPlan,
        command: ReportReviewCommand,
        *,
        now: datetime,
        previous_report: Report | None,
        report_diff: ReportDiff | None,
    ) -> None:
        if report.review_status is not ReportReviewStatus.DRAFT:
            raise ReportReviewRejected("only a draft Report can enter human review")
        self._scope_preflight(report, now)
        if plan.created_at > now or now >= plan.deadline:
            raise ReportReviewRejected("ReportReviewPlan is not currently valid")
        if plan.approval_expires_at > self.scope.valid_until:
            raise ReportReviewRejected("Report approval cannot outlive the authorized Scope")
        report_digest = domain_object_digest(report)
        if (
            plan.report_id != report.report_id
            or plan.report_family_id != report.report_family_id
            or plan.report_version != report.version
            or plan.report_digest != report_digest
            or plan.artifact_digest != domain_object_digest(artifact)
            or plan.evidence_bundle_id != evidence_bundle.bundle_id
            or plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
            or command.plan_id != plan.plan_id
            or command.report_id != report.report_id
            or command.report_digest != report_digest
            or command.reviewer != plan.reviewer
            or not plan.created_at <= command.decided_at < plan.deadline
            or command.decided_at > now
        ):
            raise ReportReviewRejected("human review bindings do not match sealed inputs")
        persisted = self.artifact_store.read_report(artifact)
        if persisted != report or artifact.report_digest != report_digest:
            raise ReportReviewRejected("reviewed Report artifact does not match Report content")
        self._evidence_preflight(report, evidence_bundle, evidence)
        if report.version == 1:
            if previous_report is not None or report_diff is not None or plan.diff_id is not None:
                raise ReportReviewRejected("the first Report version cannot bind a revision diff")
        else:
            if previous_report is None or report_diff is None:
                raise ReportReviewRejected(
                    "revised Report review requires its predecessor and diff"
                )
            expected_diff = diff_reports(previous_report, report)
            if report_diff != expected_diff or plan.diff_id != expected_diff.diff_id:
                raise ReportReviewRejected("Report review diff binding is invalid")

    def _scope_preflight(self, report: Report, now: datetime) -> None:
        if self.scope.state is not ScopeState.APPROVED:
            raise ReportReviewRejected("Report workflow requires an approved Scope")
        if not self.scope.valid_from <= now < self.scope.valid_until:
            raise ReportReviewRejected("Report workflow is outside the Scope validity window")
        if report.scope_id != self.scope.scope_id or report.scope_version != self.scope.version:
            raise ReportReviewRejected("Report is bound to another Scope version")

    def _evidence_preflight(
        self,
        report: Report,
        bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
    ) -> None:
        if (
            report.evidence_bundle_id != bundle.bundle_id
            or report.candidate_id != bundle.candidate_id
            or not set(report.evidence_refs) <= set(bundle.evidence_refs)
        ):
            raise ReportReviewRejected("Report Evidence references exceed its Finding bundle")
        catalog = {item.evidence_id: item for item in evidence}
        if len(catalog) != len(evidence) or not set(bundle.evidence_refs) <= set(catalog):
            raise ReportReviewRejected("Report review Evidence catalog is incomplete")
        for ref in bundle.evidence_refs:
            item = catalog[ref]
            if item.target_version != report.target_version:
                raise ReportReviewRejected("Report review Evidence targets another version")
            try:
                self.evidence_store.read_text(item)
            except ValueError as exc:
                raise ReportReviewRejected(
                    "Report review Evidence is unavailable or corrupt"
                ) from exc


class LocalReportExportService:
    def __init__(
        self,
        *,
        scope: Scope,
        artifact_store: ReportArtifactStore,
        store: ReportExportStore,
    ):
        self.scope = scope
        self.artifact_store = artifact_store
        self.store = store

    def export(
        self,
        report: Report,
        artifact: ReportArtifact,
        review: ReportReviewRecord,
        plan: ReportExportPlan,
        *,
        now: datetime,
    ) -> ReportExportOutcome:
        self._preflight(report, artifact, review, plan, now=now)
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        exported = mark_report_exported(report)
        exported_artifact = self.artifact_store.put(exported)
        outcome = ReportExportOutcome(
            plan_id=plan.plan_id,
            report=exported,
            artifact=exported_artifact,
            review=review,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome

    def _preflight(
        self,
        report: Report,
        artifact: ReportArtifact,
        review: ReportReviewRecord,
        plan: ReportExportPlan,
        *,
        now: datetime,
    ) -> None:
        if report.review_status is not ReportReviewStatus.HUMAN_APPROVED:
            raise ReportReviewRejected("local export requires a human-approved Report")
        if self.scope.state is not ScopeState.APPROVED:
            raise ReportReviewRejected("local export requires an approved Scope")
        if not self.scope.valid_from <= now < self.scope.valid_until:
            raise ReportReviewRejected("local export is outside the Scope validity window")
        if plan.created_at > now or now >= plan.deadline or now >= review.expires_at:
            raise ReportReviewRejected("local export plan or human approval has expired")
        report_digest = domain_object_digest(report)
        if (
            report.scope_id != self.scope.scope_id
            or report.scope_version != self.scope.version
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
            or plan.report_id != report.report_id
            or plan.report_digest != report_digest
            or plan.artifact_digest != domain_object_digest(artifact)
            or plan.review_id != review.review_id
            or plan.review_digest != domain_object_digest(review)
            or review.decision is not ReviewDecisionKind.APPROVE
            or review.report_id != report.report_id
            or review.resulting_report_digest != report_digest
            or review.resulting_status is not ReportReviewStatus.HUMAN_APPROVED
        ):
            raise ReportReviewRejected("local export bindings do not match approved Report")
        if self.artifact_store.read_report(artifact) != report:
            raise ReportReviewRejected("approved Report artifact is unavailable or altered")
