from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest

from vulnloom.cli import main
from vulnloom.domain.models import (
    EvidenceBundle,
    EvidenceKind,
    Report,
    ReportChannel,
    ReportReviewStatus,
    ReportSection,
    ReportSectionKind,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.reporting import (
    HumanReportReviewService,
    LocalReportExportService,
    ReportArtifactStore,
    ReportExportPlan,
    ReportExportStore,
    ReportReviewCommand,
    ReportReviewOutcome,
    ReportReviewPlan,
    ReportReviewRejected,
    ReportReviewStore,
    ReportTransitionRejected,
    ReportWorkflowConflict,
    ReportWorkflowRecoveryRequired,
    ReviewDecisionKind,
    diff_reports,
    domain_object_digest,
    mark_report_exported,
)


def _inputs(tmp_path, approved_scope):
    target_version = "a" * 40
    candidate_id = uuid4()
    finding_id = uuid4()
    evidence_store = EvidenceStore(tmp_path / "evidence")
    source = evidence_store.capture_text(
        "entry app/routes.py:10 reaches app/models.py:41",
        kind=EvidenceKind.SOURCE,
        source_ref="source-graph:review-fixture",
        producer="test.source-mapper",
        target_version=target_version,
        summary="Redacted source path",
    )
    observed = evidence_store.capture_text(
        "authorized fixture returned the cross-tenant object",
        kind=EvidenceKind.HTTP,
        source_ref="validation-run:review-fixture",
        producer="test.http-validator",
        target_version=target_version,
        summary="Redacted HTTP observation",
    )
    evidence = (source, observed)
    bundle = EvidenceBundle(
        candidate_id=candidate_id,
        evidence_refs=(source.evidence_id, observed.evidence_id),
    )
    report = _report(
        approved_scope,
        finding_id=finding_id,
        candidate_id=candidate_id,
        bundle=bundle,
        target_version=target_version,
        version=1,
        plan_id="1" * 64,
    )
    artifacts = ReportArtifactStore(tmp_path / "artifacts")
    artifact = artifacts.put(report)
    return evidence_store, evidence, bundle, report, artifacts, artifact


def _report(
    scope,
    *,
    finding_id,
    candidate_id,
    bundle,
    target_version,
    version,
    plan_id,
    summary="A tenant boundary is missing.",
):
    family = uuid5(
        NAMESPACE_URL,
        f"vulnloom:report-family:{finding_id}:{ReportChannel.GENERIC.value}",
    )
    sections = (
        ReportSection(kind=ReportSectionKind.SUMMARY, text=summary),
        ReportSection(
            kind=ReportSectionKind.CODE_LOCATION,
            text="app/routes.py:10 reaches app/models.py:41.",
            evidence_refs=(bundle.evidence_refs[0],),
        ),
        ReportSection(
            kind=ReportSectionKind.REQUEST_RESPONSE,
            text="The authorized fixture returned another tenant's object.",
            evidence_refs=(bundle.evidence_refs[1],),
        ),
        ReportSection(
            kind=ReportSectionKind.REPRODUCTION,
            text="Issue the sealed read-only request.",
            evidence_refs=(bundle.evidence_refs[1],),
        ),
        ReportSection(
            kind=ReportSectionKind.IMPACT,
            text="Another tenant's invoice can be disclosed.",
            evidence_refs=bundle.evidence_refs,
        ),
        ReportSection(
            kind=ReportSectionKind.REMEDIATION,
            text="Apply a mandatory tenant predicate.",
        ),
    )
    return Report(
        report_id=uuid5(NAMESPACE_URL, f"vulnloom:report:{plan_id}"),
        report_family_id=family,
        draft_plan_id=plan_id,
        finding_id=finding_id,
        candidate_id=candidate_id,
        evidence_bundle_id=bundle.bundle_id,
        target_version=target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        channel=ReportChannel.GENERIC,
        version=version,
        title="Cross-tenant invoice disclosure",
        summary=summary,
        reproduction=("Issue the sealed read-only request.",),
        impact="Another tenant's invoice can be disclosed.",
        remediation="Apply a mandatory tenant predicate.",
        sections=sections,
        evidence_refs=bundle.evidence_refs,
    )


def _review_plan(now, scope, report, artifact, bundle, *, diff_id=None, key="review:1"):
    return ReportReviewPlan.create(
        report=report,
        artifact=artifact,
        evidence_bundle_digest=domain_object_digest(bundle),
        reviewer="human-reviewer",
        diff_id=diff_id,
        created_at=now,
        deadline=now + timedelta(minutes=2),
        approval_expires_at=min(
            now + timedelta(hours=1), scope.valid_until - timedelta(seconds=1)
        ),
        idempotency_key=key,
    )


def _command(now, plan, report, *, decision=ReviewDecisionKind.APPROVE, reviewer=None):
    return ReportReviewCommand.create(
        plan_id=plan.plan_id,
        report_id=report.report_id,
        report_digest=domain_object_digest(report),
        reviewer=reviewer or plan.reviewer,
        decision=decision,
        rationale_code=f"human_{decision.value}",
        decided_at=now + timedelta(seconds=1),
    )


def _review_service(tmp_path, scope, evidence_store, artifacts, *, name="review.db"):
    store = ReportReviewStore(tmp_path / name)
    service = HumanReportReviewService(
        scope=scope,
        evidence_store=evidence_store,
        artifact_store=artifacts,
        store=store,
    )
    return service, store


def test_human_approval_and_local_export_are_digest_bound_and_idempotent(
    tmp_path, approved_scope, now
):
    evidence_store, evidence, bundle, report, artifacts, artifact = _inputs(
        tmp_path, approved_scope
    )
    plan = _review_plan(now, approved_scope, report, artifact, bundle)
    command = _command(now, plan, report)
    service, review_store = _review_service(
        tmp_path, approved_scope, evidence_store, artifacts
    )
    first = service.review(
        report, artifact, bundle, evidence, plan, command, now=command.decided_at
    )
    second = service.review(
        report, artifact, bundle, evidence, plan, command, now=command.decided_at
    )
    assert first == second
    assert first.report.review_status is ReportReviewStatus.HUMAN_APPROVED
    review_store.close()

    export_plan = ReportExportPlan.create(
        report=first.report,
        artifact=first.artifact,
        review=first.review,
        created_at=command.decided_at,
        deadline=command.decided_at + timedelta(minutes=1),
        idempotency_key="export:1",
    )
    export_store = ReportExportStore(tmp_path / "export.db")
    exporter = LocalReportExportService(
        scope=approved_scope,
        artifact_store=artifacts,
        store=export_store,
    )
    exported = exporter.export(
        first.report,
        first.artifact,
        first.review,
        export_plan,
        now=command.decided_at,
    )
    replayed = exporter.export(
        first.report,
        first.artifact,
        first.review,
        export_plan,
        now=command.decided_at,
    )
    export_store.close()
    assert exported == replayed
    assert exported.report.review_status is ReportReviewStatus.EXPORTED
    assert artifacts.read_report(exported.artifact) == exported.report
    with pytest.raises(ReportTransitionRejected):
        mark_report_exported(exported.report)


def test_requested_changes_require_a_consecutive_diff_before_reapproval(
    tmp_path, approved_scope, now
):
    evidence_store, evidence, bundle, first, artifacts, first_artifact = _inputs(
        tmp_path, approved_scope
    )
    first_plan = _review_plan(now, approved_scope, first, first_artifact, bundle)
    changes_command = _command(
        now, first_plan, first, decision=ReviewDecisionKind.REQUEST_CHANGES
    )
    service, store = _review_service(tmp_path, approved_scope, evidence_store, artifacts)
    changes = service.review(
        first,
        first_artifact,
        bundle,
        evidence,
        first_plan,
        changes_command,
        now=changes_command.decided_at,
    )
    assert changes.report.review_status is ReportReviewStatus.CHANGES_REQUESTED

    second = _report(
        approved_scope,
        finding_id=first.finding_id,
        candidate_id=first.candidate_id,
        bundle=bundle,
        target_version=first.target_version,
        version=2,
        plan_id="2" * 64,
        summary="The tenant predicate is absent on the reachable lookup path.",
    )
    second_artifact = artifacts.put(second)
    report_diff = diff_reports(changes.report, second)
    second_plan = _review_plan(
        now + timedelta(seconds=2),
        approved_scope,
        second,
        second_artifact,
        bundle,
        diff_id=report_diff.diff_id,
        key="review:2",
    )
    approve = _command(now + timedelta(seconds=2), second_plan, second)
    approved = service.review(
        second,
        second_artifact,
        bundle,
        evidence,
        second_plan,
        approve,
        now=approve.decided_at,
        previous_report=changes.report,
        report_diff=report_diff,
    )
    store.close()
    assert approved.report.version == 2
    assert approved.review.diff_id == report_diff.diff_id
    assert approved.report.review_status is ReportReviewStatus.HUMAN_APPROVED
    assert any(change.path == "sections.summary" for change in report_diff.changes)


@pytest.mark.parametrize(
    "failure",
    ("expired", "reviewer", "content", "catalog", "target", "artifact", "scope"),
)
def test_review_rejects_expiry_identity_drift_and_integrity_failures(
    tmp_path, approved_scope, now, failure
):
    evidence_store, evidence, bundle, report, artifacts, artifact = _inputs(
        tmp_path, approved_scope
    )
    plan = _review_plan(now, approved_scope, report, artifact, bundle)
    command = _command(now, plan, report)
    scope = approved_scope
    supplied_report = report
    supplied_evidence = evidence
    review_now = command.decided_at
    if failure == "expired":
        review_now = plan.deadline
    elif failure == "reviewer":
        command = _command(now, plan, report, reviewer="another-reviewer")
    elif failure == "content":
        supplied_report = report.model_copy(update={"title": "Changed after approval request"})
    elif failure == "catalog":
        supplied_evidence = evidence[:-1]
    elif failure == "target":
        supplied_evidence = (
            evidence[0].model_copy(update={"target_version": "other"}),
            evidence[1],
        )
    elif failure == "artifact":
        path = artifacts.root / artifact.markdown_ref
        path.parent.chmod(0o700)
        path.chmod(0o600)
        path.write_text("tampered", encoding="utf-8")
    else:
        scope = approved_scope.model_copy(update={"valid_until": review_now})
    service, store = _review_service(tmp_path, scope, evidence_store, artifacts)
    with pytest.raises((ReportReviewRejected, ValueError)):
        service.review(
            supplied_report,
            artifact,
            bundle,
            supplied_evidence,
            plan,
            command,
            now=review_now,
        )
    count = store.connection.execute("SELECT COUNT(*) FROM report_reviews").fetchone()[0]
    store.close()
    assert count == 0


def test_report_content_change_invalidates_old_approval_request(
    tmp_path, approved_scope, now
):
    evidence_store, evidence, bundle, report, artifacts, artifact = _inputs(
        tmp_path, approved_scope
    )
    plan = _review_plan(now, approved_scope, report, artifact, bundle)
    command = _command(now, plan, report)
    changed = report.model_copy(update={"title": "Changed after the request was sealed"})
    changed_artifact = artifacts.put(changed)
    service, store = _review_service(tmp_path, approved_scope, evidence_store, artifacts)
    with pytest.raises(ReportReviewRejected, match="bindings"):
        service.review(
            changed,
            changed_artifact,
            bundle,
            evidence,
            plan,
            command,
            now=command.decided_at,
        )
    store.close()


def test_approval_expiry_and_nonapproval_block_local_export(
    tmp_path, approved_scope, now
):
    evidence_store, evidence, bundle, report, artifacts, artifact = _inputs(
        tmp_path, approved_scope
    )
    plan = _review_plan(now, approved_scope, report, artifact, bundle)
    command = _command(now, plan, report)
    service, review_store = _review_service(
        tmp_path, approved_scope, evidence_store, artifacts
    )
    approved = service.review(
        report, artifact, bundle, evidence, plan, command, now=command.decided_at
    )
    review_store.close()
    export_plan = ReportExportPlan.create(
        report=approved.report,
        artifact=approved.artifact,
        review=approved.review,
        created_at=command.decided_at,
        deadline=approved.review.expires_at + timedelta(minutes=1),
        idempotency_key="export:expired",
    )
    export_store = ReportExportStore(tmp_path / "export.db")
    exporter = LocalReportExportService(
        scope=approved_scope,
        artifact_store=artifacts,
        store=export_store,
    )
    with pytest.raises(ReportReviewRejected, match="expired"):
        exporter.export(
            approved.report,
            approved.artifact,
            approved.review,
            export_plan,
            now=approved.review.expires_at,
        )
    with pytest.raises(ReportReviewRejected, match="human-approved"):
        exporter.export(report, artifact, approved.review, export_plan, now=command.decided_at)
    count = export_store.connection.execute("SELECT COUNT(*) FROM report_exports").fetchone()[0]
    export_store.close()
    assert count == 0


def test_review_store_conflict_recovery_and_cleanup(
    tmp_path, approved_scope, now
):
    evidence_store, evidence, bundle, report, artifacts, artifact = _inputs(
        tmp_path, approved_scope
    )
    plan = _review_plan(now, approved_scope, report, artifact, bundle)
    approve = _command(now, plan, report)
    service, store = _review_service(tmp_path, approved_scope, evidence_store, artifacts)
    service.review(report, artifact, bundle, evidence, plan, approve, now=approve.decided_at)
    reject = _command(now, plan, report, decision=ReviewDecisionKind.REJECT)
    with pytest.raises(ReportWorkflowConflict):
        service.review(report, artifact, bundle, evidence, plan, reject, now=reject.decided_at)
    store.close()

    recovery_store = ReportReviewStore(tmp_path / "recovery.db")
    recovery_store.claim(plan, approve, now=approve.decided_at)
    recovery_service = HumanReportReviewService(
        scope=approved_scope,
        evidence_store=evidence_store,
        artifact_store=artifacts,
        store=recovery_store,
    )
    with pytest.raises(ReportWorkflowRecoveryRequired):
        recovery_service.review(
            report, artifact, bundle, evidence, plan, approve, now=approve.decided_at
        )
    recovery_store.close()

    closing = ReportExportStore(tmp_path / "closing.db")
    with pytest.raises(RuntimeError), closing:
        raise RuntimeError("boom")
    with pytest.raises(sqlite3.ProgrammingError):
        closing.connection.execute("SELECT 1")


def test_diff_rejects_nonconsecutive_or_unchanged_reports(tmp_path, approved_scope):
    _, _, bundle, first, _, _ = _inputs(tmp_path, approved_scope)
    unchanged = _report(
        approved_scope,
        finding_id=first.finding_id,
        candidate_id=first.candidate_id,
        bundle=bundle,
        target_version=first.target_version,
        version=2,
        plan_id="2" * 64,
    )
    with pytest.raises(ValueError, match="reviewable change"):
        diff_reports(first, unchanged)
    skipped = unchanged.model_copy(update={"version": 3, "summary": "Changed"})
    with pytest.raises(ValueError, match="consecutive"):
        diff_reports(first, skipped)


def test_report_review_diff_cli_is_offline_and_structured(
    tmp_path, approved_scope, capsys
):
    _, _, bundle, first, _, _ = _inputs(tmp_path, approved_scope)
    second = _report(
        approved_scope,
        finding_id=first.finding_id,
        candidate_id=first.candidate_id,
        bundle=bundle,
        target_version=first.target_version,
        version=2,
        plan_id="2" * 64,
        summary="The tenant predicate is absent on the reachable lookup path.",
    )
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(first.model_dump_json(), encoding="utf-8")
    after.write_text(second.model_dump_json(), encoding="utf-8")
    assert main(["report-review-diff", "--before", str(before), "--after", str(after)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["from_version"] == 1
    assert result["to_version"] == 2
    assert result["changes"][0]["path"] == "sections.summary"


def test_offline_review_and_export_cli_complete_without_report_body_events(
    tmp_path, approved_scope, now, capsys
):
    evidence_store, evidence, bundle, report, artifacts, artifact = _inputs(
        tmp_path, approved_scope
    )
    plan = ReportReviewPlan.create(
        report=report,
        artifact=artifact,
        evidence_bundle_digest=domain_object_digest(bundle),
        reviewer="human-reviewer",
        diff_id=None,
        created_at=now - timedelta(seconds=1),
        deadline=now + timedelta(minutes=2),
        approval_expires_at=min(
            now + timedelta(hours=1), approved_scope.valid_until - timedelta(seconds=1)
        ),
        idempotency_key="review:cli",
    )
    command = ReportReviewCommand.create(
        plan_id=plan.plan_id,
        report_id=report.report_id,
        report_digest=domain_object_digest(report),
        reviewer=plan.reviewer,
        decision=ReviewDecisionKind.APPROVE,
        rationale_code="human_approve",
        decided_at=now,
    )
    paths = {
        "scope": tmp_path / "scope.json",
        "artifact": tmp_path / "artifact.json",
        "bundle": tmp_path / "bundle.json",
        "evidence": tmp_path / "evidence.json",
        "plan": tmp_path / "review-plan.json",
        "command": tmp_path / "review-command.json",
    }
    paths["scope"].write_text(approved_scope.model_dump_json(), encoding="utf-8")
    paths["artifact"].write_text(artifact.model_dump_json(), encoding="utf-8")
    paths["bundle"].write_text(bundle.model_dump_json(), encoding="utf-8")
    paths["evidence"].write_text(
        json.dumps([item.model_dump(mode="json") for item in evidence]), encoding="utf-8"
    )
    paths["plan"].write_text(plan.model_dump_json(), encoding="utf-8")
    paths["command"].write_text(command.model_dump_json(), encoding="utf-8")
    event_db = tmp_path / "events.db"
    review_db = tmp_path / "review-cli.db"
    assert (
        main(
            [
                "--db",
                str(event_db),
                "report-review-offline",
                "--scope-file",
                str(paths["scope"]),
                "--artifact-file",
                str(paths["artifact"]),
                "--evidence-bundle-file",
                str(paths["bundle"]),
                "--evidence-catalog-file",
                str(paths["evidence"]),
                "--review-plan-file",
                str(paths["plan"]),
                "--review-command-file",
                str(paths["command"]),
                "--report-store",
                str(artifacts.root),
                "--evidence-store",
                str(evidence_store.root),
                "--review-db",
                str(review_db),
            ]
        )
        == 0
    )
    review_output = json.loads(capsys.readouterr().out)
    assert review_output["review"]["review_status"] == "human_approved"
    with ReportReviewStore(review_db) as review_store:
        row = review_store.connection.execute(
            "SELECT outcome_json FROM report_reviews"
        ).fetchone()
    outcome = ReportReviewOutcome.model_validate_json(row[0])

    approved_artifact = tmp_path / "approved-artifact.json"
    review_record = tmp_path / "review-record.json"
    export_plan_file = tmp_path / "export-plan.json"
    approved_artifact.write_text(outcome.artifact.model_dump_json(), encoding="utf-8")
    review_record.write_text(outcome.review.model_dump_json(), encoding="utf-8")
    export_plan = ReportExportPlan.create(
        report=outcome.report,
        artifact=outcome.artifact,
        review=outcome.review,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="export:cli",
    )
    export_plan_file.write_text(export_plan.model_dump_json(), encoding="utf-8")
    assert (
        main(
            [
                "--db",
                str(event_db),
                "report-export-local",
                "--scope-file",
                str(paths["scope"]),
                "--artifact-file",
                str(approved_artifact),
                "--review-record-file",
                str(review_record),
                "--export-plan-file",
                str(export_plan_file),
                "--report-store",
                str(artifacts.root),
                "--export-db",
                str(tmp_path / "export-cli.db"),
            ]
        )
        == 0
    )
    export_output = json.loads(capsys.readouterr().out)
    assert export_output["export"]["review_status"] == "exported"
    with closing(sqlite3.connect(event_db)) as connection:
        payloads = tuple(
            row[0] for row in connection.execute("SELECT payload_json FROM domain_events")
        )
    assert len(payloads) == 2
    assert all("Cross-tenant invoice disclosure" not in payload for payload in payloads)
    assert all("authorized fixture" not in payload for payload in payloads)
