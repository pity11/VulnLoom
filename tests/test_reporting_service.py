from __future__ import annotations

import sqlite3
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import (
    DETERMINISTIC_CRITIC_RULESET_DIGEST,
    CandidateState,
    CriticReview,
    CriticVerdict,
    EvidenceBundle,
    EvidenceKind,
    ReportChannel,
    ReportSection,
    ReportSectionKind,
    ValidationResult,
    ValidationRun,
)
from vulnloom.domain.state_machine import promote_candidate
from vulnloom.evidence import EvidenceStore
from vulnloom.reporting import (
    DeterministicReportService,
    ReportArtifactStore,
    ReportDraftPlan,
    ReportDraftStore,
    ReportIdempotencyConflict,
    ReportRecoveryRequired,
    ReportRejected,
    domain_object_digest,
)


def _finding_inputs(tmp_path, candidate, approved_scope, now):
    evidence_store = EvidenceStore(tmp_path / "evidence")
    source = evidence_store.capture_text(
        "entry app/routes.py:10 reaches app/models.py:41",
        kind=EvidenceKind.SOURCE,
        source_ref="source-graph:fixture",
        producer="test.source-mapper",
        target_version=candidate.target_version,
        summary="Redacted source-path Evidence",
    )
    observed = evidence_store.capture_text(
        "GET /invoice/42 returned an authorized fixture object",
        kind=EvidenceKind.HTTP,
        source_ref="validation-run:fixture",
        producer="test.http-validator",
        target_version=candidate.target_version,
        summary="Redacted request-response Evidence",
    )
    refs = (source.evidence_id, observed.evidence_id)
    run = ValidationRun(
        candidate_id=candidate.candidate_id,
        target_version=candidate.target_version,
        scope_version=candidate.scope_version,
        sandbox_image_digest="sha256:" + "a" * 64,
        policy_digest="b" * 64,
        plan=("sealed-validation-plan",),
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        result=ValidationResult.REPRODUCED,
        evidence_refs=refs,
    )
    bundle = EvidenceBundle(
        candidate_id=candidate.candidate_id,
        evidence_refs=refs,
        sealed_at=now + timedelta(seconds=1),
    )
    reviewed = candidate.model_copy(update={"state": CandidateState.CRITIC_REVIEWED})
    critic_plan_id = "1" * 64
    review = CriticReview(
        review_id=uuid5(NAMESPACE_URL, f"vulnloom:critic-review:{critic_plan_id}"),
        plan_id=critic_plan_id,
        candidate_id=candidate.candidate_id,
        validation_run_id=run.run_id,
        evidence_bundle_id=bundle.bundle_id,
        validation_context_id="2" * 64,
        review_context_id="3" * 64,
        ruleset_digest=DETERMINISTIC_CRITIC_RULESET_DIGEST,
        verdict=CriticVerdict.ACCEPTED,
        rationale_code="all_counterevidence_angles_ruled_out",
        reviewed_at=now,
    )
    promoted, finding = promote_candidate(
        reviewed,
        scope=approved_scope,
        now=now,
        root_cause="Missing tenant ownership predicate",
        affected_versions=(candidate.target_version,),
        impact="Cross-tenant invoice disclosure",
        severity_assessment={"cvss": 6.5},
        validation_runs=(run,),
        evidence_bundle=bundle,
        critic_review=review,
        duplicate_checked=True,
    )
    return evidence_store, (source, observed), promoted, finding, bundle


def _sections(source_ref, observed_ref, *, secret=False):
    token = " Authorization: Bearer report-secret-token" if secret else ""
    return (
        ReportSection(
            kind=ReportSectionKind.SUMMARY,
            text="A tenant boundary is missing." + token,
        ),
        ReportSection(
            kind=ReportSectionKind.CODE_LOCATION,
            text="app/routes.py:10 reaches app/models.py:41.",
            evidence_refs=(source_ref,),
        ),
        ReportSection(
            kind=ReportSectionKind.REQUEST_RESPONSE,
            text="The authorized fixture returned another tenant's object.",
            evidence_refs=(observed_ref,),
        ),
        ReportSection(
            kind=ReportSectionKind.REPRODUCTION,
            text="Issue the sealed read-only fixture request.",
            evidence_refs=(observed_ref,),
        ),
        ReportSection(
            kind=ReportSectionKind.IMPACT,
            text="An authenticated tenant can read another tenant's invoice.",
            evidence_refs=(source_ref, observed_ref),
        ),
        ReportSection(
            kind=ReportSectionKind.REMEDIATION,
            text="Apply a mandatory tenant predicate before object retrieval.",
        ),
    )


def _plan(now, candidate, finding, bundle, *, sections=None, key="report:1", **updates):
    values = {
        "finding_id": finding.finding_id,
        "finding_digest": domain_object_digest(finding),
        "candidate_id": candidate.candidate_id,
        "candidate_digest": domain_object_digest(candidate),
        "evidence_bundle_id": bundle.bundle_id,
        "evidence_bundle_digest": domain_object_digest(bundle),
        "scope_id": candidate.scope_id,
        "scope_version": candidate.scope_version,
        "channel": ReportChannel.GENERIC,
        "title": "Cross-tenant invoice disclosure <script>alert(1)</script>",
        "sections": sections or _sections(*bundle.evidence_refs),
        "prepared_by": "human-report-reviewer",
        "created_at": now + timedelta(seconds=2),
        "deadline": now + timedelta(minutes=2),
        "idempotency_key": key,
    }
    values.update(updates)
    return ReportDraftPlan.create(**values)


def _service(tmp_path, scope, evidence_store, *, artifact_store=None):
    store = ReportDraftStore(tmp_path / "reports.db")
    artifacts = artifact_store or ReportArtifactStore(tmp_path / "reports")
    service = DeterministicReportService(
        scope=scope,
        evidence_store=evidence_store,
        store=store,
        artifact_store=artifacts,
    )
    return service, store, artifacts


def test_report_draft_is_redacted_traceable_deterministic_and_locally_exported(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, promoted, finding, bundle = _finding_inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(
        now,
        promoted,
        finding,
        bundle,
        sections=_sections(*bundle.evidence_refs, secret=True),
    )
    service, store, artifacts = _service(tmp_path, approved_scope, evidence_store)

    first = service.draft(finding, promoted, bundle, evidence, plan, now=plan.created_at)
    second = service.draft(finding, promoted, bundle, evidence, plan, now=plan.created_at)
    markdown = artifacts.read_markdown(first.artifact)
    persisted = artifacts.read_report(first.artifact)
    store.close()

    assert first == second
    assert first.report == persisted
    assert "report-secret-token" not in first.report.model_dump_json()
    assert "[REDACTED]" in first.report.summary
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    for ref in bundle.evidence_refs:
        assert ref in markdown
        assert ref in first.report.evidence_refs
    assert first.report.review_status.value == "draft"
    unsafe = first.report.model_copy(update={"title": "Authorization: Bearer leaked-token"})
    with pytest.raises(ValueError, match="not passed redaction"):
        artifacts.put(unsafe)


@pytest.mark.parametrize(
    ("channel", "heading"),
    ((ReportChannel.EDUSRC, "漏洞概述"), (ReportChannel.VENDOR, "Executive summary")),
)
def test_channel_mapping_changes_only_deterministic_headings(
    tmp_path, candidate, approved_scope, now, channel, heading
):
    evidence_store, evidence, promoted, finding, bundle = _finding_inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, promoted, finding, bundle, channel=channel)
    service, store, artifacts = _service(tmp_path, approved_scope, evidence_store)
    outcome = service.draft(finding, promoted, bundle, evidence, plan, now=plan.created_at)
    markdown = artifacts.read_markdown(outcome.artifact)
    store.close()
    assert f"## {heading}" in markdown


def test_report_plan_requires_all_sections_and_evidence_backing(
    tmp_path, candidate, approved_scope, now
):
    _, _, promoted, finding, bundle = _finding_inputs(tmp_path, candidate, approved_scope, now)
    with pytest.raises(ValidationError, match="at least 6"):
        _plan(now, promoted, finding, bundle, sections=_sections(*bundle.evidence_refs)[:-1])
    with pytest.raises(ValidationError, match="requires Evidence"):
        ReportSection(kind=ReportSectionKind.IMPACT, text="Unsupported impact claim")


@pytest.mark.parametrize(
    "failure",
    ("candidate", "scope", "provenance", "foreign_ref", "catalog", "target", "corrupt"),
)
def test_report_rejects_invalid_state_scope_provenance_or_evidence(
    tmp_path, candidate, approved_scope, now, failure
):
    evidence_store, evidence, promoted, finding, bundle = _finding_inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, promoted, finding, bundle)
    scope = approved_scope
    supplied_candidate = promoted
    supplied_evidence = evidence
    if failure == "candidate":
        supplied_candidate = promoted.model_copy(update={"state": CandidateState.VALIDATED})
    elif failure == "scope":
        scope = approved_scope.model_copy(update={"valid_until": plan.created_at})
    elif failure == "provenance":
        finding = finding.model_copy(update={"impact": "changed after sealing"})
    elif failure == "foreign_ref":
        sections = list(plan.sections)
        sections[1] = sections[1].model_copy(update={"evidence_refs": ("f" * 64,)})
        plan = _plan(now, promoted, finding, bundle, sections=tuple(sections))
    elif failure == "catalog":
        supplied_evidence = evidence[:-1]
    elif failure == "target":
        supplied_evidence = (
            evidence[0].model_copy(update={"target_version": "other"}),
            evidence[1],
        )
    else:
        path = tmp_path / "evidence" / evidence[0].content_ref
        path.write_text("tampered", encoding="utf-8")
    service, store, _ = _service(tmp_path, scope, evidence_store)

    with pytest.raises(ReportRejected):
        service.draft(
            finding,
            supplied_candidate,
            bundle,
            supplied_evidence,
            plan,
            now=plan.created_at,
        )
    count = store.connection.execute("SELECT COUNT(*) FROM report_executions").fetchone()[0]
    store.close()
    assert count == 0


def test_expired_report_plan_stops_before_checkpoint_or_artifact(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, promoted, finding, bundle = _finding_inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, promoted, finding, bundle)
    service, store, artifacts = _service(tmp_path, approved_scope, evidence_store)

    with pytest.raises(ReportRejected, match="not currently valid"):
        service.draft(finding, promoted, bundle, evidence, plan, now=plan.deadline)
    count = store.connection.execute("SELECT COUNT(*) FROM report_executions").fetchone()[0]
    store.close()
    assert count == 0
    assert tuple(artifacts.objects.iterdir()) == ()


def test_report_artifact_failure_cleans_temporary_directory(
    tmp_path, candidate, approved_scope, now, monkeypatch
):
    evidence_store, evidence, promoted, finding, bundle = _finding_inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, promoted, finding, bundle)
    artifacts = ReportArtifactStore(tmp_path / "reports")
    original = artifacts._write
    calls = 0

    def fail_second_write(path, content):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture write failure")
        original(path, content)

    monkeypatch.setattr(artifacts, "_write", fail_second_write)
    service, store, _ = _service(
        tmp_path, approved_scope, evidence_store, artifact_store=artifacts
    )
    with pytest.raises(OSError, match="fixture"):
        service.draft(finding, promoted, bundle, evidence, plan, now=plan.created_at)
    assert not tuple(artifacts.objects.glob("report-*"))
    state = store.connection.execute("SELECT state FROM report_executions").fetchone()[0]
    store.close()
    assert state == "started"


def test_report_store_rejects_conflicts_unfinished_replay_and_closes(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, promoted, finding, bundle = _finding_inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, promoted, finding, bundle)
    service, store, _ = _service(tmp_path, approved_scope, evidence_store)
    service.draft(finding, promoted, bundle, evidence, plan, now=plan.created_at)
    changed = _plan(
        now,
        promoted,
        finding,
        bundle,
        key=plan.idempotency_key,
        title="Changed title",
    )
    with pytest.raises(ReportIdempotencyConflict):
        service.draft(finding, promoted, bundle, evidence, changed, now=changed.created_at)
    store.close()

    recovery_store = ReportDraftStore(tmp_path / "recovery.db")
    recovery_store.claim(plan, now=plan.created_at)
    recovery_service = DeterministicReportService(
        scope=approved_scope,
        evidence_store=evidence_store,
        store=recovery_store,
        artifact_store=ReportArtifactStore(tmp_path / "recovery-reports"),
    )
    with pytest.raises(ReportRecoveryRequired):
        recovery_service.draft(
            finding, promoted, bundle, evidence, plan, now=plan.created_at
        )
    recovery_store.close()

    closing_store = ReportDraftStore(tmp_path / "closing.db")
    with pytest.raises(RuntimeError), closing_store:
        raise RuntimeError("boom")
    with pytest.raises(sqlite3.ProgrammingError):
        closing_store.connection.execute("SELECT 1")


def test_report_artifact_integrity_rejects_tampering_and_symlinks(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, promoted, finding, bundle = _finding_inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, promoted, finding, bundle)
    service, store, artifacts = _service(tmp_path, approved_scope, evidence_store)
    outcome = service.draft(finding, promoted, bundle, evidence, plan, now=plan.created_at)
    markdown_path = artifacts.root / outcome.artifact.markdown_ref
    outside = tmp_path / "outside-report"
    markdown_path.parent.chmod(0o700)
    markdown_path.rename(outside)
    markdown_path.symlink_to(outside)
    with pytest.raises(ValueError, match="unavailable or unsafe"):
        artifacts.read_markdown(outcome.artifact)
    store.close()
