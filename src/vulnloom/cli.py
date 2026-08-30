"""VulnLoom CLI for trusted workflow and offline source mapping."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import UUID

from vulnloom.analyzers import PythonWebSourceMapper, SourceGraphStore
from vulnloom.benchmark import (
    AnalyzerImportLimits,
    AnalyzerImportPlan,
    AnalyzerImportService,
    AnalyzerImportStore,
    AnalyzerKind,
    AnalyzerObservationArtifactStore,
    AnalyzerResultSnapshot,
    AutoPenBenchSnapshotAdapter,
    BenchmarkArtifactStore,
    BenchmarkGateStatus,
    BenchmarkObservationSet,
    BenchmarkPlan,
    BenchmarkService,
    BenchmarkStore,
    BenchmarkSuite,
    BountyBenchSnapshotAdapter,
    ExternalBenchmarkArtifactStore,
    ExternalBenchmarkImportPlan,
    ExternalBenchmarkImportService,
    ExternalBenchmarkImportStore,
    ExternalBenchmarkKind,
    ExternalBenchmarkSnapshot,
    ExternalImportLimits,
    create_analyzer_snapshot,
    create_external_snapshot,
    default_analyzer_adapters,
)
from vulnloom.broker import OfflineHttpTransport, StaticResolver, ToolBroker, default_tool_registry
from vulnloom.domain.models import (
    ArtifactKind,
    Engagement,
    EngagementState,
    Evidence,
    EvidenceBundle,
    Report,
    Scope,
    ScopeState,
    TargetSnapshot,
    utc_now,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.hypotheses import CandidateGenerator, CandidateSetStore
from vulnloom.ingestion import IngestionService
from vulnloom.reporting import (
    HumanReportReviewService,
    LocalReportExportService,
    ReportArtifact,
    ReportArtifactStore,
    ReportDiff,
    ReportExportPlan,
    ReportExportStore,
    ReportReviewCommand,
    ReportReviewPlan,
    ReportReviewRecord,
    ReportReviewStore,
    diff_reports,
)
from vulnloom.runners import OfflineSandboxRunner
from vulnloom.storage.events import Event, EventStore
from vulnloom.validation import ValidationPlan, ValidationService, ValidationStore


def _store(path: str) -> EventStore:
    return EventStore(Path(path))


def create_engagement(args: argparse.Namespace) -> int:
    engagement = Engagement(
        name=args.name,
        authority_reference=args.authority,
        state=EngagementState.ACTIVE,
    )
    event = Event(
        engagement_id=engagement.engagement_id,
        event_type="EngagementCreated",
        aggregate_id=str(engagement.engagement_id),
        payload=engagement.model_dump(mode="json"),
        idempotency_key=args.idempotency_key or f"engagement:create:{engagement.engagement_id}",
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(json.dumps({"created": created, "event": stored.model_dump(mode="json")}, indent=2))
    return 0


def approve_scope(args: argparse.Namespace) -> int:
    raw = json.loads(Path(args.file).read_text(encoding="utf-8"))
    scope = Scope.model_validate(raw)
    now = utc_now()
    if not scope.valid_from <= now < scope.valid_until:
        raise SystemExit("refusing to approve Scope outside its validity window")
    approved = scope.model_copy(
        update={"state": ScopeState.APPROVED, "approved_by": args.approver, "approved_at": now}
    )
    event = Event(
        engagement_id=approved.engagement_id,
        event_type="ScopeApproved",
        aggregate_id=str(approved.scope_id),
        payload=approved.model_dump(mode="json"),
        idempotency_key=args.idempotency_key
        or f"scope:approve:{approved.scope_id}:v{approved.version}",
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(json.dumps({"created": created, "event": stored.model_dump(mode="json")}, indent=2))
    return 0


def show_status(args: argparse.Namespace) -> int:
    engagement_id = UUID(args.engagement_id)
    with _store(args.db) as store:
        events = store.list_for_engagement(engagement_id)
    print(json.dumps([event.model_dump(mode="json") for event in events], indent=2))
    return 0


def _load_scope(path: str) -> Scope:
    return Scope.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _record_snapshot(args: argparse.Namespace, snapshot: TargetSnapshot) -> int:
    event = Event(
        engagement_id=snapshot.target.engagement_id,
        event_type="TargetIngested",
        aggregate_id=str(snapshot.target.target_id),
        payload=snapshot.model_dump(mode="json"),
        idempotency_key=(
            args.idempotency_key
            or f"target:ingest:{snapshot.target.target_id}:{snapshot.manifest.manifest_id}"
        ),
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(
        json.dumps(
            {"created": created, "event": stored.model_dump(mode="json")},
            indent=2,
        )
    )
    return 0


def ingest_archive(args: argparse.Namespace) -> int:
    snapshot = IngestionService(Path(args.store)).ingest_archive(
        Path(args.source),
        scope=_load_scope(args.scope_file),
        kind=ArtifactKind(args.kind),
    )
    return _record_snapshot(args, snapshot)


def quarantine_artifact(args: argparse.Namespace) -> int:
    artifact = IngestionService(Path(args.store)).quarantine_artifact(
        Path(args.source),
        engagement_id=UUID(args.engagement_id),
        kind=ArtifactKind(args.kind),
    )
    event = Event(
        engagement_id=artifact.engagement_id,
        event_type="ArtifactQuarantined",
        aggregate_id=artifact.artifact_id,
        payload=artifact.model_dump(mode="json", exclude={"captured_at"}),
        idempotency_key=(
            args.idempotency_key
            or f"artifact:quarantine:{artifact.engagement_id}:{artifact.artifact_id}"
        ),
    )
    with _store(args.db) as store:
        stored, created = store.append(event)
    print(json.dumps({"created": created, "event": stored.model_dump(mode="json")}, indent=2))
    return 0


def ingest_git(args: argparse.Namespace) -> int:
    snapshot = IngestionService(Path(args.store)).ingest_git(
        Path(args.source),
        repository_url=args.repository_url,
        commit=args.commit,
        scope=_load_scope(args.scope_file),
    )
    return _record_snapshot(args, snapshot)


def register_image(args: argparse.Namespace) -> int:
    snapshot = IngestionService(Path(args.store)).register_oci_image(
        args.image_ref,
        args.digest,
        scope=_load_scope(args.scope_file),
    )
    return _record_snapshot(args, snapshot)


def source_map(args: argparse.Namespace) -> int:
    service = IngestionService(Path(args.store))
    snapshot = service.load_snapshot(args.snapshot_id)
    scope = _load_scope(args.scope_file)
    graph = PythonWebSourceMapper().analyze(snapshot, service.root, scope=scope)
    graph_path, graph_created = SourceGraphStore(Path(args.analysis_store)).put(graph)
    summary = {
        "graph_id": graph.graph_id,
        "manifest_id": graph.manifest_id,
        "scope_id": str(graph.scope_id),
        "scope_version": graph.scope_version,
        "analyzer_version": graph.analyzer_version,
        "graph_ref": graph_path.name,
        "files_analyzed": len(graph.files_analyzed),
        "routes": len(graph.routes),
        "flows": len(graph.flows),
        "signals": len(graph.signals),
    }
    event = Event(
        engagement_id=snapshot.target.engagement_id,
        event_type="SourceGraphBuilt",
        aggregate_id=graph.graph_id,
        payload=summary,
        idempotency_key=args.idempotency_key or f"source-map:{graph.graph_id}",
    )
    with _store(args.db) as store:
        stored, event_created = store.append(event)
    print(
        json.dumps(
            {
                "graph_created": graph_created,
                "event_created": event_created,
                "graph": summary,
                "graph_path": str(graph_path),
                "event_id": str(stored.event_id),
            },
            indent=2,
        )
    )
    return 0


def generate_candidates(args: argparse.Namespace) -> int:
    scope = _load_scope(args.scope_file)
    graph = SourceGraphStore(Path(args.analysis_store)).load(args.graph_id)
    candidate_set = CandidateGenerator().generate(graph, scope=scope, now=utc_now())
    set_path, set_created = CandidateSetStore(Path(args.candidate_store)).put(candidate_set)
    summary = {
        "candidate_set_id": candidate_set.candidate_set_id,
        "source_graph_id": candidate_set.source_graph_id,
        "scope_id": str(candidate_set.scope_id),
        "scope_version": candidate_set.scope_version,
        "generator_version": candidate_set.generator_version,
        "candidate_set_ref": set_path.name,
        "candidates": len(candidate_set.candidates),
        "excluded_signals": len(candidate_set.excluded_signal_ids),
    }
    event = Event(
        engagement_id=scope.engagement_id,
        event_type="CandidatesGenerated",
        aggregate_id=candidate_set.candidate_set_id,
        payload=summary,
        idempotency_key=args.idempotency_key
        or f"candidate-generate:{candidate_set.candidate_set_id}",
    )
    with _store(args.db) as store:
        stored, event_created = store.append(event)
    print(
        json.dumps(
            {
                "candidate_set_created": set_created,
                "event_created": event_created,
                "candidate_set": summary,
                "candidate_set_path": str(set_path),
                "event_id": str(stored.event_id),
            },
            indent=2,
        )
    )
    return 0


def run_validation_offline(args: argparse.Namespace) -> int:
    """Exercise orchestration without executing target code or opening sockets."""
    scope = _load_scope(args.scope_file)
    candidate_set = CandidateSetStore(Path(args.candidate_store)).load(args.candidate_set_id)
    candidate_id = UUID(args.candidate_id)
    matches = tuple(
        candidate
        for candidate in candidate_set.candidates
        if candidate.candidate_id == candidate_id
    )
    if len(matches) != 1:
        raise SystemExit("Candidate is absent from the selected immutable CandidateSet")
    plan = ValidationPlan.model_validate_json(Path(args.plan_file).read_text(encoding="utf-8"))
    if plan.broker_calls:
        raise SystemExit("offline validation CLI refuses Broker calls and all network activity")
    broker = ToolBroker(
        scope=scope,
        registry=default_tool_registry(),
        resolver=StaticResolver({}),
        http_transport=OfflineHttpTransport({}),
    )
    with ValidationStore(Path(args.validation_db)) as validation_store:
        outcome = ValidationService(
            scope=scope,
            runner=OfflineSandboxRunner(frozenset({plan.runner_request.invocation.tool_id})),
            broker=broker,
            store=validation_store,
            evidence_store=EvidenceStore(Path(args.evidence_store)),
        ).execute(matches[0], plan, now=utc_now())
    summary = {
        "mode": "offline_orchestration_only",
        "plan_id": outcome.plan_id,
        "candidate_id": str(outcome.candidate.candidate_id),
        "candidate_state": outcome.candidate.state.value,
        "validation_run_id": str(outcome.validation_run.run_id),
        "result": outcome.validation_run.result.value,
        "evidence_refs": list(outcome.validation_run.evidence_refs),
    }
    event = Event(
        engagement_id=scope.engagement_id,
        event_type="ValidationCompleted",
        aggregate_id=str(outcome.candidate.candidate_id),
        payload=summary,
        idempotency_key=f"validation:completed:{outcome.plan_id}",
    )
    with _store(args.db) as event_store:
        stored, event_created = event_store.append(event)
    print(
        json.dumps(
            {
                "event_created": event_created,
                "validation": summary,
                "event_id": str(stored.event_id),
            },
            indent=2,
        )
    )
    return 0


def show_report_diff(args: argparse.Namespace) -> int:
    previous = Report.model_validate_json(Path(args.before).read_text(encoding="utf-8"))
    current = Report.model_validate_json(Path(args.after).read_text(encoding="utf-8"))
    result = diff_reports(previous, current)
    print(result.model_dump_json(indent=2))
    return 0


def review_report_offline(args: argparse.Namespace) -> int:
    scope = _load_scope(args.scope_file)
    artifact = ReportArtifact.model_validate_json(
        Path(args.artifact_file).read_text(encoding="utf-8")
    )
    artifact_store = ReportArtifactStore(Path(args.report_store))
    report = artifact_store.read_report(artifact)
    bundle = EvidenceBundle.model_validate_json(
        Path(args.evidence_bundle_file).read_text(encoding="utf-8")
    )
    evidence = tuple(
        Evidence.model_validate(item)
        for item in json.loads(Path(args.evidence_catalog_file).read_text(encoding="utf-8"))
    )
    plan = ReportReviewPlan.model_validate_json(
        Path(args.review_plan_file).read_text(encoding="utf-8")
    )
    command = ReportReviewCommand.model_validate_json(
        Path(args.review_command_file).read_text(encoding="utf-8")
    )
    previous = (
        Report.model_validate_json(Path(args.previous_report_file).read_text(encoding="utf-8"))
        if args.previous_report_file
        else None
    )
    report_diff = (
        ReportDiff.model_validate_json(Path(args.diff_file).read_text(encoding="utf-8"))
        if args.diff_file
        else None
    )
    with ReportReviewStore(Path(args.review_db)) as review_store:
        outcome = HumanReportReviewService(
            scope=scope,
            evidence_store=EvidenceStore(Path(args.evidence_store)),
            artifact_store=artifact_store,
            store=review_store,
        ).review(
            report,
            artifact,
            bundle,
            evidence,
            plan,
            command,
            now=utc_now(),
            previous_report=previous,
            report_diff=report_diff,
        )
    summary = {
        "mode": "offline_human_review",
        "report_id": str(outcome.report.report_id),
        "report_version": outcome.report.version,
        "review_id": str(outcome.review.review_id),
        "decision": outcome.review.decision.value,
        "review_status": outcome.report.review_status.value,
        "artifact": outcome.artifact.model_dump(mode="json"),
    }
    event = Event(
        engagement_id=scope.engagement_id,
        event_type="ReportReviewed",
        aggregate_id=str(outcome.report.report_id),
        payload=summary,
        idempotency_key=f"report:reviewed:{outcome.review.command_id}",
    )
    with _store(args.db) as event_store:
        stored, event_created = event_store.append(event)
    print(
        json.dumps(
            {"event_created": event_created, "review": summary, "event_id": str(stored.event_id)},
            indent=2,
        )
    )
    return 0


def export_report_local(args: argparse.Namespace) -> int:
    scope = _load_scope(args.scope_file)
    artifact = ReportArtifact.model_validate_json(
        Path(args.artifact_file).read_text(encoding="utf-8")
    )
    artifact_store = ReportArtifactStore(Path(args.report_store))
    report = artifact_store.read_report(artifact)
    review = ReportReviewRecord.model_validate_json(
        Path(args.review_record_file).read_text(encoding="utf-8")
    )
    plan = ReportExportPlan.model_validate_json(
        Path(args.export_plan_file).read_text(encoding="utf-8")
    )
    with ReportExportStore(Path(args.export_db)) as export_store:
        outcome = LocalReportExportService(
            scope=scope,
            artifact_store=artifact_store,
            store=export_store,
        ).export(report, artifact, review, plan, now=utc_now())
    summary = {
        "mode": "local_export_only",
        "report_id": str(outcome.report.report_id),
        "report_version": outcome.report.version,
        "review_status": outcome.report.review_status.value,
        "artifact": outcome.artifact.model_dump(mode="json"),
    }
    event = Event(
        engagement_id=scope.engagement_id,
        event_type="ReportExported",
        aggregate_id=str(outcome.report.report_id),
        payload=summary,
        idempotency_key=f"report:exported:{outcome.plan_id}",
    )
    with _store(args.db) as event_store:
        stored, event_created = event_store.append(event)
    print(
        json.dumps(
            {"event_created": event_created, "export": summary, "event_id": str(stored.event_id)},
            indent=2,
        )
    )
    return 0


def evaluate_benchmark_offline(args: argparse.Namespace) -> int:
    """Evaluate sealed local observations without running targets or opening sockets."""
    suite = BenchmarkSuite.model_validate_json(
        Path(args.suite_file).read_text(encoding="utf-8")
    )
    observations = BenchmarkObservationSet.model_validate_json(
        Path(args.observations_file).read_text(encoding="utf-8")
    )
    plan = BenchmarkPlan.model_validate_json(
        Path(args.plan_file).read_text(encoding="utf-8")
    )
    artifact_store = BenchmarkArtifactStore(Path(args.result_store))
    with BenchmarkStore(Path(args.benchmark_db)) as benchmark_store:
        outcome = BenchmarkService(
            store=benchmark_store,
            artifact_store=artifact_store,
        ).evaluate(suite, observations, plan, now=utc_now())
    summary = {
        "mode": "offline_fixture_evaluation",
        "plan_id": outcome.plan_id,
        "suite_id": outcome.result.suite_id,
        "result_id": str(outcome.result.result_id),
        "gate_status": outcome.result.gate_status.value,
        "metrics": outcome.result.metrics.model_dump(mode="json"),
        "violations": [item.model_dump(mode="json") for item in outcome.result.violations],
        "artifact": outcome.artifact.model_dump(mode="json"),
    }
    print(json.dumps(summary, indent=2))
    return 0 if outcome.result.gate_status is BenchmarkGateStatus.PASSED else 2


def create_benchmark_snapshot_manifest(args: argparse.Namespace) -> int:
    limits = ExternalImportLimits(
        max_files=args.max_files,
        max_single_file_bytes=args.max_single_file_bytes,
        max_total_bytes=args.max_total_bytes,
        timeout_seconds=args.timeout_seconds,
    )
    snapshot = create_external_snapshot(
        Path(args.source),
        kind=ExternalBenchmarkKind(args.kind),
        upstream_revision=args.upstream_revision,
        license_spdx=args.license_spdx,
        limits=limits,
    )
    print(snapshot.model_dump_json(indent=2))
    return 0


def import_external_benchmark_offline(args: argparse.Namespace) -> int:
    snapshot = ExternalBenchmarkSnapshot.model_validate_json(
        Path(args.snapshot_file).read_text(encoding="utf-8")
    )
    plan = ExternalBenchmarkImportPlan.model_validate_json(
        Path(args.plan_file).read_text(encoding="utf-8")
    )
    adapters = {
        ExternalBenchmarkKind.BOUNTYBENCH: BountyBenchSnapshotAdapter(),
        ExternalBenchmarkKind.AUTOPENBENCH: AutoPenBenchSnapshotAdapter(),
    }
    adapter = adapters[snapshot.kind]
    artifact_store = ExternalBenchmarkArtifactStore(Path(args.suite_store))
    with ExternalBenchmarkImportStore(Path(args.import_db)) as import_store:
        outcome = ExternalBenchmarkImportService(
            adapter=adapter,
            store=import_store,
            artifact_store=artifact_store,
        ).import_snapshot(Path(args.source), snapshot, plan, now=utc_now())
    summary = {
        "mode": "offline_external_snapshot_import",
        "plan_id": outcome.plan_id,
        "snapshot_id": outcome.snapshot_id,
        "suite_id": outcome.suite.suite_id,
        "suite_source": outcome.suite.source.value,
        "cases": len(outcome.suite.cases),
        "exclusions": [item.model_dump(mode="json") for item in outcome.exclusions],
        "artifact": outcome.artifact.model_dump(mode="json"),
    }
    print(json.dumps(summary, indent=2))
    return 0


def create_analyzer_result_manifest(args: argparse.Namespace) -> int:
    limits = AnalyzerImportLimits(
        max_output_bytes=args.max_output_bytes,
        max_cwe_map_bytes=args.max_cwe_map_bytes,
        timeout_seconds=args.timeout_seconds,
    )
    snapshot = create_analyzer_snapshot(
        Path(args.output),
        analyzer=AnalyzerKind(args.analyzer),
        target_id=UUID(args.target_id),
        target_version=args.target_version,
        tool_version=args.tool_version,
        rules_digest=args.rules_digest,
        cwe_map_path=Path(args.cwe_map) if args.cwe_map else None,
        limits=limits,
    )
    print(snapshot.model_dump_json(indent=2))
    return 0


def import_analyzer_observations_offline(args: argparse.Namespace) -> int:
    snapshot = AnalyzerResultSnapshot.model_validate_json(
        Path(args.snapshot_file).read_text(encoding="utf-8")
    )
    plan = AnalyzerImportPlan.model_validate_json(
        Path(args.plan_file).read_text(encoding="utf-8")
    )
    adapter = default_analyzer_adapters()[snapshot.analyzer]
    artifact_store = AnalyzerObservationArtifactStore(Path(args.observation_store))
    with AnalyzerImportStore(Path(args.import_db)) as import_store:
        outcome = AnalyzerImportService(
            adapter=adapter,
            store=import_store,
            artifact_store=artifact_store,
        ).import_result(
            Path(args.output),
            snapshot,
            plan,
            now=utc_now(),
            cwe_map_path=Path(args.cwe_map) if args.cwe_map else None,
        )
    observations = outcome.observation_set
    summary = {
        "mode": "offline_precomputed_analyzer_import",
        "plan_id": outcome.plan_id,
        "snapshot_id": outcome.snapshot_id,
        "observation_set_id": observations.observation_set_id,
        "analyzer": observations.analyzer.value,
        "target_id": str(observations.target_id),
        "target_version": observations.target_version,
        "observations": len(observations.observations),
        "exclusions": len(observations.exclusions),
        "artifact": outcome.artifact.model_dump(mode="json"),
    }
    print(json.dumps(summary, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnloom")
    parser.add_argument("--db", default=".vulnloom/events.db")
    parser.add_argument("--store", default=".vulnloom/targets")
    sub = parser.add_subparsers(required=True)

    engagement = sub.add_parser("engagement-create")
    engagement.add_argument("--name", required=True)
    engagement.add_argument("--authority", required=True)
    engagement.add_argument("--idempotency-key")
    engagement.set_defaults(handler=create_engagement)

    scope = sub.add_parser("scope-approve")
    scope.add_argument("--file", required=True)
    scope.add_argument("--approver", required=True)
    scope.add_argument("--idempotency-key")
    scope.set_defaults(handler=approve_scope)

    status = sub.add_parser("status")
    status.add_argument("--engagement-id", required=True)
    status.set_defaults(handler=show_status)

    quarantine = sub.add_parser("artifact-quarantine")
    quarantine.add_argument("--engagement-id", required=True)
    quarantine.add_argument("--source", required=True)
    quarantine.add_argument(
        "--kind",
        choices=(ArtifactKind.SOURCE_ARCHIVE.value, ArtifactKind.IAC_BUNDLE.value),
        default=ArtifactKind.SOURCE_ARCHIVE.value,
    )
    quarantine.add_argument("--idempotency-key")
    quarantine.set_defaults(handler=quarantine_artifact)

    archive = sub.add_parser("target-ingest-archive")
    archive.add_argument("--scope-file", required=True)
    archive.add_argument("--source", required=True)
    archive.add_argument(
        "--kind",
        choices=(ArtifactKind.SOURCE_ARCHIVE.value, ArtifactKind.IAC_BUNDLE.value),
        default=ArtifactKind.SOURCE_ARCHIVE.value,
    )
    archive.add_argument("--idempotency-key")
    archive.set_defaults(handler=ingest_archive)

    git = sub.add_parser("target-ingest-git")
    git.add_argument("--scope-file", required=True)
    git.add_argument("--source", required=True)
    git.add_argument("--repository-url", required=True)
    git.add_argument("--commit", required=True)
    git.add_argument("--idempotency-key")
    git.set_defaults(handler=ingest_git)

    image = sub.add_parser("target-register-image")
    image.add_argument("--scope-file", required=True)
    image.add_argument("--image-ref", required=True)
    image.add_argument("--digest", required=True)
    image.add_argument("--idempotency-key")
    image.set_defaults(handler=register_image)

    mapping = sub.add_parser("source-map")
    mapping.add_argument("--snapshot-id", required=True)
    mapping.add_argument("--scope-file", required=True)
    mapping.add_argument("--analysis-store", default=".vulnloom/analysis")
    mapping.add_argument("--idempotency-key")
    mapping.set_defaults(handler=source_map)

    candidates = sub.add_parser("candidate-generate")
    candidates.add_argument("--graph-id", required=True)
    candidates.add_argument("--scope-file", required=True)
    candidates.add_argument("--analysis-store", default=".vulnloom/analysis")
    candidates.add_argument("--candidate-store", default=".vulnloom/candidates")
    candidates.add_argument("--idempotency-key")
    candidates.set_defaults(handler=generate_candidates)

    validation = sub.add_parser("validation-run-offline")
    validation.add_argument("--scope-file", required=True)
    validation.add_argument("--candidate-store", default=".vulnloom/candidates")
    validation.add_argument("--candidate-set-id", required=True)
    validation.add_argument("--candidate-id", required=True)
    validation.add_argument("--plan-file", required=True)
    validation.add_argument("--validation-db", default=".vulnloom/validation.db")
    validation.add_argument("--evidence-store", default=".vulnloom/evidence")
    validation.set_defaults(handler=run_validation_offline)

    report_diff = sub.add_parser("report-review-diff")
    report_diff.add_argument("--before", required=True)
    report_diff.add_argument("--after", required=True)
    report_diff.set_defaults(handler=show_report_diff)

    review = sub.add_parser("report-review-offline")
    review.add_argument("--scope-file", required=True)
    review.add_argument("--artifact-file", required=True)
    review.add_argument("--evidence-bundle-file", required=True)
    review.add_argument("--evidence-catalog-file", required=True)
    review.add_argument("--review-plan-file", required=True)
    review.add_argument("--review-command-file", required=True)
    review.add_argument("--previous-report-file")
    review.add_argument("--diff-file")
    review.add_argument("--report-store", default=".vulnloom/reports")
    review.add_argument("--evidence-store", default=".vulnloom/evidence")
    review.add_argument("--review-db", default=".vulnloom/report-reviews.db")
    review.set_defaults(handler=review_report_offline)

    export = sub.add_parser("report-export-local")
    export.add_argument("--scope-file", required=True)
    export.add_argument("--artifact-file", required=True)
    export.add_argument("--review-record-file", required=True)
    export.add_argument("--export-plan-file", required=True)
    export.add_argument("--report-store", default=".vulnloom/reports")
    export.add_argument("--export-db", default=".vulnloom/report-exports.db")
    export.set_defaults(handler=export_report_local)

    benchmark = sub.add_parser("benchmark-evaluate-offline")
    benchmark.add_argument("--suite-file", required=True)
    benchmark.add_argument("--observations-file", required=True)
    benchmark.add_argument("--plan-file", required=True)
    benchmark.add_argument("--benchmark-db", default=".vulnloom/benchmarks.db")
    benchmark.add_argument("--result-store", default=".vulnloom/benchmark-results")
    benchmark.set_defaults(handler=evaluate_benchmark_offline)

    snapshot = sub.add_parser("benchmark-snapshot-manifest-local")
    snapshot.add_argument("--source", required=True)
    snapshot.add_argument(
        "--kind", choices=tuple(item.value for item in ExternalBenchmarkKind), required=True
    )
    snapshot.add_argument("--upstream-revision", required=True)
    snapshot.add_argument("--license-spdx", required=True)
    snapshot.add_argument("--max-files", type=int, default=20_000)
    snapshot.add_argument("--max-single-file-bytes", type=int, default=20 * 1024 * 1024)
    snapshot.add_argument("--max-total-bytes", type=int, default=200 * 1024 * 1024)
    snapshot.add_argument("--timeout-seconds", type=float, default=60.0)
    snapshot.set_defaults(handler=create_benchmark_snapshot_manifest)

    external = sub.add_parser("benchmark-import-offline")
    external.add_argument("--source", required=True)
    external.add_argument("--snapshot-file", required=True)
    external.add_argument("--plan-file", required=True)
    external.add_argument("--import-db", default=".vulnloom/benchmark-imports.db")
    external.add_argument("--suite-store", default=".vulnloom/benchmark-suites")
    external.set_defaults(handler=import_external_benchmark_offline)

    analyzer_snapshot = sub.add_parser("analyzer-result-manifest-local")
    analyzer_snapshot.add_argument("--output", required=True)
    analyzer_snapshot.add_argument("--cwe-map")
    analyzer_snapshot.add_argument(
        "--analyzer", choices=tuple(item.value for item in AnalyzerKind), required=True
    )
    analyzer_snapshot.add_argument("--target-id", required=True)
    analyzer_snapshot.add_argument("--target-version", required=True)
    analyzer_snapshot.add_argument("--tool-version", required=True)
    analyzer_snapshot.add_argument("--rules-digest", required=True)
    analyzer_snapshot.add_argument("--max-output-bytes", type=int, default=32 * 1024 * 1024)
    analyzer_snapshot.add_argument("--max-cwe-map-bytes", type=int, default=1024 * 1024)
    analyzer_snapshot.add_argument("--timeout-seconds", type=float, default=60.0)
    analyzer_snapshot.set_defaults(handler=create_analyzer_result_manifest)

    analyzer_import = sub.add_parser("analyzer-observations-import-offline")
    analyzer_import.add_argument("--output", required=True)
    analyzer_import.add_argument("--cwe-map")
    analyzer_import.add_argument("--snapshot-file", required=True)
    analyzer_import.add_argument("--plan-file", required=True)
    analyzer_import.add_argument("--import-db", default=".vulnloom/analyzer-imports.db")
    analyzer_import.add_argument(
        "--observation-store", default=".vulnloom/analyzer-observations"
    )
    analyzer_import.set_defaults(handler=import_analyzer_observations_offline)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
