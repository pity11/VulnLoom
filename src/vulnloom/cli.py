"""VulnLoom CLI for trusted workflow and offline source mapping."""

from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from uuid import UUID

from vulnloom.agent_runtime import AgentSessionAuditArtifact, AgentSessionAuditArtifactStore
from vulnloom.analyzers import PythonWebSourceMapper, SourceGraphStore
from vulnloom.benchmark import (
    AnalyzerEvaluationArtifactStore,
    AnalyzerEvaluationPlan,
    AnalyzerEvaluationService,
    AnalyzerEvaluationStore,
    AnalyzerExecutionPlan,
    AnalyzerExecutionStore,
    AnalyzerImportLimits,
    AnalyzerImportPlan,
    AnalyzerImportService,
    AnalyzerImportStore,
    AnalyzerKind,
    AnalyzerObservationArtifactStore,
    AnalyzerObservationSet,
    AnalyzerResultSnapshot,
    AnalyzerToolRegistration,
    AnalyzerToolRegistry,
    AnalyzerTruthAlignment,
    AuthorizedPilotManifest,
    AuthorizedPilotReadinessArtifactStore,
    AuthorizedPilotReadinessPlan,
    AuthorizedPilotReadinessPolicy,
    AuthorizedPilotReadinessService,
    AuthorizedPilotReadinessStore,
    AutoPenBenchSnapshotAdapter,
    BenchmarkArtifactStore,
    BenchmarkBaseline,
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
    LocalSourceEffectCounters,
    LocalSourceObservationSet,
    LocalSourceRobustnessProfile,
    LocalSourceSuite,
    OfflineAnalyzerExecutionService,
    PilotCandidateSelectionService,
    PilotCandidateSelectionStore,
    create_analyzer_snapshot,
    create_external_snapshot,
    default_analyzer_adapters,
    evaluate_local_source_robustness,
)
from vulnloom.broker import OfflineHttpTransport, StaticResolver, ToolBroker, default_tool_registry
from vulnloom.critic import (
    AgentCriticIntakeCommand,
    AgentCriticIntakePlan,
    AgentCriticIntakeService,
    AgentCriticIntakeStore,
    AgentCriticOutcomeBindingPlan,
    AgentCriticOutcomeBindingService,
    AgentCriticOutcomeBindingStore,
    CriticPlan,
    CriticStore,
    DeterministicCritic,
    PilotCriticExecutionPlan,
    PilotCriticExecutionService,
    PilotCriticExecutionStore,
    PilotCriticIntakePlan,
    PilotCriticIntakeService,
    PilotCriticIntakeStore,
)
from vulnloom.domain.models import (
    ApprovalRequest,
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
from vulnloom.findings import (
    AgentFindingIntakeCommand,
    AgentFindingIntakePlan,
    AgentFindingIntakeService,
    AgentFindingIntakeStore,
    FindingDuplicateCheck,
    FindingDuplicateCheckStore,
    FindingPromotionExecutionPlan,
    FindingPromotionPlan,
    FindingPromotionService,
    FindingPromotionStore,
    PilotFindingIntakePlan,
    PilotFindingIntakeService,
    PilotFindingIntakeStore,
    PilotFindingPromotionPlan,
    PilotFindingPromotionService,
    PilotFindingPromotionStore,
)
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
from vulnloom.validation import (
    AgentValidationIntakeCommand,
    AgentValidationIntakePlan,
    AgentValidationIntakeService,
    AgentValidationIntakeStore,
    AgentValidationOutcomeBindingPlan,
    AgentValidationOutcomeBindingService,
    AgentValidationOutcomeBindingStore,
    PilotValidationExecutionService,
    PilotValidationExecutionStore,
    PilotValidationIntakeService,
    PilotValidationIntakeStore,
    PilotValidationOutcomePlan,
    PilotValidationOutcomeService,
    PilotValidationOutcomeStore,
    ValidationPlan,
    ValidationService,
    ValidationStore,
)

_ADMITTED_M9_4_PROFILE_ID = "e26b65b236daf7c40631643fe973f1760d33e183748c2c8178f95de1c732021b"
_ADMITTED_M9_4_RESULT_ID = "fd43cbf7d5833ee2244578d001215daddf28c2f6e51f61f60049e3378ea22c83"


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


def _load_admitted_local_quality(root: Path):
    local = root / "m9_4"
    suite = LocalSourceSuite.model_validate_json((local / "suite.json").read_text(encoding="utf-8"))
    observations = LocalSourceObservationSet.model_validate_json(
        (local / "observations.json").read_text(encoding="utf-8")
    )
    profile = LocalSourceRobustnessProfile.model_validate_json(
        (local / "profile.json").read_text(encoding="utf-8")
    )
    baseline = BenchmarkBaseline.model_validate_json(
        (root / "m6_1" / "baseline.json").read_text(encoding="utf-8")
    )
    _, result = evaluate_local_source_robustness(suite, observations, baseline, profile)
    if (
        profile.profile_id != _ADMITTED_M9_4_PROFILE_ID
        or result.result_id != _ADMITTED_M9_4_RESULT_ID
        or result.gate_status is not BenchmarkGateStatus.PASSED
    ):
        raise SystemExit("local shadow pilot refuses an unadmitted quality baseline")
    return profile, result


def run_shadow_pilot_local(args: argparse.Namespace) -> int:
    """Build a review-only Candidate set from one already-ingested local Snapshot."""
    now = utc_now()
    scope = _load_scope(args.scope_file)
    ingestion = IngestionService(Path(args.store))
    snapshot = ingestion.load_snapshot(args.snapshot_id)
    IngestionService.require_snapshot_scope(snapshot, scope, now)
    graph = PythonWebSourceMapper().analyze(snapshot, ingestion.root, scope=scope, now=now)
    candidate_set = CandidateGenerator().generate(graph, scope=scope, now=now)
    profile, quality_result = _load_admitted_local_quality(
        Path(__file__).resolve().parents[2] / "benchmarks"
    )
    manifest = AuthorizedPilotManifest.create(
        scope=scope,
        snapshot=snapshot,
        graph=graph,
        candidate_set=candidate_set,
    )
    plan = AuthorizedPilotReadinessPlan.create(
        manifest=manifest,
        quality_profile=profile,
        quality_result=quality_result,
        policy=AuthorizedPilotReadinessPolicy(),
        effects=LocalSourceEffectCounters(),
        created_at=max(scope.valid_from, snapshot.manifest.created_at),
        deadline=scope.valid_until,
        idempotency_key=args.idempotency_key or f"shadow-pilot:{manifest.pilot_manifest_id}",
    )
    graph_path, graph_created = SourceGraphStore(Path(args.analysis_store)).put(graph)
    candidate_path, candidates_created = CandidateSetStore(Path(args.candidate_store)).put(
        candidate_set
    )
    with AuthorizedPilotReadinessStore(Path(args.readiness_db)) as readiness_store:
        outcome = AuthorizedPilotReadinessService(
            store=readiness_store,
            artifact_store=AuthorizedPilotReadinessArtifactStore(Path(args.readiness_store)),
        ).evaluate(
            scope=scope,
            snapshot=snapshot,
            target_store_root=ingestion.root,
            graph=graph,
            candidate_set=candidate_set,
            quality_profile=profile,
            quality_result=quality_result,
            manifest=manifest,
            plan=plan,
            now=now,
        )
    summary = {
        "mode": "authorized_local_shadow_pilot",
        "gate_status": outcome.result.gate_status.value,
        "pilot_manifest_id": manifest.pilot_manifest_id,
        "plan_id": plan.plan_id,
        "graph_id": graph.graph_id,
        "graph_created": graph_created,
        "graph_path": str(graph_path),
        "candidate_set_id": candidate_set.candidate_set_id,
        "candidate_set_created": candidates_created,
        "candidate_set_path": str(candidate_path),
        "candidate_count": len(candidate_set.candidates),
        "selected_candidate_ids": [],
        "candidates": [
            {
                "candidate_id": str(candidate.candidate_id),
                "state": candidate.state.value,
                "cwe": candidate.cwe,
                "title": candidate.title,
                "confidence": candidate.confidence,
                "entry": candidate.entry_point.model_dump(mode="json"),
                "sink": candidate.sink.model_dump(mode="json"),
            }
            for candidate in candidate_set.candidates
        ],
        "readiness_artifact": outcome.artifact.model_dump(mode="json"),
    }
    print(json.dumps(summary, indent=2))
    return 0 if outcome.result.gate_status is BenchmarkGateStatus.PASSED else 2


def select_pilot_candidate_local(args: argparse.Namespace) -> int:
    """Record one explicit human selection without planning or running Validation."""
    try:
        decided_at = datetime.fromisoformat(args.decided_at)
    except ValueError as exc:
        raise SystemExit("--decided-at must be an ISO 8601 timestamp") from exc
    now = utc_now()
    scope = _load_scope(args.scope_file)
    with (
        AuthorizedPilotReadinessStore(Path(args.readiness_db)) as readiness_store,
        PilotCandidateSelectionStore(Path(args.selection_db)) as selection_store,
    ):
        service = PilotCandidateSelectionService(
            scope=scope,
            ingestion=IngestionService(Path(args.store)),
            graph_store=SourceGraphStore(Path(args.analysis_store)),
            candidate_store=CandidateSetStore(Path(args.candidate_store)),
            readiness_store=readiness_store,
            readiness_artifact_store=AuthorizedPilotReadinessArtifactStore(
                Path(args.readiness_store)
            ),
            selection_store=selection_store,
        )
        command = service.prepare(
            readiness_plan_id=args.readiness_plan_id,
            candidate_set_id=args.candidate_set_id,
            candidate_id=UUID(args.candidate_id),
            reviewer=args.reviewer,
            decided_at=decided_at,
            now=now,
            idempotency_key=args.idempotency_key
            or f"pilot-select:{args.readiness_plan_id}:{args.candidate_id}",
        )
        record = service.record(command, now=now)
    print(
        json.dumps(
            {
                "mode": "human_pilot_candidate_selection",
                "candidate_state": "proposed",
                "validation_planned": False,
                "record": record.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def bind_pilot_validation_intake_local(args: argparse.Namespace) -> int:
    """Consume one pilot selection into M8.1 without executing Validation."""
    now = utc_now()
    scope = _load_scope(args.scope_file)
    audit_artifact = AgentSessionAuditArtifact.model_validate_json(
        Path(args.audit_artifact_file).read_text(encoding="utf-8")
    )
    intake_plan = AgentValidationIntakePlan.model_validate_json(
        Path(args.intake_plan_file).read_text(encoding="utf-8")
    )
    intake_command = AgentValidationIntakeCommand.model_validate_json(
        Path(args.intake_command_file).read_text(encoding="utf-8")
    )
    validation_plan = ValidationPlan.model_validate_json(
        Path(args.validation_plan_file).read_text(encoding="utf-8")
    )
    with (
        PilotCandidateSelectionStore(Path(args.selection_db)) as selection_store,
        AgentValidationIntakeStore(Path(args.intake_db)) as intake_store,
        PilotValidationIntakeStore(Path(args.pilot_intake_db)) as pilot_store,
    ):
        intake_service = AgentValidationIntakeService(
            scope=scope,
            audit_artifact_store=AgentSessionAuditArtifactStore(Path(args.audit_store)),
            candidate_set_store=CandidateSetStore(Path(args.candidate_store)),
            store=intake_store,
        )
        service = PilotValidationIntakeService(
            selection_store=selection_store,
            intake_service=intake_service,
            store=pilot_store,
        )
        plan = service.prepare(
            selection_readiness_plan_id=args.selection_readiness_plan_id,
            intake_plan=intake_plan,
            intake_command=intake_command,
            validation_plan=validation_plan,
            now=now,
            deadline=min(intake_plan.decision_deadline, scope.valid_until),
            idempotency_key=args.idempotency_key or f"pilot-intake:{intake_plan.intake_plan_id}",
        )
        binding = service.execute(
            plan,
            selection_readiness_plan_id=args.selection_readiness_plan_id,
            intake_plan=intake_plan,
            intake_command=intake_command,
            audit_artifact=audit_artifact,
            validation_plan=validation_plan,
            now=now,
        )
    print(
        json.dumps(
            {
                "mode": "pilot_bound_human_validation_intake",
                "candidate_state": "proposed",
                "validation_executed": False,
                "binding": binding.model_dump(mode="json"),
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


def run_pilot_validation_offline(args: argparse.Namespace) -> int:
    """Execute one explicitly approved M9.8-bound plan without Broker/network activity."""
    now = utc_now()
    scope = _load_scope(args.scope_file)
    validation_plan = ValidationPlan.model_validate_json(
        Path(args.validation_plan_file).read_text(encoding="utf-8")
    )
    approval = ApprovalRequest.model_validate_json(
        Path(args.approval_file).read_text(encoding="utf-8")
    )
    if validation_plan.broker_calls:
        raise SystemExit("offline pilot Validation refuses Broker calls and all network activity")
    with (
        PilotCandidateSelectionStore(Path(args.selection_db)) as selection_store,
        AgentValidationIntakeStore(Path(args.intake_db)) as intake_store,
        PilotValidationIntakeStore(Path(args.pilot_intake_db)) as pilot_intake_store,
        ValidationStore(Path(args.validation_db)) as validation_store,
        PilotValidationExecutionStore(Path(args.pilot_execution_db)) as execution_store,
    ):
        intake_service = AgentValidationIntakeService(
            scope=scope,
            audit_artifact_store=AgentSessionAuditArtifactStore(Path(args.audit_store)),
            candidate_set_store=CandidateSetStore(Path(args.candidate_store)),
            store=intake_store,
        )
        pilot_intake_service = PilotValidationIntakeService(
            selection_store=selection_store,
            intake_service=intake_service,
            store=pilot_intake_store,
        )
        validation_service = ValidationService(
            scope=scope,
            runner=OfflineSandboxRunner(
                frozenset({validation_plan.runner_request.invocation.tool_id})
            ),
            broker=ToolBroker(
                scope=scope,
                registry=default_tool_registry(),
                resolver=StaticResolver({}),
                http_transport=OfflineHttpTransport({}),
            ),
            store=validation_store,
            evidence_store=EvidenceStore(Path(args.evidence_store)),
        )
        service = PilotValidationExecutionService(
            pilot_intake_service=pilot_intake_service,
            validation_service=validation_service,
            store=execution_store,
        )
        intake_record = intake_store.load_completed(args.intake_plan_id)
        plan = service.prepare(
            pilot_intake_plan_id=args.pilot_intake_plan_id,
            intake_plan_id=args.intake_plan_id,
            validation_plan=validation_plan,
            approval=approval,
            now=now,
            deadline=min(scope.valid_until, intake_record.expires_at, approval.expires_at),
            idempotency_key=args.idempotency_key or f"pilot-validation:{args.pilot_intake_plan_id}",
        )
        binding = service.execute(
            plan,
            intake_plan_id=args.intake_plan_id,
            validation_plan=validation_plan,
            approval=approval,
            now=now,
        )
    print(
        json.dumps(
            {
                "mode": "approved_pilot_validation_offline",
                "network_accessed": False,
                "broker_calls": 0,
                "binding": binding.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def bind_pilot_validation_outcome_local(args: argparse.Namespace) -> int:
    """Bind existing M9.9/M8.2 provenance without invoking any execution service."""
    scope = _load_scope(args.scope_file)
    plan = PilotValidationOutcomePlan.model_validate_json(Path(args.plan_file).read_text())
    outcome_plan = AgentValidationOutcomeBindingPlan.model_validate_json(
        Path(args.outcome_plan_file).read_text()
    )
    validation_plan = ValidationPlan.model_validate_json(
        Path(args.validation_plan_file).read_text()
    )
    artifact = AgentSessionAuditArtifact.model_validate_json(
        Path(args.audit_artifact_file).read_text()
    )
    with (
        AgentValidationIntakeStore(Path(args.intake_db)) as intake_store,
        PilotValidationIntakeStore(Path(args.pilot_intake_db)) as pilot_intake_store,
        PilotValidationExecutionStore(Path(args.pilot_execution_db)) as execution_store,
        ValidationStore(Path(args.validation_db)) as validation_store,
        AgentValidationOutcomeBindingStore(Path(args.outcome_db)) as outcome_store,
        PilotValidationOutcomeStore(Path(args.pilot_outcome_db)) as pilot_store,
    ):
        outcome_service = AgentValidationOutcomeBindingService(
            scope=scope,
            audit_store=AgentSessionAuditArtifactStore(Path(args.audit_store)),
            candidate_store=CandidateSetStore(Path(args.candidate_store)),
            intake_store=intake_store,
            validation_store=validation_store,
            evidence_store=EvidenceStore(Path(args.evidence_store)),
            binding_store=outcome_store,
        )
        service = PilotValidationOutcomeService(
            execution_store=execution_store,
            pilot_intake_store=pilot_intake_store,
            outcome_service=outcome_service,
            store=pilot_store,
        )
        binding = service.execute(
            plan,
            outcome_plan=outcome_plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            now=utc_now(),
        )
    print(
        json.dumps(
            {
                "mode": "pilot_validation_outcome_binding",
                "validation_executed": False,
                "candidate_changed": False,
                "network_accessed": False,
                "binding": binding.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def bind_pilot_critic_intake_local(args: argparse.Namespace) -> int:
    """Apply an independently supplied human Intake without running Critic or Validation."""
    scope = _load_scope(args.scope_file)
    plan = PilotCriticIntakePlan.model_validate_json(Path(args.plan_file).read_text())
    pilot_outcome_plan = PilotValidationOutcomePlan.model_validate_json(
        Path(args.pilot_outcome_plan_file).read_text()
    )
    outcome_plan = AgentValidationOutcomeBindingPlan.model_validate_json(
        Path(args.outcome_plan_file).read_text()
    )
    intake_plan = AgentCriticIntakePlan.model_validate_json(Path(args.intake_plan_file).read_text())
    command = AgentCriticIntakeCommand.model_validate_json(
        Path(args.intake_command_file).read_text()
    )
    critic_plan = CriticPlan.model_validate_json(Path(args.critic_plan_file).read_text())
    validation_plan = ValidationPlan.model_validate_json(
        Path(args.validation_plan_file).read_text()
    )
    artifact = AgentSessionAuditArtifact.model_validate_json(
        Path(args.audit_artifact_file).read_text()
    )
    with (
        AgentValidationIntakeStore(Path(args.intake_db)) as validation_intake_store,
        PilotValidationIntakeStore(Path(args.pilot_intake_db)) as pilot_intake_store,
        PilotValidationExecutionStore(Path(args.pilot_execution_db)) as execution_store,
        ValidationStore(Path(args.validation_db)) as validation_store,
        AgentValidationOutcomeBindingStore(Path(args.outcome_db)) as outcome_store,
        PilotValidationOutcomeStore(Path(args.pilot_outcome_db)) as pilot_outcome_store,
        AgentCriticIntakeStore(Path(args.critic_intake_db)) as critic_intake_store,
        PilotCriticIntakeStore(Path(args.pilot_critic_db)) as pilot_store,
    ):
        audit_store = AgentSessionAuditArtifactStore(Path(args.audit_store))
        candidate_store = CandidateSetStore(Path(args.candidate_store))
        evidence_store = EvidenceStore(Path(args.evidence_store))
        outcome_service = AgentValidationOutcomeBindingService(
            scope=scope,
            audit_store=audit_store,
            candidate_store=candidate_store,
            intake_store=validation_intake_store,
            validation_store=validation_store,
            evidence_store=evidence_store,
            binding_store=outcome_store,
        )
        pilot_outcome_service = PilotValidationOutcomeService(
            execution_store=execution_store,
            pilot_intake_store=pilot_intake_store,
            outcome_service=outcome_service,
            store=pilot_outcome_store,
        )
        intake_service = AgentCriticIntakeService(
            scope=scope,
            audit_store=audit_store,
            candidate_store=candidate_store,
            outcome_binding_store=outcome_store,
            validation_store=validation_store,
            evidence_store=evidence_store,
            store=critic_intake_store,
        )
        service = PilotCriticIntakeService(
            pilot_outcome_service=pilot_outcome_service,
            intake_service=intake_service,
            store=pilot_store,
        )
        binding = service.execute(
            plan,
            pilot_outcome_plan=pilot_outcome_plan,
            intake_plan=intake_plan,
            command=command,
            outcome_plan=outcome_plan,
            audit_artifact=artifact,
            validation_plan=validation_plan,
            critic_plan=critic_plan,
            now=utc_now(),
        )
    print(
        json.dumps(
            {
                "mode": "pilot_critic_intake_binding",
                "critic_executed": False,
                "validation_executed": False,
                "candidate_changed": False,
                "network_accessed": False,
                "binding": binding.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def _load_pilot_critic_inputs(args: argparse.Namespace):
    """Read the already sealed upstream files; never derive operational parameters."""
    pilot_intake_plan = PilotCriticIntakePlan.model_validate_json(
        Path(args.pilot_intake_plan_file).read_text()
    )
    raw_catalog = json.loads(Path(args.evidence_catalog_file).read_text())
    if not isinstance(raw_catalog, list) or len(raw_catalog) > 256:
        raise ValueError("pilot Critic Evidence catalog must be a bounded array")
    evidence = tuple(Evidence.model_validate(item) for item in raw_catalog)
    pilot_outcome_plan = PilotValidationOutcomePlan.model_validate_json(
        Path(args.pilot_outcome_plan_file).read_text()
    )
    outcome_plan = AgentValidationOutcomeBindingPlan.model_validate_json(
        Path(args.outcome_plan_file).read_text()
    )
    intake_plan = AgentCriticIntakePlan.model_validate_json(Path(args.intake_plan_file).read_text())
    command = AgentCriticIntakeCommand.model_validate_json(
        Path(args.intake_command_file).read_text()
    )
    critic_plan = CriticPlan.model_validate_json(Path(args.critic_plan_file).read_text())
    validation_plan = ValidationPlan.model_validate_json(
        Path(args.validation_plan_file).read_text()
    )
    artifact = AgentSessionAuditArtifact.model_validate_json(
        Path(args.audit_artifact_file).read_text()
    )
    return dict(
        pilot_intake_plan=pilot_intake_plan,
        evidence=evidence,
        pilot_outcome_plan=pilot_outcome_plan,
        intake_plan=intake_plan,
        command=command,
        outcome_plan=outcome_plan,
        audit_artifact=artifact,
        validation_plan=validation_plan,
        critic_plan=critic_plan,
    )


@contextmanager
def _open_pilot_critic_service(args: argparse.Namespace):
    """Share the same authoritative stores for execution and read-only downstream verification."""
    scope = _load_scope(args.scope_file)
    with (
        AgentValidationIntakeStore(Path(args.intake_db)) as validation_intake_store,
        PilotValidationIntakeStore(Path(args.pilot_intake_db)) as pilot_intake_store,
        PilotValidationExecutionStore(Path(args.pilot_execution_db)) as execution_store,
        ValidationStore(Path(args.validation_db)) as validation_store,
        AgentValidationOutcomeBindingStore(Path(args.outcome_db)) as outcome_store,
        PilotValidationOutcomeStore(Path(args.pilot_outcome_db)) as pilot_outcome_store,
        AgentCriticIntakeStore(Path(args.critic_intake_db)) as critic_intake_store,
        PilotCriticIntakeStore(Path(args.pilot_critic_db)) as pilot_store,
        CriticStore(Path(args.critic_db)) as critic_store,
        AgentCriticOutcomeBindingStore(Path(args.critic_outcome_db)) as critic_outcome_store,
        PilotCriticExecutionStore(Path(args.pilot_critic_execution_db)) as pilot_execution_store,
    ):
        audit_store = AgentSessionAuditArtifactStore(Path(args.audit_store))
        candidate_store = CandidateSetStore(Path(args.candidate_store))
        evidence_store = EvidenceStore(Path(args.evidence_store))
        outcome_service = AgentValidationOutcomeBindingService(
            scope=scope,
            audit_store=audit_store,
            candidate_store=candidate_store,
            intake_store=validation_intake_store,
            validation_store=validation_store,
            evidence_store=evidence_store,
            binding_store=outcome_store,
        )
        pilot_outcome_service = PilotValidationOutcomeService(
            execution_store=execution_store,
            pilot_intake_store=pilot_intake_store,
            outcome_service=outcome_service,
            store=pilot_outcome_store,
        )
        intake_service = AgentCriticIntakeService(
            scope=scope,
            audit_store=audit_store,
            candidate_store=candidate_store,
            outcome_binding_store=outcome_store,
            validation_store=validation_store,
            evidence_store=evidence_store,
            store=critic_intake_store,
        )
        service = PilotCriticIntakeService(
            pilot_outcome_service=pilot_outcome_service,
            intake_service=intake_service,
            store=pilot_store,
        )
        critic = DeterministicCritic(scope=scope, evidence_store=evidence_store, store=critic_store)
        critic_outcomes = AgentCriticOutcomeBindingService(
            scope=scope,
            critic_intake_store=critic_intake_store,
            outcome_binding_store=outcome_store,
            validation_store=validation_store,
            critic_store=critic_store,
            evidence_store=evidence_store,
            binding_store=critic_outcome_store,
        )
        execution = PilotCriticExecutionService(
            pilot_intake_service=service,
            critic=critic,
            outcome_service=critic_outcomes,
            store=pilot_execution_store,
        )
        yield execution


def run_pilot_critic_local(args: argparse.Namespace) -> int:
    """Execute one approved deterministic Critic review and bind its M8.4 outcome."""
    plan = PilotCriticExecutionPlan.model_validate_json(Path(args.plan_file).read_text())
    approval = ApprovalRequest.model_validate_json(Path(args.approval_file).read_text())
    inputs = _load_pilot_critic_inputs(args)
    with _open_pilot_critic_service(args) as execution:
        binding = execution.execute(plan, approval=approval, now=utc_now(), **inputs)
    print(
        json.dumps(
            {
                "mode": "approved_pilot_critic_local",
                "review_recorded": True,
                "validation_executed": False,
                "source_candidate_unchanged": True,
                "network_accessed": False,
                "binding": binding.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def _load_pilot_finding_inputs(args):
    execution_plan = PilotCriticExecutionPlan.model_validate_json(
        Path(args.critic_execution_plan_file).read_text()
    )
    approval = ApprovalRequest.model_validate_json(Path(args.approval_file).read_text())
    execution_inputs = _load_pilot_critic_inputs(args)
    critic_binding_plan = AgentCriticOutcomeBindingPlan.model_validate_json(
        Path(args.critic_binding_plan_file).read_text()
    )
    intake_plan = AgentFindingIntakePlan.model_validate_json(
        Path(args.finding_intake_plan_file).read_text()
    )
    command = AgentFindingIntakeCommand.model_validate_json(
        Path(args.finding_intake_command_file).read_text()
    )
    promotion_plan = FindingPromotionPlan.model_validate_json(
        Path(args.promotion_plan_file).read_text()
    )
    duplicate_check = FindingDuplicateCheck.model_validate_json(
        Path(args.duplicate_check_file).read_text()
    )
    return dict(
        critic_execution_plan=execution_plan,
        execution_approval=approval,
        execution_inputs=execution_inputs,
        intake_plan=intake_plan,
        command=command,
        critic_binding_plan=critic_binding_plan,
        promotion_plan=promotion_plan,
        duplicate_check=duplicate_check,
    )


@contextmanager
def _open_pilot_finding_service(args):
    with (
        _open_pilot_critic_service(args) as execution,
        FindingDuplicateCheckStore(Path(args.duplicate_check_db)) as duplicate_store,
        AgentFindingIntakeStore(Path(args.finding_intake_db)) as intake_store,
        PilotFindingIntakeStore(Path(args.pilot_finding_db)) as store,
    ):
        upstream = execution.outcome_service
        intake = AgentFindingIntakeService(
            scope=execution.scope,
            critic_binding_store=upstream.binding_store,
            validation_binding_store=upstream.outcome_binding_store,
            validation_store=upstream.validation_store,
            critic_store=upstream.critic_store,
            evidence_store=upstream.evidence_store,
            duplicate_check_store=duplicate_store,
            store=intake_store,
        )
        service = PilotFindingIntakeService(
            critic_execution_service=execution, intake_service=intake, store=store
        )
        yield service


def bind_pilot_finding_intake_local(args: argparse.Namespace) -> int:
    """Consume completed pilot Critic provenance into human Intake, without promotion."""
    plan = PilotFindingIntakePlan.model_validate_json(Path(args.plan_file).read_text())
    inputs = _load_pilot_finding_inputs(args)
    with _open_pilot_finding_service(args) as service:
        binding = service.execute(plan, **inputs, now=utc_now())
    print(
        json.dumps(
            {
                "mode": "pilot_finding_intake_binding",
                "finding_created": False,
                "candidate_changed": False,
                "critic_executed": False,
                "validation_executed": False,
                "network_accessed": False,
                "binding": binding.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def promote_pilot_finding_local(args: argparse.Namespace) -> int:
    """Record an explicitly approved Finding promotion with exact pilot provenance."""
    plan = PilotFindingPromotionPlan.model_validate_json(Path(args.plan_file).read_text())
    intake_plan = PilotFindingIntakePlan.model_validate_json(
        Path(args.pilot_finding_intake_plan_file).read_text()
    )
    execution_plan = FindingPromotionExecutionPlan.model_validate_json(
        Path(args.promotion_execution_plan_file).read_text()
    )
    approval = ApprovalRequest.model_validate_json(Path(args.promotion_approval_file).read_text())
    inputs = _load_pilot_finding_inputs(args)
    with (
        _open_pilot_finding_service(args) as intake,
        FindingPromotionStore(Path(args.promotion_db)) as outcomes,
        PilotFindingPromotionStore(Path(args.pilot_promotion_db)) as store,
    ):
        promotion = FindingPromotionService(intake_service=intake.intake_service, store=outcomes)
        service = PilotFindingPromotionService(
            pilot_intake_service=intake,
            promotion_service=promotion,
            store=store,
        )
        binding = service.execute(
            plan,
            pilot_intake_plan=intake_plan,
            intake_inputs=inputs,
            execution_plan=execution_plan,
            approval=approval,
            now=utc_now(),
        )
    print(
        json.dumps(
            {
                "mode": "approved_pilot_finding_promotion",
                "finding_recorded": True,
                "source_candidate_unchanged": True,
                "critic_executed": False,
                "validation_executed": False,
                "network_accessed": False,
                "binding": binding.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def provider_probe_local(args: argparse.Namespace) -> int:
    """Bounded synthetic provider test; errors never include input or provider text."""
    import os
    import stat
    from datetime import timedelta

    from vulnloom.adapters.model_credentials import EnvironmentModelCredentialProvider
    from vulnloom.agent_runtime.provider_admission import (
        AgentProviderEgressPurpose,
        AgentProviderEgressStore,
    )
    from vulnloom.agent_runtime.provider_probe import ProviderProbeService, create_cuc_probe_config
    from vulnloom.agent_runtime.provider_probe_models import ProviderProbeConfig, ProviderProbePlan
    from vulnloom.agent_runtime.provider_probe_store import ProviderProbeStore

    def read_sealed(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                raise ValueError("invalid provider probe file")
            content = handle.read(65537)
            if len(content) > 65536:
                raise ValueError("provider probe file over budget")
            return content

    try:
        if getattr(args, "probe_config", False):
            config = create_cuc_probe_config(
                grant_id=args.grant_id, structured=getattr(args, "structured", False)
            )
            with AgentProviderEgressStore(Path(args.egress_store)) as egress:
                grant = egress.require_active(
                    args.grant_id, admission=config.admission, now=utc_now()
                )
                if grant.purpose is not AgentProviderEgressPurpose.MODEL_INFERENCE:
                    raise ValueError("CUC probe needs inference grant")
            print(config.model_dump_json(indent=2))
            return 0
        if args.probe_run and not args.allow_provider_network:
            raise ValueError("explicit provider network opt-in required")
        config = ProviderProbeConfig.model_validate_json(read_sealed(args.config_file))
        with (
            AgentProviderEgressStore(Path(args.egress_store)) as egress,
            ProviderProbeStore(Path(args.probe_db)) as store,
        ):
            service = ProviderProbeService(
                config=config,
                now=utc_now,
                egress_store=egress,
                store=store,
                credential_provider=EnvironmentModelCredentialProvider(
                    allowed_references=(config.credential_reference,),
                ),
            )
            if not args.probe_run:
                now = utc_now()
                plan = service.prepare(
                    now=now,
                    deadline=now + timedelta(seconds=args.ttl_seconds),
                    idempotency_key=args.idempotency_key,
                )
                print(plan.model_dump_json(indent=2))
                return 0
            plan = ProviderProbePlan.model_validate_json(read_sealed(args.plan_file))
            result = service.execute(plan)
        print(result.model_dump_json(indent=2))
        return 0 if result.status == "passed" else 1
    except Exception:
        print(json.dumps({"status": "rejected", "error_code": "provider_probe_rejected"}))
        return 1


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
    suite = BenchmarkSuite.model_validate_json(Path(args.suite_file).read_text(encoding="utf-8"))
    observations = BenchmarkObservationSet.model_validate_json(
        Path(args.observations_file).read_text(encoding="utf-8")
    )
    plan = BenchmarkPlan.model_validate_json(Path(args.plan_file).read_text(encoding="utf-8"))
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
    plan = AnalyzerImportPlan.model_validate_json(Path(args.plan_file).read_text(encoding="utf-8"))
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


def evaluate_analyzers_offline(args: argparse.Namespace) -> int:
    suite = BenchmarkSuite.model_validate_json(Path(args.suite_file).read_text(encoding="utf-8"))
    observation_sets = tuple(
        AnalyzerObservationSet.model_validate_json(Path(path).read_text(encoding="utf-8"))
        for path in args.observation_set_file
    )
    alignment = AnalyzerTruthAlignment.model_validate_json(
        Path(args.alignment_file).read_text(encoding="utf-8")
    )
    plan = AnalyzerEvaluationPlan.model_validate_json(
        Path(args.plan_file).read_text(encoding="utf-8")
    )
    artifact_store = AnalyzerEvaluationArtifactStore(Path(args.result_store))
    with AnalyzerEvaluationStore(Path(args.evaluation_db)) as evaluation_store:
        outcome = AnalyzerEvaluationService(
            store=evaluation_store,
            artifact_store=artifact_store,
        ).evaluate(suite, observation_sets, alignment, plan, now=utc_now())
    summary = {
        "mode": "offline_explicit_analyzer_evaluation",
        "plan_id": outcome.plan_id,
        "suite_id": outcome.result.suite_id,
        "alignment_id": outcome.result.alignment_id,
        "result_id": str(outcome.result.result_id),
        "gate_status": outcome.result.gate_status.value,
        "metrics": outcome.result.metrics.model_dump(mode="json"),
        "violations": [item.model_dump(mode="json") for item in outcome.result.violations],
        "artifact": outcome.artifact.model_dump(mode="json"),
    }
    print(json.dumps(summary, indent=2))
    return 0 if outcome.result.gate_status is BenchmarkGateStatus.PASSED else 2


def check_analyzer_execution_offline(args: argparse.Namespace) -> int:
    """Validate a sealed analyzer execution through the non-executing Runner."""
    scope = _load_scope(args.scope_file)
    target = IngestionService(Path(args.store)).load_snapshot(args.snapshot_id)
    registration = AnalyzerToolRegistration.model_validate_json(
        Path(args.registration_file).read_text(encoding="utf-8")
    )
    registry = AnalyzerToolRegistry((registration,))
    plan = AnalyzerExecutionPlan.model_validate_json(
        Path(args.plan_file).read_text(encoding="utf-8")
    )
    with AnalyzerExecutionStore(Path(args.execution_db)) as execution_store:
        outcome = OfflineAnalyzerExecutionService(
            scope=scope,
            registry=registry,
            runner=OfflineSandboxRunner(registry.tool_ids),
            store=execution_store,
        ).execute(target, plan, now=utc_now())
    summary = {
        "mode": "offline_protocol_only",
        "plan_id": outcome.plan_id,
        "registration_id": outcome.registration_id,
        "target_id": str(outcome.target_id),
        "target_version": outcome.target_version,
        "status": outcome.status.value,
        "analyzer_result_snapshot": None,
        "cleanup_complete": outcome.runner_result.cleanup.complete,
    }
    print(json.dumps(summary, indent=2))
    return 0 if outcome.status.value == "protocol_completed" else 2


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

    shadow = sub.add_parser("shadow-pilot-local")
    shadow.add_argument("--snapshot-id", required=True)
    shadow.add_argument("--scope-file", required=True)
    shadow.add_argument("--analysis-store", default=".vulnloom/analysis")
    shadow.add_argument("--candidate-store", default=".vulnloom/candidates")
    shadow.add_argument("--readiness-db", default=".vulnloom/pilot-readiness.db")
    shadow.add_argument("--readiness-store", default=".vulnloom/pilot-readiness")
    shadow.add_argument("--idempotency-key")
    shadow.set_defaults(handler=run_shadow_pilot_local)

    selection = sub.add_parser("pilot-candidate-select-local")
    selection.add_argument("--readiness-plan-id", required=True)
    selection.add_argument("--candidate-set-id", required=True)
    selection.add_argument("--candidate-id", required=True)
    selection.add_argument("--scope-file", required=True)
    selection.add_argument("--reviewer", required=True)
    selection.add_argument("--decided-at", required=True)
    selection.add_argument("--analysis-store", default=".vulnloom/analysis")
    selection.add_argument("--candidate-store", default=".vulnloom/candidates")
    selection.add_argument("--readiness-db", default=".vulnloom/pilot-readiness.db")
    selection.add_argument("--readiness-store", default=".vulnloom/pilot-readiness")
    selection.add_argument("--selection-db", default=".vulnloom/pilot-selections.db")
    selection.add_argument("--idempotency-key")
    selection.set_defaults(handler=select_pilot_candidate_local)

    pilot_intake = sub.add_parser("pilot-validation-intake-bind-local")
    pilot_intake.add_argument("--selection-readiness-plan-id", required=True)
    pilot_intake.add_argument("--scope-file", required=True)
    pilot_intake.add_argument("--audit-artifact-file", required=True)
    pilot_intake.add_argument("--intake-plan-file", required=True)
    pilot_intake.add_argument("--intake-command-file", required=True)
    pilot_intake.add_argument("--validation-plan-file", required=True)
    pilot_intake.add_argument("--audit-store", default=".vulnloom/agent-audits")
    pilot_intake.add_argument("--candidate-store", default=".vulnloom/candidates")
    pilot_intake.add_argument("--selection-db", default=".vulnloom/pilot-selections.db")
    pilot_intake.add_argument("--intake-db", default=".vulnloom/agent-validation-intakes.db")
    pilot_intake.add_argument("--pilot-intake-db", default=".vulnloom/pilot-intakes.db")
    pilot_intake.add_argument("--idempotency-key")
    pilot_intake.set_defaults(handler=bind_pilot_validation_intake_local)

    pilot_validation = sub.add_parser("pilot-validation-run-offline")
    pilot_validation.add_argument("--pilot-intake-plan-id", required=True)
    pilot_validation.add_argument("--intake-plan-id", required=True)
    pilot_validation.add_argument("--scope-file", required=True)
    pilot_validation.add_argument("--validation-plan-file", required=True)
    pilot_validation.add_argument("--approval-file", required=True)
    pilot_validation.add_argument("--audit-store", default=".vulnloom/agent-audits")
    pilot_validation.add_argument("--candidate-store", default=".vulnloom/candidates")
    pilot_validation.add_argument("--selection-db", default=".vulnloom/pilot-selections.db")
    pilot_validation.add_argument("--intake-db", default=".vulnloom/agent-validation-intakes.db")
    pilot_validation.add_argument("--pilot-intake-db", default=".vulnloom/pilot-intakes.db")
    pilot_validation.add_argument("--validation-db", default=".vulnloom/validation.db")
    pilot_validation.add_argument("--evidence-store", default=".vulnloom/evidence")
    pilot_validation.add_argument(
        "--pilot-execution-db", default=".vulnloom/pilot-validation-executions.db"
    )
    pilot_validation.add_argument("--idempotency-key")
    pilot_validation.set_defaults(handler=run_pilot_validation_offline)

    pilot_outcome = sub.add_parser("pilot-validation-outcome-bind-local")
    for name in (
        "plan-file",
        "outcome-plan-file",
        "scope-file",
        "validation-plan-file",
        "audit-artifact-file",
    ):
        pilot_outcome.add_argument(f"--{name}", required=True)
    for name, default in (
        ("audit-store", ".vulnloom/agent-audits"),
        ("candidate-store", ".vulnloom/candidates"),
        ("evidence-store", ".vulnloom/evidence"),
        ("intake-db", ".vulnloom/agent-validation-intakes.db"),
        ("pilot-intake-db", ".vulnloom/pilot-intakes.db"),
        ("pilot-execution-db", ".vulnloom/pilot-validation-executions.db"),
        ("validation-db", ".vulnloom/validation.db"),
        ("outcome-db", ".vulnloom/agent-validation-outcomes.db"),
        ("pilot-outcome-db", ".vulnloom/pilot-validation-outcomes.db"),
    ):
        pilot_outcome.add_argument(f"--{name}", default=default)
    pilot_outcome.set_defaults(handler=bind_pilot_validation_outcome_local)

    pilot_critic = sub.add_parser("pilot-critic-intake-bind-local")
    for name in (
        "plan-file",
        "pilot-outcome-plan-file",
        "outcome-plan-file",
        "intake-plan-file",
        "intake-command-file",
        "critic-plan-file",
        "scope-file",
        "validation-plan-file",
        "audit-artifact-file",
    ):
        pilot_critic.add_argument(f"--{name}", required=True)
    for name, default in (
        ("audit-store", ".vulnloom/agent-audits"),
        ("candidate-store", ".vulnloom/candidates"),
        ("evidence-store", ".vulnloom/evidence"),
        ("intake-db", ".vulnloom/agent-validation-intakes.db"),
        ("pilot-intake-db", ".vulnloom/pilot-intakes.db"),
        ("pilot-execution-db", ".vulnloom/pilot-validation-executions.db"),
        ("validation-db", ".vulnloom/validation.db"),
        ("outcome-db", ".vulnloom/agent-validation-outcomes.db"),
        ("pilot-outcome-db", ".vulnloom/pilot-validation-outcomes.db"),
        ("critic-intake-db", ".vulnloom/agent-critic-intakes.db"),
        ("pilot-critic-db", ".vulnloom/pilot-critic-intakes.db"),
    ):
        pilot_critic.add_argument(f"--{name}", default=default)
    pilot_critic.set_defaults(handler=bind_pilot_critic_intake_local)

    pilot_critic_run = sub.add_parser("pilot-critic-run-local")
    for name in (
        "plan-file",
        "pilot-intake-plan-file",
        "approval-file",
        "evidence-catalog-file",
        "pilot-outcome-plan-file",
        "outcome-plan-file",
        "intake-plan-file",
        "intake-command-file",
        "critic-plan-file",
        "scope-file",
        "validation-plan-file",
        "audit-artifact-file",
    ):
        pilot_critic_run.add_argument(f"--{name}", required=True)
    for name, default in (
        ("audit-store", ".vulnloom/agent-audits"),
        ("candidate-store", ".vulnloom/candidates"),
        ("evidence-store", ".vulnloom/evidence"),
        ("intake-db", ".vulnloom/agent-validation-intakes.db"),
        ("pilot-intake-db", ".vulnloom/pilot-intakes.db"),
        ("pilot-execution-db", ".vulnloom/pilot-validation-executions.db"),
        ("validation-db", ".vulnloom/validation.db"),
        ("outcome-db", ".vulnloom/agent-validation-outcomes.db"),
        ("pilot-outcome-db", ".vulnloom/pilot-validation-outcomes.db"),
        ("critic-intake-db", ".vulnloom/agent-critic-intakes.db"),
        ("pilot-critic-db", ".vulnloom/pilot-critic-intakes.db"),
        ("critic-db", ".vulnloom/critic.db"),
        ("critic-outcome-db", ".vulnloom/agent-critic-outcomes.db"),
        ("pilot-critic-execution-db", ".vulnloom/pilot-critic-executions.db"),
    ):
        pilot_critic_run.add_argument(f"--{name}", default=default)
    pilot_critic_run.set_defaults(handler=run_pilot_critic_local)

    pilot_finding = sub.add_parser("pilot-finding-intake-bind-local")
    for name in (
        "plan-file",
        "critic-execution-plan-file",
        "critic-binding-plan-file",
        "finding-intake-plan-file",
        "finding-intake-command-file",
        "promotion-plan-file",
        "duplicate-check-file",
        "pilot-intake-plan-file",
        "approval-file",
        "evidence-catalog-file",
        "pilot-outcome-plan-file",
        "outcome-plan-file",
        "intake-plan-file",
        "intake-command-file",
        "critic-plan-file",
        "scope-file",
        "validation-plan-file",
        "audit-artifact-file",
    ):
        pilot_finding.add_argument(f"--{name}", required=True)
    for name, default in (
        ("audit-store", ".vulnloom/agent-audits"),
        ("candidate-store", ".vulnloom/candidates"),
        ("evidence-store", ".vulnloom/evidence"),
        ("intake-db", ".vulnloom/agent-validation-intakes.db"),
        ("pilot-intake-db", ".vulnloom/pilot-intakes.db"),
        ("pilot-execution-db", ".vulnloom/pilot-validation-executions.db"),
        ("validation-db", ".vulnloom/validation.db"),
        ("outcome-db", ".vulnloom/agent-validation-outcomes.db"),
        ("pilot-outcome-db", ".vulnloom/pilot-validation-outcomes.db"),
        ("critic-intake-db", ".vulnloom/agent-critic-intakes.db"),
        ("pilot-critic-db", ".vulnloom/pilot-critic-intakes.db"),
        ("critic-db", ".vulnloom/critic.db"),
        ("critic-outcome-db", ".vulnloom/agent-critic-outcomes.db"),
        ("pilot-critic-execution-db", ".vulnloom/pilot-critic-executions.db"),
        ("duplicate-check-db", ".vulnloom/finding-duplicate-checks.db"),
        ("finding-intake-db", ".vulnloom/agent-finding-intakes.db"),
        ("pilot-finding-db", ".vulnloom/pilot-finding-intakes.db"),
    ):
        pilot_finding.add_argument(f"--{name}", default=default)
    pilot_finding.set_defaults(handler=bind_pilot_finding_intake_local)

    pilot_promotion = sub.add_parser("pilot-finding-promote-local")
    for name in (
        "plan-file",
        "pilot-finding-intake-plan-file",
        "promotion-execution-plan-file",
        "promotion-approval-file",
        "critic-execution-plan-file",
        "critic-binding-plan-file",
        "finding-intake-plan-file",
        "finding-intake-command-file",
        "promotion-plan-file",
        "duplicate-check-file",
        "pilot-intake-plan-file",
        "approval-file",
        "evidence-catalog-file",
        "pilot-outcome-plan-file",
        "outcome-plan-file",
        "intake-plan-file",
        "intake-command-file",
        "critic-plan-file",
        "scope-file",
        "validation-plan-file",
        "audit-artifact-file",
    ):
        pilot_promotion.add_argument(f"--{name}", required=True)
    for name, default in (
        ("audit-store", ".vulnloom/agent-audits"),
        ("candidate-store", ".vulnloom/candidates"),
        ("evidence-store", ".vulnloom/evidence"),
        ("intake-db", ".vulnloom/agent-validation-intakes.db"),
        ("pilot-intake-db", ".vulnloom/pilot-intakes.db"),
        ("pilot-execution-db", ".vulnloom/pilot-validation-executions.db"),
        ("validation-db", ".vulnloom/validation.db"),
        ("outcome-db", ".vulnloom/agent-validation-outcomes.db"),
        ("pilot-outcome-db", ".vulnloom/pilot-validation-outcomes.db"),
        ("critic-intake-db", ".vulnloom/agent-critic-intakes.db"),
        ("pilot-critic-db", ".vulnloom/pilot-critic-intakes.db"),
        ("critic-db", ".vulnloom/critic.db"),
        ("critic-outcome-db", ".vulnloom/agent-critic-outcomes.db"),
        ("pilot-critic-execution-db", ".vulnloom/pilot-critic-executions.db"),
        ("duplicate-check-db", ".vulnloom/finding-duplicate-checks.db"),
        ("finding-intake-db", ".vulnloom/agent-finding-intakes.db"),
        ("pilot-finding-db", ".vulnloom/pilot-finding-intakes.db"),
        ("promotion-db", ".vulnloom/finding-promotions.db"),
        ("pilot-promotion-db", ".vulnloom/pilot-finding-promotions.db"),
    ):
        pilot_promotion.add_argument(f"--{name}", default=default)
    pilot_promotion.set_defaults(handler=promote_pilot_finding_local)

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
    analyzer_import.add_argument("--observation-store", default=".vulnloom/analyzer-observations")
    analyzer_import.set_defaults(handler=import_analyzer_observations_offline)

    analyzer_evaluation = sub.add_parser("analyzer-evaluate-offline")
    analyzer_evaluation.add_argument("--suite-file", required=True)
    analyzer_evaluation.add_argument("--observation-set-file", action="append", required=True)
    analyzer_evaluation.add_argument("--alignment-file", required=True)
    analyzer_evaluation.add_argument("--plan-file", required=True)
    analyzer_evaluation.add_argument("--evaluation-db", default=".vulnloom/analyzer-evaluations.db")
    analyzer_evaluation.add_argument(
        "--result-store", default=".vulnloom/analyzer-evaluation-results"
    )
    analyzer_evaluation.set_defaults(handler=evaluate_analyzers_offline)

    analyzer_execution = sub.add_parser("analyzer-execution-check-offline")
    analyzer_execution.add_argument("--scope-file", required=True)
    analyzer_execution.add_argument("--snapshot-id", required=True)
    analyzer_execution.add_argument("--registration-file", required=True)
    analyzer_execution.add_argument("--plan-file", required=True)
    analyzer_execution.add_argument("--execution-db", default=".vulnloom/analyzer-executions.db")
    analyzer_execution.set_defaults(handler=check_analyzer_execution_offline)
    cuc_config = sub.add_parser("provider-cuc-probe-config")
    cuc_config.add_argument("--egress-store", required=True)
    cuc_config.add_argument("--grant-id", required=True)
    cuc_config.add_argument(
        "--structured", action="store_true", help="Use the fixed, tool-free JSON probe"
    )
    cuc_config.set_defaults(handler=provider_probe_local, probe_config=True)
    for command, run in (("provider-probe-prepare", False), ("provider-probe-run", True)):
        probe = sub.add_parser(command)
        probe.add_argument("--config-file", required=True)
        probe.add_argument("--egress-store", required=True)
        probe.add_argument("--probe-db", default=".vulnloom/provider-probes.db")
        if run:
            probe.add_argument("--plan-file", required=True)
            probe.add_argument("--allow-provider-network", action="store_true")
        else:
            probe.add_argument("--idempotency-key", required=True)
            probe.add_argument("--ttl-seconds", type=int, default=120)
        probe.set_defaults(handler=provider_probe_local, probe_run=run)
    from vulnloom.review_assist.cli import register_review_commands

    register_review_commands(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
