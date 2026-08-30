"""Export the trusted protocol and domain contracts as JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

from vulnloom.analyzers import SourceGraph, SourceMapperLimits
from vulnloom.benchmark import (
    AnalyzerExclusion,
    AnalyzerImportLimits,
    AnalyzerImportOutcome,
    AnalyzerImportPlan,
    AnalyzerLocation,
    AnalyzerObservation,
    AnalyzerObservationArtifact,
    AnalyzerObservationSet,
    AnalyzerResultFile,
    AnalyzerResultSnapshot,
    BenchmarkArtifact,
    BenchmarkBaseline,
    BenchmarkCase,
    BenchmarkMetrics,
    BenchmarkObservation,
    BenchmarkObservationSet,
    BenchmarkOutcome,
    BenchmarkPlan,
    BenchmarkRegressionPolicy,
    BenchmarkResult,
    BenchmarkSuite,
    ExternalBenchmarkArtifact,
    ExternalBenchmarkImportOutcome,
    ExternalBenchmarkImportPlan,
    ExternalBenchmarkSnapshot,
    ExternalCaseExclusion,
    ExternalImportLimits,
    GroundTruthFinding,
    RegressionViolation,
    SnapshotFile,
)
from vulnloom.broker import (
    BrokerCall,
    BrokerResult,
    HttpRequestPlan,
    HttpToolResult,
    ToolRegistration,
)
from vulnloom.critic import (
    CounterevidenceAssessment,
    CriticOutcome,
    CriticPlan,
)
from vulnloom.domain.models import (
    ApprovalRequest,
    Artifact,
    Candidate,
    CriticReview,
    DisclosureCase,
    Evidence,
    EvidenceBundle,
    Finding,
    Report,
    ReportSection,
    Scope,
    TargetManifest,
    TargetSnapshot,
    ValidationRun,
)
from vulnloom.domain.protocol import TaskEnvelope, WorkerResult
from vulnloom.hypotheses import CandidateGeneratorLimits, CandidateSet
from vulnloom.ingestion import IngestionLimits
from vulnloom.reporting import (
    ReportArtifact,
    ReportDiff,
    ReportDraftPlan,
    ReportExportOutcome,
    ReportExportPlan,
    ReportFieldChange,
    ReportOutcome,
    ReportReviewCommand,
    ReportReviewOutcome,
    ReportReviewPlan,
    ReportReviewRecord,
)
from vulnloom.runners import (
    RunnerCheckpoint,
    SandboxProfile,
    SandboxRunRequest,
    SandboxRunResult,
    ToolInvocation,
)
from vulnloom.validation import (
    HttpResponseAssertion,
    ValidationOutcome,
    ValidationPlan,
    ValidationVerdict,
)

MODELS = (
    Scope,
    Artifact,
    TargetManifest,
    TargetSnapshot,
    IngestionLimits,
    SourceMapperLimits,
    SourceGraph,
    Candidate,
    CandidateGeneratorLimits,
    CandidateSet,
    ApprovalRequest,
    ValidationRun,
    Evidence,
    EvidenceBundle,
    Finding,
    Report,
    ReportSection,
    ReportDraftPlan,
    ReportArtifact,
    ReportOutcome,
    ReportFieldChange,
    ReportDiff,
    ReportReviewPlan,
    ReportReviewCommand,
    ReportReviewRecord,
    ReportReviewOutcome,
    ReportExportPlan,
    ReportExportOutcome,
    DisclosureCase,
    TaskEnvelope,
    WorkerResult,
    SandboxProfile,
    ToolInvocation,
    RunnerCheckpoint,
    SandboxRunRequest,
    SandboxRunResult,
    ToolRegistration,
    HttpRequestPlan,
    BrokerCall,
    HttpToolResult,
    BrokerResult,
    HttpResponseAssertion,
    ValidationPlan,
    ValidationVerdict,
    ValidationOutcome,
    CriticReview,
    CounterevidenceAssessment,
    CriticPlan,
    CriticOutcome,
    GroundTruthFinding,
    BenchmarkCase,
    BenchmarkSuite,
    BenchmarkObservation,
    BenchmarkObservationSet,
    BenchmarkMetrics,
    BenchmarkBaseline,
    BenchmarkRegressionPolicy,
    BenchmarkPlan,
    RegressionViolation,
    BenchmarkResult,
    BenchmarkArtifact,
    BenchmarkOutcome,
    SnapshotFile,
    ExternalBenchmarkSnapshot,
    ExternalImportLimits,
    ExternalCaseExclusion,
    ExternalBenchmarkImportPlan,
    ExternalBenchmarkArtifact,
    ExternalBenchmarkImportOutcome,
    AnalyzerResultFile,
    AnalyzerResultSnapshot,
    AnalyzerImportLimits,
    AnalyzerLocation,
    AnalyzerObservation,
    AnalyzerExclusion,
    AnalyzerObservationSet,
    AnalyzerImportPlan,
    AnalyzerObservationArtifact,
    AnalyzerImportOutcome,
)


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas"
    root.mkdir(parents=True, exist_ok=True)
    for model in MODELS:
        path = root / f"{model.__name__}.schema.json"
        path.write_text(
            json.dumps(model.model_json_schema(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
