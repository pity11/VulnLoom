"""Sealed local-source benchmark for the trusted static Candidate path.

The harness only materializes repository-owned source fixtures, ingests them as
local archives, and runs the AST mapper and Candidate generator.  It never
executes fixture code or invokes Runner, Broker, a model provider, or a network
adapter.  Finding-level quality is imported from an exact M6.1 baseline rather
than inferred from static Candidates.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
import zipfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Annotated, Self
from uuid import UUID

from pydantic import Field, model_validator

from vulnloom.analyzers import PythonWebSourceMapper
from vulnloom.analyzers.models import WebFramework
from vulnloom.benchmark.models import BenchmarkBaseline, BenchmarkGateStatus
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ArtifactKind, ArtifactScope, DomainModel, Scope, ScopeState
from vulnloom.hypotheses import CandidateGenerator
from vulnloom.ingestion import IngestionService

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Ratio = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Cwe = Annotated[str, Field(pattern=r"^CWE-[1-9][0-9]*$")]


class LocalSourceFile(DomainModel):
    path: str = Field(min_length=1, max_length=512)
    sha256: Digest

    @model_validator(mode="after")
    def safe_path(self) -> Self:
        path = PurePosixPath(self.path)
        if (
            path.is_absolute()
            or path.as_posix() != self.path
            or ".." in path.parts
            or path.suffix != ".py"
        ):
            raise ValueError("local benchmark source path is unsafe")
        return self


class LocalSourceCase(DomainModel):
    case_id: Digest
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    files: Annotated[tuple[LocalSourceFile, ...], Field(min_length=1, max_length=16)]
    expected_cwes: tuple[Cwe, ...] = ()

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.case_id != local_source_case_digest(self):
            raise ValueError("LocalSourceCase content digest mismatch")
        paths = tuple(item.path for item in self.files)
        if len(paths) != len(set(paths)):
            raise ValueError("local benchmark file paths must be unique")
        return self

    @classmethod
    def create(
        cls, *, name: str, files: tuple[LocalSourceFile, ...], expected_cwes: tuple[str, ...]
    ) -> LocalSourceCase:
        values = {"name": name, "files": files, "expected_cwes": expected_cwes}
        digest_values = {
            **values,
            "files": tuple(item.model_dump(mode="python") for item in files),
        }
        return cls(case_id=canonical_digest(digest_values), **values)


def local_source_case_digest(case: LocalSourceCase) -> str:
    return canonical_digest(case.model_dump(mode="python", exclude={"case_id"}))


class LocalSourceSuite(DomainModel):
    suite_id: Digest
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=32)
    cases: Annotated[tuple[LocalSourceCase, ...], Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.suite_id != local_source_suite_digest(self):
            raise ValueError("LocalSourceSuite content digest mismatch")
        identities = tuple(item.case_id for item in self.cases)
        names = tuple(item.name for item in self.cases)
        if len(identities) != len(set(identities)) or len(names) != len(set(names)):
            raise ValueError("local benchmark cases must be unique")
        if not any(item.expected_cwes for item in self.cases):
            raise ValueError("local benchmark suite requires positive ground truth")
        return self

    @classmethod
    def create(
        cls, *, name: str, version: str, cases: tuple[LocalSourceCase, ...]
    ) -> LocalSourceSuite:
        values = {"name": name, "version": version, "cases": cases}
        digest_values = {
            **values,
            "cases": tuple(item.model_dump(mode="python") for item in cases),
        }
        return cls(suite_id=canonical_digest(digest_values), **values)


def local_source_suite_digest(suite: LocalSourceSuite) -> str:
    return canonical_digest(suite.model_dump(mode="python", exclude={"suite_id"}))


class LocalCandidateObservation(DomainModel):
    candidate_id: UUID
    cwe: Cwe
    duplicate_fingerprint: Digest
    signal_ids: Annotated[tuple[Digest, ...], Field(min_length=1)]
    entry_path: str = Field(min_length=1, max_length=512)
    sink_path: str = Field(min_length=1, max_length=512)
    code_path_count: int = Field(ge=1, le=1_000)
    framework: WebFramework
    call_chain_length: int = Field(ge=1, le=1_000)


class LocalSourceCaseObservation(DomainModel):
    case_id: Digest
    target_version: Digest
    source_graph_id: Digest
    candidate_set_id: Digest
    files_analyzed: Annotated[tuple[str, ...], Field(min_length=1, max_length=10_000)]
    parse_failure_count: int = Field(ge=0, le=10_000)
    candidates: tuple[LocalCandidateObservation, ...] = ()


class LocalSourceEffectCounters(DomainModel):
    runner_calls: int = Field(default=0, ge=0)
    broker_calls: int = Field(default=0, ge=0)
    provider_calls: int = Field(default=0, ge=0)
    target_processes: int = Field(default=0, ge=0)
    public_network_calls: int = Field(default=0, ge=0)
    target_builds: int = Field(default=0, ge=0)
    automatic_approvals: int = Field(default=0, ge=0)
    submissions: int = Field(default=0, ge=0)


class LocalSourceObservationSet(DomainModel):
    observation_set_id: Digest
    suite_id: Digest
    observations: tuple[LocalSourceCaseObservation, ...]
    effects: LocalSourceEffectCounters = LocalSourceEffectCounters()

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.observation_set_id != local_source_observation_set_digest(self):
            raise ValueError("LocalSourceObservationSet content digest mismatch")
        case_ids = tuple(item.case_id for item in self.observations)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("local source observations must be unique per case")
        candidate_ids = tuple(
            item.candidate_id for case in self.observations for item in case.candidates
        )
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("local Candidate observations must be unique")
        return self

    @classmethod
    def create(
        cls,
        *,
        suite_id: str,
        observations: tuple[LocalSourceCaseObservation, ...],
        effects: LocalSourceEffectCounters | None = None,
    ) -> LocalSourceObservationSet:
        values = {
            "suite_id": suite_id,
            "observations": observations,
            "effects": effects or LocalSourceEffectCounters(),
        }
        digest_values = {
            **values,
            "observations": tuple(item.model_dump(mode="python") for item in observations),
            "effects": values["effects"].model_dump(mode="python"),
        }
        return cls(observation_set_id=canonical_digest(digest_values), **values)


def local_source_observation_set_digest(value: LocalSourceObservationSet) -> str:
    return canonical_digest(value.model_dump(mode="python", exclude={"observation_set_id"}))


class LocalSourceBenchmarkLimits(DomainModel):
    max_source_bytes: int = Field(default=1_000_000, gt=0)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)


class LocalSourceQualityPolicy(DomainModel):
    required_workflow_baseline_id: Digest
    min_candidate_recall: Ratio = 1.0
    min_candidate_precision: Ratio = 1.0
    min_trace_completeness: Ratio = 1.0
    min_finding_precision: Ratio = 1.0
    min_evidence_completeness: Ratio = 1.0
    max_forbidden_effects: int = Field(default=0, ge=0, le=0)

    @model_validator(mode="after")
    def non_weakenable(self) -> Self:
        if (
            self.min_candidate_recall != 1
            or self.min_candidate_precision != 1
            or self.min_trace_completeness != 1
            or self.min_finding_precision != 1
            or self.min_evidence_completeness != 1
        ):
            raise ValueError("local source quality policy cannot be weakened")
        return self


class LocalSourceQualityMetrics(DomainModel):
    case_count: int = Field(ge=0)
    truth_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    matched_candidate_count: int = Field(ge=0)
    candidate_recall: Ratio
    candidate_precision: Ratio
    trace_completeness: Ratio
    finding_precision: Ratio
    evidence_completeness: Ratio
    forbidden_effect_count: int = Field(ge=0)


class LocalSourceQualityResult(DomainModel):
    result_id: Digest
    suite_id: Digest
    observation_set_id: Digest
    workflow_baseline_id: Digest
    metrics: LocalSourceQualityMetrics
    violations: tuple[str, ...]
    gate_status: BenchmarkGateStatus

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.result_id != canonical_digest(
            self.model_dump(mode="python", exclude={"result_id"})
        ):
            raise ValueError("LocalSourceQualityResult content digest mismatch")
        return self


class LocalSourceBenchmarkRejected(ValueError):
    pass


def observe_local_source_suite(
    suite: LocalSourceSuite,
    source_root: Path,
    *,
    limits: LocalSourceBenchmarkLimits | None = None,
) -> LocalSourceObservationSet:
    """Run only the trusted, local static pipeline over sealed fixture files."""
    limits = limits or LocalSourceBenchmarkLimits()
    started = time.monotonic()
    source_root = source_root.resolve()
    total = 0
    observations = []
    with tempfile.TemporaryDirectory(prefix="vulnloom-m9.3-") as temporary:
        work_root = Path(temporary)
        for case in suite.cases:
            _check_deadline(started, limits.timeout_seconds)
            archive = work_root / f"{case.name}.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as handle:
                for source in case.files:
                    content = _read_fixture(source_root, source)
                    total += len(content)
                    if total > limits.max_source_bytes:
                        raise LocalSourceBenchmarkRejected(
                            "local source benchmark exceeds size limit"
                        )
                    info = zipfile.ZipInfo(source.path, date_time=(2020, 1, 1, 0, 0, 0))
                    info.external_attr = 0o100644 << 16
                    handle.writestr(info, content)
            archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            now = datetime(2030, 1, 1, tzinfo=UTC)
            scope = Scope(
                scope_id=UUID("00000000-0000-5000-8000-000000000093"),
                engagement_id=UUID("00000000-0000-5000-8000-000000000039"),
                authority_reference="sealed-local-m9.3-fixture",
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
                artifacts=(
                    ArtifactScope(
                        kind=ArtifactKind.SOURCE_ARCHIVE,
                        sha256=archive_digest,
                        source_name=archive.name,
                    ),
                ),
                allowed_test_classes=frozenset({"static_analysis"}),
                state=ScopeState.APPROVED,
                approved_by="trusted-fixture-generator",
                approved_at=now,
            )
            store_root = work_root / f"store-{case.name}"
            snapshot = IngestionService(store_root).ingest_archive(archive, scope=scope, now=now)
            graph = PythonWebSourceMapper().analyze(snapshot, store_root, scope=scope, now=now)
            candidate_set = CandidateGenerator().generate(graph, scope=scope, now=now)
            signals = {item.signal_id: item for item in graph.signals}
            routes = {item.route_id: item for item in graph.routes}
            flows = {item.flow_id: item for item in graph.flows}
            candidates = []
            for item in candidate_set.candidates:
                try:
                    candidate_signals = tuple(signals[value] for value in item.signal_ids)
                    route_ids = {value.route_id for value in candidate_signals}
                    flow_ids = {value.flow_id for value in candidate_signals}
                    if (
                        None in route_ids
                        or None in flow_ids
                        or len(route_ids) != 1
                        or len(flow_ids) != 1
                    ):
                        raise KeyError
                    route = routes[route_ids.pop()]
                    flow = flows[flow_ids.pop()]
                except KeyError as exc:
                    raise LocalSourceBenchmarkRejected(
                        "Candidate trace does not resolve to one route and flow"
                    ) from exc
                candidates.append(
                    LocalCandidateObservation(
                        candidate_id=item.candidate_id,
                        cwe=item.cwe,
                        duplicate_fingerprint=item.duplicate_fingerprint,
                        signal_ids=item.signal_ids,
                        entry_path=item.entry_point.path,
                        sink_path=item.sink.path,
                        code_path_count=len(item.code_path),
                        framework=route.framework,
                        call_chain_length=len(flow.call_chain),
                    )
                )
            observations.append(
                LocalSourceCaseObservation(
                    case_id=case.case_id,
                    target_version=snapshot.target.version,
                    source_graph_id=graph.graph_id,
                    candidate_set_id=candidate_set.candidate_set_id,
                    files_analyzed=graph.files_analyzed,
                    parse_failure_count=len(graph.parse_failures),
                    candidates=tuple(candidates),
                )
            )
    return LocalSourceObservationSet.create(
        suite_id=suite.suite_id, observations=tuple(observations)
    )


def evaluate_local_source_quality(
    suite: LocalSourceSuite,
    observations: LocalSourceObservationSet,
    workflow_baseline: BenchmarkBaseline,
    policy: LocalSourceQualityPolicy,
) -> LocalSourceQualityResult:
    if observations.suite_id != suite.suite_id:
        raise LocalSourceBenchmarkRejected("observation set belongs to another suite")
    if workflow_baseline.baseline_id != policy.required_workflow_baseline_id:
        raise LocalSourceBenchmarkRejected("workflow quality baseline does not match policy")
    by_case = {item.case_id: item for item in observations.observations}
    if set(by_case) != {item.case_id for item in suite.cases}:
        raise LocalSourceBenchmarkRejected("observation set does not cover the exact suite")
    truth_count = candidate_count = matched = complete = 0
    for case in suite.cases:
        truth = Counter(case.expected_cwes)
        observed = Counter(item.cwe for item in by_case[case.case_id].candidates)
        truth_count += sum(truth.values())
        candidate_count += sum(observed.values())
        matched += sum((truth & observed).values())
        complete += sum(
            bool(
                item.signal_ids
                and item.entry_path
                and item.sink_path
                and item.code_path_count
                and item.call_chain_length
            )
            for item in by_case[case.case_id].candidates
        )
    effects = sum(observations.effects.model_dump(mode="python").values())
    metrics = LocalSourceQualityMetrics(
        case_count=len(suite.cases),
        truth_count=truth_count,
        candidate_count=candidate_count,
        matched_candidate_count=matched,
        candidate_recall=matched / truth_count if truth_count else 1.0,
        candidate_precision=matched / candidate_count if candidate_count else 1.0,
        trace_completeness=complete / candidate_count if candidate_count else 1.0,
        finding_precision=workflow_baseline.metrics.finding_precision,
        evidence_completeness=workflow_baseline.metrics.evidence_completeness,
        forbidden_effect_count=effects,
    )
    checks = (
        ("candidate_recall_below_minimum", metrics.candidate_recall < policy.min_candidate_recall),
        (
            "candidate_precision_below_minimum",
            metrics.candidate_precision < policy.min_candidate_precision,
        ),
        (
            "trace_completeness_below_minimum",
            metrics.trace_completeness < policy.min_trace_completeness,
        ),
        (
            "finding_precision_below_minimum",
            metrics.finding_precision < policy.min_finding_precision,
        ),
        (
            "evidence_completeness_below_minimum",
            metrics.evidence_completeness < policy.min_evidence_completeness,
        ),
        ("forbidden_effect_observed", effects > policy.max_forbidden_effects),
    )
    violations = tuple(code for code, failed in checks if failed)
    values = {
        "suite_id": suite.suite_id,
        "observation_set_id": observations.observation_set_id,
        "workflow_baseline_id": workflow_baseline.baseline_id,
        "metrics": metrics,
        "violations": violations,
        "gate_status": BenchmarkGateStatus.FAILED if violations else BenchmarkGateStatus.PASSED,
    }
    digest_values = {**values, "metrics": metrics.model_dump(mode="python")}
    return LocalSourceQualityResult(result_id=canonical_digest(digest_values), **values)


def _read_fixture(root: Path, source: LocalSourceFile) -> bytes:
    path = (root / source.path).resolve()
    if path == root or root not in path.parents:
        raise LocalSourceBenchmarkRejected("local source fixture escapes its root")
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise LocalSourceBenchmarkRejected("local source fixture is unavailable") from exc
    if not stat.S_ISREG(mode) or path.is_symlink():
        raise LocalSourceBenchmarkRejected("local source fixture must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LocalSourceBenchmarkRejected("local source fixture cannot be opened safely") from exc
    with os.fdopen(fd, "rb") as handle:
        content = handle.read()
    if hashlib.sha256(content).hexdigest() != source.sha256:
        raise LocalSourceBenchmarkRejected("local source fixture digest mismatch")
    return content


def _check_deadline(started: float, timeout: float) -> None:
    if time.monotonic() - started >= timeout:
        raise LocalSourceBenchmarkRejected("local source benchmark timed out")
