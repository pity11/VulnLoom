"""Build the deterministic, repository-owned M9.5 local pilot inputs."""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from vulnloom.analyzers import PythonWebSourceMapper, SourceGraph
from vulnloom.domain.models import ArtifactKind, ArtifactScope, Scope, ScopeState, TargetSnapshot
from vulnloom.hypotheses import CandidateGenerator, CandidateSet
from vulnloom.ingestion import IngestionService

from .local_source import LocalSourceEffectCounters, LocalSourceObservationSet, LocalSourceSuite
from .local_source_robustness import (
    LocalSourceRobustnessProfile,
    LocalSourceRobustnessResult,
    evaluate_local_source_robustness,
)
from .models import BenchmarkBaseline
from .pilot_readiness_models import (
    AuthorizedPilotManifest,
    AuthorizedPilotReadinessPlan,
    AuthorizedPilotReadinessPolicy,
)

PILOT_NOW = datetime(2030, 1, 15, 12, tzinfo=UTC)


@dataclass(frozen=True)
class PilotFixture:
    scope: Scope
    snapshot: TargetSnapshot
    target_store_root: Path
    graph: SourceGraph
    candidate_set: CandidateSet
    quality_profile: LocalSourceRobustnessProfile
    quality_result: LocalSourceRobustnessResult
    manifest: AuthorizedPilotManifest
    plan: AuthorizedPilotReadinessPlan


def _write_archive(path: Path, source_root: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for source in sorted(source_root.rglob("*.py")):
            info = zipfile.ZipInfo(source.relative_to(source_root).as_posix())
            info.date_time = (2026, 1, 1, 0, 0, 0)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())


def build_pilot_fixture(work_root: Path) -> PilotFixture:
    work_root.mkdir(parents=True, exist_ok=True)
    repository_root = Path(__file__).resolve().parents[3]
    benchmark_root = repository_root / "benchmarks"
    robustness_root = benchmark_root / "m9_4"
    archive = work_root / "authorized-pilot.zip"
    _write_archive(archive, robustness_root / "sources")
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    scope = Scope(
        scope_id=UUID("00000000-0000-5000-8000-000000000951"),
        engagement_id=UUID("00000000-0000-5000-8000-000000000952"),
        authority_reference="repository-owned-m9.5-fixture",
        valid_from=PILOT_NOW - timedelta(days=1),
        valid_until=PILOT_NOW + timedelta(days=1),
        artifacts=(
            ArtifactScope(
                kind=ArtifactKind.SOURCE_ARCHIVE,
                sha256=archive_digest,
                source_name=archive.name,
            ),
        ),
        allowed_test_classes=frozenset({"read_only_static_analysis"}),
        denied_actions=frozenset(
            {
                "automatic_approval",
                "automatic_validation",
                "public_network",
                "submission",
                "target_build",
            }
        ),
        state=ScopeState.APPROVED,
        approved_by="vulnloom-release-owner",
        approved_at=PILOT_NOW,
    )
    target_store_root = work_root / "targets"
    snapshot = IngestionService(target_store_root).ingest_archive(
        archive, scope=scope, now=PILOT_NOW
    )
    graph = PythonWebSourceMapper().analyze(snapshot, target_store_root, scope=scope, now=PILOT_NOW)
    candidate_set = CandidateGenerator().generate(graph, scope=scope, now=PILOT_NOW)
    suite = LocalSourceSuite.model_validate_json(
        (robustness_root / "suite.json").read_text(encoding="utf-8")
    )
    observations = LocalSourceObservationSet.model_validate_json(
        (robustness_root / "observations.json").read_text(encoding="utf-8")
    )
    quality_profile = LocalSourceRobustnessProfile.model_validate_json(
        (robustness_root / "profile.json").read_text(encoding="utf-8")
    )
    baseline = BenchmarkBaseline.model_validate_json(
        (benchmark_root / "m6_1" / "baseline.json").read_text(encoding="utf-8")
    )
    _, quality_result = evaluate_local_source_robustness(
        suite, observations, baseline, quality_profile
    )
    manifest = AuthorizedPilotManifest.create(
        scope=scope,
        snapshot=snapshot,
        graph=graph,
        candidate_set=candidate_set,
    )
    plan = AuthorizedPilotReadinessPlan.create(
        manifest=manifest,
        quality_profile=quality_profile,
        quality_result=quality_result,
        policy=AuthorizedPilotReadinessPolicy(),
        effects=LocalSourceEffectCounters(),
        created_at=PILOT_NOW,
        deadline=PILOT_NOW + timedelta(minutes=15),
        idempotency_key="m9.5-authorized-local-pilot-v1",
    )
    return PilotFixture(
        scope=scope,
        snapshot=snapshot,
        target_store_root=target_store_root,
        graph=graph,
        candidate_set=candidate_set,
        quality_profile=quality_profile,
        quality_result=quality_result,
        manifest=manifest,
        plan=plan,
    )
