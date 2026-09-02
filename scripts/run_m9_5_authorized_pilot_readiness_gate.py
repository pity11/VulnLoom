"""Run the M9.5 authorized local-pilot readiness gate offline."""

from __future__ import annotations

import tempfile
from pathlib import Path

from vulnloom.benchmark import (
    AuthorizedPilotManifest,
    AuthorizedPilotReadinessArtifactStore,
    AuthorizedPilotReadinessPlan,
    AuthorizedPilotReadinessResult,
    AuthorizedPilotReadinessService,
    AuthorizedPilotReadinessStore,
    BenchmarkGateStatus,
)
from vulnloom.benchmark.pilot_readiness_fixture import PILOT_NOW, build_pilot_fixture


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sealed = root / "benchmarks" / "m9_5"
    expected_manifest = AuthorizedPilotManifest.model_validate_json(
        (sealed / "manifest.json").read_text(encoding="utf-8")
    )
    expected_plan = AuthorizedPilotReadinessPlan.model_validate_json(
        (sealed / "plan.json").read_text(encoding="utf-8")
    )
    expected_result = AuthorizedPilotReadinessResult.model_validate_json(
        (sealed / "result.json").read_text(encoding="utf-8")
    )
    with tempfile.TemporaryDirectory(prefix="vulnloom-m9.5-gate-") as temporary:
        work = Path(temporary)
        fixture = build_pilot_fixture(work)
        if fixture.manifest != expected_manifest or fixture.plan != expected_plan:
            print("M9.5 sealed manifest or plan drifted")
            return 1
        with AuthorizedPilotReadinessStore(work / "readiness.sqlite3") as store:
            outcome = AuthorizedPilotReadinessService(
                store=store,
                artifact_store=AuthorizedPilotReadinessArtifactStore(work / "artifacts"),
            ).evaluate(
                scope=fixture.scope,
                snapshot=fixture.snapshot,
                target_store_root=fixture.target_store_root,
                graph=fixture.graph,
                candidate_set=fixture.candidate_set,
                quality_profile=fixture.quality_profile,
                quality_result=fixture.quality_result,
                manifest=fixture.manifest,
                plan=fixture.plan,
                now=PILOT_NOW,
            )
    if (
        outcome.result != expected_result
        or outcome.result.gate_status is not BenchmarkGateStatus.PASSED
    ):
        print("M9.5 authorized pilot readiness result failed or drifted")
        return 1
    metrics = outcome.result.metrics
    print(
        "M9.5 authorized pilot readiness gate passed: "
        f"files={metrics.source_file_count} candidates={metrics.candidate_count} "
        f"human_gates={metrics.human_gate_count} forbidden_effects={metrics.forbidden_effect_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
