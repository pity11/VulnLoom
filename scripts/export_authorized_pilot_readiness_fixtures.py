"""Generate the sealed M9.5 authorized local-pilot readiness fixtures."""

from __future__ import annotations

import tempfile
from pathlib import Path

from vulnloom.benchmark import (
    AuthorizedPilotReadinessArtifactStore,
    AuthorizedPilotReadinessService,
    AuthorizedPilotReadinessStore,
)
from vulnloom.benchmark.pilot_readiness_fixture import PILOT_NOW, build_pilot_fixture


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    destination = root / "benchmarks" / "m9_5"
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vulnloom-m9.5-") as temporary:
        work = Path(temporary)
        fixture = build_pilot_fixture(work)
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
        for name, value in (
            ("manifest.json", fixture.manifest),
            ("plan.json", fixture.plan),
            ("result.json", outcome.result),
        ):
            (destination / name).write_text(
                value.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )


if __name__ == "__main__":
    main()
