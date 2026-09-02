"""Generate the sealed M9.4 local-source robustness fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

from vulnloom.benchmark.local_source import (
    LocalSourceCase,
    LocalSourceFile,
    LocalSourceSuite,
    observe_local_source_suite,
)
from vulnloom.benchmark.local_source_robustness import (
    M9_4_CASE_CONTRACT,
    LocalSourceRobustnessProfile,
)
from vulnloom.benchmark.models import BenchmarkBaseline


def build_suite(root: Path) -> LocalSourceSuite:
    source_root = root / "sources"
    cases = []
    for (
        name,
        _framework,
        _disposition,
        _cross_file,
        _min_files,
        _min_chain,
        expected_cwes,
    ) in M9_4_CASE_CONTRACT:
        paths = tuple(sorted((source_root / name).glob("*.py")))
        files = tuple(
            LocalSourceFile(
                path=path.relative_to(source_root).as_posix(),
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in paths
        )
        cases.append(LocalSourceCase.create(name=name, files=files, expected_cwes=expected_cwes))
    return LocalSourceSuite.create(
        name="vulnloom-m9.4-local-source-robustness",
        version="1",
        cases=tuple(cases),
    )


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "m9_4"
    suite = build_suite(root)
    observations = observe_local_source_suite(suite, root / "sources")
    baseline = BenchmarkBaseline.model_validate_json(
        (root.parent / "m6_1" / "baseline.json").read_text(encoding="utf-8")
    )
    profile = LocalSourceRobustnessProfile.create(suite=suite, workflow_baseline=baseline)
    for name, value in (
        ("suite.json", suite),
        ("observations.json", observations),
        ("profile.json", profile),
    ):
        (root / name).write_text(value.model_dump_json(indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
