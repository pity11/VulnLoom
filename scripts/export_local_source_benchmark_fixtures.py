"""Generate the sealed M9.3 local-source benchmark and observations."""

from __future__ import annotations

import hashlib
from pathlib import Path

from vulnloom.benchmark.local_source import (
    LocalSourceCase,
    LocalSourceFile,
    LocalSourceQualityPolicy,
    LocalSourceSuite,
    observe_local_source_suite,
)
from vulnloom.benchmark.models import BenchmarkBaseline

CASES = (
    ("sql", ("CWE-89",)),
    ("command", ("CWE-78",)),
    ("file", ("CWE-22",)),
    ("network", ("CWE-918",)),
    ("template", ("CWE-1336",)),
    ("deserialization", ("CWE-502",)),
    ("redirect", ("CWE-601",)),
    ("object_lookup", ("CWE-639",)),
    ("guarded_object", ()),
)


def build_suite(root: Path) -> LocalSourceSuite:
    source_root = root / "sources"
    cases = []
    for name, expected_cwes in CASES:
        path = f"{name}/app.py"
        digest = hashlib.sha256((source_root / path).read_bytes()).hexdigest()
        cases.append(
            LocalSourceCase.create(
                name=name,
                files=(LocalSourceFile(path=path, sha256=digest),),
                expected_cwes=expected_cwes,
            )
        )
    return LocalSourceSuite.create(
        name="vulnloom-m9.3-local-source", version="1", cases=tuple(cases)
    )


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "m9_3"
    suite = build_suite(root)
    observations = observe_local_source_suite(suite, root / "sources")
    baseline = BenchmarkBaseline.model_validate_json(
        (root.parent / "m6_1" / "baseline.json").read_text(encoding="utf-8")
    )
    policy = LocalSourceQualityPolicy(required_workflow_baseline_id=baseline.baseline_id)
    for name, value in (
        ("suite.json", suite),
        ("observations.json", observations),
        ("policy.json", policy),
    ):
        (root / name).write_text(value.model_dump_json(indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
