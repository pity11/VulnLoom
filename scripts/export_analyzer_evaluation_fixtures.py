"""Generate the sealed M6.3 cross-analyzer evaluation fixture."""

from __future__ import annotations

from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from vulnloom.benchmark import (
    AlignmentProvenance,
    AnalyzerCaseBinding,
    AnalyzerEvaluationBaseline,
    AnalyzerEvaluationLimits,
    AnalyzerEvaluationPolicy,
    AnalyzerKind,
    AnalyzerObservation,
    AnalyzerObservationSet,
    AnalyzerResultFile,
    AnalyzerResultSnapshot,
    AnalyzerSeverity,
    AnalyzerTruthAlignment,
    AnalyzerTruthMatch,
    BenchmarkCase,
    BenchmarkSuite,
    EvaluationDeadline,
    GroundTruthFinding,
    evaluate_analyzer_metrics,
)
from vulnloom.domain.digests import canonical_digest

CASES = (
    ("a" * 64, "commit-a", "1" * 64, "CWE-79"),
    ("b" * 64, "commit-b", "2" * 64, "CWE-89"),
)


def build_fixture():
    suite = BenchmarkSuite.create(
        name="vulnloom-m6.3-cross-analyzer",
        version="1",
        cases=tuple(
            BenchmarkCase(
                case_id=case_id,
                target_version=version,
                ground_truth=(
                    GroundTruthFinding(
                        truth_id=truth_id,
                        cwe=cwe,
                        duplicate_family=canonical_digest(
                            {"case": case_id, "duplicate-family": 1}
                        ),
                    ),
                ),
            )
            for case_id, version, truth_id, cwe in CASES
        ),
    )
    observation_sets = []
    matches = []
    bindings = []
    for case_id, version, truth_id, cwe in CASES:
        for analyzer in AnalyzerKind:
            snapshot = AnalyzerResultSnapshot.create(
                analyzer=analyzer,
                target_id=uuid5(
                    NAMESPACE_URL, f"vulnloom:m6.3:{case_id}:{analyzer.value}"
                ),
                target_version=version,
                tool_version="fixture-1.0.0",
                rules_digest=canonical_digest(
                    {"fixture": "m6.3", "analyzer": analyzer}
                ),
                output=AnalyzerResultFile(
                    logical_name="output.json",
                    size=2,
                    sha256=canonical_digest(
                        {"fixture": "m6.3", "case": case_id, "analyzer": analyzer}
                    ),
                ),
            )
            observation = AnalyzerObservation.create(
                analyzer=analyzer,
                target_id=snapshot.target_id,
                target_version=version,
                rule_id=f"fixture/{analyzer.value}/{case_id[0]}",
                rule_fingerprint=canonical_digest(
                    {"fixture-rule": analyzer, "case": case_id}
                ),
                cwes=(cwe,),
                severity=AnalyzerSeverity.HIGH,
                message_digest=canonical_digest(
                    {"fixture-message": analyzer, "case": case_id}
                ),
            )
            observations = AnalyzerObservationSet.create(
                snapshot=snapshot,
                adapter_id=f"{analyzer.value}.fixture.v1",
                adapter_digest=canonical_digest(
                    {"fixture-adapter": analyzer, "version": 1}
                ),
                observations=(observation,),
                exclusions=(),
            )
            observation_sets.append(observations)
            bindings.append(
                AnalyzerCaseBinding.create(case_id=case_id, observations=observations)
            )
            matches.append(
                AnalyzerTruthMatch(
                    case_id=case_id,
                    observation_set_id=observations.observation_set_id,
                    observation_id=observation.observation_id,
                    truth_id=truth_id,
                    matched_cwe=cwe,
                )
            )
    sealed_sets = tuple(observation_sets)
    alignment = AnalyzerTruthAlignment.create(
        suite=suite,
        provenance=AlignmentProvenance.FIXTURE,
        producer_id="vulnloom.m6.3.fixture.v1",
        bindings=tuple(bindings),
        matches=tuple(matches),
    )
    metrics = evaluate_analyzer_metrics(
        suite,
        sealed_sets,
        alignment,
        limits=AnalyzerEvaluationLimits(),
        deadline=EvaluationDeadline(60),
    )
    baseline = AnalyzerEvaluationBaseline.create(suite=suite, metrics=metrics)
    policy = AnalyzerEvaluationPolicy(
        min_truth_recall=1.0,
        min_observation_precision=1.0,
        max_duplicate_rate=0.75,
        max_exclusion_rate=0.0,
        required_analyzers=tuple(sorted(AnalyzerKind, key=lambda item: item.value)),
        require_full_case_matrix=True,
    )
    return suite, sealed_sets, alignment, baseline, policy


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "m6_3"
    root.mkdir(parents=True, exist_ok=True)
    suite, observation_sets, alignment, baseline, policy = build_fixture()
    static_values = {
        "suite.json": suite,
        "alignment.json": alignment,
        "baseline.json": baseline,
        "policy.json": policy,
    }
    for name, value in static_values.items():
        (root / name).write_text(value.model_dump_json(indent=2) + "\n", encoding="utf-8")
    for observations in observation_sets:
        case_id = next(
            item.case_id
            for item in alignment.bindings
            if item.observation_set_id == observations.observation_set_id
        )
        name = f"observation-{case_id[0]}-{observations.analyzer.value}.json"
        (root / name).write_text(
            observations.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
