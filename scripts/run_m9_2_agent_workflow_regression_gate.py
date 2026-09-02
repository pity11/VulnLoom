"""Run the sealed M9.2 Agent workflow mutation corpus entirely offline."""

from __future__ import annotations

from pathlib import Path

from vulnloom.benchmark import (
    AgentWorkflowRegressionCorpus,
    BenchmarkGateStatus,
    evaluate_agent_workflow_corpus,
)


def main() -> int:
    fixture = Path(__file__).resolve().parents[1] / "benchmarks" / "m9_2" / "corpus.json"
    corpus = AgentWorkflowRegressionCorpus.model_validate_json(
        fixture.read_text(encoding="utf-8")
    )
    result = evaluate_agent_workflow_corpus(corpus)
    if result.gate_status is BenchmarkGateStatus.FAILED:
        for scenario in result.scenario_results:
            if not scenario.expectation_matched:
                print(
                    f"{scenario.mutation.value}: unexpected violations="
                    f"{','.join(scenario.actual_violation_codes)}"
                )
        return 1
    print(
        f"M9.2 Agent workflow gate passed: "
        f"scenarios={result.matched_count}/{result.scenario_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
