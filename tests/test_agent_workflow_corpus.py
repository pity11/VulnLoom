from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import vulnloom.benchmark.agent_workflow_corpus as corpus_module
from vulnloom.benchmark import (
    AgentWorkflowMutation,
    AgentWorkflowRegressionCorpus,
    AgentWorkflowRegressionCorpusResult,
    AgentWorkflowRegressionScenario,
    BenchmarkGateStatus,
    apply_agent_workflow_mutation,
    evaluate_agent_workflow_corpus,
)


def _fixture() -> AgentWorkflowRegressionCorpus:
    path = Path(__file__).resolve().parents[1] / "benchmarks" / "m9_2" / "corpus.json"
    return AgentWorkflowRegressionCorpus.model_validate_json(path.read_text(encoding="utf-8"))


def test_m9_2_corpus_covers_every_fixed_mutation_and_passes():
    corpus = _fixture()
    result = evaluate_agent_workflow_corpus(corpus)

    assert tuple(item.mutation for item in corpus.scenarios) == tuple(AgentWorkflowMutation)
    assert result.gate_status is BenchmarkGateStatus.PASSED
    assert result.scenario_count == len(AgentWorkflowMutation) == 23
    assert result.matched_count == result.scenario_count
    assert all(item.expectation_matched for item in result.scenario_results)
    assert all(
        apply_agent_workflow_mutation(corpus.base_observation, item.mutation).observation_id
        for item in corpus.scenarios
    )


def test_m9_2_corpus_result_fails_when_evaluator_behavior_drifts(monkeypatch):
    corpus = _fixture()
    monkeypatch.setattr(
        corpus_module,
        "evaluate_agent_workflow",
        lambda _observation, _policy: (None, ()),
    )
    result = evaluate_agent_workflow_corpus(corpus)

    assert result.gate_status is BenchmarkGateStatus.FAILED
    assert result.matched_count == 1
    assert not all(item.expectation_matched for item in result.scenario_results)


def test_m9_2_corpus_rejects_weakened_expectation_and_missing_scenario():
    corpus = _fixture()
    payload = json.loads(corpus.model_dump_json())
    payload["scenarios"][1]["expected_violation_codes"] = []
    with pytest.raises(ValidationError, match="expectation cannot be changed"):
        AgentWorkflowRegressionCorpus.model_validate(payload)

    payload = json.loads(corpus.model_dump_json())
    payload["scenarios"].pop()
    with pytest.raises(ValidationError, match="every fixed mutation"):
        AgentWorkflowRegressionCorpus.model_validate(payload)

    result_payload = json.loads(evaluate_agent_workflow_corpus(corpus).model_dump_json())
    result_payload["scenario_results"][0]["expectation_matched"] = False
    with pytest.raises(ValidationError, match="match flag is inconsistent"):
        AgentWorkflowRegressionCorpusResult.model_validate(result_payload)


def test_m9_2_corpus_and_result_contracts_exclude_operational_inputs():
    forbidden = {
        "prose",
        "prompt",
        "url",
        "path",
        "credential",
        "token",
        "runner",
        "broker",
        "submission",
    }
    for model in (
        AgentWorkflowRegressionScenario,
        AgentWorkflowRegressionCorpus,
        AgentWorkflowRegressionCorpusResult,
    ):
        assert not set(model.model_fields) & forbidden
