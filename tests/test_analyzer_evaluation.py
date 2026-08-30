from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    AlignmentProvenance,
    AnalyzerCaseBinding,
    AnalyzerEvaluationArtifactStore,
    AnalyzerEvaluationBaseline,
    AnalyzerEvaluationIdempotencyConflict,
    AnalyzerEvaluationLimits,
    AnalyzerEvaluationPlan,
    AnalyzerEvaluationPolicy,
    AnalyzerEvaluationRecoveryRequired,
    AnalyzerEvaluationRejected,
    AnalyzerEvaluationService,
    AnalyzerEvaluationStore,
    AnalyzerExclusion,
    AnalyzerKind,
    AnalyzerObservation,
    AnalyzerObservationSet,
    AnalyzerResultFile,
    AnalyzerResultSnapshot,
    AnalyzerSeverity,
    AnalyzerTruthAlignment,
    AnalyzerTruthMatch,
    BenchmarkCase,
    BenchmarkGateStatus,
    BenchmarkSuite,
    EvaluationDeadline,
    GroundTruthFinding,
    evaluate_analyzer_metrics,
)
from vulnloom.cli import main
from vulnloom.domain.digests import canonical_digest

CASE_A = "a" * 64
CASE_B = "b" * 64
TRUTH_A = "1" * 64
TRUTH_B = "2" * 64
VERSION_A = "commit-a"
VERSION_B = "commit-b"


def _suite():
    return BenchmarkSuite.create(
        name="m6.3-cross-analyzer",
        version="1",
        cases=(
            BenchmarkCase(
                case_id=CASE_A,
                target_version=VERSION_A,
                ground_truth=(
                    GroundTruthFinding(
                        truth_id=TRUTH_A,
                        cwe="CWE-79",
                        duplicate_family="3" * 64,
                    ),
                ),
            ),
            BenchmarkCase(
                case_id=CASE_B,
                target_version=VERSION_B,
                ground_truth=(
                    GroundTruthFinding(
                        truth_id=TRUTH_B,
                        cwe="CWE-89",
                        duplicate_family="4" * 64,
                    ),
                ),
            ),
        ),
    )


def _observation_set(kind, case_id, *, cwe=None, extra=False, exclusion=False):
    version = VERSION_A if case_id == CASE_A else VERSION_B
    snapshot = AnalyzerResultSnapshot.create(
        analyzer=kind,
        target_id=uuid4(),
        target_version=version,
        tool_version="1.0.0",
        rules_digest=canonical_digest({"kind": kind, "rules": 1}),
        output=AnalyzerResultFile(
            logical_name="output.json",
            size=2,
            sha256=canonical_digest({"kind": kind, "case": case_id}),
        ),
    )
    expected_cwe = cwe or ("CWE-79" if case_id == CASE_A else "CWE-89")
    observations = [
        AnalyzerObservation.create(
            analyzer=kind,
            target_id=snapshot.target_id,
            target_version=version,
            rule_id=f"{kind.value}/{case_id[0]}",
            rule_fingerprint=canonical_digest({"rule": kind, "case": case_id}),
            cwes=(expected_cwe,),
            severity=AnalyzerSeverity.HIGH,
            message_digest=canonical_digest({"message": kind, "case": case_id}),
        )
    ]
    if extra:
        observations.append(
            AnalyzerObservation.create(
                analyzer=kind,
                target_id=snapshot.target_id,
                target_version=version,
                rule_id=f"{kind.value}/{case_id[0]}/extra",
                rule_fingerprint=canonical_digest({"rule": kind, "case": case_id, "extra": True}),
                cwes=(expected_cwe,),
                severity=AnalyzerSeverity.MEDIUM,
                message_digest=canonical_digest({"message": kind, "case": case_id, "extra": True}),
            )
        )
    exclusions = (
        (
            AnalyzerExclusion(
                source_ref_digest=canonical_digest({"excluded": kind, "case": case_id}),
                reason_code="missing_cwe_mapping",
            ),
        )
        if exclusion
        else ()
    )
    return AnalyzerObservationSet.create(
        snapshot=snapshot,
        adapter_id=f"{kind.value}.fixture.v1",
        adapter_digest=canonical_digest({"adapter": kind}),
        observations=tuple(observations),
        exclusions=exclusions,
    )


def _sets(*, extra=False, exclusion=False):
    return tuple(
        _observation_set(
            kind,
            case_id,
            extra=extra and kind is AnalyzerKind.CODEQL and case_id == CASE_A,
            exclusion=exclusion and kind is AnalyzerKind.TRIVY and case_id == CASE_B,
        )
        for case_id in (CASE_A, CASE_B)
        for kind in AnalyzerKind
    )


def _alignment(suite, sets, *, matched=True):
    case_by_version = {VERSION_A: CASE_A, VERSION_B: CASE_B}
    bindings = tuple(
        AnalyzerCaseBinding.create(case_id=case_by_version[item.target_version], observations=item)
        for item in sets
    )
    matches = ()
    if matched:
        matches = tuple(
            AnalyzerTruthMatch(
                case_id=case_by_version[item.target_version],
                observation_set_id=item.observation_set_id,
                observation_id=item.observations[0].observation_id,
                truth_id=TRUTH_A if item.target_version == VERSION_A else TRUTH_B,
                matched_cwe="CWE-79" if item.target_version == VERSION_A else "CWE-89",
            )
            for item in sets
        )
    return AnalyzerTruthAlignment.create(
        suite=suite,
        provenance=AlignmentProvenance.FIXTURE,
        producer_id="m6.3.fixture",
        bindings=bindings,
        matches=matches,
    )


def _policy(**changes):
    values = {
        "min_truth_recall": 1.0,
        "min_observation_precision": 1.0,
        "max_duplicate_rate": 0.75,
        "max_exclusion_rate": 1.0,
        "required_analyzers": tuple(sorted(AnalyzerKind, key=lambda item: item.value)),
        "require_full_case_matrix": True,
    }
    values.update(changes)
    return AnalyzerEvaluationPolicy(**values)


def _plan(suite, alignment, now, *, policy=None, baseline=None, key="analyzer-eval:1", limits=None):
    return AnalyzerEvaluationPlan.create(
        suite=suite,
        alignment=alignment,
        policy=policy or _policy(),
        limits=limits or AnalyzerEvaluationLimits(),
        baseline=baseline,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )


def _service(tmp_path):
    store = AnalyzerEvaluationStore(tmp_path / "evaluation.db")
    artifacts = AnalyzerEvaluationArtifactStore(tmp_path / "artifacts")
    return (
        AnalyzerEvaluationService(store=store, artifact_store=artifacts),
        store,
        artifacts,
    )


def test_cross_analyzer_evaluation_passes_and_replays(tmp_path, now):
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    service, store, artifacts = _service(tmp_path)
    plan = _plan(suite, alignment, now)

    first = service.evaluate(suite, sets, alignment, plan, now=now)
    second = service.evaluate(suite, sets, alignment, plan, now=now)

    assert first == second
    assert first.result.gate_status is BenchmarkGateStatus.PASSED
    assert first.result.metrics.truth_recall == 1.0
    assert first.result.metrics.observation_precision == 1.0
    assert first.result.metrics.duplicate_rate == 0.75
    assert len(first.result.metrics.by_analyzer) == 4
    assert all(item.truth_recall == 1.0 for item in first.result.metrics.by_analyzer)
    assert all(item.duplicate_rate == 0.0 for item in first.result.metrics.by_analyzer)
    assert artifacts.read_result(first.artifact) == first.result
    assert "`codeql`" in artifacts.read_markdown(first.artifact)
    store.close()


def test_cwe_compatibility_does_not_auto_match_unaligned_observations():
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets, matched=False)
    metrics = evaluate_analyzer_metrics(
        suite,
        sets,
        alignment,
        limits=AnalyzerEvaluationLimits(),
        deadline=EvaluationDeadline(1),
    )
    assert metrics.truth_recall == 0.0
    assert metrics.observation_precision == 0.0
    assert metrics.false_positive_count == 8


def test_false_positive_exclusion_and_gate_metrics(tmp_path, now):
    suite = _suite()
    sets = _sets(extra=True, exclusion=True)
    alignment = _alignment(suite, sets)
    policy = _policy(
        min_observation_precision=1.0,
        max_exclusion_rate=0.0,
    )
    service, store, _ = _service(tmp_path)
    outcome = service.evaluate(
        suite, sets, alignment, _plan(suite, alignment, now, policy=policy), now=now
    )
    assert outcome.result.metrics.observation_count == 9
    assert outcome.result.metrics.false_positive_count == 1
    assert outcome.result.metrics.exclusion_count == 1
    assert outcome.result.gate_status is BenchmarkGateStatus.FAILED
    assert {item.code for item in outcome.result.violations} == {
        "analyzer.threshold.observation_precision",
        "analyzer.threshold.exclusion_rate",
        "analyzer.threshold.codeql.observation_precision",
        "analyzer.threshold.trivy.exclusion_rate",
    }
    store.close()


def test_cross_case_and_incompatible_cwe_matches_are_rejected(tmp_path, now):
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    first = alignment.matches[0]
    cross_case = first.model_copy(update={"truth_id": TRUTH_B})
    changed = AnalyzerTruthAlignment.create(
        suite=suite,
        provenance=alignment.provenance,
        producer_id=alignment.producer_id,
        bindings=alignment.bindings,
        matches=(cross_case, *alignment.matches[1:]),
    )
    service, store, _ = _service(tmp_path)
    with pytest.raises(AnalyzerEvaluationRejected, match="sealed case"):
        service.evaluate(suite, sets, changed, _plan(suite, changed, now), now=now)
    assert store.connection.execute("SELECT COUNT(*) FROM analyzer_evaluations").fetchone()[0] == 0
    store.close()

    incompatible = first.model_copy(update={"matched_cwe": "CWE-89"})
    changed = AnalyzerTruthAlignment.create(
        suite=suite,
        provenance=alignment.provenance,
        producer_id=alignment.producer_id,
        bindings=alignment.bindings,
        matches=(incompatible, *alignment.matches[1:]),
    )
    service, store, _ = _service(tmp_path / "cwe")
    with pytest.raises(AnalyzerEvaluationRejected, match="incompatible CWE"):
        service.evaluate(suite, sets, changed, _plan(suite, changed, now), now=now)
    store.close()


def test_exact_set_digest_target_and_plan_bindings_are_required(tmp_path, now):
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    plan = _plan(suite, alignment, now)
    service, store, _ = _service(tmp_path)
    with pytest.raises(AnalyzerEvaluationRejected, match="exact ObservationSets"):
        service.evaluate(suite, sets[:-1], alignment, plan, now=now)
    changed_set = sets[0].model_copy(update={"target_version": "other"})
    with pytest.raises(AnalyzerEvaluationRejected, match="case/Target binding"):
        service.evaluate(suite, (changed_set, *sets[1:]), alignment, plan, now=now)
    changed_alignment = alignment.model_copy(update={"producer_id": "changed"})
    with pytest.raises(AnalyzerEvaluationRejected, match="plan input binding"):
        service.evaluate(suite, sets, changed_alignment, plan, now=now)
    store.close()


def test_required_analyzer_matrix_and_baseline_regression(tmp_path, now):
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    metrics = evaluate_analyzer_metrics(
        suite,
        sets,
        alignment,
        limits=AnalyzerEvaluationLimits(),
        deadline=EvaluationDeadline(1),
    )
    baseline = AnalyzerEvaluationBaseline.create(suite=suite, metrics=metrics)
    partial_sets = tuple(item for item in sets if item.analyzer is not AnalyzerKind.KUBESEC)
    partial = _alignment(suite, partial_sets)
    service, store, _ = _service(tmp_path)
    outcome = service.evaluate(
        suite,
        partial_sets,
        partial,
        _plan(suite, partial, now, baseline=baseline, key="partial"),
        now=now,
    )
    assert {item.code for item in outcome.result.violations} == {
        "analyzer.required.kubesec",
        "analyzer.policy.case_matrix",
    }
    store.close()

    unaligned = _alignment(suite, sets, matched=False)
    policy = _policy(min_truth_recall=0.0, min_observation_precision=0.0)
    service, store, _ = _service(tmp_path / "baseline")
    outcome = service.evaluate(
        suite,
        sets,
        unaligned,
        _plan(
            suite,
            unaligned,
            now,
            policy=policy,
            baseline=baseline,
            key="baseline-drop",
        ),
        now=now,
    )
    codes = {item.code for item in outcome.result.violations}
    assert {
        "analyzer.baseline.truth_recall",
        "analyzer.baseline.observation_precision",
    } <= codes
    assert "analyzer.baseline.codeql.truth_recall" in codes
    assert "analyzer.baseline.kubesec.observation_precision" in codes
    store.close()


def test_limits_timeout_and_inactive_plan_fail_before_checkpoint(tmp_path, now):
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    with pytest.raises(AnalyzerEvaluationRejected, match="ObservationSet limit"):
        evaluate_analyzer_metrics(
            suite,
            sets,
            alignment,
            limits=AnalyzerEvaluationLimits(max_observation_sets=1),
            deadline=EvaluationDeadline(1),
        )
    ticks = iter((0.0, 2.0))
    deadline = EvaluationDeadline(1, clock=lambda: next(ticks))
    with pytest.raises(AnalyzerEvaluationRejected, match="timed out"):
        deadline.check()
    service, store, _ = _service(tmp_path)
    plan = _plan(suite, alignment, now)
    with pytest.raises(AnalyzerEvaluationRejected, match="not active"):
        service.evaluate(suite, sets, alignment, plan, now=plan.deadline)
    assert store.connection.execute("SELECT COUNT(*) FROM analyzer_evaluations").fetchone()[0] == 0
    store.close()


def test_checkpoint_conflict_recovery_and_artifact_cleanup(tmp_path, now, monkeypatch):
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    plan = _plan(suite, alignment, now)
    service, store, artifacts = _service(tmp_path)
    monkeypatch.setattr(artifacts, "_write", lambda *_: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError, match="disk"):
        service.evaluate(suite, sets, alignment, plan, now=now)
    assert not list(artifacts.objects.iterdir())
    with pytest.raises(AnalyzerEvaluationRecoveryRequired, match="unfinished"):
        service.evaluate(suite, sets, alignment, plan, now=now)
    store.close()

    store = AnalyzerEvaluationStore(tmp_path / "conflict.db")
    store.claim(plan, now=now)
    changed = _plan(
        suite,
        alignment,
        now,
        key=plan.idempotency_key,
        limits=AnalyzerEvaluationLimits(max_matches=9),
    )
    with pytest.raises(AnalyzerEvaluationIdempotencyConflict):
        store.claim(changed, now=now)
    store.close()


def test_alignment_model_rejects_one_observation_matching_multiple_truths():
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    duplicate = alignment.matches[0].model_copy(update={"truth_id": TRUTH_B})
    with pytest.raises(ValidationError, match="cannot match multiple"):
        AnalyzerTruthAlignment.create(
            suite=suite,
            provenance=alignment.provenance,
            producer_id=alignment.producer_id,
            bindings=alignment.bindings,
            matches=(*alignment.matches, duplicate),
        )


def test_alignment_and_metric_models_reject_internal_ambiguity():
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    first = alignment.bindings[0]
    rebound = first.model_copy(update={"case_id": CASE_B, "analyzer": AnalyzerKind.TRIVY})
    with pytest.raises(ValidationError, match="may be bound only once"):
        AnalyzerTruthAlignment.create(
            suite=suite,
            provenance=alignment.provenance,
            producer_id=alignment.producer_id,
            bindings=(first, rebound),
        )

    metrics = evaluate_analyzer_metrics(
        suite,
        sets,
        alignment,
        limits=AnalyzerEvaluationLimits(),
        deadline=EvaluationDeadline(1),
    )
    raw = metrics.model_dump(mode="python")
    raw["false_positive_count"] = 1
    with pytest.raises(ValidationError, match="internally inconsistent"):
        type(metrics).model_validate(raw)


def test_cli_offline_evaluation_emits_safe_metrics_only(tmp_path, now, capsys):
    suite = _suite()
    sets = _sets()
    alignment = _alignment(suite, sets)
    plan = _plan(suite, alignment, now)
    suite_file = tmp_path / "suite.json"
    alignment_file = tmp_path / "alignment.json"
    plan_file = tmp_path / "plan.json"
    suite_file.write_text(suite.model_dump_json(), encoding="utf-8")
    alignment_file.write_text(alignment.model_dump_json(), encoding="utf-8")
    plan_file.write_text(plan.model_dump_json(), encoding="utf-8")
    set_files = []
    for index, item in enumerate(sets):
        path = tmp_path / f"set-{index}.json"
        path.write_text(item.model_dump_json(), encoding="utf-8")
        set_files.append(str(path))
    argv = [
        "analyzer-evaluate-offline",
        "--suite-file",
        str(suite_file),
        "--alignment-file",
        str(alignment_file),
        "--plan-file",
        str(plan_file),
        "--evaluation-db",
        str(tmp_path / "cli.db"),
        "--result-store",
        str(tmp_path / "results"),
    ]
    for path in set_files:
        argv.extend(("--observation-set-file", path))
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert "offline_explicit_analyzer_evaluation" in output
    assert '"truth_recall": 1.0' in output
    for forbidden in ("candidate_id", "finding_id", "message_digest", "rule_id"):
        assert forbidden not in output


def test_protocol_has_no_execution_or_workflow_authority():
    schema = json.dumps(AnalyzerEvaluationPlan.model_json_schema()).lower()
    for forbidden in (
        "credential",
        "token",
        "submission",
        "command",
        "docker",
        "candidate",
        "finding",
        "validation",
        "critic",
        "approval",
        "url",
    ):
        assert forbidden not in schema


def test_evaluation_store_context_manager_closes_connection(tmp_path):
    with AnalyzerEvaluationStore(tmp_path / "closed.db") as store:
        connection = store.connection
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
