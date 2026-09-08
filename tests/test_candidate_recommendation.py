"""A model recommendation can prioritize, but cannot author or mutate a Candidate."""

import json
from contextlib import contextmanager
from datetime import timedelta
from uuid import uuid4

import pytest
from test_candidate_generation import _graph

from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.analyzers import SourceGraphStore
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, SourceLocation
from vulnloom.hypotheses import CandidateGenerator, CandidateSetStore
from vulnloom.recommendations import (
    CandidateRecommendation,
    CandidateRecommendationAdmissionService,
    CandidateRecommendationStore,
    RecommendationPriority,
)
from vulnloom.recommendations.service import (
    CandidateRecommendationRejected,
    CandidateRecommendationTimedOut,
)
from vulnloom.recommendations.store import CandidateRecommendationRecoveryRequired
from vulnloom.validation.models import candidate_content_digest


@contextmanager
def case(tmp_path, approved_scope, now):
    graph, scope = _graph(
        tmp_path,
        approved_scope,
        {
            "app.py": """
from flask import Flask
app = Flask(__name__)
@app.get('/file/<name>')
def download(name):
    return open(name).read()
""",
        },
    )
    candidate_set = CandidateGenerator().generate(graph, scope=scope, now=now)
    candidate = candidate_set.candidates[0]
    graph_store = SourceGraphStore(tmp_path / "graphs")
    candidate_store = CandidateSetStore(tmp_path / "candidates")
    graph_store.put(graph)
    candidate_store.put(candidate_set)
    with CandidateRecommendationStore(tmp_path / "recommendations.db") as store:
        service = CandidateRecommendationAdmissionService(
            scope=scope,
            graph_store=graph_store,
            candidate_store=candidate_store,
            store=store,
        )
        provider = ProviderProbeResult.create(
            plan_id="1" * 64,
            status="passed",
            input_tokens=100,
            output_tokens=40,
            process_started=True,
            cleanup_verified=True,
            attempt_digest="2" * 64,
            receipt_digest="3" * 64,
            completed_at=now,
            response_model="deepseek-v4-flash-0731",
        )
        recommendation = CandidateRecommendation.create(
            candidate_set_id=candidate_set.candidate_set_id,
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate_content_digest(candidate),
            source_graph_id=graph.graph_id,
            target_id=candidate.target_id,
            target_version_digest=canonical_digest(candidate.target_version),
            scope_id=scope.scope_id,
            scope_version=scope.version,
            supporting_signal_ids=candidate.signal_ids,
            cited_locations=(candidate.entry_point, candidate.sink),
            priority=RecommendationPriority.HIGH,
            rationale="静态数据流值得优先人工核查，但尚未完成动态验证。",
            review_questions=("路径参数是否经过规范化和根目录约束？",),
            producer_result_id=provider.result_id,
            producer_plan_id=provider.plan_id,
            producer_receipt_digest=provider.receipt_digest,
            created_at=now,
        )
        yield service, recommendation, provider, candidate_set, candidate, graph, store


def prepare(service, recommendation, provider, now):
    return service.prepare(
        recommendation,
        provider,
        now=now,
        deadline=now + timedelta(seconds=60),
        idempotency_key="recommendation-one",
    )


def test_admission_keeps_candidate_unchanged_and_replays(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as values:
        service, recommendation, provider, _, candidate, _, store = values
        original = candidate.model_dump_json()
        plan = prepare(service, recommendation, provider, now)
        record = service.admit(plan, recommendation, provider, now=now)
        assert record.candidate_id == candidate.candidate_id
        assert record.candidate_digest == candidate_content_digest(candidate)
        assert record.candidate_unchanged and record.requires_human_selection
        assert not record.producer_content_binding_verified
        assert not record.eligible_for_validation_intake
        assert candidate.model_dump_json() == original
        assert service.admit(plan, recommendation, provider, now=now) == record
        row = store.connection.execute("SELECT state FROM candidate_recommendations").fetchone()
        assert row["state"] == "completed"


@pytest.mark.parametrize(
    "change",
    [
        "candidate",
        "candidate-digest",
        "candidate-state",
        "candidate-set",
        "graph",
        "target",
        "target-version",
        "scope",
        "scope-version",
        "signals",
        "locations",
        "provider-status",
        "cleanup",
        "receipt",
        "result",
        "provider-plan",
        "provider-receipt",
        "provider-time",
    ],
)
def test_admission_rejects_untrusted_bindings(tmp_path, approved_scope, now, change):
    with case(tmp_path, approved_scope, now) as values:
        service, rec, provider, candidate_set, candidate, graph, store = values
        if change == "candidate":
            rec = rec.model_copy(update={"candidate_id": uuid4()})
        elif change == "candidate-digest":
            rec = rec.model_copy(update={"candidate_digest": "f" * 64})
        elif change == "candidate-state":
            changed = candidate.model_copy(update={"state": CandidateState.VALIDATED})
            changed_set = candidate_set.model_copy(update={"candidates": (changed,)})
            service.candidate_store._read = lambda _: changed_set
        elif change == "candidate-set":
            rec = rec.model_copy(update={"candidate_set_id": "f" * 64})
        elif change == "graph":
            rec = rec.model_copy(update={"source_graph_id": "f" * 64})
        elif change == "target":
            rec = rec.model_copy(update={"target_id": uuid4()})
        elif change == "target-version":
            rec = rec.model_copy(update={"target_version_digest": "f" * 64})
        elif change == "scope":
            rec = rec.model_copy(update={"scope_id": uuid4()})
        elif change == "scope-version":
            rec = rec.model_copy(update={"scope_version": rec.scope_version + 1})
        elif change == "signals":
            rec = rec.model_copy(update={"supporting_signal_ids": ("f" * 64,)})
        elif change == "locations":
            rec = rec.model_copy(
                update={"cited_locations": (SourceLocation(path="other.py", line=1),)}
            )
        elif change == "provider-status":
            provider = ProviderProbeResult.create(
                **{
                    **provider.model_dump(exclude={"result_id", "status", "receipt_digest"}),
                    "status": "rejected",
                    "receipt_digest": None,
                }
            )
        elif change == "cleanup":
            provider = provider.model_copy(update={"cleanup_verified": False})
        elif change == "receipt":
            provider = provider.model_copy(update={"receipt_digest": None})
        elif change == "result":
            rec = rec.model_copy(update={"producer_result_id": "f" * 64})
        elif change == "provider-plan":
            rec = rec.model_copy(update={"producer_plan_id": "f" * 64})
        elif change == "provider-receipt":
            rec = rec.model_copy(update={"producer_receipt_digest": "f" * 64})
        else:
            provider = provider.model_copy(update={"completed_at": now + timedelta(seconds=1)})
        with pytest.raises(CandidateRecommendationRejected):
            prepare(service, rec, provider, now)
        assert (
            store.connection.execute("SELECT COUNT(*) FROM candidate_recommendations").fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("change", ["draft", "expired", "future-recommendation", "plan", "late"])
def test_admission_scope_plan_and_time_fail_closed(tmp_path, approved_scope, now, change):
    with case(tmp_path, approved_scope, now) as values:
        service, recommendation, provider, _, _, _, store = values
        if change == "draft":
            service.scope = service.scope.model_copy(update={"state": "draft"})
            with pytest.raises(CandidateRecommendationRejected):
                prepare(service, recommendation, provider, now)
        elif change == "expired":
            with pytest.raises(CandidateRecommendationRejected):
                prepare(service, recommendation, provider, service.scope.valid_until)
        elif change == "future-recommendation":
            recommendation = recommendation.model_copy(
                update={"created_at": now + timedelta(seconds=1)}
            )
            with pytest.raises(CandidateRecommendationRejected):
                prepare(service, recommendation, provider, now)
        else:
            plan = prepare(service, recommendation, provider, now)
            if change == "plan":
                plan = plan.model_copy(update={"candidate_digest": "f" * 64})
                with pytest.raises((ValueError, CandidateRecommendationRejected)):
                    service.admit(plan, recommendation, provider, now=now)
            else:
                with pytest.raises(CandidateRecommendationTimedOut):
                    service.admit(plan, recommendation, provider, now=plan.deadline)
        assert (
            store.connection.execute("SELECT COUNT(*) FROM candidate_recommendations").fetchone()[0]
            == 0
        )


def test_admission_timeout_before_write(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as values:
        service, recommendation, provider, _, _, _, store = values
        ticks = iter((0.0, 3.0))
        service.clock = lambda: next(ticks)
        with pytest.raises(CandidateRecommendationTimedOut):
            prepare(service, recommendation, provider, now)
        assert (
            store.connection.execute("SELECT COUNT(*) FROM candidate_recommendations").fetchone()[0]
            == 0
        )


def test_interrupted_completion_requires_recovery(tmp_path, approved_scope, now, monkeypatch):
    with case(tmp_path, approved_scope, now) as values:
        service, recommendation, provider, _, _, _, store = values
        plan = prepare(service, recommendation, provider, now)

        def fail(_):
            raise OSError("synthetic completion failure")

        monkeypatch.setattr(store, "complete", fail)
        with pytest.raises(OSError):
            service.admit(plan, recommendation, provider, now=now)
        with pytest.raises(CandidateRecommendationRecoveryRequired):
            service.admit(plan, recommendation, provider, now=now)
        assert (
            store.connection.execute("SELECT state FROM candidate_recommendations").fetchone()[0]
            == "started"
        )


def test_completed_record_tamper_is_rejected(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as values:
        service, recommendation, provider, _, _, _, store = values
        plan = prepare(service, recommendation, provider, now)
        record = service.admit(plan, recommendation, provider, now=now)
        payload = record.model_dump(mode="json")
        payload["candidate_digest"] = "f" * 64
        payload["record_id"] = canonical_digest(
            {key: value for key, value in payload.items() if key != "record_id"}
        )
        store.connection.execute(
            "UPDATE candidate_recommendations SET record_json=?", (json.dumps(payload),)
        )
        store.connection.commit()
        with pytest.raises(CandidateRecommendationRecoveryRequired):
            service.admit(plan, recommendation, provider, now=now)


@pytest.mark.parametrize(
    "field,value",
    [
        ("rationale", " password=secret"),
        ("rationale", "contains\u200bhidden"),
        ("review_questions", ("password=abcdefghijklmnop",)),
        ("supporting_signal_ids", ("f" * 64, "f" * 64)),
        ("producer_protocol_digest", "f" * 64),
    ],
)
def test_recommendation_contract_rejects_unsafe_content(
    tmp_path, approved_scope, now, field, value
):
    with case(tmp_path, approved_scope, now) as values:
        _, recommendation, _, _, _, _, _ = values
        payload = recommendation.model_dump(exclude={"recommendation_id"})
        payload["cited_locations"] = recommendation.cited_locations
        payload[field] = value
        with pytest.raises(ValueError):
            CandidateRecommendation.create(**payload)


def test_recommendation_cli_prepare_admit_and_replay(
    tmp_path, approved_scope, now, monkeypatch, capsys
):
    from vulnloom import cli

    with case(tmp_path, approved_scope, now) as values:
        service, recommendation, provider, _, _, _, store = values
        scope_path = tmp_path / "scope.json"
        recommendation_path = tmp_path / "recommendation.json"
        provider_path = tmp_path / "provider.json"
        plan_path = tmp_path / "plan.json"
        scope_path.write_text(service.scope.model_dump_json())
        recommendation_path.write_text(recommendation.model_dump_json())
        provider_path.write_text(provider.model_dump_json())
        monkeypatch.setattr(cli, "utc_now", lambda: now)
        from vulnloom.recommendations import cli as recommendation_cli

        monkeypatch.setattr(recommendation_cli, "utc_now", lambda: now)
        common = [
            "--scope-file",
            str(scope_path),
            "--recommendation-file",
            str(recommendation_path),
            "--provider-result-file",
            str(provider_path),
            "--graph-store",
            str(service.graph_store.root),
            "--candidate-store",
            str(service.candidate_store.root),
            "--recommendation-db",
            str(tmp_path / "cli-recommendations.db"),
        ]
        assert (
            cli.main(
                [
                    "candidate-recommendation-prepare-local",
                    *common,
                    "--idempotency-key",
                    "cli-recommendation",
                ]
            )
            == 0
        )
        plan = service.prepare(
            recommendation,
            provider,
            now=now,
            deadline=now + timedelta(seconds=120),
            idempotency_key="cli-recommendation",
        )
        assert json.loads(capsys.readouterr().out)["plan_id"] == plan.plan_id
        plan_path.write_text(plan.model_dump_json())
        command = [
            "candidate-recommendation-admit-local",
            *common,
            "--plan-file",
            str(plan_path),
        ]
        assert cli.main(command) == 0
        first = json.loads(capsys.readouterr().out)
        assert first["candidate_unchanged"] and first["requires_human_selection"]
        assert cli.main(command) == 0
        assert json.loads(capsys.readouterr().out) == first
        assert (
            store.connection.execute("SELECT COUNT(*) FROM candidate_recommendations").fetchone()[0]
            == 0
        )


def test_recommendation_cli_safe_rejection(tmp_path, approved_scope, now, monkeypatch, capsys):
    from vulnloom import cli

    with case(tmp_path, approved_scope, now) as values:
        service, recommendation, provider, _, _, _, _ = values
        files = {}
        for name, model in (
            ("scope", service.scope),
            ("recommendation", recommendation),
            ("provider", provider),
        ):
            path = tmp_path / f"{name}.json"
            path.write_text(model.model_dump_json())
            files[name] = path
        from vulnloom.recommendations import cli as recommendation_cli

        monkeypatch.setattr(recommendation_cli, "utc_now", lambda: now)
        result = cli.main(
            [
                "candidate-recommendation-prepare-local",
                "--scope-file",
                str(files["scope"]),
                "--recommendation-file",
                str(files["recommendation"]),
                "--provider-result-file",
                str(files["provider"]),
                "--graph-store",
                str(service.graph_store.root),
                "--candidate-store",
                str(service.candidate_store.root),
                "--recommendation-db",
                str(tmp_path / "rejected.db"),
                "--idempotency-key",
                "bad-window",
                "--ttl-seconds",
                "999",
            ]
        )
        assert result == 1
        assert json.loads(capsys.readouterr().out) == {
            "status": "rejected",
            "error_code": "recommendation_rejected",
        }
