"""Offline acceptance for the sealed Candidate Recommendation Provider chain."""

import json
from contextlib import contextmanager
from datetime import timedelta

import pytest
from test_candidate_generation import _graph

from vulnloom.adapters.model_credentials import EnvironmentModelCredentialProvider
from vulnloom.agent_runtime.provider_admission import (
    AgentProviderEgressAuthority,
    AgentProviderEgressIssuerPolicy,
    AgentProviderEgressPurpose,
    AgentProviderEgressStore,
)
from vulnloom.agent_runtime.provider_probe import cuc_probe_admission
from vulnloom.agent_runtime.provider_process import (
    ProviderProcessExecutionError,
    ProviderProcessResult,
)
from vulnloom.agent_runtime.transport import AgentProviderTransportMode
from vulnloom.analyzers import SourceGraphStore
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalStatus, CandidateState
from vulnloom.hypotheses import CandidateGenerator, CandidateSetStore
from vulnloom.recommendations import (
    CandidateRecommendationGenerationOutcome,
    CandidateRecommendationGenerationService,
    CandidateRecommendationGenerationStore,
    recommendation_generation_approval_request,
)
from vulnloom.recommendations.generation_store import (
    CandidateRecommendationGenerationRecoveryRequired,
)


class Resolver:
    def resolve(self, host):
        assert host == "openai.cuc.edu.cn"
        return ("8.8.8.8",)


class Runner:
    def __init__(self):
        self.calls = 0
        self.transform = lambda value: value
        self.wire_transform = lambda value: value
        self.error = None
        self.clean = True

    def exchange(self, **values):
        self.calls += 1
        self.request, self.credential = values["request_body"], values["credential"]
        body = json.loads(self.request)
        assert set(body) == {"model", "messages", "max_tokens", "stream"}
        assert body["stream"] is False and body["max_tokens"] == 512
        packet = json.loads(body["messages"][1]["content"])
        self.packet = packet
        projection = packet["projection"]
        if self.error:
            raise self.error
        response = self.transform(
            {
                "projection_id": projection["projection_id"],
                "priority": "high",
                "rationale": "静态信号值得优先人工核查，结论仍需验证。",
                "review_questions": ["入口与危险点之间是否存在未建模的约束？"],
                "cited_location_indexes": [0],
            }
        )
        payload = self.wire_transform(
            {
                "id": "not-persisted",
                "object": "chat.completion",
                "created": 1,
                "model": "deepseek-v4-flash-0731",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(response, ensure_ascii=False),
                            "reasoning_content": "not-persisted-reasoning",
                        },
                    }
                ],
                "usage": {"prompt_tokens": 300, "completion_tokens": 80, "total_tokens": 380},
            }
        )
        self.response = bytearray(json.dumps(payload, ensure_ascii=False).encode())
        return ProviderProcessResult(
            response_body=self.response,
            latency_seconds=0.1,
            peer_ip="8.8.8.8",
            tls_version="TLSv1.3",
            process_terminated=self.clean,
        )


@contextmanager
def case(tmp_path, approved_scope, now):
    graph, scope = _graph(
        tmp_path,
        approved_scope,
        {
            "private_app.py": """
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
    policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="test-recommendation",
        allowed_provider_ids=("cuc",),
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=120,
    )
    with (
        AgentProviderEgressStore(tmp_path / "egress") as egress,
        CandidateRecommendationGenerationStore(tmp_path / "generations.db") as store,
    ):
        grant = AgentProviderEgressAuthority(store=egress, issuer_policies=(policy,)).issue(
            admission=cuc_probe_admission(),
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(seconds=120),
            deadline=now + timedelta(seconds=5),
            idempotency_key="recommendation-generation-grant",
        )
        runner = Runner()
        service = CandidateRecommendationGenerationService(
            scope=scope,
            graph_store=graph_store,
            candidate_store=candidate_store,
            egress_store=egress,
            store=store,
            resolver=Resolver(),
            process_runner=runner,
            now=lambda: now,
        )
        plan = service.prepare(
            candidate_set_id=candidate_set.candidate_set_id,
            candidate_id=candidate.candidate_id,
            grant_id=grant.grant_id,
            deadline=now + timedelta(seconds=60),
            idempotency_key="recommendation-generation-one",
        )
        service.credentials = EnvironmentModelCredentialProvider(
            environment={"CUC_DEEPSEEK_API_KEY": "synthetic-generation-key"},
            allowed_references=(plan.config.credential_reference,),
        )
        approval = recommendation_generation_approval_request(plan, scope).model_copy(
            update={"status": ApprovalStatus.GRANTED, "decided_by": "human", "decided_at": now}
        )
        yield service, plan, approval, runner, candidate_set, candidate, store


def execute(service, plan, approval):
    return service.execute(plan=plan, approval=approval, allow_provider_network=True)


def test_generation_success_is_bound_read_only_and_replay_safe(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, candidate_set, candidate, _ = values
        original = candidate_set.model_dump_json()
        outcome = execute(service, plan, approval)
        assert outcome.status == "recommendation_ready"
        assert outcome.producer_content_binding_verified
        assert not outcome.eligible_for_validation_intake
        assert outcome.recommendation.candidate_id == candidate.candidate_id
        assert outcome.recommendation.producer_result_id == outcome.transport.result_id
        assert outcome.response.projection_id == plan.projection.projection_id
        assert execute(service, plan, approval) == outcome and runner.calls == 1
        assert service.candidates.load(candidate_set.candidate_set_id).model_dump_json() == original
        assert "private_app.py" not in json.dumps(runner.packet)
        assert not any(runner.request) and not any(runner.response) and not any(runner.credential)
        stored = (tmp_path / "generations.db").read_bytes()
        for forbidden in (
            b"synthetic-generation-key",
            b"not-persisted-reasoning",
            b"not-persisted",
        ):
            assert forbidden not in stored
        assert (
            CandidateRecommendationGenerationOutcome.model_validate_json(outcome.model_dump_json())
            == outcome
        )


@pytest.mark.parametrize(
    "kind", ["projection", "outside", "duplicate", "secret", "extra", "priority", "empty"]
)
def test_generation_rejects_invalid_model_content(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, *_ = values

        def change(response):
            if kind == "projection":
                response["projection_id"] = "f" * 64
            elif kind == "outside":
                response["cited_location_indexes"] = [99]
            elif kind == "duplicate":
                response["cited_location_indexes"] = [0, 0]
            elif kind == "secret":
                response["rationale"] = "password=abcdefghijklmnop"
            elif kind == "extra":
                response["tool_call"] = {"name": "shell"}
            elif kind == "priority":
                response["priority"] = "critical"
            else:
                response["rationale"] = ""
            return response

        runner.transform = change
        outcome = execute(service, plan, approval)
        assert outcome.status == "rejected"
        assert outcome.response is None and outcome.recommendation is None
        assert outcome.transport.cleanup_verified
        assert execute(service, plan, approval) == outcome and runner.calls == 1


@pytest.mark.parametrize("kind", ["tools", "model", "truncated", "budget", "malformed"])
def test_generation_rejects_invalid_wire(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, *_ = values

        def change(payload):
            if kind == "tools":
                payload["choices"][0]["message"]["tool_calls"] = [{"name": "shell"}]
            elif kind == "model":
                payload["model"] = "unknown"
            elif kind == "truncated":
                payload["choices"][0]["finish_reason"] = "length"
            elif kind == "budget":
                payload["usage"] = {
                    "prompt_tokens": 9000,
                    "completion_tokens": 80,
                    "total_tokens": 9080,
                }
            else:
                payload["choices"][0]["message"]["content"] = '{"projection_id":0,'
            return payload

        runner.wire_transform = change
        outcome = execute(service, plan, approval)
        assert outcome.status == "rejected" and outcome.recommendation is None
        assert outcome.transport.cleanup_verified and not any(runner.credential)


@pytest.mark.parametrize(
    "kind", ["pending", "digest", "actor", "future", "scope", "optin", "drift"]
)
def test_generation_preflight_rejects_before_transport(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, candidate_set, candidate, _ = values
        updates = {
            "pending": {"status": ApprovalStatus.PENDING},
            "digest": {"action_digest": "f" * 64},
            "actor": {"decided_by": None},
            "future": {"decided_at": now + timedelta(seconds=1)},
        }
        approval = approval.model_copy(update=updates.get(kind, {}))
        network = kind != "optin"
        if kind == "scope":
            service.scope = service.scope.model_copy(update={"version": 2})
        elif kind == "drift":
            changed = candidate.model_copy(update={"state": CandidateState.VALIDATED})
            service.candidates._read = lambda _: candidate_set.model_copy(
                update={"candidates": (changed,)}
            )
        with pytest.raises(ValueError):
            service.execute(plan=plan, approval=approval, allow_provider_network=network)
        assert runner.calls == 0


def test_generation_timeout_and_cleanup_failure_are_not_ready(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, *_ = values
        runner.error = ProviderProcessExecutionError("synthetic_timeout", timed_out=True)
        outcome = execute(service, plan, approval)
        assert outcome.status == "timed_out" and outcome.recommendation is None
        assert outcome.transport.cleanup_verified

    unclean = tmp_path / "unclean"
    unclean.mkdir()
    with case(unclean, approved_scope, now) as values:
        service, plan, approval, runner, *_ = values
        runner.clean = False
        outcome = execute(service, plan, approval)
        assert outcome.status == "rejected" and not outcome.transport.cleanup_verified


def test_generation_interruption_and_tamper_require_recovery(
    tmp_path, approved_scope, now, monkeypatch
):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, *_, store = values
        monkeypatch.setattr(store, "complete", lambda _: (_ for _ in ()).throw(OSError("fail")))
        with pytest.raises(OSError):
            execute(service, plan, approval)
        with pytest.raises(CandidateRecommendationGenerationRecoveryRequired):
            execute(service, plan, approval)
        assert runner.calls == 1


def test_generation_completed_tamper_requires_recovery(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, *_, store = values
        execute(service, plan, approval)
        store.db.execute(
            "UPDATE candidate_recommendation_generations SET result_json=? WHERE plan_id=?",
            ('{"outcome_id":"' + "0" * 64 + '"}', plan.plan_id),
        )
        store.db.commit()
        with pytest.raises(CandidateRecommendationGenerationRecoveryRequired):
            execute(service, plan, approval)
        assert runner.calls == 1


def test_generation_semantic_binding_tamper_requires_recovery(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as values:
        service, plan, approval, runner, *_, store = values
        outcome = execute(service, plan, approval)
        payload = outcome.model_dump(mode="json")
        payload["response"]["cited_location_indexes"] = [1]
        payload["outcome_id"] = canonical_digest(
            {key: value for key, value in payload.items() if key != "outcome_id"}
        )
        store.db.execute(
            "UPDATE candidate_recommendation_generations SET result_json=? WHERE plan_id=?",
            (json.dumps(payload), plan.plan_id),
        )
        store.db.commit()
        with pytest.raises(CandidateRecommendationGenerationRecoveryRequired):
            execute(service, plan, approval)
        assert runner.calls == 1


def test_generation_cli_preview_is_local_and_minimal(
    tmp_path, approved_scope, now, monkeypatch, capsys
):
    from vulnloom import cli
    from vulnloom.recommendations import generation_cli

    with case(tmp_path, approved_scope, now) as values:
        service, _, _, runner, candidate_set, candidate, _ = values
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(service.scope.model_dump_json())
        monkeypatch.setattr(generation_cli, "utc_now", lambda: now)
        assert (
            cli.main(
                [
                    "candidate-recommendation-preview",
                    "--scope-file",
                    str(scope_file),
                    "--graph-store",
                    str(tmp_path / "graphs"),
                    "--candidate-store",
                    str(tmp_path / "candidates"),
                    "--candidate-set-id",
                    candidate_set.candidate_set_id,
                    "--candidate-id",
                    str(candidate.candidate_id),
                ]
            )
            == 0
        )
        output = capsys.readouterr().out
        assert '"disclosure_profile": "digests-lines-static-signals-v1"' in output
        assert "private_app.py" not in output
        assert runner.calls == 0
