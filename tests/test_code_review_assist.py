"""Offline review acceptance: real service composition with fake DNS and transport."""

import json
from contextlib import contextmanager
from datetime import timedelta

import pytest
from test_openai_chat_profile_adapter import _prepare
from test_source_mapping import _snapshot

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
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.model_routing import ModelAgentRole, ModelEngine
from vulnloom.domain.models import ApprovalStatus
from vulnloom.domain.protocol import WorkerRole
from vulnloom.ingestion import IngestionService
from vulnloom.review_assist.models import CodeReviewOutcome
from vulnloom.review_assist.provider import (
    CodeReviewCodec,
    CodeReviewPlan,
    RoutedCodeReviewConfig,
    routed_review_config,
)
from vulnloom.review_assist.service import CodeReviewService, approval_request
from vulnloom.review_assist.source import select_snippet
from vulnloom.review_assist.store import CodeReviewStore, ReviewRecoveryRequired

SOURCE = (
    "# person@example.test\ndef normalize(value):\n"
    "    secret = 'super-private'\n    return value.strip()\n"
)


class Resolver:
    def resolve(self, host):
        assert host == "openai.cuc.edu.cn"
        return ("8.8.8.8",)


class RoutedResolver:
    def __init__(self, hostname):
        self.hostname = hostname

    def resolve(self, host):
        assert host == self.hostname
        return ("8.8.8.8",)


class Runner:
    def __init__(
        self,
        *,
        hostname="openai.cuc.edu.cn",
        request_model="cuc/deepseek",
        response_model="deepseek-v4-flash-0731",
    ):
        self.calls = 0
        self.hostname = hostname
        self.request_model = request_model
        self.response_model = response_model
        self.transform = lambda value: value
        self.wire_transform = lambda value: value
        self.error = None
        self.clean = True

    def exchange(self, **values):
        self.calls += 1
        self.request, self.credential = values["request_body"], values["credential"]
        assert values["hostname"] == self.hostname and values["port"] == 443
        assert values["request_path"] == "/v1/chat/completions"
        body = json.loads(self.request)
        assert set(body) == {"model", "messages", "max_tokens", "stream"}
        assert body["model"] == self.request_model
        assert body["stream"] is False and body["max_tokens"] == 512
        packet = json.loads(body["messages"][1]["content"])
        assert b"super-private" not in self.request and b"person@example.test" not in self.request
        self.packet = packet
        if self.error:
            raise self.error
        response = self.transform(
            {
                "source_digest": packet["source_digest"],
                "comments": [
                    {"category": "explanation", "text": "函数接收一个参数。", "lines": [2]}
                ],
            }
        )
        payload = self.wire_transform(
            {
                "id": "not-persisted",
                "object": "chat.completion",
                "created": 1,
                "model": self.response_model,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(response),
                            "reasoning_content": "never-persist-reasoning",
                        },
                    }
                ],
                "usage": {"prompt_tokens": 200, "completion_tokens": 80, "total_tokens": 280},
            }
        )
        self.response = bytearray(json.dumps(payload).encode())
        return ProviderProcessResult(
            response_body=self.response,
            latency_seconds=0.1,
            peer_ip="8.8.8.8",
            tls_version="TLSv1.3",
            process_terminated=self.clean,
        )


@contextmanager
def case(tmp_path, scope, now):
    snapshot, root, scope = _snapshot(tmp_path, scope, {"app.py": SOURCE})
    ingestion = IngestionService(root)
    policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="test-review",
        allowed_provider_ids=("cuc",),
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=120,
    )
    with (
        AgentProviderEgressStore(tmp_path / "egress") as egress,
        CodeReviewStore(tmp_path / "reviews.db") as store,
    ):
        authority = AgentProviderEgressAuthority(store=egress, issuer_policies=(policy,))
        grant = authority.issue(
            admission=cuc_probe_admission(),
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(seconds=120),
            deadline=now + timedelta(seconds=5),
            idempotency_key="review-grant",
        )
        runner = Runner()
        service = CodeReviewService(
            ingestion=ingestion,
            scope=scope,
            egress_store=egress,
            store=store,
            resolver=Resolver(),
            process_runner=runner,
            now=lambda: now,
        )
        plan = service.prepare(
            snapshot_id=snapshot.manifest.manifest_id,
            path="app.py",
            start_line=2,
            end_line=4,
            grant_id=grant.grant_id,
            deadline=now + timedelta(seconds=60),
            idempotency_key="review-one",
        )
        service.credentials = EnvironmentModelCredentialProvider(
            environment={"CUC_DEEPSEEK_API_KEY": "synthetic-review-key"},
            allowed_references=(plan.config.credential_reference,),
        )
        pending = approval_request(plan, scope)
        approval = pending.model_copy(
            update={"status": ApprovalStatus.GRANTED, "decided_by": "test-human", "decided_at": now}
        )
        yield service, plan, approval, runner, snapshot


@contextmanager
def routed_case(tmp_path, scope, now):
    snapshot, root, scope = _snapshot(tmp_path, scope, {"app.py": SOURCE})
    ingestion = IngestionService(root)
    preparation, profile, _, flow, _, credential_reference = _prepare(
        "alpha",
        "model-a",
        engine=ModelEngine.SOURCE_HUNT,
        agent_role=ModelAgentRole.REPORTER,
        worker_role=WorkerRole.REPORTER,
    )
    policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="test-routed-review",
        allowed_provider_ids=("alpha",),
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=120,
    )
    with (
        AgentProviderEgressStore(tmp_path / "routed-egress") as egress,
        CodeReviewStore(tmp_path / "routed-reviews.db") as store,
    ):
        grant = AgentProviderEgressAuthority(
            store=egress, issuer_policies=(policy,)
        ).issue(
            admission=preparation.transport_admission,
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(seconds=120),
            deadline=now + timedelta(seconds=5),
            idempotency_key="routed-review-grant",
        )

        def config_factory(*, grant_id, now, deadline):
            return routed_review_config(
                preparation=preparation,
                current_profile=profile,
                current_flow_snapshot=flow,
                credential_reference=credential_reference,
                grant_id=grant_id,
                egress_verifier=egress,
                accepted_response_models=("model-a",),
                now=now,
                deadline=deadline,
            )

        runner = Runner(
            hostname="alpha.example",
            request_model="model-a",
            response_model="model-a",
        )
        service = CodeReviewService(
            ingestion=ingestion,
            scope=scope,
            egress_store=egress,
            store=store,
            credential_provider=EnvironmentModelCredentialProvider(
                environment={"ALPHA_MODEL_KEY": "synthetic-routed-review-key"},
                allowed_references=(credential_reference,),
            ),
            resolver=RoutedResolver("alpha.example"),
            process_runner=runner,
            provider_config_factory=config_factory,
            now=lambda: now,
        )
        plan = service.prepare(
            snapshot_id=snapshot.manifest.manifest_id,
            path="app.py",
            start_line=2,
            end_line=4,
            grant_id=grant.grant_id,
            deadline=now + timedelta(seconds=60),
            idempotency_key="routed-review-one",
        )
        pending = approval_request(plan, scope)
        approval = pending.model_copy(
            update={
                "status": ApprovalStatus.GRANTED,
                "decided_by": "test-human",
                "decided_at": now,
            }
        )
        yield service, plan, approval, runner


def execute(service, plan, approval):
    return service.execute(plan=plan, approval=approval, path="app.py", allow_provider_network=True)


def test_review_success_and_read_only_replay(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, snapshot):
        result = execute(service, plan, approval)
        assert result.status == "review_ready", result.model_dump()
        assert result.requires_human_review and result.review.comments[0].lines == (2,)
        assert result.transport.cleanup_verified and result.transport.receipt_digest
        assert execute(service, plan, approval) == result and runner.calls == 1
        assert not any(runner.request) and not any(runner.response) and not any(runner.credential)
        stored = (tmp_path / "reviews.db").read_bytes()
        for forbidden in (
            b"super-private",
            b"person@example.test",
            b"synthetic-review-key",
            b"never-persist-reasoning",
            b"not-persisted",
        ):
            assert forbidden not in stored
        assert service.ingestion.load_snapshot(snapshot.manifest.manifest_id) == snapshot
        assert CodeReviewOutcome.model_validate_json(result.model_dump_json()) == result


def test_profile_routed_review_uses_selected_provider_and_preserves_cleanup(
    tmp_path, approved_scope, now
):
    with routed_case(tmp_path, approved_scope, now) as (service, plan, approval, runner):
        assert isinstance(plan.config, RoutedCodeReviewConfig)
        result = execute(service, plan, approval)

        assert result.status == "review_ready"
        assert result.transport.response_model == "model-a"
        assert result.transport.cleanup_verified
        assert execute(service, plan, approval) == result
        assert runner.calls == 1
        assert not any(runner.request)
        assert not any(runner.response)
        assert not any(runner.credential)
        stored = (tmp_path / "routed-reviews.db").read_bytes()
        for forbidden in (
            b"super-private",
            b"person@example.test",
            b"synthetic-routed-review-key",
            b"never-persist-reasoning",
            b"not-persisted",
        ):
            assert forbidden not in stored


@pytest.mark.parametrize("kind", ["identity", "timeout", "cleanup"])
def test_profile_routed_review_failure_paths(tmp_path, approved_scope, now, kind):
    with routed_case(tmp_path, approved_scope, now) as (service, plan, approval, runner):
        if kind == "identity":
            runner.response_model = "unadmitted-model"
        elif kind == "timeout":
            runner.error = ProviderProcessExecutionError("review_timeout", timed_out=True)
        else:
            runner.clean = False

        result = execute(service, plan, approval)

        assert result.status == ("timed_out" if kind == "timeout" else "rejected")
        assert result.transport.cleanup_verified is (kind != "cleanup")
        assert result.review is None
        assert execute(service, plan, approval) == result
        assert runner.calls == 1
        assert not any(runner.credential)


@pytest.mark.parametrize(
    "kind", ["outside", "bool", "missing", "tool", "secret", "source", "duplicate", "category"]
)
def test_review_output_rejections(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, _):

        def change(response):
            comment = response["comments"][0]
            if kind == "outside":
                comment["lines"] = [99]
            elif kind == "bool":
                comment["lines"] = [True]
            elif kind == "missing":
                comment["lines"] = []
            elif kind == "tool":
                response["tool_call"] = {"tool_id": "shell"}
            elif kind == "secret":
                comment["text"] = "Email person@example.test"
            elif kind == "source":
                response["source_digest"] = "f" * 64
            elif kind == "duplicate":
                comment["lines"] = [2, 2]
            else:
                comment["category"] = "confirmed_finding"
            return response

        runner.transform = change
        result = execute(service, plan, approval)
        assert result.status == "rejected" and result.review is None
        assert result.transport.cleanup_verified
        assert execute(service, plan, approval) == result and runner.calls == 1
        assert not any(runner.response)


@pytest.mark.parametrize("kind", ["tools", "identity", "truncated", "budget", "malformed"])
def test_review_wire_rejections(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, _):

        def change(payload):
            if kind == "tools":
                payload["choices"][0]["message"]["tool_calls"] = [{"name": "shell"}]
            elif kind == "identity":
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
                payload["choices"][0]["message"]["content"] = (
                    '{"source_digest":0,"source_digest":1}'
                )
            return payload

        runner.wire_transform = change
        result = execute(service, plan, approval)
        assert result.status == "rejected" and result.review is None
        assert result.transport.cleanup_verified and not any(runner.credential)


@pytest.mark.parametrize(
    "kind", ["pending", "digest", "actor", "expired", "future", "scope", "optin", "path"]
)
def test_review_preflight_denies_before_transport(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, _):
        updates = {
            "pending": {"status": ApprovalStatus.PENDING},
            "digest": {"action_digest": "e" * 64},
            "actor": {"decided_by": None},
            "expired": {"expires_at": now},
            "future": {"decided_at": now + timedelta(seconds=1)},
        }
        approval = approval.model_copy(update=updates.get(kind, {}))
        if kind == "scope":
            service.scope = service.scope.model_copy(update={"version": 2})
        with pytest.raises(ValueError):
            service.execute(
                plan=plan,
                approval=approval,
                path="../app.py" if kind == "path" else "app.py",
                allow_provider_network=kind != "optin",
            )
        assert runner.calls == 0
        assert service.store.db.execute("SELECT COUNT(*) FROM code_reviews").fetchone()[0] == 0


@pytest.mark.parametrize("kind", ["timeout", "unknown_error", "cleanup"])
def test_review_timeout_failure_and_cleanup(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, _):
        if kind == "timeout":
            runner.error = ProviderProcessExecutionError("review_timeout", timed_out=True)
        elif kind == "unknown_error":
            runner.error = RuntimeError("private-provider-error")
        else:
            runner.clean = False
        result = execute(service, plan, approval)
        assert result.status == ("timed_out" if kind == "timeout" else "rejected")
        assert result.transport.cleanup_verified is (kind == "timeout")
        assert execute(service, plan, approval) == result and runner.calls == 1
        assert b"private-provider-error" not in (tmp_path / "reviews.db").read_bytes()
        assert not any(runner.credential)


def test_review_interrupted_write_never_retries(tmp_path, approved_scope, now, monkeypatch):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, _):

        def fail(_):
            raise OSError("test-write-interrupted")

        monkeypatch.setattr(service.store, "complete", fail)
        with pytest.raises(OSError):
            execute(service, plan, approval)
        with pytest.raises(ReviewRecoveryRequired):
            execute(service, plan, approval)
        assert runner.calls == 1 and not any(runner.credential)


def test_review_tampered_result_rejected(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, _):
        result = execute(service, plan, approval)
        payload = result.model_dump(mode="json")
        payload["review"]["comments"][0]["lines"] = [500]
        payload["outcome_id"] = canonical_digest(
            {k: v for k, v in payload.items() if k != "outcome_id"}
        )
        service.store.db.execute("UPDATE code_reviews SET result_json=?", (json.dumps(payload),))
        service.store.db.commit()
        with pytest.raises(ValueError):
            execute(service, plan, approval)
        assert runner.calls == 1


def test_source_masks_multiline_fstrings_unicode_numbers_comments(tmp_path, approved_scope, now):
    source = (
        '名字 = "hidden" # private@example.test\nvalue = f"private-{123}"\n'
        'text = """first\nsecond"""\ncount = 987654321\n'
    )
    snapshot, root, scope = _snapshot(tmp_path, approved_scope, {"app.py": source})
    snippet = select_snippet(
        ingestion=IngestionService(root),
        snapshot=snapshot,
        scope=scope,
        path="app.py",
        start_line=1,
        end_line=5,
        now=now,
    )
    text = snippet.model_dump_json()
    assert [line.number for line in snippet.lines] == list(range(1, 6))
    for forbidden in ("hidden", "private", "123", "first", "second", "987654321"):
        assert forbidden not in "\n".join(line.text for line in snippet.lines)
    assert "名字" in text


@pytest.mark.parametrize("kind", ["traversal", "range", "syntax", "symlink", "size", "timeout"])
def test_source_selection_fail_closed(tmp_path, approved_scope, now, kind):
    source = SOURCE if kind != "syntax" else "def invalid(\n"
    snapshot, root, scope = _snapshot(tmp_path, approved_scope, {"app.py": source})
    if kind == "symlink":
        file = root / snapshot.root_ref / "app.py"
        file.parent.chmod(0o700)
        file.unlink()
        file.symlink_to(tmp_path / "outside.py")
    if kind == "size":
        entry = snapshot.manifest.files[0].model_copy(update={"size": 65537})
        snapshot = snapshot.model_copy(
            update={"manifest": snapshot.manifest.model_copy(update={"files": (entry,)})}
        )
    ticks = iter((0, 3))
    kwargs = {"clock": lambda: next(ticks)} if kind == "timeout" else {}
    with pytest.raises((ValueError, OSError, SyntaxError, TimeoutError)):
        select_snippet(
            ingestion=IngestionService(root),
            snapshot=snapshot,
            scope=scope,
            path="../app.py" if kind == "traversal" else "app.py",
            start_line=1,
            end_line=80 if kind == "range" else 4,
            now=now,
            **kwargs,
        )


def test_review_codec_request_denies_tool_capabilities(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as (service, plan, _, runner, _):
        _, envelope = service._message(plan)
        codec = CodeReviewCodec(plan.config.codec, snippet=plan.snippet)
        with pytest.raises(ValueError):
            codec.encode(
                model_registration=plan.config.registration,
                envelope=envelope.model_copy(update={"allowed_tools": frozenset({"shell"})}),
            )
        assert runner.calls == 0


@pytest.mark.parametrize("kind", ["changed_file", "changed_snippet", "expired", "revoked"])
def test_review_rechecks_source_and_authority(tmp_path, approved_scope, now, kind):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, snapshot):
        if kind == "changed_file":
            file = service.ingestion.root / snapshot.root_ref / "app.py"
            file.chmod(0o600)
            file.write_text(SOURCE + "\nchanged = True\n")
        elif kind == "changed_snippet":
            lines = plan.snippet.lines
            changed = plan.snippet.create(
                **{
                    **plan.snippet.model_dump(exclude={"snippet_id", "lines"}),
                    "lines": (lines[0].model_copy(update={"text": "unapproved_input"}), *lines[1:]),
                }
            )
            plan = CodeReviewPlan.create(
                **{
                    **plan.model_dump(exclude={"plan_id", "snippet", "config"}),
                    "snippet": changed,
                    "config": plan.config,
                }
            )
            approval = approval.model_copy(update={"action_digest": plan.plan_id})
        elif kind == "expired":
            service.now = lambda: now + timedelta(seconds=61)
        else:
            service.egress.connection.execute(
                "UPDATE provider_egress_issuances SET status='revoked'"
            )
            service.egress.connection.commit()
        with pytest.raises((ValueError, OSError)):
            execute(service, plan, approval)
        assert runner.calls == 0


def test_review_near_deadline_records_timeout_without_call(tmp_path, approved_scope, now):
    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, _):
        service.now = lambda: now + timedelta(seconds=51)
        result = execute(service, plan, approval)
        assert result.status == "timed_out" and result.transport.cleanup_verified
        assert runner.calls == 0


def test_review_codec_timeout(tmp_path, approved_scope, now):
    from vulnloom.agent_runtime.provider_codec import AgentProviderCodecTimedOut

    with case(tmp_path, approved_scope, now) as (service, plan, _, runner, _):
        _, envelope = service._message(plan)
        ticks = iter((0, 0.1, 3))
        codec = CodeReviewCodec(plan.config.codec, snippet=plan.snippet, clock=lambda: next(ticks))
        with pytest.raises(AgentProviderCodecTimedOut):
            codec.encode(model_registration=plan.config.registration, envelope=envelope)
        assert runner.calls == 0


def test_review_contract_cannot_enter_probe_path(tmp_path, approved_scope, now):
    from vulnloom.agent_runtime.provider_probe_models import ProviderProbeConfig

    with case(tmp_path, approved_scope, now) as (_, plan, _, runner, _):
        with pytest.raises(ValueError):
            ProviderProbeConfig.model_validate_json(plan.config.model_dump_json())
        assert runner.calls == 0


def test_review_cli_preview_prepare_approval_run_replay(
    tmp_path, approved_scope, now, monkeypatch, capsys
):
    from vulnloom.cli import main
    from vulnloom.review_assist import service as implementation
    from vulnloom.review_assist.models import CodeReviewSnippet

    with case(tmp_path, approved_scope, now) as (service, plan, approval, runner, snapshot):
        scope_path, plan_path = tmp_path / "scope.json", tmp_path / "plan.json"
        approval_path = tmp_path / "approval.json"
        scope_path.write_text(service.scope.model_dump_json())
        plan_path.write_text(plan.model_dump_json())
        approval_path.write_text(approval.model_dump_json())
        selection = [
            "--scope-file",
            str(scope_path),
            "--store",
            str(service.ingestion.root),
            "--source-path",
            "app.py",
            "--snapshot-id",
            snapshot.manifest.manifest_id,
            "--start-line",
            "2",
            "--end-line",
            "4",
        ]
        assert main(["code-review-preview", *selection]) == 0
        assert CodeReviewSnippet.model_validate_json(capsys.readouterr().out) == plan.snippet
        assert (
            main(
                [
                    "code-review-prepare",
                    *selection,
                    "--egress-store",
                    str(tmp_path / "egress"),
                    "--grant-id",
                    plan.config.registration.egress_grant_id,
                    "--idempotency-key",
                    "cli-prepared",
                ]
            )
            == 0
        )
        prepared = CodeReviewPlan.model_validate_json(capsys.readouterr().out)
        assert prepared.snippet == plan.snippet and runner.calls == 0
        assert (
            main(
                [
                    "code-review-approval-request",
                    "--scope-file",
                    str(scope_path),
                    "--plan-file",
                    str(plan_path),
                ]
            )
            == 0
        )
        pending = json.loads(capsys.readouterr().out)
        assert pending["status"] == "pending" and pending["action_digest"] == plan.plan_id
        assert runner.calls == 0
        original = implementation.SubprocessHttpsProviderAdapter

        def fake(**kwargs):
            return original(**{**kwargs, "resolver": Resolver(), "process_runner": runner})

        monkeypatch.setattr(implementation, "SubprocessHttpsProviderAdapter", fake)
        monkeypatch.setenv("CUC_DEEPSEEK_API_KEY", "synthetic-review-key")
        args = [
            "code-review-run",
            "--scope-file",
            str(scope_path),
            "--store",
            str(service.ingestion.root),
            "--source-path",
            "app.py",
            "--plan-file",
            str(plan_path),
            "--approval-file",
            str(approval_path),
            "--egress-store",
            str(tmp_path / "egress"),
            "--review-db",
            str(tmp_path / "reviews.db"),
        ]
        assert main(args) == 1
        assert json.loads(capsys.readouterr().out)["status"] == "rejected" and runner.calls == 0
        assert main([*args, "--allow-provider-network"]) == 0
        first = CodeReviewOutcome.model_validate_json(capsys.readouterr().out)
        assert main([*args, "--allow-provider-network"]) == 0
        assert CodeReviewOutcome.model_validate_json(capsys.readouterr().out) == first
        assert runner.calls == 1
