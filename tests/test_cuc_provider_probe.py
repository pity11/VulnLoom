"""CUC fixed PONG protocol: synthetic offline responses, no real keys or sockets."""

import json
from contextlib import contextmanager
from datetime import timedelta

import pytest

from vulnloom.adapters import EnvironmentModelCredentialProvider
from vulnloom.agent_runtime import (
    AgentProviderEgressAuthority,
    AgentProviderEgressIssuerPolicy,
    AgentProviderEgressPurpose,
    AgentProviderEgressStore,
    AgentProviderTransportMode,
    ProviderProcessResult,
)
from vulnloom.agent_runtime.provider_probe import (
    ProviderProbeService,
    create_cuc_probe_config,
    cuc_probe_admission,
)
from vulnloom.agent_runtime.provider_probe_cuc import (
    CucChatProbeCodec,
)
from vulnloom.agent_runtime.provider_probe_fixture import CUC_RESPONSE_MODELS, PROBE_DIGEST
from vulnloom.agent_runtime.provider_probe_models import (
    ProviderProbeConfig,
    ProviderProbePlan,
    ProviderProbeResult,
)
from vulnloom.agent_runtime.provider_probe_store import (
    ProviderProbeStore,
)
from vulnloom.domain.digests import canonical_digest


class Resolver:
    def resolve(self, hostname):
        assert hostname == "openai.cuc.edu.cn"
        return ("8.8.8.8",)


class Runner:
    def __init__(self):
        self.calls = 0
        self.payload = {
            "id": "test-cuc-response",
            "object": "chat.completion",
            "created": 1,
            "model": CUC_RESPONSE_MODELS[0],
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "PONG",
                        "reasoning_content": "discard-me",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10},
        }
        self.raw_override = None

    def exchange(self, **values):
        self.calls += 1
        assert values["hostname"] == "openai.cuc.edu.cn" and values["port"] == 443
        assert values["request_path"] == "/v1/chat/completions"
        assert json.loads(values["request_body"]) == {
            "model": "cuc/deepseek",
            "messages": [{"role": "user", "content": "Reply with exactly PONG."}],
            "stream": False,
            "max_tokens": 256,
        }
        self.credential = values["credential"]
        assert bytes(self.credential) == b"synthetic-cuc-key"
        self.request = values["request_body"]
        self.response = bytearray(self.raw_override or json.dumps(self.payload).encode())
        return ProviderProcessResult(
            response_body=self.response,
            latency_seconds=0.1,
            peer_ip="8.8.8.8",
            tls_version="TLSv1.3",
        )


@contextmanager
def _case(tmp_path, now):
    admission = cuc_probe_admission()
    policy = AgentProviderEgressIssuerPolicy.create(
        issuer_id="test-operator",
        allowed_provider_ids=("cuc",),
        allowed_modes=(AgentProviderTransportMode.LIVE_HTTPS,),
        max_lifetime_seconds=300,
    )
    with (
        AgentProviderEgressStore(tmp_path / "egress") as egress,
        ProviderProbeStore(tmp_path / "probe.db") as store,
    ):
        grant = AgentProviderEgressAuthority(store=egress, issuer_policies=(policy,)).issue(
            admission=admission,
            issuer_policy_id=policy.policy_id,
            purpose=AgentProviderEgressPurpose.MODEL_INFERENCE,
            now=now,
            expires_at=now + timedelta(seconds=120),
            deadline=now + timedelta(seconds=5),
            idempotency_key="test-grant",
        )
        config = create_cuc_probe_config(grant_id=grant.grant_id)
        runner = Runner()
        service = ProviderProbeService(
            config=config,
            egress_store=egress,
            store=store,
            credential_provider=EnvironmentModelCredentialProvider(
                environment={
                    "CUC_DEEPSEEK_API_KEY": "synthetic-cuc-key",
                    "SHIM_DUMMY_KEY": "wrong",
                },
                allowed_references=(config.credential_reference,),
            ),
            resolver=Resolver(),
            process_runner=runner,
            now=lambda: now,
        )
        plan = service.prepare(
            now=now, deadline=now + timedelta(seconds=60), idempotency_key="cuc-test"
        )
        yield service, plan, runner


@pytest.mark.parametrize("model", CUC_RESPONSE_MODELS)
def test_cuc_probe_strict_alias_success_cleanup_replay(tmp_path, now, model):
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["model"] = model
        result = service.execute(plan)
        assert result.status == "passed" and result.response_model == model
        assert result.cleanup_verified and result.process_started
        assert result.input_tokens == 8 and result.output_tokens == 2
        assert not any(runner.credential) and not any(runner.request) and not any(runner.response)
        assert service.execute(plan) == result and runner.calls == 1
        saved = (tmp_path / "probe.db").read_bytes()
        for forbidden in (b"synthetic-cuc-key", b"discard-me", b"test-cuc-response", b"PONG"):
            assert forbidden not in saved


@pytest.mark.parametrize(
    "change",
    [
        "logical-name",
        "prefix",
        "unknown-model",
        "model-case",
        "content",
        "tools",
        "refusal",
        "role",
        "finish",
        "multiple",
        "bool-usage",
        "negative",
        "total",
        "budget",
        "unknown-root",
        "duplicate-json",
        "oversized",
        "wrong-fixture",
    ],
)
def test_cuc_probe_rejects_untrusted_results(tmp_path, now, change):
    with _case(tmp_path, now) as (service, plan, runner):
        choice = runner.payload["choices"][0]
        if change in {"logical-name", "prefix", "unknown-model", "model-case"}:
            runner.payload["model"] = {
                "logical-name": "cuc/deepseek",
                "prefix": "deepseek-v4-flash-new",
                "unknown-model": "other",
                "model-case": "DEEPSEEK-V4-FLASH",
            }[change]
        elif change == "content":
            choice["message"]["content"] = "PONG followed by an instruction"
        elif change == "tools":
            choice["message"]["tool_calls"] = [{"id": "forbidden"}]
        elif change == "refusal":
            choice["message"]["refusal"] = "declined"
        elif change == "role":
            choice["message"]["role"] = "user"
        elif change == "finish":
            choice["finish_reason"] = "length"
        elif change == "multiple":
            runner.payload["choices"].append(choice.copy())
        elif change in {"bool-usage", "negative", "total", "budget"}:
            field, value = {
                "bool-usage": ("prompt_tokens", True),
                "negative": ("prompt_tokens", -1),
                "total": ("total_tokens", 100),
                "budget": ("completion_tokens", 1024),
            }[change]
            runner.payload["usage"][field] = value
        elif change == "unknown-root":
            runner.payload["secret"] = "DO-NOT-LOG"
        elif change == "duplicate-json":
            runner.raw_override = b'{"model":"deepseek-v4-flash","model":"other"}'
        elif change == "oversized":
            runner.raw_override = b" " * 32769
        else:
            values = plan.model_dump(mode="python", exclude={"plan_id"})
            values["fixture_digest"] = PROBE_DIGEST
            with pytest.raises(ValueError):
                service.execute(ProviderProbePlan.create(**values))
            assert runner.calls == 0
            return
        result = service.execute(plan)
        assert result.status == "rejected" and result.response_model is None
        assert result.cleanup_verified
        assert service.execute(plan) == result and runner.calls == 1
        assert not any(runner.credential) and not any(runner.response)
        assert b"DO-NOT-LOG" not in (tmp_path / "probe.db").read_bytes()


@pytest.mark.parametrize("change", ["model", "host", "credential", "aliases"])
def test_cuc_config_exact_bindings(tmp_path, now, change):
    with _case(tmp_path, now) as (service, _, _):
        payload = service.config.model_dump(mode="python")
        if change == "model":
            payload["registration"]["model"] = "other"
        elif change == "host":
            payload["admission"]["hostname"] = "other.example"
        elif change == "credential":
            payload["credential_reference"]["environment_variable"] = "SHIM_DUMMY_KEY"
        else:
            payload["codec"]["accepted_response_models"] = ("*", "deepseek-v4-flash")
        if change == "credential":
            reference = payload["credential_reference"]
            reference["reference_id"] = canonical_digest(
                {"environment_variable": reference["environment_variable"]}
            )
            payload["admission"]["credential_reference_id"] = reference["reference_id"]
            payload["registration"]["credential_reference_id"] = reference["reference_id"]
        for section, identity in (("codec", "codec_id"), ("admission", "admission_id")):
            values = payload[section]
            values[identity] = canonical_digest({k: v for k, v in values.items() if k != identity})
        payload["registration"]["transport_admission_id"] = payload["admission"]["admission_id"]
        payload["registration"]["provider_codec_id"] = payload["codec"]["codec_id"]
        values = payload["registration"]
        values["registration_id"] = canonical_digest(
            {k: v for k, v in values.items() if k != "registration_id"}
        )
        with pytest.raises(ValueError):
            ProviderProbeConfig.model_validate(payload)


def test_cuc_codec_timeout_and_fixed_message(tmp_path, now):
    from vulnloom.agent_runtime.provider_codec import AgentProviderCodecTimedOut

    with _case(tmp_path, now) as (service, plan, _):
        _, envelope = service._message(plan)
        clock = iter((0, 3))
        codec = CucChatProbeCodec(service.config.codec, clock=lambda: next(clock))
        with pytest.raises(AgentProviderCodecTimedOut):
            codec.encode(model_registration=service.config.registration, envelope=envelope)
        with pytest.raises(ValueError):
            CucChatProbeCodec(service.config.codec).encode(
                model_registration=service.config.registration,
                envelope=envelope.model_copy(
                    update={"allowed_tools": frozenset({"source.search"})}
                ),
            )
        clock = iter((0, 3))
        with pytest.raises(AgentProviderCodecTimedOut):
            CucChatProbeCodec(service.config.codec, clock=lambda: next(clock)).decode(
                bytearray(json.dumps(Runner().payload).encode()),
                model_registration=service.config.registration,
                latency_seconds=0.1,
            )


def test_m915_result_digest_backward_compatible(now):
    values = dict(
        plan_id="a" * 64,
        status="rejected",
        input_tokens=0,
        output_tokens=0,
        process_started=False,
        cleanup_verified=True,
        attempt_digest=None,
        receipt_digest=None,
        completed_at=now,
    )
    result = ProviderProbeResult(result_id=canonical_digest(values), **values)
    assert result.response_model is None
    assert ProviderProbeResult.create(**values, response_model=None) == result


def test_cuc_cli_config_is_read_only_and_requires_issued_grant(tmp_path, now, monkeypatch, capsys):
    from vulnloom import cli

    with _case(tmp_path, now) as (service, plan, runner):
        monkeypatch.setattr(cli, "utc_now", lambda: now)
        args = [
            "provider-cuc-probe-config",
            "--egress-store",
            str(tmp_path / "egress"),
            "--grant-id",
            plan.grant_id,
        ]
        assert cli.main(args) == 0
        assert ProviderProbeConfig.model_validate_json(capsys.readouterr().out) == service.config
        assert runner.calls == 0
        args[-1] = "0" * 64
        assert cli.main(args) == 1
        assert json.loads(capsys.readouterr().out)["error_code"] == "provider_probe_rejected"
        assert runner.calls == 0


def test_cuc_probe_cli_run_and_replay(tmp_path, now, monkeypatch, capsys):
    from vulnloom import cli
    from vulnloom.agent_runtime import provider_probe

    with _case(tmp_path, now) as (service, plan, runner):
        config_path, plan_path = tmp_path / "config.json", tmp_path / "plan.json"
        config_path.write_text(service.config.model_dump_json())
        plan_path.write_text(plan.model_dump_json())
        original = provider_probe.SubprocessHttpsProviderAdapter

        def fake_transport(**kwargs):
            kwargs.update(resolver=Resolver(), process_runner=runner)
            return original(**kwargs)

        monkeypatch.setattr(provider_probe, "SubprocessHttpsProviderAdapter", fake_transport)
        monkeypatch.setattr(cli, "utc_now", lambda: now)
        monkeypatch.setenv("CUC_DEEPSEEK_API_KEY", "synthetic-cuc-key")
        args = [
            "provider-probe-run",
            "--config-file",
            str(config_path),
            "--plan-file",
            str(plan_path),
            "--egress-store",
            str(tmp_path / "egress"),
            "--probe-db",
            str(tmp_path / "probe.db"),
            "--allow-provider-network",
        ]
        assert cli.main(args) == 0
        first = ProviderProbeResult.model_validate_json(capsys.readouterr().out)
        assert first.status == "passed" and first.response_model == CUC_RESPONSE_MODELS[0]
        assert cli.main(args) == 0
        assert ProviderProbeResult.model_validate_json(capsys.readouterr().out) == first
        assert runner.calls == 1


def test_cuc_probe_interrupted_completion_no_retry(tmp_path, now, monkeypatch):
    from vulnloom.agent_runtime.provider_probe_store import ProviderProbeRecoveryRequired

    with _case(tmp_path, now) as (service, plan, runner):

        def fail(_):
            raise OSError("synthetic ledger failure")

        monkeypatch.setattr(service.store, "complete", fail)
        with pytest.raises(OSError):
            service.execute(plan)
        assert runner.calls == 1 and not any(runner.credential) and not any(runner.response)
        with pytest.raises(ProviderProbeRecoveryRequired):
            service.execute(plan)
        assert runner.calls == 1
        assert not tuple(tmp_path.rglob("*.tmp"))


def test_cuc_completed_result_requires_served_model(tmp_path, now):
    from vulnloom.agent_runtime.provider_probe_store import ProviderProbeRecoveryRequired

    with _case(tmp_path, now) as (service, plan, runner):
        result = service.execute(plan)
        values = result.model_dump(mode="python", exclude={"result_id"})
        values["response_model"] = None
        tampered = ProviderProbeResult.create(**values)
        service.store.connection.execute(
            "UPDATE provider_probes SET result_json=?", (tampered.model_dump_json(),)
        )
        service.store.connection.commit()
        with pytest.raises(ProviderProbeRecoveryRequired):
            service.execute(plan)
        assert runner.calls == 1


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("model", "response_identity_mismatch"),
        ("content", "response_content_other"),
        ("usage", "usage_mismatch"),
        ("shape", "response_root_extra_fields"),
    ],
)
def test_cuc_safe_diagnostic_persistence(tmp_path, now, kind, expected):
    with _case(tmp_path, now) as (service, plan, runner):
        if kind == "model":
            runner.payload["model"] = "untrusted-secret-model"
        elif kind == "content":
            runner.payload["choices"][0]["message"]["content"] = "untrusted-secret-content"
        elif kind == "usage":
            runner.payload["usage"]["total_tokens"] = -1
        else:
            runner.payload["untrusted-secret-field"] = True
        result = service.execute(plan)
        assert result.status == "rejected"
        assert result.diagnostic.failure_stage == "response_codec"
        assert result.diagnostic.error_code == expected
        assert result.diagnostic.http_status == 200
        assert result.diagnostic.network_opened is True
        assert result.diagnostic.captured_response_bytes > 0
        assert result.cleanup_verified and not any(runner.response)
        assert service.execute(plan) == result and runner.calls == 1
        assert b"untrusted-secret" not in (tmp_path / "probe.db").read_bytes()


@pytest.mark.parametrize(
    "path,value,expected",
    [
        ((), [], "response_root_type"),
        (("created",), True, "response_root_metadata"),
        (("choices",), {}, "response_choices_type"),
        (("choices",), [], "response_choices_count"),
        (("choices", 0), None, "response_choice_type"),
        (("choices", 0), {}, "response_choice_missing_fields"),
        (("choices", 0, "private-field"), "secret", "response_choice_extra_fields"),
        (("choices", 0, "index"), True, "response_choice_index"),
        (("choices", 0, "finish_reason"), "length", "response_choice_finish_reason"),
        (("choices", 0, "logprobs"), {}, "response_choice_logprobs"),
        (("choices", 0, "message"), [], "response_message_type"),
        (("choices", 0, "message"), {}, "response_message_missing_fields"),
        (("choices", 0, "message", "private-field"), "secret", "response_message_extra_fields"),
        (("choices", 0, "message", "role"), "tool", "response_message_role"),
        (("choices", 0, "message", "refusal"), "secret", "response_message_refusal"),
        (("choices", 0, "message", "reasoning_content"), [], "response_message_reasoning_type"),
    ],
)
def test_cuc_fine_shape_diagnostics_are_sealed_and_body_free(tmp_path, now, path, value, expected):
    with _case(tmp_path, now) as (service, plan, runner):
        if not path:
            runner.payload = value
        else:
            parent = runner.payload
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = value
        result = service.execute(plan)
        assert result.status == "rejected"
        assert result.diagnostic.error_code == expected
        assert result.diagnostic.http_status == 200
        assert result.cleanup_verified and not any(runner.response)
        assert result.receipt_digest is None and result.response_model is None
        assert service.execute(plan) == result and runner.calls == 1
        saved = (tmp_path / "probe.db").read_bytes()
        assert b"private-field" not in saved and b"secret" not in saved


def test_cuc_fixed_shape_observations_do_not_copy_provider_fields(tmp_path, now):
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload.update(prompt_logprobs=None, kv_transfer_params={"secret": "value"})
        runner.payload["private-dynamic-name"] = "private-value"
        runner.payload["choices"][0]["message"].update(tool_calls=None, function_call=None)
        result = service.execute(plan)
        assert result.status == "rejected"
        assert result.diagnostic.shape_observations == (
            "root_kv_transfer_params_non_null",
            "root_prompt_logprobs_null",
            "root_other_fields",
            "message_function_call_null",
            "message_tool_calls_null",
        )
        assert service.execute(plan) == result and runner.calls == 1
        saved = (tmp_path / "probe.db").read_bytes()
        for forbidden in (b"private-dynamic-name", b"private-value", b"secret", b'"value"'):
            assert forbidden not in saved


def _vllm_empty_response(runner, *, empty=False):
    root = runner.payload
    root.update(
        prompt_logprobs=[] if empty else None,
        prompt_token_ids=[] if empty else None,
        prompt_text="" if empty else None,
        kv_transfer_params={} if empty else None,
        ec_transfer_params={} if empty else None,
        metrics={} if empty else None,
    )
    choice = root["choices"][0]
    choice.update(
        stop_reason="" if empty else None,
        token_ids=[] if empty else None,
        routed_experts="" if empty else None,
    )
    choice["message"].update(
        annotations={} if empty else None,
        audio={} if empty else None,
        function_call=None,
        tool_calls=[] if empty else None,
        reasoning="" if empty else None,
    )
    root["usage"]["prompt_tokens_details"] = {} if empty else None


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("model", CUC_RESPONSE_MODELS)
def test_vllm_explicit_empty_extensions_pass_with_sealed_observations(tmp_path, now, empty, model):
    with _case(tmp_path, now) as (service, plan, runner):
        _vllm_empty_response(runner, empty=empty)
        runner.payload["model"] = model
        result = service.execute(plan)
        assert result.status == "passed" and result.response_model == model
        assert result.receipt_digest and result.cleanup_verified
        assert len(result.diagnostic.shape_observations) == 15
        assert not any(runner.response) and not any(runner.credential)
        assert service.execute(plan) == result and runner.calls == 1
        saved = (tmp_path / "probe.db").read_bytes()
        for forbidden in (b"discard-me", b"test-cuc-response", b"synthetic-cuc-key"):
            assert forbidden not in saved


@pytest.mark.parametrize(
    "level,field",
    [
        ("root", "prompt_logprobs"),
        ("root", "prompt_token_ids"),
        ("root", "prompt_text"),
        ("root", "kv_transfer_params"),
        ("root", "ec_transfer_params"),
        ("root", "metrics"),
        ("choice", "stop_reason"),
        ("choice", "token_ids"),
        ("choice", "routed_experts"),
        ("message", "annotations"),
        ("message", "audio"),
        ("message", "function_call"),
        ("message", "tool_calls"),
        ("message", "reasoning"),
        ("usage", "prompt_tokens_details"),
    ],
)
@pytest.mark.parametrize("value", ["private-nonempty-value", {"private": True}, [0], 0, False])
def test_vllm_extensions_reject_payloads_and_falsey_wrong_types(tmp_path, now, level, field, value):
    with _case(tmp_path, now) as (service, plan, runner):
        _vllm_empty_response(runner)
        root = runner.payload
        destination = {
            "root": root,
            "choice": root["choices"][0],
            "message": root["choices"][0]["message"],
            "usage": root["usage"],
        }[level]
        destination[field] = value
        result = service.execute(plan)
        assert result.status == "rejected" and result.receipt_digest is None
        assert result.diagnostic.error_code == (
            "usage_details_mismatch" if level == "usage" else f"response_{level}_extension_nonempty"
        )
        assert result.cleanup_verified and not any(runner.response)
        assert service.execute(plan) == result and runner.calls == 1
        assert b"private" not in (tmp_path / "probe.db").read_bytes()


@pytest.mark.parametrize("level", ["root", "choice", "message", "usage"])
def test_vllm_compatibility_still_rejects_unknown_fields(tmp_path, now, level):
    with _case(tmp_path, now) as (service, plan, runner):
        _vllm_empty_response(runner)
        root = runner.payload
        destination = {
            "root": root,
            "choice": root["choices"][0],
            "message": root["choices"][0]["message"],
            "usage": root["usage"],
        }[level]
        destination["unknown-private-field"] = None
        result = service.execute(plan)
        assert result.status == "rejected" and result.receipt_digest is None
        assert level + "_other_fields" in result.diagnostic.shape_observations
        assert b"unknown-private-field" not in (tmp_path / "probe.db").read_bytes()


def test_vllm_change_requires_new_codec_identity():
    from vulnloom.agent_runtime.provider_probe_cuc import CucChatProbeCodecRegistration
    from vulnloom.agent_runtime.provider_probe_fixture import CUC_PROBE_TEXT

    previous = canonical_digest(
        {
            "contract": "vulnloom.cuc-chat-pong-probe",
            "version": 1,
            "request_model": "cuc/deepseek",
            "response_models": CUC_RESPONSE_MODELS,
            "path": "/v1/chat/completions",
            "request_text": CUC_PROBE_TEXT,
            "expected_content": "PONG",
            "stream": False,
            "tools": False,
            "usage": "bounded_nonnegative_integer_counts",
            "choice": "single_stop_assistant",
        }
    )
    values = CucChatProbeCodecRegistration.create().model_dump(mode="python", exclude={"codec_id"})
    assert values["implementation_digest"] != previous
    values["implementation_digest"] = previous
    with pytest.raises(ValueError):
        CucChatProbeCodecRegistration(codec_id=canonical_digest(values), **values)


@pytest.mark.parametrize(
    "content,classification,passed",
    [
        ("PONG", "response_content_exact", True),
        (" \nPONG\t", "response_content_trimmed_match", True),
        ("pong", "response_content_casefold_match", False),
        ("PONG.", "response_content_punctuation_match", True),
        ("PONG!", "response_content_punctuation_match", True),
        ("`PONG`", "response_content_punctuation_match", True),
        ("", "response_content_empty", False),
        ("  ", "response_content_other", False),
        ("prefix PONG private-suffix", "response_content_other", False),
        (None, "response_content_type", False),
        (["PONG"], "response_content_type", False),
    ],
)
def test_pong_content_closed_classification(tmp_path, now, content, classification, passed):
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["choices"][0]["message"]["content"] = content
        result = service.execute(plan)
        assert result.diagnostic.content_classification == classification
        assert (result.status == "passed") is passed
        assert bool(result.receipt_digest) is passed
        assert result.cleanup_verified and not any(runner.response)
        assert service.execute(plan) == result and runner.calls == 1
        assert b"private-suffix" not in (tmp_path / "probe.db").read_bytes()


@pytest.mark.parametrize(
    "extra,code",
    [
        ({"reasoning_tokens": 0}, None),
        ({"reasoning_tokens": 2}, None),
        ({"completion_tokens_details": None}, None),
        ({"completion_tokens_details": {"reasoning_tokens": 1}}, None),
        ({"prompt_tokens_details": {"cached_tokens": 8}}, None),
        ({"reasoning_tokens": True}, "usage_details_mismatch"),
        ({"reasoning_tokens": -1}, "usage_details_mismatch"),
        ({"reasoning_tokens": 3}, "usage_details_mismatch"),
        ({"reasoning_tokens": None}, "usage_details_mismatch"),
        ({"completion_tokens_details": {"reasoning_tokens": True}}, "usage_details_mismatch"),
        ({"completion_tokens_details": {"private-field": 0}}, "usage_details_mismatch"),
        ({"prompt_tokens_details": {"cached_tokens": 9}}, "usage_details_mismatch"),
        ({"prompt_tokens_details": {"cached_tokens": []}}, "usage_details_mismatch"),
        ({"cached_tokens": 0}, "usage_unknown_fields"),
        ({"private-usage-field": None}, "usage_unknown_fields"),
        ({"reasoning_tokens": 1, "total_tokens": 11}, "usage_total_mismatch"),
    ],
)
def test_cuc_bounded_usage_details(tmp_path, now, extra, code):
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["usage"].update(extra)
        result = service.execute(plan)
        assert result.diagnostic.error_code == code
        assert (result.status == "passed") is (code is None)
        assert result.cleanup_verified and not any(runner.response)
        assert b"private-field" not in (tmp_path / "probe.db").read_bytes()
        assert b"private-usage-field" not in (tmp_path / "probe.db").read_bytes()


@pytest.mark.parametrize(
    "extra,code",
    [
        ({"prompt_cache_hit_tokens": 0, "prompt_cache_miss_tokens": 8}, None),
        ({"prompt_cache_hit_tokens": 3, "prompt_cache_miss_tokens": 5}, None),
        ({"prompt_cache_hit_tokens": 8, "prompt_cache_miss_tokens": 0}, None),
        ({"prompt_cache_hit_tokens": 4}, None),
        ({"prompt_cache_miss_tokens": 4}, None),
        ({"prompt_cache_hit_tokens": 3, "prompt_cache_miss_tokens": 4}, "usage_cache_mismatch"),
        ({"prompt_cache_hit_tokens": True}, "usage_cache_mismatch"),
        ({"prompt_cache_miss_tokens": False}, "usage_cache_mismatch"),
        ({"prompt_cache_hit_tokens": -1}, "usage_cache_mismatch"),
        ({"prompt_cache_miss_tokens": 9}, "usage_cache_mismatch"),
        ({"prompt_cache_hit_tokens": 1.0}, "usage_cache_mismatch"),
        ({"prompt_cache_hit_tokens": None}, "usage_cache_mismatch"),
        ({"prompt_cache_miss_tokens": "8"}, "usage_cache_mismatch"),
        (
            {"prompt_cache_hit_tokens": 0, "prompt_cache_miss_tokens": 8, "other_cache": 0},
            "usage_unknown_fields",
        ),
        (
            {"prompt_cache_hit_tokens": 0, "prompt_cache_miss_tokens": 8, "total_tokens": 11},
            "usage_total_mismatch",
        ),
    ],
)
def test_deepseek_cache_usage_closed_and_consistent(tmp_path, now, extra, code):
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["choices"][0]["message"]["content"] = "PONG!"
        runner.payload["usage"].update(extra)
        result = service.execute(plan)
        assert result.diagnostic.error_code == code
        assert result.diagnostic.content_classification == "response_content_punctuation_match"
        assert (result.status == "passed") is (code is None)
        assert bool(result.receipt_digest) is (code is None)
        assert result.cleanup_verified and not any(runner.response)
        assert service.execute(plan) == result and runner.calls == 1
        assert b"other_cache" not in (tmp_path / "probe.db").read_bytes()


@pytest.mark.parametrize(
    "content",
    ["PONG?", "PONG!!", "PONG...", "pong!", "xPONG!", "```PONG```", "`PONG` extra", "PONG。"],
)
def test_pong_punctuation_allowlist_is_exact(tmp_path, now, content):
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["choices"][0]["message"]["content"] = content
        result = service.execute(plan)
        assert result.status == "rejected" and result.receipt_digest is None
        assert result.cleanup_verified and not any(runner.response)
        assert service.execute(plan) == result and runner.calls == 1


def test_usage_key_fingerprint_persisted_without_name_or_value(tmp_path, now):
    from hashlib import sha256

    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["usage"]["sensitive-unknown-field"] = {"sensitive-value": 1}
        result = service.execute(plan)
        observation = result.diagnostic.usage_key_observations[0]
        assert observation.name_sha256 == sha256(b"sensitive-unknown-field").hexdigest()
        assert observation.value_type == "dict"
        assert result.status == "rejected" and result.cleanup_verified
        assert service.execute(plan) == result and runner.calls == 1
        saved = (tmp_path / "probe.db").read_bytes()
        assert b"sensitive-unknown-field" not in saved and b"sensitive-value" not in saved


@pytest.mark.parametrize(
    "field,maximum",
    [
        ("time_per_output_token_ms", 10000),
        ("time_to_first_token_ms", 10000),
        ("tokens_per_second", 1000000),
    ],
)
@pytest.mark.parametrize(
    "case",
    [
        "zero",
        "maximum",
        "negative",
        "overflow",
        "boolean",
        "float",
        "null",
        "string",
        "dict",
        "float_zero",
        "fraction",
        "float_max",
        "nan",
        "infinity",
        "negative_infinity",
        "negative_fraction",
        "overflow_float",
        "huge_int",
    ],
)
def test_cuc_observed_metrics_have_finite_number_bounds(tmp_path, now, field, maximum, case):
    values = {
        "zero": 0,
        "maximum": maximum,
        "negative": -1,
        "overflow": maximum + 1,
        "boolean": True,
        "float": 1.0,
        "float_zero": 0.0,
        "fraction": 1.25,
        "float_max": float(maximum),
        "nan": float("nan"),
        "infinity": float("inf"),
        "negative_infinity": -float("inf"),
        "negative_fraction": -0.1,
        "overflow_float": maximum + 0.5,
        "huge_int": 10**400,
        "null": None,
        "string": "0",
        "dict": {},
    }
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["choices"][0]["message"]["content"] = "PONG."
        runner.payload["usage"][field] = values[case]
        result = service.execute(plan)
        passed = case in {"zero", "maximum", "float", "float_zero", "fraction", "float_max"}
        assert (result.status == "passed") is passed
        assert result.diagnostic.error_code == (None if passed else "usage_metrics_mismatch")
        assert bool(result.receipt_digest) is passed
        if not passed:
            assert result.diagnostic.metric_issues[0].field == field
        assert result.cleanup_verified and not any(runner.response)
        assert service.execute(plan) == result and runner.calls == 1


def test_cuc_metrics_do_not_relax_accounting_or_unknown_fields(tmp_path, now):
    with _case(tmp_path, now) as (service, plan, runner):
        runner.payload["usage"].update(
            time_to_first_token_ms=0,
            time_per_output_token_ms=0,
            tokens_per_second=0,
            total_tokens=11,
        )
        result = service.execute(plan)
        assert (
            result.status == "rejected" and result.diagnostic.error_code == "usage_total_mismatch"
        )
        assert result.receipt_digest is None
