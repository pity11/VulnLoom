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
            choice["message"]["tool_calls"] = []
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
