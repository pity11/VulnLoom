"""No-socket provider smoke tests over the production transport composition."""

import json
from contextlib import contextmanager
from datetime import timedelta

import pytest
from test_agent_transport import _live_fixture, _ProcessRunner, _Resolver

from vulnloom.agent_runtime import AgentModelRegistration, AgentProviderTransportLimits
from vulnloom.agent_runtime.provider_probe import ProviderProbeService
from vulnloom.agent_runtime.provider_probe_models import (
    PROBE_SUMMARY,
    PROBE_TEXT,
    ProviderProbeConfig,
    ProviderProbePlan,
    ProviderProbeResult,
)
from vulnloom.agent_runtime.provider_probe_store import (
    ProviderProbeRecoveryRequired,
    ProviderProbeStore,
)
from vulnloom.agent_runtime.provider_process import ProviderProcessExecutionError
from vulnloom.domain.protocol import WorkerRole


class ProbeRunner(_ProcessRunner):
    def exchange(self, **values):
        self.request_buffer = values["request_body"]
        self.credential_buffer = values["credential"]
        assert PROBE_TEXT.encode() in self.request_buffer
        assert b"raw-context-secret" not in self.request_buffer
        assert b"source.search" not in self.request_buffer
        result = super().exchange(**values)
        body = json.loads(result.response_body)
        payload = json.loads(body["output"][0]["content"][0]["text"])
        payload["summary_digest"] = PROBE_SUMMARY
        payload.update(getattr(self, "payload_updates", {}))
        body["output"][0]["content"][0]["text"] = json.dumps(payload)
        result.response_body[:] = json.dumps(body).encode()
        self.response_buffer = result.response_body
        return result


@contextmanager
def _case(tmp_path, now):
    fixture = _live_fixture(
        tmp_path,
        now,
        limits=AgentProviderTransportLimits(
            max_request_bytes=32768,
            max_response_bytes=32768,
            timeout_seconds=10,
            max_requests_per_minute=1,
        ),
    )
    old = fixture["registration"]
    registration = AgentModelRegistration.create_subprocess_https(
        provider_id=old.provider_id,
        model=old.model,
        adapter_digest=old.adapter_digest,
        credential_reference_id=old.credential_reference_id,
        transport_admission_id=old.transport_admission_id,
        egress_grant_id=old.egress_grant_id,
        provider_codec_id=old.provider_codec_id,
        supported_roles=(WorkerRole.REPORTER,),
        max_output_tokens=256,
    )
    config = ProviderProbeConfig(
        registration=registration,
        admission=fixture["admission"],
        credential_reference=fixture["credential_reference"],
        codec=fixture["provider_codec"].registration,
    )
    resolver, runner = _Resolver(), ProbeRunner(fixture)
    with ProviderProbeStore(tmp_path / "probes.db") as store:
        service = ProviderProbeService(
            config=config,
            egress_store=fixture["egress_store"],
            credential_provider=fixture["provider"],
            store=store,
            resolver=resolver,
            process_runner=runner,
            now=lambda: now,
        )
        plan = service.prepare(
            now=now, deadline=now + timedelta(seconds=60), idempotency_key="probe-one"
        )
        try:
            yield service, plan, fixture, resolver, runner
        finally:
            fixture["egress_store"].close()


def test_provider_probe_success_replay(tmp_path, now):
    with _case(tmp_path, now) as (service, plan, fixture, resolver, runner):
        result = service.execute(plan)
        assert result.status == "passed" and result.cleanup_verified
        assert result.attempt_digest and result.receipt_digest and result.process_started
        assert result.output_tokens == 2
        assert not any(runner.request_buffer) and not any(runner.credential_buffer)
        assert not any(runner.response_buffer)
        assert service.execute(plan) == result
        assert len(runner.calls) == len(resolver.calls) == 1
        persisted = (tmp_path / "probes.db").read_bytes()
        for forbidden in (fixture["secret"], PROBE_TEXT, "raw-context-secret", "resp_test"):
            assert forbidden.encode() not in persisted
        new = service.prepare(now=now, deadline=plan.deadline, idempotency_key="another")
        with pytest.raises(ValueError, match="consumed"):
            service.execute(new)
        assert len(runner.calls) == 1


@pytest.mark.parametrize("change", ["deadline", "future", "plan", "grant", "revoked"])
def test_probe_preflight_no_dns_or_credential(tmp_path, now, change):
    with _case(tmp_path, now) as (service, plan, fixture, resolver, runner):
        if change == "deadline":
            service.now = lambda: plan.deadline
        elif change == "future":
            service.now = lambda: now - timedelta(seconds=1)
        elif change == "plan":
            values = plan.model_dump(mode="python", exclude={"plan_id", "fixture_digest"})
            values["config_digest"] = "0" * 64
            plan = ProviderProbePlan.create(**values)
        elif change == "grant":
            fixture["egress_store"].connection.execute("DELETE FROM provider_egress_issuances")
            fixture["egress_store"].connection.commit()
        else:
            fixture["egress_authority"].revoke(
                grant_id=plan.grant_id,
                issuer_policy_id=fixture["issuer_policy"].policy_id,
                reason_digest="a" * 64,
                now=now,
                deadline=now + timedelta(seconds=5),
                idempotency_key="revoke-probe",
            )
        with pytest.raises((ValueError, RuntimeError)):
            service.execute(plan)
        assert not resolver.calls and not runner.calls
        assert (
            service.store.connection.execute("SELECT count(*) FROM provider_probes").fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "change", ["dns", "credential", "timeout", "secret_error", "wrong_reply", "late"]
)
def test_probe_failed_attempt_consumed_and_cleaned(tmp_path, now, change):
    with _case(tmp_path, now) as (service, plan, fixture, resolver, runner):
        if change == "dns":
            resolver.addresses = ("127.0.0.1",)
        elif change == "credential":
            fixture["provider"]._environment = {}
        elif change == "timeout":
            runner.error = ProviderProcessExecutionError("probe_timeout", timed_out=True)
        elif change == "secret_error":
            runner.error = RuntimeError("api_key=DO-NOT-LOG")
        elif change == "wrong_reply":
            runner.payload_updates = {"summary_digest": "0" * 64}
        else:
            service.now = lambda: plan.deadline - timedelta(seconds=1)
        result = service.execute(plan)
        assert result.status == ("timed_out" if change in {"timeout", "late"} else "rejected")
        assert result.cleanup_verified is (change != "secret_error")
        calls = len(runner.calls)
        assert service.execute(plan) == result and len(runner.calls) == calls
        assert b"DO-NOT-LOG" not in (tmp_path / "probes.db").read_bytes()
        if hasattr(runner, "credential_buffer"):
            assert not any(runner.credential_buffer) and not any(runner.request_buffer)


@pytest.mark.parametrize("stage", ["started", "complete", "tamper"])
def test_probe_recovery_no_retry(tmp_path, now, monkeypatch, stage):
    with _case(tmp_path, now) as (service, plan, fixture, resolver, runner):
        if stage == "started":
            service.store.claim(plan)
        elif stage == "complete":

            def fail(_result):
                raise OSError("synthetic persistence failure")

            monkeypatch.setattr(service.store, "complete", fail)
            with pytest.raises(OSError):
                service.execute(plan)
        else:
            service.execute(plan)
            service.store.connection.execute("UPDATE provider_probes SET grant_id='drifted'")
            service.store.connection.commit()
        calls = len(runner.calls)
        with pytest.raises((ValueError, ProviderProbeRecoveryRequired)):
            service.execute(plan)
        assert len(runner.calls) == calls
        assert not tuple(tmp_path.rglob("*.tmp"))


def test_probe_config_and_schema_restrict_inputs(tmp_path, now):
    with _case(tmp_path, now) as (service, plan, *_):
        for field in ("prompt", "target", "tools", "api_key", "url"):
            with pytest.raises(ValueError):
                ProviderProbeConfig.model_validate(
                    {**service.config.model_dump(mode="python"), field: "x"}
                )
        for model in (ProviderProbePlan, ProviderProbeResult):
            assert model.model_json_schema()["additionalProperties"] is False
        with pytest.raises(ValueError):
            service.prepare(now=now, deadline=now + timedelta(seconds=301), idempotency_key="long")
        with pytest.raises(ValueError):
            service.prepare(now=now, deadline=now + timedelta(seconds=1), idempotency_key="short")


def test_provider_probe_cli_requires_optin_and_redacts_errors(tmp_path, now, monkeypatch, capsys):
    from vulnloom import cli
    from vulnloom.agent_runtime import provider_probe

    with _case(tmp_path, now) as (service, plan, fixture, resolver, runner):
        config_path, plan_path = tmp_path / "config.json", tmp_path / "plan.json"
        config_path.write_text(service.config.model_dump_json())
        plan_path.write_text(plan.model_dump_json())
        monkeypatch.setattr(cli, "utc_now", lambda: now)
        base = [
            "--config-file",
            str(config_path),
            "--egress-store",
            str(tmp_path / "provider-egress"),
            "--probe-db",
            str(tmp_path / "probes.db"),
        ]
        prepare = [
            "provider-probe-prepare",
            *base,
            "--idempotency-key",
            "probe-one",
            "--ttl-seconds",
            "60",
        ]
        # Planning needs no credential and does not consume a probe.
        monkeypatch.delenv(service.config.credential_reference.environment_variable, raising=False)
        assert cli.main(prepare) == 0
        assert ProviderProbePlan.model_validate_json(capsys.readouterr().out) == plan
        run = ["provider-probe-run", *base, "--plan-file", str(plan_path)]
        assert cli.main(run) == 1
        assert json.loads(capsys.readouterr().out)["error_code"] == "provider_probe_rejected"
        assert not resolver.calls and not runner.calls
        original = provider_probe.SubprocessHttpsProviderAdapter

        def fake_network(**kwargs):
            kwargs.update(resolver=resolver, process_runner=runner)
            return original(**kwargs)

        monkeypatch.setattr(provider_probe, "SubprocessHttpsProviderAdapter", fake_network)
        monkeypatch.setenv(
            service.config.credential_reference.environment_variable, fixture["secret"]
        )
        assert cli.main([*run, "--allow-provider-network"]) == 0
        first = json.loads(capsys.readouterr().out)
        assert first["status"] == "passed"
        assert cli.main([*run, "--allow-provider-network"]) == 0
        assert json.loads(capsys.readouterr().out) == first
        assert len(runner.calls) == 1
        config_path.write_text('{"api_key":"DO-NOT-LOG"}')
        assert cli.main(prepare) == 1
        captured = capsys.readouterr()
        assert "DO-NOT-LOG" not in captured.out + captured.err


@pytest.mark.parametrize("kind", ["symlink", "oversized", "directory"])
def test_probe_cli_rejects_unsafe_config(tmp_path, capsys, kind):
    from vulnloom import cli

    config = tmp_path / "config.json"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_text("DO-NOT-LOG")
        config.symlink_to(target)
    elif kind == "directory":
        config.mkdir()
    else:
        config.write_bytes(b"x" * 65537)
    assert (
        cli.main(
            [
                "provider-probe-prepare",
                "--config-file",
                str(config),
                "--egress-store",
                str(tmp_path / "egress"),
                "--idempotency-key",
                "one",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out) == {
        "status": "rejected",
        "error_code": "provider_probe_rejected",
    }
    assert not (tmp_path / "egress").exists()


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "blocked"},
        {"supporting_ref_digests": ["a" * 64]},
        {
            "kind": "propose_tool",
            "summary_digest": None,
            "tool_call": {
                "tool_id": "source.search",
                "arguments": [],
                "working_directory": "source",
            },
        },
    ],
)
def test_probe_never_accepts_model_workflow_intents(tmp_path, now, payload):
    with _case(tmp_path, now) as (service, plan, _, _, runner):
        runner.payload_updates = payload
        result = service.execute(plan)
        assert result.status == "rejected" and result.cleanup_verified
        assert len(runner.calls) == 1
        assert service.execute(plan) == result


def test_probe_approval_rechecked_between_plan_and_transport(tmp_path, now):
    with _case(tmp_path, now) as (service, plan, fixture, resolver, runner):
        original = service._message

        def revoke_after_preflight(plan):
            result = original(plan)
            fixture["egress_authority"].revoke(
                grant_id=plan.grant_id,
                issuer_policy_id=fixture["issuer_policy"].policy_id,
                reason_digest="a" * 64,
                now=now,
                deadline=now + timedelta(seconds=5),
                idempotency_key="mid-probe-revocation",
            )
            return result

        service._message = revoke_after_preflight
        result = service.execute(plan)
        assert result.status == "rejected" and result.cleanup_verified
        assert not resolver.calls and not runner.calls
