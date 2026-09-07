"""Synthetic diagnostics never contain headers, credentials or response text."""

import io
import json
import ssl
import struct
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import provider_transport_worker as worker
from vulnloom.agent_runtime.provider_diagnostics import ProviderDiagnostic
from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.agent_runtime.provider_process import (
    ProviderProcessExecutionError,
    _parse_failure_output,
)


def frame(value):
    data = json.dumps(value).encode()
    return bytearray(struct.pack("!I", len(data)) + data)


@pytest.mark.parametrize(
    "change",
    [
        {"error_code": "secret-from-server"},
        {"http_status": True},
        {"network_opened": "true"},
        {"captured_response_bytes": -1},
        {"tls_version": "secret"},
        {"body": "sensitive-body"},
        {"failure_stage": "response_codec"},
    ],
)
def test_untrusted_diagnostics_are_closed_and_zeroed(change):
    value = dict(
        failure_stage="http_status",
        error_code="http_non_200",
        http_status=401,
        network_opened=True,
        tls_version="TLSv1.3",
    )
    value.update(change)
    captured = frame(value)
    with pytest.raises(ProviderProcessExecutionError):
        _parse_failure_output(captured)
    assert not any(captured)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"failure_stage":null,"failure_stage":"http_status"}',
        b"{}trailing",
    ],
)
def test_duplicate_and_invalid_json_rejected(raw):
    captured = bytearray(struct.pack("!I", len(raw)) + raw)
    with pytest.raises(ProviderProcessExecutionError):
        _parse_failure_output(captured)
    assert not any(captured)


@pytest.mark.parametrize(
    "scenario,expected,network",
    [
        ("401", "http_non_200", True),
        ("403", "http_non_200", True),
        ("404", "http_non_200", True),
        ("302", "http_non_200", True),
        ("tls", "tls_failed", True),
        ("connect", "connect_failed", False),
        ("timeout", "transport_timeout", False),
        ("empty", "response_empty", True),
        ("headers", "response_headers_rejected", True),
    ],
)
def test_worker_fixed_failure_frame_and_cleanup(monkeypatch, scenario, expected, network):
    credential = b"synthetic-secret"
    header = dict(
        ca_bytes=0,
        contract="vulnloom.provider-process.v1",
        credential_bytes=len(credential),
        hostname="api.example.test",
        max_response_bytes=1024,
        pinned_ip="127.0.0.1",
        port=443,
        request_bytes=2,
        request_path="/v1/chat/completions",
        timeout_seconds=1,
    )
    stdin = io.BytesIO(frame(header) + credential + b"{}")
    stdout = io.BytesIO()
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=stdin))
    monkeypatch.setattr(worker.sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(worker, "_environment_is_minimal", lambda: True)
    monkeypatch.setattr(worker, "_restrict_process", lambda: None)
    connections = []

    class Connection:
        def __init__(self, *args, **kwargs):
            self.network_opened = False
            self.closed = False
            self.sock = SimpleNamespace(
                settimeout=lambda _: None,
                getpeername=lambda: ("127.0.0.1", 443),
                version=lambda: "TLSv1.3",
            )
            connections.append(self)

        def connect(self):
            if scenario == "connect":
                raise OSError("sensitive-error")
            if scenario == "timeout":
                raise TimeoutError("sensitive-error")
            self.network_opened = True
            if scenario == "tls":
                raise ssl.SSLError("sensitive-error")

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return SimpleNamespace(
                status=int(scenario) if scenario.isdigit() else 200,
                getheaders=lambda: (
                    [("location", "sensitive-header")] if scenario == "headers" else []
                ),
                read=lambda _: b"",
            )

        def close(self):
            self.closed = True

    monkeypatch.setattr(worker, "_PinnedHTTPSConnection", Connection)
    assert worker.main() in (20, 21)
    output = stdout.getvalue()
    assert b"sensitive" not in output and credential not in output
    diagnostic = _parse_failure_output(bytearray(output))
    assert diagnostic.error_code == expected
    assert diagnostic.network_opened is network
    assert diagnostic.http_status == (
        int(scenario) if scenario.isdigit() else 200 if scenario in ("headers", "empty") else None
    )
    assert connections[0].closed


def test_diagnostic_result_hash_and_legacy_replay(now):
    legacy = ProviderProbeResult.create(
        plan_id="a" * 64,
        status="rejected",
        input_tokens=0,
        output_tokens=0,
        process_started=True,
        cleanup_verified=True,
        attempt_digest="b" * 64,
        receipt_digest=None,
        completed_at=now,
    )
    value = legacy.model_dump(mode="python")
    value.pop("diagnostic")
    assert ProviderProbeResult.model_validate(value) == legacy
    diagnostic = ProviderDiagnostic(failure_stage="transport_process", error_code="tls_failed")
    value["diagnostic"] = diagnostic.model_dump()
    with pytest.raises(ValidationError):
        ProviderProbeResult.model_validate(value)


@pytest.mark.parametrize('value,kind', [(None, 'null'), (7, 'int'), ({}, 'dict'),
                                       (False, 'other'), ('sensitive-value', 'other')])
def test_usage_candidate_observations_are_closed(value, kind):
    from vulnloom.agent_runtime.provider_diagnostics import observe_usage_keys
    observed, truncated = observe_usage_keys({'num_cached_tokens': value}, set())
    assert not truncated and len(observed) == 1
    assert observed[0].candidate == 'num_cached_tokens'
    assert observed[0].name_sha256 is None and observed[0].value_type == kind
    assert 'sensitive-value' not in observed[0].model_dump_json()


def test_unknown_usage_keys_only_hash_names_and_bound_count():
    from hashlib import sha256

    from vulnloom.agent_runtime.provider_diagnostics import observe_usage_keys
    name = 'sensitive-unknown-key'
    observed, truncated = observe_usage_keys({name: 'sensitive-body'}, set())
    assert not truncated and observed[0].candidate is None
    assert observed[0].name_sha256 == sha256(name.encode()).hexdigest()
    assert name not in observed[0].model_dump_json()
    assert 'sensitive-body' not in observed[0].model_dump_json()
    observed, truncated = observe_usage_keys({str(i): None for i in range(33)}, set())
    assert len(observed) == 32 and truncated


def test_usage_fingerprint_rejects_arbitrary_labels():
    from vulnloom.agent_runtime.provider_diagnostics import UsageKeyObservation
    with pytest.raises(ValidationError):
        UsageKeyObservation(candidate='sensitive-key', value_type='null')
    with pytest.raises(ValidationError):
        UsageKeyObservation(name_sha256='a'*64, value_type='sensitive-value')
    with pytest.raises(ValidationError):
        UsageKeyObservation(candidate='num_cached_tokens', name_sha256='a'*64, value_type='int')
