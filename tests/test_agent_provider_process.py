from __future__ import annotations

import io
import json
import struct
import subprocess

import pytest

from vulnloom.agent_runtime.provider_process import (
    ProviderProcessExecutionError,
    SubprocessProviderTransportRunner,
    _parse_worker_output,
)


def _worker_frame(body: bytes, *, peer_ip: str = "203.0.113.10") -> bytes:
    metadata = json.dumps(
        {
            "peer_ip": peer_ip,
            "response_bytes": len(body),
            "tls_version": "TLSv1.3",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return struct.pack("!I", len(metadata)) + metadata + body


class _RecordingInput(io.BytesIO):
    written = b""

    def close(self) -> None:
        self.written = self.getvalue()
        super().close()


class _CompletedProcess:
    def __init__(self, output: bytes):
        self.stdin = _RecordingInput()
        self.stdout = io.BytesIO(output)
        self.pid = 4312

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0

    def kill(self):
        raise AssertionError("completed provider process must not be killed")


def test_subprocess_runner_uses_fixed_command_and_minimal_process_boundary(monkeypatch):
    response = b'{"provider_id":"sealed"}'
    process = _CompletedProcess(_worker_frame(response))
    observed = {}

    def fake_popen(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return process

    monkeypatch.setattr(
        "vulnloom.agent_runtime.provider_process.subprocess.Popen", fake_popen
    )
    result = SubprocessProviderTransportRunner().exchange(
        hostname="api.provider.example",
        port=443,
        request_path="/v1/responses",
        pinned_ip="203.0.113.10",
        request_body=bytearray(b'{"request":"sealed"}'),
        credential=memoryview(bytearray(b"ephemeral-secret")).toreadonly(),
        ca_bundle=None,
        timeout_seconds=3,
        max_response_bytes=1024,
    )

    command = observed["command"]
    kwargs = observed["kwargs"]
    assert command[1:] == (
        "-I",
        "-m",
        "vulnloom.agent_runtime.provider_transport_worker",
    )
    assert kwargs["env"] == {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    assert kwargs["cwd"] == "/"
    assert kwargs["close_fds"] is True
    assert kwargs["start_new_session"] is True
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert result.response_body == response
    assert result.peer_ip == "203.0.113.10"
    assert result.tls_version == "TLSv1.3"
    assert b"ephemeral-secret" in process.stdin.written


class _TimedOutProcess:
    def __init__(self):
        self.stdin = _RecordingInput()
        self.stdout = io.BytesIO()
        self.pid = 4313
        self.terminated = False

    def wait(self, timeout=None):
        if not self.terminated:
            raise subprocess.TimeoutExpired("provider-worker", timeout)
        return -9

    def poll(self):
        return -9 if self.terminated else None

    def kill(self):
        self.terminated = True


def test_subprocess_runner_timeout_kills_process_group(monkeypatch):
    process = _TimedOutProcess()
    killed = []

    monkeypatch.setattr(
        "vulnloom.agent_runtime.provider_process.subprocess.Popen",
        lambda *args, **kwargs: process,
    )

    def fake_killpg(pid, signal_number):
        killed.append((pid, signal_number))
        process.terminated = True

    monkeypatch.setattr("vulnloom.agent_runtime.provider_process.os.killpg", fake_killpg)
    with pytest.raises(ProviderProcessExecutionError) as failure:
        SubprocessProviderTransportRunner().exchange(
            hostname="api.provider.example",
            port=443,
            request_path="/v1/responses",
            pinned_ip="203.0.113.10",
            request_body=bytearray(b"{}"),
            credential=memoryview(bytearray(b"timeout-secret")).toreadonly(),
            ca_bundle=None,
            timeout_seconds=0.01,
            max_response_bytes=128,
        )

    assert failure.value.code == "provider_process_timeout"
    assert failure.value.timed_out is True
    assert killed and killed[0][0] == process.pid
    assert process.terminated is True


@pytest.mark.parametrize(
    "captured",
    [
        bytearray(b"bad"),
        bytearray(struct.pack("!I", 5000)),
        bytearray(_worker_frame(b"ok")[:-1]),
        bytearray(
            struct.pack("!I", 67)
            + b'{"peer_ip":"203.0.113.10","response_bytes":1,"tls_version":"SSLv3"}'
            + b"x"
        ),
    ],
)
def test_worker_output_parser_rejects_malformed_frames_and_zeroes_capture(captured):
    with pytest.raises(ProviderProcessExecutionError) as failure:
        _parse_worker_output(captured, max_response_bytes=64)

    assert failure.value.code == "provider_process_output_invalid"
    assert captured == bytearray(len(captured))
