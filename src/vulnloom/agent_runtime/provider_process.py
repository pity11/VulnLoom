"""Fixed subprocess boundary for one pinned HTTPS provider request."""

from __future__ import annotations

import json
import os
import signal
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from vulnloom.domain.digests import canonical_digest

SUBPROCESS_HTTPS_ADAPTER_DIGEST = canonical_digest(
    {
        "adapter": "vulnloom.subprocess-https-provider",
        "version": 1,
        "shell": False,
        "environment": ["PYTHONIOENCODING", "PYTHONUTF8"],
        "redirects": False,
        "proxy": False,
        "bounded_stdout": True,
    }
)


class ProviderProcessExecutionError(RuntimeError):
    def __init__(self, code: str, *, timed_out: bool = False, captured_bytes: int = 0):
        super().__init__(code)
        self.code = code
        self.timed_out = timed_out
        self.captured_bytes = captured_bytes
        self.process_started = True
        self.process_terminated = True
        self.stderr_discarded = True


@dataclass(frozen=True)
class ProviderProcessResult:
    response_body: bytearray
    latency_seconds: float
    peer_ip: str
    tls_version: str
    process_started: bool = True
    process_terminated: bool = True
    stderr_discarded: bool = True
    network_opened: bool = True


class SubprocessProviderTransportRunner:
    """Launch the fixed worker with no inherited environment and bounded stdout."""

    def exchange(
        self,
        *,
        hostname: str,
        port: int,
        request_path: str,
        pinned_ip: str,
        request_body: bytearray,
        credential: memoryview,
        ca_bundle: bytes | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ProviderProcessResult:
        ca_bytes = b"" if ca_bundle is None else ca_bundle
        header = json.dumps(
            {
                "ca_bytes": len(ca_bytes),
                "contract": "vulnloom.provider-process.v1",
                "credential_bytes": len(credential),
                "hostname": hostname,
                "max_response_bytes": max_response_bytes,
                "pinned_ip": pinned_ip,
                "port": port,
                "request_bytes": len(request_body),
                "request_path": request_path,
                "timeout_seconds": timeout_seconds,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        wire = bytearray()
        wire.extend(struct.pack("!I", len(header)))
        wire.extend(header)
        wire.extend(credential)
        wire.extend(request_body)
        wire.extend(ca_bytes)
        command = (
            sys.executable,
            "-I",
            "-m",
            "vulnloom.agent_runtime.provider_transport_worker",
        )
        environment = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            cwd="/",
            close_fds=True,
            start_new_session=True,
        )
        captured = bytearray()
        capture_limit = max_response_bytes + 4096
        overflow = threading.Event()

        def capture() -> None:
            assert process.stdout is not None
            while chunk := process.stdout.read(64 * 1024):
                remaining = capture_limit + 1 - len(captured)
                captured.extend(chunk[:remaining])
                if len(captured) > capture_limit or len(chunk) > remaining:
                    overflow.set()
                    _terminate(process)
                    break

        started = time.monotonic()
        reader = threading.Thread(
            target=capture, name="provider-response-capture", daemon=True
        )
        try:
            assert process.stdin is not None
            written = process.stdin.write(wire)
            if written != len(wire):
                raise OSError("provider process frame was not written completely")
            process.stdin.close()
            reader.start()
            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                _terminate(process)
                process.wait(timeout=5)
                raise ProviderProcessExecutionError(
                    "provider_process_timeout",
                    timed_out=True,
                    captured_bytes=min(len(captured), max_response_bytes),
                ) from exc
            reader.join(timeout=5)
            if reader.is_alive():
                _terminate(process)
                process.wait(timeout=5)
                raise ProviderProcessExecutionError(
                    "provider_process_cleanup_failed",
                    captured_bytes=min(len(captured), max_response_bytes),
                )
            if overflow.is_set():
                raise ProviderProcessExecutionError(
                    "provider_response_size_exceeded", captured_bytes=max_response_bytes
                )
            if return_code != 0:
                code = {
                    20: "provider_https_rejected",
                    21: "provider_https_timeout",
                    22: "provider_response_size_exceeded",
                    23: "provider_peer_mismatch",
                }.get(return_code, "provider_process_failed")
                raise ProviderProcessExecutionError(
                    code,
                    timed_out=return_code == 21,
                    captured_bytes=min(len(captured), max_response_bytes),
                )
            if not captured:
                raise ProviderProcessExecutionError("provider_response_empty")
            response, peer_ip, tls_version = _parse_worker_output(
                captured, max_response_bytes=max_response_bytes
            )
            return ProviderProcessResult(
                response_body=response,
                latency_seconds=time.monotonic() - started,
                peer_ip=peer_ip,
                tls_version=tls_version,
            )
        except (BrokenPipeError, OSError) as exc:
            _terminate(process)
            process.wait(timeout=5)
            raise ProviderProcessExecutionError(
                "provider_process_io_failed",
                captured_bytes=min(len(captured), max_response_bytes),
            ) from exc
        finally:
            wire[:] = b"\x00" * len(wire)
            if process.poll() is None:
                _terminate(process)
                process.wait(timeout=5)
            if reader.ident is not None:
                reader.join(timeout=5)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()


def _parse_worker_output(
    captured: bytearray, *, max_response_bytes: int
) -> tuple[bytearray, str, str]:
    try:
        if len(captured) < 4:
            raise ValueError("missing metadata length")
        metadata_size = struct.unpack("!I", captured[:4])[0]
        if not 1 <= metadata_size <= 4092 or len(captured) < 4 + metadata_size:
            raise ValueError("invalid metadata length")
        metadata = json.loads(captured[4 : 4 + metadata_size])
        if not isinstance(metadata, dict) or set(metadata) != {
            "peer_ip",
            "response_bytes",
            "tls_version",
        }:
            raise ValueError("invalid metadata")
        response = bytearray(captured[4 + metadata_size :])
        if (
            isinstance(metadata["response_bytes"], bool)
            or not isinstance(metadata["response_bytes"], int)
            or len(response) != metadata["response_bytes"]
            or not 1 <= len(response) <= max_response_bytes
        ):
            raise ValueError("response size mismatch")
        peer_ip = str(metadata["peer_ip"])
        tls_version = str(metadata["tls_version"])
        if tls_version not in {"TLSv1.2", "TLSv1.3"}:
            raise ValueError("TLS version mismatch")
        return response, peer_ip, tls_version
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProviderProcessExecutionError(
            "provider_process_output_invalid",
            captured_bytes=min(len(captured), max_response_bytes),
        ) from exc
    finally:
        captured[:] = b"\x00" * len(captured)
