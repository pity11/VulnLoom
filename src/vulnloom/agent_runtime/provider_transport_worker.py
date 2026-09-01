"""One-shot pinned HTTPS worker. It is invoked only by the trusted parent adapter."""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import resource
import socket
import ssl
import struct
import sys
from typing import BinaryIO


def main() -> int:
    credential = bytearray()
    request_body = bytearray()
    ca_bundle = bytearray()
    response_body = bytearray()
    connection: http.client.HTTPSConnection | None = None
    try:
        if not _environment_is_minimal():
            return 20
        _restrict_process()
        header_size = struct.unpack("!I", _read_exact(sys.stdin.buffer, 4))[0]
        if not 1 <= header_size <= 4096:
            return 20
        header = json.loads(_read_exact(sys.stdin.buffer, header_size))
        expected = {
            "ca_bytes",
            "contract",
            "credential_bytes",
            "hostname",
            "max_response_bytes",
            "pinned_ip",
            "port",
            "request_bytes",
            "request_path",
            "timeout_seconds",
        }
        if not isinstance(header, dict) or set(header) != expected:
            return 20
        if header["contract"] != "vulnloom.provider-process.v1":
            return 20
        credential_size = _bounded_int(header["credential_bytes"], 1, 16_384)
        request_size = _bounded_int(header["request_bytes"], 1, 2_162_688)
        ca_size = _bounded_int(header["ca_bytes"], 0, 1_048_576)
        response_limit = _bounded_int(header["max_response_bytes"], 1, 2_097_152)
        port = _bounded_int(header["port"], 1, 65_535)
        timeout = _bounded_float(header["timeout_seconds"], 0, 600)
        hostname = header["hostname"]
        request_path = header["request_path"]
        pinned_ip = str(ipaddress.ip_address(header["pinned_ip"]))
        if (
            not _canonical_hostname(hostname)
            or not isinstance(request_path, str)
            or not request_path.startswith("/")
            or any(
                item in request_path
                for item in ("?", "#", "\\", "%", "..", "\r", "\n", "\x00")
            )
        ):
            return 20
        credential.extend(_read_exact(sys.stdin.buffer, credential_size))
        request_body.extend(_read_exact(sys.stdin.buffer, request_size))
        ca_bundle.extend(_read_exact(sys.stdin.buffer, ca_size))
        if sys.stdin.buffer.read(1):
            return 20
        if any(character in credential for character in (0, 10, 13)):
            return 20
        context = ssl.create_default_context(
            cadata=None if not ca_bundle else ca_bundle.decode("ascii")
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = _PinnedHTTPSConnection(
            hostname,
            port,
            pinned_ip=pinned_ip,
            timeout=timeout,
            context=context,
        )
        connection.connect()
        if connection.sock is None:
            return 23
        connection.sock.settimeout(timeout)
        peer_ip = str(ipaddress.ip_address(connection.sock.getpeername()[0]))
        if peer_ip != pinned_ip:
            return 23
        tls_version = connection.sock.version()
        if tls_version not in {"TLSv1.2", "TLSv1.3"}:
            return 20
        authorization = "Bearer " + credential.decode("ascii")
        connection.request(
            "POST",
            request_path,
            body=request_body,
            headers={
                "accept": "application/json",
                "accept-encoding": "identity",
                "authorization": authorization,
                "connection": "close",
                "content-type": "application/json",
            },
        )
        response = connection.getresponse()
        headers = tuple(response.getheaders())
        header_bytes = sum(
            len(name.encode("latin-1")) + len(value.encode("latin-1")) + 4
            for name, value in headers
        )
        if header_bytes > 64 * 1024:
            return 22
        if response.status != 200 or any(
            name.lower() == "location" for name, _ in headers
        ):
            return 20
        if any(
            name.lower() == "content-encoding" and value.lower() != "identity"
            for name, value in headers
        ):
            return 20
        content_lengths = [
            value for name, value in headers if name.lower() == "content-length"
        ]
        if len(content_lengths) > 1:
            return 20
        if content_lengths:
            content_length = int(content_lengths[0])
            if content_length < 0:
                return 20
            if content_length > response_limit:
                return 22
        while True:
            chunk = response.read(min(64 * 1024, response_limit + 1 - len(response_body)))
            if not chunk:
                break
            response_body.extend(chunk)
            if len(response_body) > response_limit:
                return 22
        if not response_body:
            return 20
        metadata = json.dumps(
            {
                "peer_ip": peer_ip,
                "response_bytes": len(response_body),
                "tls_version": tls_version,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        sys.stdout.buffer.write(struct.pack("!I", len(metadata)))
        sys.stdout.buffer.write(metadata)
        sys.stdout.buffer.write(response_body)
        sys.stdout.buffer.flush()
        return 0
    except TimeoutError:
        return 21
    except (OSError, ssl.SSLError, ValueError, UnicodeError, json.JSONDecodeError):
        return 20
    finally:
        if connection is not None:
            connection.close()
        _zero(credential)
        _zero(request_body)
        _zero(ca_bundle)
        _zero(response_body)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        pinned_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ):
        super().__init__(host, port, timeout=timeout, context=context)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated provider process frame")
    return data


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError("provider process integer is outside bounds")
    return value


def _bounded_float(value: object, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("provider process number is outside bounds")
    result = float(value)
    if not math.isfinite(result) or not minimum < result <= maximum:
        raise ValueError("provider process number is outside bounds")
    return result


def _canonical_hostname(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 253
        or value != value.lower()
        or value.startswith(".")
        or value.endswith(".")
    ):
        return False
    labels = value.split(".")
    return all(
        1 <= len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and all(
            character.isascii() and (character.isalnum() or character == "-")
            for character in label
        )
        for label in labels
    )


def _restrict_process() -> None:
    for limit, maximum in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_NOFILE, 32),
        (resource.RLIMIT_FSIZE, 4 * 1024 * 1024),
    ):
        soft, hard = resource.getrlimit(limit)
        bounded_soft = maximum if soft == resource.RLIM_INFINITY else min(soft, maximum)
        bounded_hard = maximum if hard == resource.RLIM_INFINITY else min(hard, maximum)
        resource.setrlimit(limit, (bounded_soft, bounded_hard))


def _environment_is_minimal() -> bool:
    allowed = {
        "LC_CTYPE",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "__CF_USER_TEXT_ENCODING",
    }
    return set(os.environ) <= allowed and os.environ.get("PYTHONUTF8") == "1"


def _zero(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


if __name__ == "__main__":
    raise SystemExit(main())
