"""Pinned, bounded HTTP transport owned by the trusted Tool Broker."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import stat
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from vulnloom.domain.models import Evidence, EvidenceKind
from vulnloom.evidence.store import EvidenceStore

from .http import HttpWireRequest, OfflineHttpHop
from .implementation import PINNED_HTTP_IMPLEMENTATION_DIGEST
from .models import url_digest


class LiveHttpRejected(RuntimeError):
    """A live HTTP request or trusted material failed boundary validation."""


class HttpResponseLimitExceeded(RuntimeError):
    """The remote response exceeded a configured transport limit."""


class HttpMaterialUnavailable(RuntimeError):
    """An opaque credential or body reference could not be resolved."""


class HttpPeerMismatch(RuntimeError):
    """The connected peer differs from the Broker-selected numeric IP."""


@dataclass(frozen=True, repr=False)
class CredentialMaterial:
    """Secret headers resolved inside the Broker; repr deliberately hides values."""

    headers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        allowed = {"authorization", "cookie", "x-api-key", "x-auth-token"}
        normalized: list[tuple[str, str]] = []
        for name, value in self.headers:
            header = name.lower()
            try:
                encoded = value.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise ValueError("credential material is not Latin-1 encodable") from exc
            if (
                header not in allowed
                or any(character in value for character in "\r\n\x00")
                or len(encoded) > 16_384
            ):
                raise ValueError("credential material contains an unsupported header")
            normalized.append((header, value))
        if not normalized or len({name for name, _ in normalized}) != len(normalized):
            raise ValueError("credential material must contain unique secret headers")
        object.__setattr__(self, "headers", tuple(normalized))


class CredentialProvider(Protocol):
    def resolve(self, credential_ref: str) -> CredentialMaterial: ...


class BodyProvider(Protocol):
    def read(self, body_ref: str, *, max_bytes: int) -> bytes: ...


class HttpEvidenceSink(Protocol):
    def capture(
        self,
        request: HttpWireRequest,
        *,
        status_code: int,
        peer_ip: str,
        response_headers: Sequence[tuple[str, str]],
        body: bytes,
        elapsed_seconds: float,
    ) -> str: ...


class RejectingCredentialProvider:
    def resolve(self, credential_ref: str) -> CredentialMaterial:
        raise HttpMaterialUnavailable("no credential provider is configured")


class RejectingBodyProvider:
    def read(self, body_ref: str, *, max_bytes: int) -> bytes:
        raise HttpMaterialUnavailable("no body provider is configured")


class ContentAddressedBodyStore:
    """Read request bodies by digest from one trusted, non-symlink object directory."""

    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)

    def read(self, body_ref: str, *, max_bytes: int) -> bytes:
        if len(body_ref) != 64 or any(
            character not in "0123456789abcdef" for character in body_ref
        ):
            raise HttpMaterialUnavailable("invalid request body reference")
        path = self.root / body_ref
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise HttpMaterialUnavailable("request body object is unavailable") from exc
        if resolved != path or not resolved.is_file() or resolved.parent != self.root:
            raise HttpMaterialUnavailable("request body object is not a safe regular file")
        if not hasattr(os, "O_NOFOLLOW"):
            raise HttpMaterialUnavailable("platform cannot enforce no-follow body reads")
        flags = os.O_RDONLY | os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise HttpMaterialUnavailable("request body object could not be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                raise HttpMaterialUnavailable("request body exceeds its declared size")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(max_bytes + 1)
        finally:
            os.close(descriptor)
        if len(data) != metadata.st_size or hashlib.sha256(data).hexdigest() != body_ref:
            raise HttpMaterialUnavailable("request body integrity check failed")
        return data


class EvidenceStoreHttpSink:
    """Persist a redacted response transcript without request credentials or raw URLs."""

    _SAFE_HEADERS = frozenset(
        {"cache-control", "content-language", "content-length", "content-type", "etag"}
    )

    def __init__(self, store: EvidenceStore, *, target_version: str):
        self.store = store
        self.target_version = target_version
        self.records: dict[str, Evidence] = {}

    def capture(
        self,
        request: HttpWireRequest,
        *,
        status_code: int,
        peer_ip: str,
        response_headers: Sequence[tuple[str, str]],
        body: bytes,
        elapsed_seconds: float,
    ) -> str:
        selected = sorted(
            (name.lower(), value)
            for name, value in response_headers
            if name.lower() in self._SAFE_HEADERS
        )
        header_text = "\n".join(f"{name}: {value}" for name, value in selected)
        content_type = next(
            (value.lower() for name, value in selected if name == "content-type"), ""
        )
        textual = (
            content_type.startswith("text/")
            or "json" in content_type
            or "xml" in content_type
            or not body
        )
        if textual:
            body_text = body.decode("utf-8", errors="replace")
        else:
            body_text = f"[binary body sha256={hashlib.sha256(body).hexdigest()}]"
        source = f"url-sha256:{url_digest(request.url)}"
        transcript = (
            f"method: {request.method.value}\n"
            f"url_sha256: {url_digest(request.url)}\n"
            f"peer_ip: {peer_ip}\n"
            f"status: {status_code}\n"
            f"elapsed_seconds: {elapsed_seconds:.6f}\n"
            f"response_bytes: {len(body)}\n"
            f"{header_text}\n\n{body_text}"
        )
        evidence = self.store.capture_text(
            transcript,
            kind=EvidenceKind.HTTP,
            source_ref=source,
            producer="broker.http.pinned-v1",
            target_version=self.target_version,
            summary=f"HTTP {status_code} from pinned peer {peer_ip}; {len(body)} body bytes",
        )
        self.records[evidence.evidence_id] = evidence
        return evidence.evidence_id


class SystemResolver:
    """Resolve addresses with the system resolver; policy validation remains in ToolBroker."""

    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def resolve(self, host: str) -> tuple[str, ...]:
        try:
            return (str(ipaddress.ip_address(host)),)
        except ValueError:
            pass
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = {str(ipaddress.ip_address(record[4][0])) for record in records}
        return tuple(sorted(addresses))


class _Connection(Protocol):
    sock: socket.socket | ssl.SSLSocket | None

    def connect(self) -> None: ...

    def request(
        self, method: str, url: str, body: bytes | None, headers: Mapping[str, str]
    ) -> None: ...

    def getresponse(self) -> http.client.HTTPResponse: ...

    def close(self) -> None: ...


class PinnedConnectionFactory(Protocol):
    def open(
        self,
        *,
        host: str,
        port: int,
        pinned_ip: str,
        secure: bool,
        timeout: float,
    ) -> _Connection: ...


class StdlibPinnedConnectionFactory:
    def __init__(self, tls_context: ssl.SSLContext | None = None):
        self.tls_context = tls_context or ssl.create_default_context()

    def open(
        self,
        *,
        host: str,
        port: int,
        pinned_ip: str,
        secure: bool,
        timeout: float,
    ) -> _Connection:
        if secure:
            return _PinnedHTTPSConnection(
                host,
                port,
                pinned_ip=pinned_ip,
                timeout=timeout,
                context=self.tls_context,
            )
        return _PinnedHTTPConnection(host, port, pinned_ip=pinned_ip, timeout=timeout)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, *, pinned_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, *, pinned_ip: str, timeout: float, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class PinnedHttpTransport:
    """Connect only to the Broker-selected IP and return a redacted Evidence reference."""

    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def __init__(
        self,
        evidence_sink: HttpEvidenceSink,
        *,
        credential_provider: CredentialProvider | None = None,
        body_provider: BodyProvider | None = None,
        connection_factory: PinnedConnectionFactory | None = None,
        max_header_bytes: int = 64 * 1024,
    ):
        self.evidence_sink = evidence_sink
        self.credential_provider = credential_provider or RejectingCredentialProvider()
        self.body_provider = body_provider or RejectingBodyProvider()
        customized_transport = connection_factory is not None or max_header_bytes != 64 * 1024
        self.connection_factory = connection_factory or StdlibPinnedConnectionFactory()
        if not 1 <= max_header_bytes <= 1024 * 1024:
            raise ValueError("HTTP response header limit is outside the safe range")
        self.max_header_bytes = max_header_bytes
        if customized_transport:
            self.implementation_digest = hashlib.sha256(
                b"vulnloom:custom-http-transport:test-only"
            ).hexdigest()

    def send(self, request: HttpWireRequest) -> OfflineHttpHop:
        try:
            request = HttpWireRequest.model_validate(request.model_dump(mode="python"))
        except ValidationError as exc:
            raise LiveHttpRejected("live HTTP request failed boundary validation") from exc
        pinned_ip = str(ipaddress.ip_address(request.pinned_ip))
        parsed = urlsplit(request.url)
        if not parsed.hostname or parsed.scheme not in {"http", "https"}:
            raise LiveHttpRejected("live HTTP URL is not supported")
        from .models import HttpRequestPlan

        if HttpRequestPlan.safe_url(request.url) != request.url:
            raise LiveHttpRejected("live HTTP URL is not canonical")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = {header.name: header.value for header in request.headers}
        headers["connection"] = "close"
        headers["accept-encoding"] = "identity"
        if request.credential_ref:
            resolved = self.credential_provider.resolve(request.credential_ref)
            material = CredentialMaterial(headers=tuple(resolved.headers))
            for name, value in material.headers:
                if name in headers:
                    raise LiveHttpRejected("credential header collides with request headers")
                headers[name] = value
        body = None
        if request.body_ref:
            body = self.body_provider.read(request.body_ref, max_bytes=request.body_bytes)
            if (
                len(body) != request.body_bytes
                or hashlib.sha256(body).hexdigest() != request.body_ref
            ):
                raise LiveHttpRejected("resolved request body size does not match the plan")

        connection = self.connection_factory.open(
            host=parsed.hostname,
            port=port,
            pinned_ip=pinned_ip,
            secure=parsed.scheme == "https",
            timeout=request.connect_seconds,
        )
        started = time.monotonic()
        try:
            connection.connect()
            if connection.sock is None:
                raise RuntimeError("HTTP connection did not expose its peer socket")
            connection.sock.settimeout(request.read_seconds)
            peer_ip = str(ipaddress.ip_address(connection.sock.getpeername()[0]))
            if peer_ip != pinned_ip:
                raise HttpPeerMismatch("HTTP socket peer differs from its pinned IP")
            connection.request(request.method.value, target, body=body, headers=headers)
            response = connection.getresponse()
            response_headers = tuple(response.getheaders())
            header_bytes = sum(
                len(name.encode()) + len(value.encode()) + 4
                for name, value in response_headers
            )
            if header_bytes > self.max_header_bytes:
                raise HttpResponseLimitExceeded("HTTP response headers exceed the size limit")
            response_body = response.read(request.max_response_bytes + 1)
            if len(response_body) > request.max_response_bytes:
                raise HttpResponseLimitExceeded("HTTP response body exceeds the size limit")
            elapsed = time.monotonic() - started
            locations = [value for name, value in response_headers if name.lower() == "location"]
            redirect = response.status in {301, 302, 303, 307, 308}
            if len(locations) > 1 or redirect != bool(locations):
                raise LiveHttpRejected("HTTP redirect status and Location headers disagree")
            evidence_ref = self.evidence_sink.capture(
                request,
                status_code=response.status,
                peer_ip=peer_ip,
                response_headers=response_headers,
                body=response_body,
                elapsed_seconds=elapsed,
            )
            return OfflineHttpHop(
                status_code=response.status,
                peer_ip=peer_ip,
                response_bytes=len(response_body),
                response_body_sha256=hashlib.sha256(response_body).hexdigest(),
                evidence_ref=evidence_ref,
                elapsed_seconds=elapsed,
                location=locations[0] if locations else None,
            )
        finally:
            connection.close()
