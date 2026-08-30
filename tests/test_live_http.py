from __future__ import annotations

import hashlib
import socket

import pytest

from vulnloom.broker import (
    CredentialMaterial,
    EvidenceStoreHttpSink,
    HttpMaterialUnavailable,
    HttpPeerMismatch,
    HttpResponseLimitExceeded,
    LiveHttpRejected,
    PinnedHttpTransport,
    SystemResolver,
)
from vulnloom.broker.http import HttpWireRequest
from vulnloom.evidence import EvidenceStore

IP = "192.0.2.10"
URL = "http://app.example.test:8080/items?q=7"


class FakeSocket:
    def __init__(self, peer=IP):
        self.peer = peer
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def getpeername(self):
        return (self.peer, 8080)


class FakeResponse:
    def __init__(self, *, status=200, headers=(), body=b"ok"):
        self.status = status
        self._headers = tuple(headers)
        self.body = body
        self.read_limit = None

    def getheaders(self):
        return self._headers

    def read(self, limit):
        self.read_limit = limit
        return self.body[:limit]


class FakeConnection:
    def __init__(self, response, *, peer=IP):
        self.response = response
        self.sock = FakeSocket(peer)
        self.connected = False
        self.closed = False
        self.request_call = None
        self.connect_error = None

    def connect(self):
        if self.connect_error:
            raise self.connect_error
        self.connected = True

    def request(self, method, url, body, headers):
        self.request_call = (method, url, body, dict(headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class FakeFactory:
    def __init__(self, connection):
        self.connection = connection
        self.calls = []

    def open(self, **values):
        self.calls.append(values)
        return self.connection


class FakeSink:
    evidence_ref = "e" * 64

    def __init__(self):
        self.calls = []

    def capture(self, request, **values):
        self.calls.append((request, values))
        return self.evidence_ref


class FakeCredentials:
    def __init__(self, material):
        self.material = material

    def resolve(self, credential_ref):
        return self.material


class FakeBodies:
    def __init__(self, body):
        self.body = body

    def read(self, body_ref, *, max_bytes):
        return self.body


def _request(**values):
    payload = {
        "method": "GET",
        "url": URL,
        "pinned_ip": IP,
        "headers": ({"name": "accept", "value": "application/json"},),
        "connect_seconds": 1,
        "read_seconds": 2,
        "max_response_bytes": 32,
        "body_bytes": 0,
        **values,
    }
    return HttpWireRequest(**payload)


def test_transport_connects_to_only_pinned_ip_and_reports_actual_peer():
    response = FakeResponse(headers=(("Content-Type", "text/plain"),), body=b"hello")
    connection = FakeConnection(response)
    factory = FakeFactory(connection)
    sink = FakeSink()
    transport = PinnedHttpTransport(sink, connection_factory=factory)

    hop = transport.send(_request())

    assert hop.peer_ip == IP
    assert hop.evidence_ref == sink.evidence_ref
    assert hop.response_body_sha256 == hashlib.sha256(b"hello").hexdigest()
    assert factory.calls == [
        {
            "host": "app.example.test",
            "port": 8080,
            "pinned_ip": IP,
            "secure": False,
            "timeout": 1.0,
        }
    ]
    method, target, body, headers = connection.request_call
    assert (method, target, body) == ("GET", "/items?q=7", None)
    assert headers["connection"] == "close"
    assert headers["accept-encoding"] == "identity"
    assert connection.sock.timeout == 2.0
    assert connection.closed


def test_credentials_and_body_are_resolved_inside_transport_without_entering_evidence_call():
    body = b'{"id":7}'
    body_ref = hashlib.sha256(body).hexdigest()
    secret = "Bearer do-not-log-this"
    credentials = CredentialMaterial(headers=(("Authorization", secret),))
    connection = FakeConnection(FakeResponse(body=b"saved"))
    sink = FakeSink()
    transport = PinnedHttpTransport(
        sink,
        credential_provider=FakeCredentials(credentials),
        body_provider=FakeBodies(body),
        connection_factory=FakeFactory(connection),
    )

    transport.send(
        _request(
            method="POST",
            credential_ref="c" * 64,
            body_ref=body_ref,
            body_bytes=len(body),
        )
    )

    assert connection.request_call[2] == body
    assert connection.request_call[3]["authorization"] == secret
    captured_request = sink.calls[0][0]
    assert captured_request.credential_ref == "c" * 64
    assert secret not in repr(credentials)
    assert secret not in repr(captured_request)


def test_transport_refuses_oversized_response_bad_redirect_and_wrong_body():
    oversized = FakeConnection(FakeResponse(body=b"x" * 33))
    with pytest.raises(HttpResponseLimitExceeded):
        PinnedHttpTransport(FakeSink(), connection_factory=FakeFactory(oversized)).send(_request())
    assert oversized.closed

    redirect = FakeConnection(FakeResponse(status=302, headers=(), body=b""))
    with pytest.raises(LiveHttpRejected, match="redirect"):
        PinnedHttpTransport(FakeSink(), connection_factory=FakeFactory(redirect)).send(_request())
    assert redirect.closed

    body = b"wrong"
    request = _request(
        method="POST",
        body_ref="a" * 64,
        body_bytes=len(body),
    )
    factory = FakeFactory(FakeConnection(FakeResponse()))
    with pytest.raises(LiveHttpRejected, match="body size"):
        PinnedHttpTransport(
            FakeSink(), body_provider=FakeBodies(body), connection_factory=factory
        ).send(request)
    assert factory.calls == []


def test_transport_rejects_actual_peer_mismatch_before_evidence_capture():
    sink = FakeSink()
    connection = FakeConnection(FakeResponse(), peer="192.0.2.99")
    with pytest.raises(HttpPeerMismatch):
        PinnedHttpTransport(sink, connection_factory=FakeFactory(connection)).send(_request())
    assert sink.calls == []
    assert connection.closed


def test_missing_opaque_material_fails_before_socket_creation():
    factory = FakeFactory(FakeConnection(FakeResponse()))
    with pytest.raises(HttpMaterialUnavailable):
        PinnedHttpTransport(FakeSink(), connection_factory=factory).send(
            _request(credential_ref="c" * 64)
        )
    assert factory.calls == []


def test_timeout_closes_connection_and_propagates_to_broker_boundary():
    connection = FakeConnection(FakeResponse())
    connection.connect_error = TimeoutError("fixture timeout")
    with pytest.raises(TimeoutError):
        PinnedHttpTransport(FakeSink(), connection_factory=FakeFactory(connection)).send(_request())
    assert connection.closed


def test_content_addressed_body_store_checks_digest_size_and_symlinks(tmp_path):
    body = b"authorized body"
    digest = hashlib.sha256(body).hexdigest()
    root = tmp_path / "bodies"
    root.mkdir()
    path = root / digest
    path.write_bytes(body)
    from vulnloom.broker import ContentAddressedBodyStore

    store = ContentAddressedBodyStore(root)
    assert store.read(digest, max_bytes=len(body)) == body
    with pytest.raises(HttpMaterialUnavailable, match="declared size"):
        store.read(digest, max_bytes=len(body) - 1)

    path.rename(root / "moved")
    path.symlink_to(root / "moved")
    with pytest.raises(HttpMaterialUnavailable, match="safe regular file"):
        store.read(digest, max_bytes=len(body))


def test_evidence_sink_redacts_text_and_excludes_sensitive_headers_and_raw_url(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    sink = EvidenceStoreHttpSink(store, target_version="commit-1")
    request = _request()
    evidence_ref = sink.capture(
        request,
        status_code=200,
        peer_ip=IP,
        response_headers=(
            ("Content-Type", "application/json"),
            ("Set-Cookie", "session=do-not-store"),
        ),
        body=b'{"api_key":"very-secret-value","email":"alice@example.com"}',
        elapsed_seconds=0.01,
    )

    evidence = sink.records[evidence_ref]
    content = store.read_text(evidence)
    assert "very-secret-value" not in content
    assert "alice@example.com" not in content
    assert "do-not-store" not in content
    assert URL not in content
    assert "[REDACTED]" in content


def test_system_resolver_deduplicates_and_normalizes(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    assert SystemResolver().resolve("app.example.test") == ("192.0.2.10", "2001:db8::1")
    assert SystemResolver().resolve("192.0.2.99") == ("192.0.2.99",)
