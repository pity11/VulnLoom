from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnloom.broker import EvidenceStoreHttpSink, PinnedHttpTransport
from vulnloom.broker.http import HttpWireRequest
from vulnloom.evidence import EvidenceStore


class _Handler(BaseHTTPRequestHandler):
    observed_host = None

    def do_GET(self):
        type(self).observed_host = self.headers.get("Host")
        body = b'{"api_key":"live-secret-value","email":"alice@example.com"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "session=must-not-enter-evidence")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@pytest.mark.socket_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_SOCKET_INTEGRATION") != "1",
    reason="set VULNLOOM_SOCKET_INTEGRATION=1 to run the loopback socket probe",
)
def test_real_socket_is_pinned_and_response_flows_only_to_redacted_evidence(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    store = EvidenceStore(tmp_path / "evidence")
    sink = EvidenceStoreHttpSink(store, target_version="socket-fixture-v1")
    transport = PinnedHttpTransport(sink)
    request = HttpWireRequest(
        method="GET",
        url=f"http://authorized.example.test:{port}/probe?id=7",
        pinned_ip="127.0.0.1",
        headers=(),
        body_bytes=0,
        connect_seconds=1,
        read_seconds=1,
        max_response_bytes=4096,
    )
    try:
        hop = transport.send(request)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert hop.status_code == 200
    assert hop.peer_ip == "127.0.0.1"
    assert _Handler.observed_host == f"authorized.example.test:{port}"
    evidence = sink.records[hop.evidence_ref]
    content = store.read_text(evidence)
    assert "live-secret-value" not in content
    assert "alice@example.com" not in content
    assert "must-not-enter-evidence" not in content
    assert "[REDACTED]" in content
