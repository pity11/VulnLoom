"""Pinned, verified TLS inspection owned by the trusted Tool Broker."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import ValidationError

from vulnloom.domain.models import Evidence, EvidenceKind
from vulnloom.evidence.store import EvidenceStore

from .implementation import PINNED_TLS_IMPLEMENTATION_DIGEST
from .models import TlsInspectionPlan, TlsProtocolVersion, url_digest
from .tls import OfflineTlsHandshake, TlsWireRequest


class LiveTlsRejected(RuntimeError):
    """A TLS request or verified session failed boundary validation."""


class TlsPeerMismatch(RuntimeError):
    """The connected peer differs from the Broker-selected numeric IP."""


class SystemTlsResolver:
    """System resolution with a TLS-specific implementation identity."""

    implementation_digest = PINNED_TLS_IMPLEMENTATION_DIGEST

    def resolve(self, host: str) -> tuple[str, ...]:
        try:
            return (str(ipaddress.ip_address(host)),)
        except ValueError:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            return tuple(
                sorted({str(ipaddress.ip_address(record[4][0])) for record in records})
            )


class TlsEvidenceSink(Protocol):
    def capture(
        self,
        request: TlsWireRequest,
        *,
        peer_ip: str,
        tls_version: TlsProtocolVersion,
        cipher_suite: str,
        cipher_bits: int,
        leaf_certificate_sha256: str,
        elapsed_seconds: float,
    ) -> str: ...


class EvidenceStoreTlsSink:
    """Persist only verified TLS metadata; never persist certificate contents or URLs."""

    def __init__(self, store: EvidenceStore, *, target_version: str):
        self.store = store
        self.target_version = target_version
        self.records: dict[str, Evidence] = {}

    def capture(
        self,
        request: TlsWireRequest,
        *,
        peer_ip: str,
        tls_version: TlsProtocolVersion,
        cipher_suite: str,
        cipher_bits: int,
        leaf_certificate_sha256: str,
        elapsed_seconds: float,
    ) -> str:
        endpoint_digest = url_digest(request.url)
        transcript = (
            f"endpoint_url_sha256: {endpoint_digest}\n"
            f"peer_ip: {peer_ip}\n"
            f"tls_version: {tls_version.value}\n"
            f"cipher_suite: {cipher_suite}\n"
            f"cipher_bits: {cipher_bits}\n"
            f"leaf_certificate_sha256: {leaf_certificate_sha256}\n"
            f"elapsed_seconds: {elapsed_seconds:.6f}"
        )
        evidence = self.store.capture_text(
            transcript,
            kind=EvidenceKind.TLS,
            source_ref=f"url-sha256:{endpoint_digest}",
            producer="broker.tls.pinned-v1",
            target_version=self.target_version,
            summary=f"Verified TLS session with pinned peer {peer_ip}",
        )
        self.records[evidence.evidence_id] = evidence
        return evidence.evidence_id


class PinnedTlsTransport:
    """Connect to one selected IP while verifying the authorized hostname and CA chain."""

    implementation_digest = PINNED_TLS_IMPLEMENTATION_DIGEST

    def __init__(self, evidence_sink: TlsEvidenceSink, *, context: ssl.SSLContext | None = None):
        self.evidence_sink = evidence_sink
        self.context = context or ssl.create_default_context()
        if (
            not self.context.check_hostname
            or self.context.verify_mode != ssl.CERT_REQUIRED
            or self.context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise ValueError("TLS context must verify hostnames and peers with TLS 1.2 or newer")

    def inspect(self, request: TlsWireRequest) -> OfflineTlsHandshake:
        try:
            request = TlsWireRequest.model_validate(request.model_dump(mode="python"))
            if TlsInspectionPlan.safe_https_url(request.url) != request.url:
                raise ValueError("TLS URL is not canonical")
            pinned_ip = str(ipaddress.ip_address(request.pinned_ip))
        except (ValidationError, ValueError) as exc:
            raise LiveTlsRejected("live TLS request failed boundary validation") from exc
        parsed = urlsplit(request.url)
        assert parsed.hostname is not None
        port = parsed.port or 443
        raw: socket.socket | None = None
        wrapped: ssl.SSLSocket | None = None
        started = time.monotonic()
        try:
            raw = socket.create_connection(
                (pinned_ip, port),
                timeout=min(request.connect_seconds, request.total_seconds),
            )
            raw_peer = str(ipaddress.ip_address(raw.getpeername()[0]))
            if raw_peer != pinned_ip:
                raise TlsPeerMismatch("TLS socket peer differs from its pinned IP")
            remaining = request.total_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("TLS total timeout expired before handshake")
            raw.settimeout(min(request.handshake_seconds, remaining))
            wrapped = self.context.wrap_socket(raw, server_hostname=parsed.hostname)
            raw = None
            peer_ip = str(ipaddress.ip_address(wrapped.getpeername()[0]))
            if peer_ip != pinned_ip:
                raise TlsPeerMismatch("TLS socket peer differs from its pinned IP")
            version = TlsProtocolVersion(wrapped.version())
            cipher = wrapped.cipher()
            certificate = wrapped.getpeercert(binary_form=True)
            if cipher is None or certificate is None:
                raise LiveTlsRejected("verified TLS session omitted required identity facts")
            cipher_suite, _, cipher_bits = cipher
            elapsed = time.monotonic() - started
            if elapsed >= request.total_seconds:
                raise TimeoutError("TLS total timeout expired after handshake")
            certificate_digest = hashlib.sha256(certificate).hexdigest()
            evidence_ref = self.evidence_sink.capture(
                request,
                peer_ip=peer_ip,
                tls_version=version,
                cipher_suite=cipher_suite,
                cipher_bits=cipher_bits,
                leaf_certificate_sha256=certificate_digest,
                elapsed_seconds=elapsed,
            )
            return OfflineTlsHandshake(
                peer_ip=peer_ip,
                tls_version=version,
                cipher_suite=cipher_suite,
                cipher_bits=cipher_bits,
                leaf_certificate_sha256=certificate_digest,
                evidence_ref=evidence_ref,
                elapsed_seconds=elapsed,
            )
        except TimeoutError as exc:
            raise TimeoutError("TLS connect or handshake timed out") from exc
        except ssl.SSLError as exc:
            raise LiveTlsRejected("TLS peer verification failed") from exc
        finally:
            if wrapped is not None:
                wrapped.close()
            elif raw is not None:
                raw.close()
