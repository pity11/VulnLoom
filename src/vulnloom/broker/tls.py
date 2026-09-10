"""TLS inspection adapter contracts and deterministic offline transport."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from pydantic import Field

from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .implementation import OFFLINE_TLS_IMPLEMENTATION_DIGEST
from .models import TlsProtocolVersion


class TlsWireRequest(DomainModel):
    url: str
    pinned_ip: str
    connect_seconds: float = Field(gt=0, le=30)
    handshake_seconds: float = Field(gt=0, le=30)
    total_seconds: float = Field(gt=0, le=60)


class OfflineTlsHandshake(DomainModel):
    peer_ip: str = Field(min_length=1, max_length=64)
    tls_version: TlsProtocolVersion
    cipher_suite: str = Field(pattern=r"^[A-Z0-9_-]{1,128}$")
    cipher_bits: int = Field(ge=112, le=1024)
    leaf_certificate_sha256: Digest
    evidence_ref: Digest
    elapsed_seconds: float = Field(default=0.01, ge=0)


@runtime_checkable
class TlsTransport(Protocol):
    def inspect(self, request: TlsWireRequest) -> OfflineTlsHandshake: ...


class OfflineTlsTransport:
    """Returns a sealed handshake and never opens a socket."""

    implementation_digest = OFFLINE_TLS_IMPLEMENTATION_DIGEST

    def __init__(self, handshakes: Mapping[str, OfflineTlsHandshake]):
        self.handshakes = dict(handshakes)
        self.calls: list[TlsWireRequest] = []

    def inspect(self, request: TlsWireRequest) -> OfflineTlsHandshake:
        self.calls.append(request)
        try:
            return self.handshakes[request.url]
        except KeyError as exc:
            raise RuntimeError("offline TLS handshake is not configured") from exc


class StaticTlsResolver:
    implementation_digest = OFFLINE_TLS_IMPLEMENTATION_DIGEST

    def __init__(self, records: Mapping[str, tuple[str, ...]]):
        self.records = {host.lower(): addresses for host, addresses in records.items()}
        self.calls: list[str] = []

    def resolve(self, host: str) -> tuple[str, ...]:
        normalized = host.lower()
        self.calls.append(normalized)
        try:
            return (str(ipaddress.ip_address(normalized)),)
        except ValueError:
            return self.records.get(normalized, ())
