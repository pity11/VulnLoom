"""Network adapter contracts and deterministic offline implementations."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Annotated, Protocol, Self, runtime_checkable

from pydantic import Field, model_validator

from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .implementation import OFFLINE_HTTP_IMPLEMENTATION_DIGEST
from .models import HttpHeader, HttpMethod


class HttpWireRequest(DomainModel):
    method: HttpMethod
    url: str
    pinned_ip: str
    headers: Annotated[tuple[HttpHeader, ...], Field(max_length=64)]
    credential_ref: Digest | None = None
    body_ref: Digest | None = None
    body_bytes: int = Field(ge=0, le=20 * 1024 * 1024)
    connect_seconds: float = Field(gt=0, le=30)
    read_seconds: float = Field(gt=0, le=60)
    max_response_bytes: int = Field(gt=0, le=20 * 1024 * 1024)

    @model_validator(mode="after")
    def coherent_wire_shape(self) -> Self:
        if (self.body_ref is None) != (self.body_bytes == 0):
            raise ValueError("HTTP wire body reference and size must be supplied together")
        if self.method in {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS} and self.body_ref:
            raise ValueError("read-only HTTP wire methods cannot carry a body")
        names = [header.name for header in self.headers]
        if len(names) != len(set(names)):
            raise ValueError("duplicate HTTP wire headers are not allowed")
        return self


class OfflineHttpHop(DomainModel):
    status_code: int = Field(ge=100, le=599)
    peer_ip: str = Field(min_length=1)
    response_bytes: int = Field(ge=0)
    response_body_sha256: Digest
    evidence_ref: Digest
    elapsed_seconds: float = Field(default=0.01, ge=0)
    location: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def redirect_shape(self):
        redirect = self.status_code in {301, 302, 303, 307, 308}
        if redirect != (self.location is not None):
            raise ValueError("offline redirect status and location disagree")
        return self


@runtime_checkable
class HostResolver(Protocol):
    def resolve(self, host: str) -> tuple[str, ...]: ...


@runtime_checkable
class HttpTransport(Protocol):
    def send(self, request: HttpWireRequest) -> OfflineHttpHop: ...


class StaticResolver:
    implementation_digest = OFFLINE_HTTP_IMPLEMENTATION_DIGEST

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


class OfflineHttpTransport:
    """Returns predeclared hops and never opens a socket."""

    implementation_digest = OFFLINE_HTTP_IMPLEMENTATION_DIGEST

    def __init__(self, hops: Mapping[str, OfflineHttpHop]):
        self.hops = dict(hops)
        self.calls: list[HttpWireRequest] = []

    def send(self, request: HttpWireRequest) -> OfflineHttpHop:
        self.calls.append(request)
        try:
            return self.hops[request.url]
        except KeyError as exc:
            raise RuntimeError("offline HTTP hop is not configured") from exc
