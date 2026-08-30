"""Tool registry, Broker call, and typed HTTP contracts."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Self
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.domain.protocol import TaskEnvelope
from vulnloom.policy.engine import DecisionEffect
from vulnloom.runners.models import (
    Digest,
    SandboxProfile,
    SandboxProfileKind,
    sandbox_profile_digest,
)

ToolId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]


class ToolCapability(StrEnum):
    HTTP_REQUEST = "http_request"


class SideEffectMode(StrEnum):
    READ_ONLY = "read_only"
    CONDITIONAL = "conditional"


class ToolRegistration(DomainModel):
    tool_id: ToolId
    version: str = Field(min_length=1, max_length=64)
    capability: ToolCapability
    allowed_profiles: frozenset[SandboxProfileKind]
    requires_network: bool
    accepts_credential_ref: bool
    side_effect_mode: SideEffectMode
    implementation_digest: Digest

    @model_validator(mode="after")
    def capability_invariants(self) -> Self:
        if self.capability is ToolCapability.HTTP_REQUEST and (
            not self.requires_network
            or not self.allowed_profiles
            or not self.allowed_profiles <= {SandboxProfileKind.VALIDATION}
            or self.side_effect_mode is not SideEffectMode.CONDITIONAL
        ):
            raise ValueError("HTTP tool registration violates capability invariants")
        return self


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"

    @property
    def mutates_state(self) -> bool:
        return self not in {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS}


_SENSITIVE_HEADER = re.compile(
    r"(?:authorization|cookie|token|secret|api[-_]?key|session|credential)", re.IGNORECASE
)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_FORBIDDEN_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class HttpHeader(DomainModel):
    name: str
    value: str = Field(max_length=4096)

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        normalized = value.lower()
        if (
            not _HEADER_NAME.fullmatch(value)
            or _SENSITIVE_HEADER.search(normalized)
            or normalized in _FORBIDDEN_HEADERS
        ):
            raise ValueError("sensitive or invalid HTTP header name")
        return normalized

    @field_validator("value")
    @classmethod
    def no_header_injection(cls, value: str) -> str:
        if "\r" in value or "\n" in value or "\x00" in value:
            raise ValueError("HTTP header value contains control characters")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError("HTTP header value is not Latin-1 encodable") from exc
        return value


class HttpLimits(DomainModel):
    connect_seconds: float = Field(default=3.0, gt=0, le=30)
    read_seconds: float = Field(default=10.0, gt=0, le=60)
    total_seconds: float = Field(default=15.0, gt=0, le=120)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, gt=0, le=20 * 1024 * 1024)
    max_redirects: int = Field(default=0, ge=0, le=5)
    max_requests: int = Field(default=1, ge=1, le=6)

    @model_validator(mode="after")
    def redirects_fit_request_budget(self) -> Self:
        if self.max_requests < self.max_redirects + 1:
            raise ValueError("HTTP max_requests must cover the redirect budget")
        return self


class HttpRequestPlan(DomainModel):
    method: HttpMethod
    url: str = Field(min_length=1, max_length=2048)
    test_class: str = Field(min_length=1, max_length=128)
    headers: Annotated[tuple[HttpHeader, ...], Field(max_length=64)] = ()
    credential_ref: Digest | None = None
    body_ref: Digest | None = None
    body_bytes: int = Field(default=0, ge=0, le=20 * 1024 * 1024)
    follow_redirects: bool = False
    limits: HttpLimits = Field(default_factory=HttpLimits)

    @field_validator("url")
    @classmethod
    def safe_url(cls, value: str) -> str:
        if any(ord(character) <= 32 for character in value) or "\\" in value:
            raise ValueError("HTTP URL contains whitespace, controls, or backslashes")
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise ValueError("HTTP URL must be absolute, credential-free, and fragment-free")
        sensitive_query = re.compile(
            r"(?:token|secret|password|passwd|api[-_]?key|auth|session|cookie)",
            re.IGNORECASE,
        )
        if any(sensitive_query.search(name) for name, _ in parse_qsl(parsed.query)):
            raise ValueError("credential-like query parameters are not allowed")
        host = parsed.hostname.lower()
        port = parsed.port
        netloc = f"[{host}]" if ":" in host else host
        if port is not None:
            netloc = f"{netloc}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))

    @model_validator(mode="after")
    def coherent_body_and_redirects(self) -> Self:
        if (self.body_ref is None) != (self.body_bytes == 0):
            raise ValueError("HTTP body_ref and body_bytes must be supplied together")
        if self.method in {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS} and self.body_ref:
            raise ValueError("read-only HTTP methods cannot carry a request body")
        if self.method.mutates_state and self.follow_redirects:
            raise ValueError("state-changing HTTP methods cannot follow redirects automatically")
        if self.follow_redirects != (self.limits.max_redirects > 0):
            raise ValueError("HTTP redirect flag and limit disagree")
        names = [header.name for header in self.headers]
        if len(names) != len(set(names)):
            raise ValueError("duplicate HTTP header names are not allowed")
        return self


class BrokerCall(DomainModel):
    call_id: UUID = Field(default_factory=uuid4)
    task: TaskEnvelope
    profile: SandboxProfile
    tool_id: ToolId
    http: HttpRequestPlan
    idempotency_key: str = Field(min_length=1, max_length=256)


def broker_call_digest(call: BrokerCall) -> str:
    return canonical_digest(call.model_dump(mode="python", exclude={"call_id"}))


class PolicyRecord(DomainModel):
    action_digest: Digest
    effect: DecisionEffect
    reasons: tuple[str, ...]
    obligations: tuple[str, ...]
    policy_digest: Digest


class RedirectRecord(DomainModel):
    status_code: int = Field(ge=300, le=399)
    from_url_digest: Digest
    to_url_digest: Digest
    peer_ip: str = Field(min_length=1)


class HttpToolResult(DomainModel):
    status_code: int = Field(ge=100, le=599)
    final_url_digest: Digest
    peer_ip: str = Field(min_length=1)
    response_bytes: int = Field(ge=0)
    redirects: tuple[RedirectRecord, ...] = ()
    evidence_refs: tuple[Digest, ...]


class BrokerStatus(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class BrokerResult(DomainModel):
    call_id: UUID
    task_id: UUID
    tool_id: ToolId
    status: BrokerStatus
    registry_digest: Digest
    call_digest: Digest
    tool_calls_used: int = Field(ge=0)
    policy_records: tuple[PolicyRecord, ...] = ()
    http: HttpToolResult | None = None
    error_codes: tuple[str, ...] = ()
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def result_shape_matches_status(self) -> Self:
        if self.status is BrokerStatus.COMPLETED and self.http is None:
            raise ValueError("completed Broker result requires typed tool output")
        if self.status is not BrokerStatus.COMPLETED and self.http is not None:
            raise ValueError("non-completed Broker result cannot include tool output")
        return self


def sandbox_binding_matches(call: BrokerCall) -> bool:
    return call.task.sandbox_profile_digest == sandbox_profile_digest(call.profile)


def url_digest(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()
