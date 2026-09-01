"""Sealed provider transport admission protocol with an in-memory no-network fake."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from enum import StrEnum
from typing import Self

from pydantic import Field, ValidationError, model_validator

from vulnloom.adapters.model_credentials import (
    ModelCredentialLease,
    ModelCredentialProvider,
    ModelCredentialReference,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .messages import AgentMessageEnvelope
from .models import (
    AgentAdapterKind,
    AgentModelRegistration,
    AgentModelReply,
    AgentStepRequest,
)


class AgentProviderTransportRejected(ValueError):
    pass


class AgentProviderTransportTimedOut(TimeoutError):
    pass


class AgentProviderTransportExhausted(RuntimeError):
    pass


class AgentProviderTransportMode(StrEnum):
    ADMISSION_FAKE = "admission_fake"
    LOOPBACK_HTTPS_PROBE = "loopback_https_probe"
    LIVE_HTTPS = "live_https"


class AgentProviderIpPolicy(StrEnum):
    NONE = "none"
    LOOPBACK_ONLY = "loopback_only"
    GLOBAL_ONLY = "global_only"


class AgentProviderTransportStatus(StrEnum):
    COMPLETED = "completed"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


class AgentProviderTransportLimits(DomainModel):
    max_request_bytes: int = Field(default=1_048_576, gt=0, le=2_162_688)
    max_response_bytes: int = Field(default=1_048_576, gt=0, le=2_097_152)
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_attempts: int = Field(default=1, ge=1, le=1)
    max_requests_per_minute: int = Field(default=30, ge=1, le=120)


class AgentProviderTransportAdmission(DomainModel):
    admission_id: Digest
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    hostname: str = Field(min_length=3, max_length=253)
    port: int = Field(default=443, ge=1, le=65_535)
    request_path: str = Field(min_length=1, max_length=512)
    credential_reference_id: Digest
    adapter_digest: Digest
    mode: AgentProviderTransportMode = AgentProviderTransportMode.ADMISSION_FAKE
    limits: AgentProviderTransportLimits
    tls_required: bool = True
    redirects_allowed: bool = False
    proxy_allowed: bool = False
    dns_revalidation_required: bool = True
    raw_response_persisted: bool = False
    network_enabled: bool = False
    process_isolation_required: bool = False
    ip_policy: AgentProviderIpPolicy = AgentProviderIpPolicy.NONE
    ca_bundle_digest: Digest | None = None
    minimum_tls_version: str = "TLSv1.2"

    @model_validator(mode="after")
    def sealed_non_network_admission(self) -> Self:
        hostname = self.hostname.lower()
        if self.hostname != hostname or not _HOSTNAME.fullmatch(hostname):
            raise ValueError("provider hostname must be canonical ASCII DNS")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("provider hostname cannot be an IP literal")
        if hostname == "localhost" or hostname.endswith((".localhost", ".local")):
            raise ValueError("provider hostname cannot be local")
        if (
            not self.request_path.startswith("/")
            or self.request_path.startswith("//")
            or not _REQUEST_PATH.fullmatch(self.request_path)
            or any(item in self.request_path for item in ("?", "#", "\\", "%", ".."))
        ):
            raise ValueError("provider request path is not canonical")
        if (
            self.redirects_allowed
            or self.proxy_allowed
            or not self.dns_revalidation_required
            or self.raw_response_persisted
        ):
            raise ValueError("provider transport admission cannot relax safeguards")
        if not self.tls_required or self.minimum_tls_version != "TLSv1.2":
            raise ValueError("provider transport requires TLS 1.2 or newer")
        if self.mode is AgentProviderTransportMode.ADMISSION_FAKE:
            if (
                self.port != 443
                or self.network_enabled
                or self.process_isolation_required
                or self.ip_policy is not AgentProviderIpPolicy.NONE
                or self.ca_bundle_digest is not None
            ):
                raise ValueError("M7.4 fake transport cannot enable network")
        elif self.mode is AgentProviderTransportMode.LOOPBACK_HTTPS_PROBE:
            if (
                not self.network_enabled
                or not self.process_isolation_required
                or self.ip_policy is not AgentProviderIpPolicy.LOOPBACK_ONLY
                or self.ca_bundle_digest is None
                or not hostname.endswith(".test")
            ):
                raise ValueError("loopback HTTPS probe admission is invalid")
        elif (
            self.mode is not AgentProviderTransportMode.LIVE_HTTPS
            or not self.network_enabled
            or not self.process_isolation_required
            or self.ip_policy is not AgentProviderIpPolicy.GLOBAL_ONLY
            or self.port != 443
            or hostname.endswith(".test")
        ):
            raise ValueError("live HTTPS provider admission is invalid")
        if self.admission_id != agent_provider_transport_admission_digest(self):
            raise ValueError("provider transport admission content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        hostname: str,
        request_path: str,
        credential_reference_id: str,
        adapter_digest: str,
        limits: AgentProviderTransportLimits,
    ) -> AgentProviderTransportAdmission:
        values = {
            "provider_id": provider_id,
            "hostname": hostname,
            "port": 443,
            "request_path": request_path,
            "credential_reference_id": credential_reference_id,
            "adapter_digest": adapter_digest,
            "mode": AgentProviderTransportMode.ADMISSION_FAKE,
            "limits": limits,
            "tls_required": True,
            "redirects_allowed": False,
            "proxy_allowed": False,
            "dns_revalidation_required": True,
            "raw_response_persisted": False,
            "network_enabled": False,
            "process_isolation_required": False,
            "ip_policy": AgentProviderIpPolicy.NONE,
            "ca_bundle_digest": None,
            "minimum_tls_version": "TLSv1.2",
        }
        digest_values = {**values, "limits": limits.model_dump(mode="python")}
        return cls(admission_id=canonical_digest(digest_values), **values)

    @classmethod
    def create_loopback_probe(
        cls,
        *,
        provider_id: str,
        hostname: str,
        port: int,
        request_path: str,
        credential_reference_id: str,
        adapter_digest: str,
        ca_bundle_digest: str,
        limits: AgentProviderTransportLimits,
    ) -> AgentProviderTransportAdmission:
        return cls._create_networked(
            provider_id=provider_id,
            hostname=hostname,
            port=port,
            request_path=request_path,
            credential_reference_id=credential_reference_id,
            adapter_digest=adapter_digest,
            ca_bundle_digest=ca_bundle_digest,
            limits=limits,
            mode=AgentProviderTransportMode.LOOPBACK_HTTPS_PROBE,
            ip_policy=AgentProviderIpPolicy.LOOPBACK_ONLY,
        )

    @classmethod
    def create_live_https(
        cls,
        *,
        provider_id: str,
        hostname: str,
        request_path: str,
        credential_reference_id: str,
        adapter_digest: str,
        limits: AgentProviderTransportLimits,
        ca_bundle_digest: str | None = None,
    ) -> AgentProviderTransportAdmission:
        return cls._create_networked(
            provider_id=provider_id,
            hostname=hostname,
            port=443,
            request_path=request_path,
            credential_reference_id=credential_reference_id,
            adapter_digest=adapter_digest,
            ca_bundle_digest=ca_bundle_digest,
            limits=limits,
            mode=AgentProviderTransportMode.LIVE_HTTPS,
            ip_policy=AgentProviderIpPolicy.GLOBAL_ONLY,
        )

    @classmethod
    def _create_networked(
        cls,
        *,
        provider_id: str,
        hostname: str,
        port: int,
        request_path: str,
        credential_reference_id: str,
        adapter_digest: str,
        ca_bundle_digest: str | None,
        limits: AgentProviderTransportLimits,
        mode: AgentProviderTransportMode,
        ip_policy: AgentProviderIpPolicy,
    ) -> AgentProviderTransportAdmission:
        values = {
            "provider_id": provider_id,
            "hostname": hostname,
            "port": port,
            "request_path": request_path,
            "credential_reference_id": credential_reference_id,
            "adapter_digest": adapter_digest,
            "mode": mode,
            "limits": limits,
            "tls_required": True,
            "redirects_allowed": False,
            "proxy_allowed": False,
            "dns_revalidation_required": True,
            "raw_response_persisted": False,
            "network_enabled": True,
            "process_isolation_required": True,
            "ip_policy": ip_policy,
            "ca_bundle_digest": ca_bundle_digest,
            "minimum_tls_version": "TLSv1.2",
        }
        digest_values = {**values, "limits": limits.model_dump(mode="python")}
        return cls(admission_id=canonical_digest(digest_values), **values)


def agent_provider_transport_admission_digest(
    admission: AgentProviderTransportAdmission,
) -> str:
    return canonical_digest(admission.model_dump(mode="python", exclude={"admission_id"}))


class AgentProviderTransportRequest(DomainModel):
    transport_request_id: Digest
    step_request_id: Digest
    message_envelope_id: Digest
    transport_admission_id: Digest
    model_registration_id: Digest
    provider_id: str
    model: str
    credential_reference_id: Digest
    request_body_digest: Digest
    request_bytes: int = Field(gt=0, le=2_162_688)
    max_response_bytes: int = Field(gt=0, le=2_097_152)
    timeout_seconds: float = Field(gt=0, le=600)
    attempt_limit: int = Field(ge=1, le=1)

    @model_validator(mode="after")
    def sealed_request(self) -> Self:
        if self.transport_request_id != canonical_digest(
            self.model_dump(mode="python", exclude={"transport_request_id"})
        ):
            raise ValueError("provider transport request content digest mismatch")
        return self


class AgentProviderTransportAttempt(DomainModel):
    attempt_id: Digest
    transport_request_id: Digest
    status: AgentProviderTransportStatus
    captured_response_bytes: int = Field(ge=0, le=2_097_152)
    error_code: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,64}$")
    credential_released: bool
    request_body_released: bool
    raw_response_discarded: bool
    network_opened: bool = False
    process_started: bool = False
    process_terminated: bool = True
    stderr_discarded: bool = True
    peer_ip_digest: Digest | None = None
    tls_version: str | None = Field(default=None, pattern=r"^TLSv1\.[23]$")

    @model_validator(mode="after")
    def sealed_cleanup(self) -> Self:
        if not (
            self.credential_released
            and self.request_body_released
            and self.raw_response_discarded
            and self.process_terminated
            and self.stderr_discarded
        ):
            raise ValueError("provider transport attempt cleanup is incomplete")
        if (self.status is AgentProviderTransportStatus.COMPLETED) != (
            self.error_code is None
        ):
            raise ValueError("provider transport attempt status shape mismatch")
        if self.network_opened != (
            self.peer_ip_digest is not None and self.tls_version is not None
        ):
            raise ValueError("provider transport network proof shape mismatch")
        if self.attempt_id != canonical_digest(
            self.model_dump(mode="python", exclude={"attempt_id"})
        ):
            raise ValueError("provider transport attempt content digest mismatch")
        return self


class AgentProviderTransportReceipt(DomainModel):
    receipt_id: Digest
    transport_request_id: Digest
    attempt_id: Digest
    response_body_digest: Digest
    response_bytes: int = Field(gt=0, le=2_097_152)
    provider_id: str
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_seconds: float = Field(ge=0, le=600)

    @model_validator(mode="after")
    def sealed_receipt(self) -> Self:
        if self.receipt_id != canonical_digest(
            self.model_dump(mode="python", exclude={"receipt_id"})
        ):
            raise ValueError("provider transport receipt content digest mismatch")
        return self


class AdmissionFakeTransportTurn(DomainModel):
    expected_transport_request_id: Digest
    expected_credential_digest: Digest
    structured_output: dict[str, object]
    provider_id: str
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_seconds: float = Field(default=0.01, ge=0, le=600)
    response_padding_bytes: int = Field(default=0, ge=0, le=2_097_152)
    malformed_response: bool = False

    @model_validator(mode="after")
    def bounded_fixture_response(self) -> Self:
        encoded = json.dumps(
            _provider_response_payload(self),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > 2_097_152:
            raise ValueError("admission fake response fixture exceeds the global limit")
        return self


class AdmissionFakeTransportAdapter:
    """Exercises the admitted transport lifecycle without DNS, sockets, HTTP, or SDKs."""

    def __init__(
        self,
        *,
        registration: AgentModelRegistration,
        admission: AgentProviderTransportAdmission,
        credential_reference: ModelCredentialReference,
        credential_provider: ModelCredentialProvider,
        turns: tuple[AdmissionFakeTransportTurn, ...],
    ):
        if (
            registration.adapter_kind is not AgentAdapterKind.ADMISSION_FAKE_TRANSPORT
            or registration.transport_admission_id != admission.admission_id
            or registration.credential_reference_id != credential_reference.reference_id
            or admission.credential_reference_id != credential_reference.reference_id
            or registration.provider_id != admission.provider_id
            or registration.adapter_digest != admission.adapter_digest
        ):
            raise ValueError("admission fake transport binding mismatch")
        self.registration = registration
        self.admission = admission
        self.credential_reference = credential_reference
        self.credential_provider = credential_provider
        self.turns = turns
        self.transport_requests: list[AgentProviderTransportRequest] = []
        self.attempts: list[AgentProviderTransportAttempt] = []
        self.receipts: list[AgentProviderTransportReceipt] = []
        self.released_leases: list[ModelCredentialLease] = []
        self.released_request_bodies: list[bytearray] = []
        self.discarded_response_bodies: list[bytearray] = []
        self._index = 0

    def complete(
        self,
        request: AgentStepRequest,
        *,
        message_envelope: AgentMessageEnvelope | None = None,
    ) -> AgentModelReply:
        if self._index >= len(self.turns):
            raise AgentProviderTransportExhausted(
                "admission fake transport turns are exhausted"
            )
        if (
            message_envelope is None
            or request.message_envelope_id != message_envelope.envelope_id
        ):
            raise AgentProviderTransportRejected(
                "provider transport request/envelope binding mismatch"
            )
        request_body = _provider_request_body(self.registration, message_envelope)
        try:
            transport_request = _transport_request(
                request=request,
                envelope=message_envelope,
                registration=self.registration,
                admission=self.admission,
                request_body=request_body,
            )
        except AgentProviderTransportRejected:
            _zero(request_body)
            self.released_request_bodies.append(request_body)
            raise
        turn = self.turns[self._index]
        if transport_request.transport_request_id != turn.expected_transport_request_id:
            _zero(request_body)
            self.released_request_bodies.append(request_body)
            raise AgentProviderTransportRejected(
                "provider transport request digest mismatch"
            )
        self._index += 1
        self.transport_requests.append(transport_request)
        lease: ModelCredentialLease | None = None
        response_body: bytearray | None = None
        status = AgentProviderTransportStatus.REJECTED
        error_code = "provider_transport_rejected"
        captured = 0
        response_digest: str | None = None
        try:
            lease = self.credential_provider.acquire(self.credential_reference)
            with lease:
                observed_credential = hashlib.sha256(lease.view()).hexdigest()
                if not hmac.compare_digest(
                    observed_credential, turn.expected_credential_digest
                ):
                    raise AgentProviderTransportRejected(
                        "provider transport credential mismatch"
                    )
                if turn.latency_seconds > self.admission.limits.timeout_seconds:
                    status = AgentProviderTransportStatus.TIMED_OUT
                    error_code = "provider_transport_timeout"
                    raise AgentProviderTransportTimedOut(
                        "provider transport wall budget exceeded"
                    )
                response_body = _provider_response_body(turn)
                response_digest = hashlib.sha256(response_body).hexdigest()
                captured = min(
                    len(response_body), self.admission.limits.max_response_bytes
                )
                if len(response_body) > self.admission.limits.max_response_bytes:
                    error_code = "provider_response_size_exceeded"
                    raise AgentProviderTransportRejected(
                        "provider response exceeds the capture limit"
                    )
                reply = _parse_provider_response(response_body)
                if (
                    reply.provider_id != self.registration.provider_id
                    or reply.model != self.registration.model
                ):
                    error_code = "provider_response_identity_mismatch"
                    raise AgentProviderTransportRejected(
                        "provider response identity mismatch"
                    )
                status = AgentProviderTransportStatus.COMPLETED
                error_code = ""
        except (AgentProviderTransportRejected, AgentProviderTransportTimedOut):
            raise
        finally:
            if lease is not None:
                lease.close()
                self.released_leases.append(lease)
            if response_body is not None:
                _zero(response_body)
                self.discarded_response_bodies.append(response_body)
            _zero(request_body)
            self.released_request_bodies.append(request_body)
            attempt_values = {
                "transport_request_id": transport_request.transport_request_id,
                "status": status,
                "captured_response_bytes": captured,
                "error_code": (
                    None
                    if status is AgentProviderTransportStatus.COMPLETED
                    else error_code
                ),
                "credential_released": lease is None or lease.zeroed,
                "request_body_released": not any(request_body),
                "raw_response_discarded": response_body is None or not any(response_body),
                "network_opened": False,
                "process_started": False,
                "process_terminated": True,
                "stderr_discarded": True,
                "peer_ip_digest": None,
                "tls_version": None,
            }
            attempt = AgentProviderTransportAttempt(
                attempt_id=canonical_digest(attempt_values), **attempt_values
            )
            self.attempts.append(attempt)
        assert response_digest is not None
        receipt_values = {
            "transport_request_id": transport_request.transport_request_id,
            "attempt_id": self.attempts[-1].attempt_id,
            "response_body_digest": response_digest,
            "response_bytes": captured,
            "provider_id": reply.provider_id,
            "model": reply.model,
            "input_tokens": reply.input_tokens,
            "output_tokens": reply.output_tokens,
            "latency_seconds": reply.latency_seconds,
        }
        self.receipts.append(
            AgentProviderTransportReceipt(
                receipt_id=canonical_digest(receipt_values), **receipt_values
            )
        )
        return reply


def prepare_agent_provider_transport_request(
    *,
    request: AgentStepRequest,
    envelope: AgentMessageEnvelope,
    registration: AgentModelRegistration,
    admission: AgentProviderTransportAdmission,
) -> AgentProviderTransportRequest:
    """Derive the sealed summary request while discarding the transient body."""
    request_body = _provider_request_body(registration, envelope)
    try:
        return _transport_request(
            request=request,
            envelope=envelope,
            registration=registration,
            admission=admission,
            request_body=request_body,
        )
    finally:
        _zero(request_body)


def _transport_request(
    *,
    request: AgentStepRequest,
    envelope: AgentMessageEnvelope,
    registration: AgentModelRegistration,
    admission: AgentProviderTransportAdmission,
    request_body: bytearray,
) -> AgentProviderTransportRequest:
    if (
        request.request_id != canonical_digest(
            request.model_dump(mode="python", exclude={"request_id"})
        )
        or request.plan_id != envelope.plan_id
        or request.task_id != envelope.task_id
        or request.step != envelope.step
        or request.worker_role is not envelope.worker_role
        or request.context_digest != envelope.context_snapshot_id
        or request.allowed_tools != envelope.allowed_tools
        or request.decision_schema_digest != envelope.decision_schema_digest
        or request.max_output_tokens != envelope.max_output_tokens
        or envelope.model_registration_id != registration.registration_id
        or len(request_body) > admission.limits.max_request_bytes
    ):
        raise AgentProviderTransportRejected("provider transport request binding rejected")
    values = {
        "step_request_id": request.request_id,
        "message_envelope_id": envelope.envelope_id,
        "transport_admission_id": admission.admission_id,
        "model_registration_id": registration.registration_id,
        "provider_id": registration.provider_id,
        "model": registration.model,
        "credential_reference_id": admission.credential_reference_id,
        "request_body_digest": hashlib.sha256(request_body).hexdigest(),
        "request_bytes": len(request_body),
        "max_response_bytes": admission.limits.max_response_bytes,
        "timeout_seconds": admission.limits.timeout_seconds,
        "attempt_limit": admission.limits.max_attempts,
    }
    return AgentProviderTransportRequest(
        transport_request_id=canonical_digest(values), **values
    )


def _provider_request_body(
    registration: AgentModelRegistration, envelope: AgentMessageEnvelope
) -> bytearray:
    payload = {
        "contract": "vulnloom.provider-transport-request.v1",
        "max_output_tokens": envelope.max_output_tokens,
        "messages": [
            {"content": item.content, "role": item.role.value}
            for item in envelope.messages
        ],
        "model": registration.model,
        "response_schema_digest": envelope.decision_schema_digest,
    }
    return bytearray(
        json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    )


def _provider_response_payload(turn: AdmissionFakeTransportTurn) -> dict[str, object]:
    return {
        "input_tokens": turn.input_tokens,
        "latency_seconds": turn.latency_seconds,
        "model": turn.model,
        "output_tokens": turn.output_tokens,
        "provider_id": turn.provider_id,
        "structured_output": turn.structured_output,
    }


def _provider_response_body(turn: AdmissionFakeTransportTurn) -> bytearray:
    if turn.malformed_response:
        return bytearray(b"{")
    encoded = json.dumps(
        _provider_response_payload(turn),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return bytearray(encoded + (b" " * turn.response_padding_bytes))


def _parse_provider_response(raw: bytearray) -> AgentModelReply:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentProviderTransportRejected(
            "provider response is not strict JSON"
        ) from exc
    expected = {
        "input_tokens",
        "latency_seconds",
        "model",
        "output_tokens",
        "provider_id",
        "structured_output",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise AgentProviderTransportRejected("provider response shape mismatch")
    try:
        return AgentModelReply.model_validate(payload)
    except ValidationError as exc:
        raise AgentProviderTransportRejected("provider response validation failed") from exc


def _zero(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


_HOSTNAME = re.compile(
    r"(?=.{3,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_REQUEST_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@/-]*")
