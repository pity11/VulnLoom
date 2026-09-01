"""Rate-limited, DNS-pinned HTTPS provider adapter over a fixed subprocess."""

from __future__ import annotations

import hashlib
import ipaddress
import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.adapters.model_credentials import (
    ModelCredentialLease,
    ModelCredentialProvider,
    ModelCredentialReference,
)
from vulnloom.broker.live_http import SystemResolver
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import utc_now

from .messages import AgentMessageEnvelope
from .models import (
    AgentAdapterKind,
    AgentModelRegistration,
    AgentModelReply,
    AgentStepRequest,
)
from .provider_admission import (
    AgentProviderEgressRecoveryRequired,
    AgentProviderEgressRejected,
    AgentProviderEgressStore,
)
from .provider_process import (
    SUBPROCESS_HTTPS_ADAPTER_DIGEST,
    ProviderProcessExecutionError,
    ProviderProcessResult,
    SubprocessProviderTransportRunner,
)
from .transport import (
    AgentProviderIpPolicy,
    AgentProviderTransportAdmission,
    AgentProviderTransportAttempt,
    AgentProviderTransportReceipt,
    AgentProviderTransportRejected,
    AgentProviderTransportRequest,
    AgentProviderTransportStatus,
    AgentProviderTransportTimedOut,
    _parse_provider_response,
    _provider_request_body,
    _transport_request,
    _zero,
)


class ProviderResolver(Protocol):
    def resolve(self, host: str) -> tuple[str, ...]: ...


class ProviderProcessRunner(Protocol):
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
    ) -> ProviderProcessResult: ...


class SubprocessHttpsProviderAdapter:
    def __init__(
        self,
        *,
        registration: AgentModelRegistration,
        admission: AgentProviderTransportAdmission,
        credential_reference: ModelCredentialReference,
        credential_provider: ModelCredentialProvider,
        egress_store: AgentProviderEgressStore,
        ca_bundle: bytes | None = None,
        resolver: ProviderResolver | None = None,
        process_runner: ProviderProcessRunner | None = None,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = utc_now,
    ):
        if (
            registration.adapter_kind is not AgentAdapterKind.SUBPROCESS_HTTPS_PROVIDER
            or registration.transport_admission_id != admission.admission_id
            or registration.credential_reference_id != credential_reference.reference_id
            or admission.credential_reference_id != credential_reference.reference_id
            or registration.provider_id != admission.provider_id
            or registration.adapter_digest != SUBPROCESS_HTTPS_ADAPTER_DIGEST
            or admission.adapter_digest != SUBPROCESS_HTTPS_ADAPTER_DIGEST
            or not admission.network_enabled
            or not admission.process_isolation_required
            or admission.ip_policy is AgentProviderIpPolicy.NONE
        ):
            raise ValueError("subprocess HTTPS provider binding mismatch")
        if admission.ca_bundle_digest is None:
            if ca_bundle is not None:
                raise ValueError("unexpected provider CA bundle")
        elif (
            ca_bundle is None
            or len(ca_bundle) > 1_048_576
            or hashlib.sha256(ca_bundle).hexdigest() != admission.ca_bundle_digest
        ):
            raise ValueError("provider CA bundle binding mismatch")
        self.registration = registration
        self.admission = admission
        self.credential_reference = credential_reference
        self.credential_provider = credential_provider
        self.egress_store = egress_store
        self.ca_bundle = ca_bundle
        self.resolver = resolver or SystemResolver()
        self.process_runner = process_runner or SubprocessProviderTransportRunner()
        self.clock = clock
        self.now = now
        self.transport_requests: list[AgentProviderTransportRequest] = []
        self.attempts: list[AgentProviderTransportAttempt] = []
        self.receipts: list[AgentProviderTransportReceipt] = []
        self.released_leases: list[ModelCredentialLease] = []
        self.released_request_bodies: list[bytearray] = []
        self.discarded_response_bodies: list[bytearray] = []
        self._request_times: list[float] = []

    def complete(
        self,
        request: AgentStepRequest,
        *,
        message_envelope: AgentMessageEnvelope | None = None,
    ) -> AgentModelReply:
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
        self.transport_requests.append(transport_request)
        lease: ModelCredentialLease | None = None
        process_result: ProviderProcessResult | None = None
        response_body: bytearray | None = None
        status = AgentProviderTransportStatus.REJECTED
        error_code = "provider_transport_rejected"
        captured = 0
        peer_ip_digest: str | None = None
        tls_version: str | None = None
        response_digest: str | None = None
        process_started = False
        process_terminated = True
        stderr_discarded = True
        try:
            try:
                self.egress_store.require_active(
                    self.registration.egress_grant_id,
                    admission=self.admission,
                    now=self.now(),
                )
            except AgentProviderEgressRecoveryRequired as exc:
                error_code = "provider_egress_recovery_required"
                raise AgentProviderTransportRejected(
                    "provider egress lifecycle is unresolved"
                ) from exc
            except AgentProviderEgressRejected as exc:
                error_code = "provider_egress_admission_rejected"
                raise AgentProviderTransportRejected(
                    "provider egress grant rejected"
                ) from exc
            pinned_ip = self._resolve_pinned_ip()
            self._consume_rate_slot()
            lease = self.credential_provider.acquire(self.credential_reference)
            with lease:
                try:
                    process_result = self.process_runner.exchange(
                        hostname=self.admission.hostname,
                        port=self.admission.port,
                        request_path=self.admission.request_path,
                        pinned_ip=pinned_ip,
                        request_body=request_body,
                        credential=lease.view(),
                        ca_bundle=self.ca_bundle,
                        timeout_seconds=self.admission.limits.timeout_seconds,
                        max_response_bytes=self.admission.limits.max_response_bytes,
                    )
                except ProviderProcessExecutionError as exc:
                    process_started = exc.process_started
                    process_terminated = exc.process_terminated
                    stderr_discarded = exc.stderr_discarded
                    captured = exc.captured_bytes
                    error_code = exc.code
                    if exc.timed_out:
                        status = AgentProviderTransportStatus.TIMED_OUT
                        raise AgentProviderTransportTimedOut(
                            "provider subprocess timed out"
                        ) from exc
                    raise AgentProviderTransportRejected(
                        "provider subprocess rejected the request"
                    ) from exc
                response_body = process_result.response_body
                process_started = process_result.process_started
                process_terminated = process_result.process_terminated
                stderr_discarded = process_result.stderr_discarded
                captured = len(response_body)
                if (
                    process_result.peer_ip != pinned_ip
                    or process_result.tls_version not in {"TLSv1.2", "TLSv1.3"}
                    or not process_result.process_started
                    or not process_result.process_terminated
                    or not process_result.stderr_discarded
                ):
                    error_code = "provider_process_network_proof_mismatch"
                    raise AgentProviderTransportRejected(
                        "provider process network proof mismatch"
                    )
                peer_ip_digest = canonical_digest(process_result.peer_ip)
                tls_version = process_result.tls_version
                response_digest = hashlib.sha256(response_body).hexdigest()
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
        except AgentProviderTransportTimedOut:
            raise
        except AgentProviderTransportRejected:
            raise
        except (OSError, ValueError) as exc:
            raise AgentProviderTransportRejected(
                "provider transport preflight rejected"
            ) from exc
        finally:
            if lease is not None:
                lease.close()
                self.released_leases.append(lease)
            if response_body is not None:
                _zero(response_body)
                self.discarded_response_bodies.append(response_body)
            _zero(request_body)
            self.released_request_bodies.append(request_body)
            network_verified = peer_ip_digest is not None and tls_version is not None
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
                "network_opened": network_verified,
                "process_started": process_started,
                "process_terminated": process_terminated,
                "stderr_discarded": stderr_discarded,
                "peer_ip_digest": peer_ip_digest,
                "tls_version": tls_version,
            }
            self.attempts.append(
                AgentProviderTransportAttempt(
                    attempt_id=canonical_digest(attempt_values), **attempt_values
                )
            )
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
            "latency_seconds": process_result.latency_seconds,
        }
        self.receipts.append(
            AgentProviderTransportReceipt(
                receipt_id=canonical_digest(receipt_values), **receipt_values
            )
        )
        return reply

    def _resolve_pinned_ip(self) -> str:
        addresses = self.resolver.resolve(self.admission.hostname)
        if not addresses or len(addresses) > 32:
            raise AgentProviderTransportRejected("provider DNS resolution rejected")
        normalized: set[str] = set()
        for value in addresses:
            address = ipaddress.ip_address(value)
            if self.admission.ip_policy is AgentProviderIpPolicy.GLOBAL_ONLY:
                allowed = address.is_global
            else:
                allowed = address.is_loopback
            if not allowed:
                raise AgentProviderTransportRejected("provider resolved address is forbidden")
            normalized.add(str(address))
        if not normalized:
            raise AgentProviderTransportRejected("provider DNS resolution rejected")
        return sorted(normalized)[0]

    def _consume_rate_slot(self) -> None:
        now = self.clock()
        self._request_times = [item for item in self._request_times if now - item < 60]
        if len(self._request_times) >= self.admission.limits.max_requests_per_minute:
            raise AgentProviderTransportRejected("provider rate limit exceeded")
        self._request_times.append(now)
