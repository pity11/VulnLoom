from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.broker import (
    BrokerCall,
    BrokerStatus,
    OfflineTlsHandshake,
    OfflineTlsTransport,
    StaticTlsResolver,
    TlsInspectionLimits,
    TlsInspectionPlan,
    ToolBroker,
    offline_tls_tool_registry,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkGrant, sandbox_profile_digest, validation_profile

URL = "https://app.example.test/"
IP = "192.0.2.10"
IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
EVIDENCE = "3" * 64
CERTIFICATE = "4" * 64


def _profile():
    profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id=SNAPSHOT,
        network_grants=(
            NetworkGrant(
                host="app.example.test",
                ports=frozenset({443}),
                schemes=frozenset({"https"}),
            ),
        ),
    )
    return profile.model_copy(update={"allowed_tools": frozenset({"tls.inspect"})})


def _call(now, scope, *, key="tls:1", limits=None):
    profile = _profile()
    registry = offline_tls_tool_registry()
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=uuid4(),
        target_version="5" * 40,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=registry.digest,
        input_refs=("target:" + "6" * 64,),
        allowed_tools=frozenset({"tls.inspect"}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(minutes=1),
        idempotency_key="validator:tls:1",
    )
    return BrokerCall(
        task=task,
        profile=profile,
        tool_id="tls.inspect",
        tls=TlsInspectionPlan(
            url=URL,
            test_class="read_only",
            limits=limits or TlsInspectionLimits(),
        ),
        idempotency_key=key,
    )


def _handshake(*, peer=IP, elapsed=0.01):
    return OfflineTlsHandshake(
        peer_ip=peer,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        leaf_certificate_sha256=CERTIFICATE,
        evidence_ref=EVIDENCE,
        elapsed_seconds=elapsed,
    )


def _broker(scope, resolver, transport):
    return ToolBroker(
        scope=scope,
        registry=offline_tls_tool_registry(),
        resolver=resolver,
        tls_transport=transport,
    )


def test_tls_broker_is_typed_pinned_redacted_and_idempotent(approved_scope, now):
    transport = OfflineTlsTransport({URL: _handshake()})
    broker = _broker(
        approved_scope,
        StaticTlsResolver({"app.example.test": (IP,)}),
        transport,
    )
    call = _call(now, approved_scope)

    first = broker.execute(call, now=now)
    repeated = broker.execute(call, now=now + timedelta(seconds=1))

    assert first is repeated
    assert first.status is BrokerStatus.COMPLETED
    assert first.http is None
    assert first.tls is not None
    assert first.tls.peer_ip == IP
    assert first.tls.leaf_certificate_sha256 == CERTIFICATE
    assert first.tls.endpoint_url_digest not in URL
    assert len(transport.calls) == 1
    serialized = first.model_dump_json()
    assert URL not in serialized
    assert "BEGIN CERTIFICATE" not in serialized


@pytest.mark.parametrize(
    ("resolver", "transport", "status", "code"),
    [
        (
            StaticTlsResolver({"app.example.test": ("127.0.0.1",)}),
            OfflineTlsTransport({}),
            BrokerStatus.DENIED,
            "resolved_address_forbidden",
        ),
        (
            StaticTlsResolver({"app.example.test": (IP,)}),
            OfflineTlsTransport({URL: _handshake(peer="192.0.2.11")}),
            BrokerStatus.DENIED,
            "tls_peer_ip_mismatch",
        ),
        (
            StaticTlsResolver({"app.example.test": (IP,)}),
            OfflineTlsTransport({URL: _handshake(elapsed=2.0)}),
            BrokerStatus.TIMED_OUT,
            "tls_total_timeout",
        ),
    ],
)
def test_tls_broker_fail_closed_paths(approved_scope, now, resolver, transport, status, code):
    call = _call(
        now,
        approved_scope,
        limits=TlsInspectionLimits(total_seconds=1),
    )
    result = _broker(approved_scope, resolver, transport).execute(call, now=now)
    assert result.status is status
    assert result.error_codes == (code,)
    assert result.tls is None


def test_tls_call_rejects_http_or_credential_shaped_inputs(approved_scope, now):
    call = _call(now, approved_scope)
    with pytest.raises(ValidationError, match="exactly one"):
        BrokerCall.model_validate({**call.model_dump(mode="python"), "http": {
            "method": "GET", "url": URL, "test_class": "read_only"
        }})
    with pytest.raises(ValidationError, match="HTTPS"):
        TlsInspectionPlan(url="http://app.example.test/", test_class="read_only")
