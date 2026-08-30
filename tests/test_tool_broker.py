from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.broker import (
    BrokerCall,
    BrokerIdempotencyConflict,
    BrokerRejected,
    BrokerStatus,
    HttpHeader,
    HttpLimits,
    HttpRequestPlan,
    HttpResponseLimitExceeded,
    OfflineHttpHop,
    OfflineHttpTransport,
    StaticResolver,
    ToolBroker,
    ToolRegistry,
    default_tool_registry,
    pinned_http_tool_registry,
)
from vulnloom.broker.models import broker_call_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    NetworkTargetScope,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import ActionRequest, PolicyEngine
from vulnloom.runners import NetworkGrant, sandbox_profile_digest, validation_profile

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
EVIDENCE = "3" * 64
BODY_SHA256 = "7" * 64
IP = "192.0.2.10"
URL = "https://app.example.test/items?id=7"


def _profile(*hosts: str):
    return validation_profile(
        image_digest=IMAGE,
        snapshot_id=SNAPSHOT,
        network_grants=tuple(
            NetworkGrant(host=host, ports=frozenset({443}), schemes=frozenset({"https"}))
            for host in hosts or ("app.example.test",)
        ),
    )


def _call(now, scope, *, plan=None, profile=None, key="broker:1"):
    profile = profile or _profile("app.example.test")
    plan = plan or HttpRequestPlan(method="GET", url=URL, test_class="read_only")
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=uuid4(),
        target_version="4" * 40,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=default_tool_registry().digest,
        input_refs=("candidate:" + "5" * 64,),
        allowed_tools=frozenset({"http.request"}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=3),
        deadline=now + timedelta(minutes=1),
        idempotency_key="validator:http:1",
    )
    return BrokerCall(
        task=task,
        profile=profile,
        tool_id="http.request",
        http=plan,
        idempotency_key=key,
    )


def _broker(scope, resolver, transport, *, blocked_ips=frozenset()):
    return ToolBroker(
        scope=scope,
        registry=default_tool_registry(),
        resolver=resolver,
        http_transport=transport,
        blocked_ips=blocked_ips,
    )


def _hop(*, status=200, ip=IP, evidence=EVIDENCE, **values):
    payload = {
        "status_code": status,
        "peer_ip": ip,
        "response_bytes": 128,
        "response_body_sha256": BODY_SHA256,
        "evidence_ref": evidence,
        **values,
    }
    return OfflineHttpHop(**payload)


def test_broker_http_success_pins_ip_is_idempotent_and_returns_only_evidence(approved_scope, now):
    resolver = StaticResolver({"app.example.test": (IP,)})
    transport = OfflineHttpTransport({URL: _hop()})
    broker = _broker(approved_scope, resolver, transport)
    call = _call(now, approved_scope)

    first = broker.execute(call, now=now)
    repeated = broker.execute(call, now=now + timedelta(seconds=10))

    assert first is repeated
    assert first.status is BrokerStatus.COMPLETED
    assert first.http is not None
    assert first.http.evidence_refs == (EVIDENCE,)
    assert first.http.response_body_sha256 == BODY_SHA256
    assert first.http.final_url_digest != URL
    assert first.policy_records[0].obligations == (
        "resolve_and_pin_ip",
        "recheck_each_redirect",
    )
    assert len(transport.calls) == 1
    assert first.tool_calls_used == 1
    assert transport.calls[0].pinned_ip == IP
    assert not hasattr(first.http, "body")
    assert not hasattr(first.http, "headers")


def test_scope_and_profile_denials_happen_before_transport(approved_scope, now):
    resolver = StaticResolver({"outside.example": (IP,), "app.example.test": (IP,)})
    transport = OfflineHttpTransport({})
    broker = _broker(approved_scope, resolver, transport)
    outside = _call(
        now,
        approved_scope,
        plan=HttpRequestPlan(method="GET", url="https://outside.example/", test_class="read_only"),
        profile=_profile("outside.example"),
    )
    result = broker.execute(outside, now=now)
    assert result.status is BrokerStatus.DENIED
    assert result.error_codes == ("scope_policy_not_satisfied",)
    assert transport.calls == []

    mismatched_grant = _call(now, approved_scope, profile=_profile("other.example"), key="grant")
    result = broker.execute(mismatched_grant, now=now)
    assert result.status is BrokerStatus.DENIED
    assert result.error_codes == ("sandbox_network_grant_not_satisfied",)
    assert transport.calls == []


@pytest.mark.parametrize(
    ("addresses", "blocked"),
    [
        (("127.0.0.1",), frozenset()),
        (("169.254.169.254",), frozenset()),
        (("100.100.100.200",), frozenset()),
        (("fd00:ec2::254",), frozenset()),
        (("172.17.0.1",), frozenset({"172.17.0.1"})),
        ((IP, "127.0.0.1"), frozenset()),
        (("not-an-ip",), frozenset()),
    ],
)
def test_dns_results_fail_closed_before_transport(approved_scope, now, addresses, blocked):
    resolver = StaticResolver({"app.example.test": addresses})
    transport = OfflineHttpTransport({})
    result = _broker(approved_scope, resolver, transport, blocked_ips=blocked).execute(
        _call(now, approved_scope), now=now
    )
    assert result.status is BrokerStatus.DENIED
    assert result.error_codes == ("resolved_address_forbidden",)
    assert transport.calls == []


def test_empty_dns_and_peer_mismatch_are_denied(approved_scope, now):
    empty_transport = OfflineHttpTransport({})
    result = _broker(approved_scope, StaticResolver({}), empty_transport).execute(
        _call(now, approved_scope), now=now
    )
    assert result.error_codes == ("dns_resolution_failed",)
    assert empty_transport.calls == []

    mismatch = OfflineHttpTransport({URL: _hop(ip="192.0.2.99")})
    result = _broker(approved_scope, StaticResolver({"app.example.test": (IP,)}), mismatch).execute(
        _call(now, approved_scope), now=now
    )
    assert result.status is BrokerStatus.DENIED
    assert result.error_codes == ("http_peer_ip_mismatch",)


def test_redirect_is_reauthorized_resolved_and_pinned_per_hop(approved_scope, now):
    second_host = "api.example.test"
    second_url = "https://api.example.test/next"
    scope = approved_scope.model_copy(
        update={
            "network_targets": (
                *approved_scope.network_targets,
                NetworkTargetScope(
                    host=second_host, ports=frozenset({443}), schemes=frozenset({"https"})
                ),
            )
        }
    )
    plan = HttpRequestPlan(
        method="GET",
        url=URL,
        test_class="read_only",
        follow_redirects=True,
        limits=HttpLimits(max_redirects=1, max_requests=2),
    )
    transport = OfflineHttpTransport(
        {
            URL: _hop(status=302, location=second_url),
            second_url: _hop(ip="192.0.2.20", evidence="6" * 64),
        }
    )
    resolver = StaticResolver({"app.example.test": (IP,), second_host: ("192.0.2.20",)})
    result = _broker(scope, resolver, transport).execute(
        _call(now, scope, plan=plan, profile=_profile("app.example.test", second_host)),
        now=now,
    )

    assert result.status is BrokerStatus.COMPLETED
    assert result.http is not None
    assert result.http.evidence_refs == (EVIDENCE, "6" * 64)
    assert len(result.http.redirects) == 1
    assert len(result.policy_records) == 2
    assert result.tool_calls_used == 2
    assert resolver.calls == ["app.example.test", second_host]
    assert [item.pinned_ip for item in transport.calls] == [IP, "192.0.2.20"]


def test_out_of_scope_and_credentialed_redirects_are_not_followed(approved_scope, now):
    redirect = OfflineHttpTransport(
        {URL: _hop(status=302, location="https://outside.example/next")}
    )
    plan = HttpRequestPlan(
        method="GET",
        url=URL,
        test_class="read_only",
        follow_redirects=True,
        limits=HttpLimits(max_redirects=1, max_requests=2),
    )
    result = _broker(
        approved_scope,
        StaticResolver({"app.example.test": (IP,), "outside.example": ("192.0.2.30",)}),
        redirect,
    ).execute(
        _call(
            now,
            approved_scope,
            plan=plan,
            profile=_profile("app.example.test", "outside.example"),
        ),
        now=now,
    )
    assert result.status is BrokerStatus.DENIED
    assert len(redirect.calls) == 1

    credentialed = plan.model_copy(update={"credential_ref": "7" * 64})
    call = _call(now, approved_scope, plan=credentialed, key="credentialed")
    approval = _approval(call, now, ApprovalAction.USE_REAL_CREDENTIALS)
    transport = OfflineHttpTransport({URL: _hop(status=302, location="/next")})
    result = _broker(
        approved_scope, StaticResolver({"app.example.test": (IP,)}), transport
    ).execute(call, now=now, approvals=(approval,))
    assert result.status is BrokerStatus.DENIED
    assert result.error_codes == ("credentialed_redirect_forbidden",)


def _approval(call, now, action):
    request = ActionRequest(
        engagement_id=call.task.engagement_id,
        target_id=call.task.target_id,
        action=call.tool_id,
        requested_at=now,
        url=call.http.url,
        test_class=call.http.test_class,
        mutates_state=call.http.method.mutates_state,
        uses_real_credentials=call.http.credential_ref is not None,
    )
    return ApprovalRequest(
        engagement_id=call.task.engagement_id,
        target_id=call.task.target_id,
        action=action,
        action_digest=request.digest(),
        expected_side_effects=("authorized HTTP validation",),
        evidence_summary="Candidate selected for controlled validation",
        policy_version=call.task.scope_version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="reviewer",
        decided_at=now,
    )


def test_state_change_and_credential_use_require_exact_approvals(approved_scope, now):
    plan = HttpRequestPlan(
        method="POST",
        url=URL,
        test_class="idor",
        body_ref="8" * 64,
        body_bytes=32,
    )
    call = _call(now, approved_scope, plan=plan)
    transport = OfflineHttpTransport({URL: _hop()})
    broker = _broker(approved_scope, StaticResolver({"app.example.test": (IP,)}), transport)
    result = broker.execute(call, now=now)
    assert result.status is BrokerStatus.APPROVAL_REQUIRED
    assert transport.calls == []

    approval = _approval(call, now, ApprovalAction.MUTATE_TARGET_STATE)
    approved_call = call.model_copy(update={"idempotency_key": "broker:approved"})
    result = broker.execute(approved_call, now=now, approvals=(approval,))
    assert result.status is BrokerStatus.COMPLETED
    assert transport.calls[0].body_ref == "8" * 64

    credential_call = _call(
        now,
        approved_scope,
        plan=HttpRequestPlan(
            method="GET", url=URL, test_class="read_only", credential_ref="9" * 64
        ),
        key="credential",
    )
    result = broker.execute(credential_call, now=now)
    assert result.status is BrokerStatus.APPROVAL_REQUIRED


@pytest.mark.parametrize(
    "payload",
    [
        {"method": "GET", "url": "https://user:pass@app.example.test/", "test_class": "read_only"},
        {
            "method": "GET",
            "url": "https://app.example.test/?token=secret",
            "test_class": "read_only",
        },
        {
            "method": "GET",
            "url": URL,
            "test_class": "read_only",
            "headers": ({"name": "Authorization", "value": "Bearer secret"},),
        },
        {
            "method": "GET",
            "url": URL,
            "test_class": "read_only",
            "headers": ({"name": "X-Test", "value": "bad\r\nInjected: yes"},),
        },
        {
            "method": "GET",
            "url": URL,
            "test_class": "read_only",
            "headers": ({"name": "X-Test", "value": "not-http-🙂"},),
        },
        {
            "method": "GET",
            "url": URL,
            "test_class": "read_only",
            "body_ref": "a" * 64,
            "body_bytes": 1,
        },
        {
            "method": "POST",
            "url": URL,
            "test_class": "idor",
            "follow_redirects": True,
            "limits": {"max_redirects": 1, "max_requests": 2},
        },
    ],
)
def test_http_plan_rejects_credentials_injection_and_incoherent_requests(payload):
    with pytest.raises(ValidationError):
        HttpRequestPlan.model_validate(payload)


def test_timeout_size_transport_failure_and_request_budget_paths(approved_scope, now):
    scenarios = [
        (_hop(elapsed_seconds=16), BrokerStatus.TIMED_OUT, "http_total_timeout"),
        (
            _hop(response_bytes=3 * 1024 * 1024),
            BrokerStatus.FAILED,
            "http_response_size_exceeded",
        ),
    ]
    for index, (hop, status, error) in enumerate(scenarios):
        broker = _broker(
            approved_scope,
            StaticResolver({"app.example.test": (IP,)}),
            OfflineHttpTransport({URL: hop}),
        )
        result = broker.execute(_call(now, approved_scope, key=f"limit:{index}"), now=now)
        assert result.status is status
        assert result.error_codes == (error,)

    failed = _broker(
        approved_scope,
        StaticResolver({"app.example.test": (IP,)}),
        OfflineHttpTransport({}),
    ).execute(_call(now, approved_scope, key="transport"), now=now)
    assert failed.status is BrokerStatus.FAILED
    assert failed.error_codes == ("http_transport_failed",)

    class LiveSizeFailure:
        implementation_digest = OfflineHttpTransport.implementation_digest

        def send(self, request):
            raise HttpResponseLimitExceeded("fixture response too large")

    live_size = _broker(
        approved_scope,
        StaticResolver({"app.example.test": (IP,)}),
        LiveSizeFailure(),
    ).execute(_call(now, approved_scope, key="live-size"), now=now)
    assert live_size.error_codes == ("http_response_size_exceeded",)

    expired = _call(now, approved_scope, key="expired")
    expired = expired.model_copy(update={"task": expired.task.model_copy(update={"deadline": now})})
    result = _broker(approved_scope, StaticResolver({}), OfflineHttpTransport({})).execute(
        expired, now=now
    )
    assert result.status is BrokerStatus.TIMED_OUT

    redirect_plan = HttpRequestPlan(
        method="GET",
        url=URL,
        test_class="read_only",
        follow_redirects=True,
        limits=HttpLimits(max_redirects=1, max_requests=2),
    )
    budget_call = _call(now, approved_scope, plan=redirect_plan, key="budget")
    budget_call = budget_call.model_copy(
        update={
            "task": budget_call.task.model_copy(
                update={"budget": budget_call.task.budget.model_copy(update={"tool_calls": 1})}
            )
        }
    )
    result = _broker(
        approved_scope,
        StaticResolver({"app.example.test": (IP,)}),
        OfflineHttpTransport({URL: _hop(status=302, location="/next")}),
    ).execute(budget_call, now=now)
    assert result.status is BrokerStatus.FAILED
    assert result.error_codes == ("http_request_budget_exhausted",)
    assert result.tool_calls_used == 1


def test_redirect_disabled_and_invalid_redirect_are_denied(approved_scope, now):
    disabled_transport = OfflineHttpTransport({URL: _hop(status=302, location="/next")})
    result = _broker(
        approved_scope,
        StaticResolver({"app.example.test": (IP,)}),
        disabled_transport,
    ).execute(_call(now, approved_scope), now=now)
    assert result.error_codes == ("http_redirect_not_allowed",)
    assert result.tool_calls_used == 1

    plan = HttpRequestPlan(
        method="GET",
        url=URL,
        test_class="read_only",
        follow_redirects=True,
        limits=HttpLimits(max_redirects=1, max_requests=2),
    )
    invalid_transport = OfflineHttpTransport({URL: _hop(status=302, location="/?api_key=secret")})
    result = _broker(
        approved_scope,
        StaticResolver({"app.example.test": (IP,)}),
        invalid_transport,
    ).execute(_call(now, approved_scope, plan=plan, key="invalid-redirect"), now=now)
    assert result.error_codes == ("http_redirect_url_invalid",)
    assert len(invalid_transport.calls) == 1


@pytest.mark.parametrize(
    "failure",
    ["profile", "scope", "policy", "registry_digest", "task", "role", "registry"],
)
def test_broker_preflight_rejects_untrusted_bindings(approved_scope, now, failure):
    call = _call(now, approved_scope)
    registry = default_tool_registry()
    if failure == "profile":
        call = call.model_copy(
            update={"task": call.task.model_copy(update={"sandbox_profile_digest": "a" * 64})}
        )
    elif failure == "scope":
        call = call.model_copy(update={"task": call.task.model_copy(update={"scope_id": uuid4()})})
    elif failure == "policy":
        call = call.model_copy(
            update={"task": call.task.model_copy(update={"policy_digest": "b" * 64})}
        )
    elif failure == "registry_digest":
        call = call.model_copy(
            update={"task": call.task.model_copy(update={"tool_registry_digest": "c" * 64})}
        )
    elif failure == "task":
        call = call.model_copy(
            update={"task": call.task.model_copy(update={"allowed_tools": frozenset()})}
        )
    elif failure == "role":
        call = call.model_copy(
            update={"task": call.task.model_copy(update={"worker_role": WorkerRole.REPORTER})}
        )
    elif failure == "registry":
        registry = ToolRegistry(())
    broker = ToolBroker(
        scope=approved_scope,
        registry=registry,
        resolver=StaticResolver({}),
        http_transport=OfflineHttpTransport({}),
    )
    with pytest.raises(BrokerRejected):
        broker.execute(call, now=now)
    assert broker._results == {}


def test_broker_revalidates_bypassed_models_and_detects_idempotency_conflict(approved_scope, now):
    call = _call(now, approved_scope)
    broker = _broker(
        approved_scope,
        StaticResolver({"app.example.test": (IP,)}),
        OfflineHttpTransport({URL: _hop()}),
    )
    broker.execute(call, now=now)
    changed = call.model_copy(update={"http": call.http.model_copy(update={"url": "not a url"})})
    with pytest.raises(BrokerRejected, match="boundary validation"):
        broker.execute(changed, now=now)

    valid_changed = call.model_copy(
        update={
            "http": call.http.model_copy(
                update={"headers": (HttpHeader(name="accept", value="text/plain"),)}
            )
        }
    )
    with pytest.raises(BrokerIdempotencyConflict):
        broker.execute(valid_changed, now=now)


def test_broker_call_digest_survives_boundary_reparse(approved_scope, now):
    call = _call(now, approved_scope)
    reparsed = BrokerCall.model_validate(call.model_dump(mode="python"))
    assert broker_call_digest(reparsed) == broker_call_digest(call)


def test_broker_rejects_transport_not_bound_by_registry(approved_scope, now):
    registry = pinned_http_tool_registry()
    call = _call(now, approved_scope)
    call = call.model_copy(
        update={
            "task": call.task.model_copy(update={"tool_registry_digest": registry.digest})
        }
    )
    broker = ToolBroker(
        scope=approved_scope,
        registry=registry,
        resolver=StaticResolver({"app.example.test": (IP,)}),
        http_transport=OfflineHttpTransport({URL: _hop()}),
    )
    with pytest.raises(BrokerRejected, match="adapters"):
        broker.execute(call, now=now)
    assert broker._results == {}


def test_registry_is_deterministic_and_rejects_duplicates():
    registry = default_tool_registry()
    registration = registry.require("http.request")
    assert registry.digest == default_tool_registry().digest
    with pytest.raises(ValueError, match="duplicate"):
        ToolRegistry((registration, registration))
    with pytest.raises(ValueError, match="trusted registry"):
        registry.require("missing.tool")
    weakened = registration.model_copy(update={"requires_network": False})
    with pytest.raises(ValueError, match="boundary validation"):
        ToolRegistry((weakened,))
