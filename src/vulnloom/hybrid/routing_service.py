"""Fail-closed materialization of exact live Validation plans."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlsplit

from vulnloom.broker import (
    BrokerCall,
    HttpLimits,
    HttpMethod,
    HttpRequestPlan,
    ToolRegistry,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Candidate, CandidateState, Scope, ScopeState, ValidationResult
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    NetworkGrant,
    SandboxProfile,
    SandboxRunRequest,
    ToolInvocation,
    validation_profile,
)
from vulnloom.runners.models import sandbox_profile_digest
from vulnloom.validation import HttpResponseAssertion, ValidationPlan

from .models import DeploymentProof
from .routing_adapters import LiveEndpointProvider, LiveEndpointUnavailable
from .routing_models import (
    HybridRouteOutcome,
    HybridRoutePolicy,
    HybridRouteRequest,
    HybridRouteState,
    LiveEndpointReference,
)
from .routing_store import HybridRouteStore


class HybridRouteRejected(ValueError):
    pass


class HybridRouteService:
    def __init__(
        self,
        *,
        policy: HybridRoutePolicy,
        tool_registry: ToolRegistry,
        endpoint_provider: LiveEndpointProvider,
        store: HybridRouteStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.policy = policy
        if tool_registry.digest != policy.tool_registry_digest:
            raise ValueError("Hybrid Route Policy is bound to another Tool Registry")
        self.tool_registry = tool_registry
        self.endpoint_provider = endpoint_provider
        self.store = store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        candidate: Candidate,
        deployment_proof: DeploymentProof,
        endpoint_reference: LiveEndpointReference,
        expected_status_code: int,
        expected_body_sha256: str,
        test_class: str,
        scope: Scope,
        selected_by: str,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> HybridRouteRequest:
        self._preflight_source(
            candidate=candidate,
            proof=deployment_proof,
            scope=scope,
            now=created_at,
        )
        values = {
            "candidate_id": candidate.candidate_id,
            "candidate_digest": self._digest(candidate),
            "source_target_id": candidate.target_id,
            "source_target_version": candidate.target_version,
            "source_manifest_digest": deployment_proof.source_manifest_digest,
            "live_target_id": deployment_proof.live_target_id,
            "deployment_proof_id": deployment_proof.proof_id,
            "deployment_proof_digest": self._digest(deployment_proof),
            "endpoint_reference": endpoint_reference,
            "endpoint_url_digest": deployment_proof.endpoint_url_digest,
            "expected_status_code": expected_status_code,
            "expected_body_sha256": expected_body_sha256,
            "test_class": test_class,
            "scope_id": scope.scope_id,
            "scope_version": scope.version,
            "route_policy_id": self.policy.policy_id,
            "selected_by": selected_by,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        request = HybridRouteRequest.create(**values)
        if (
            request.deadline > scope.valid_until
            or request.deadline > deployment_proof.expires_at
            or request.test_class not in scope.allowed_test_classes
        ):
            raise HybridRouteRejected("Hybrid Route exceeds its authorized bounds")
        return request

    def execute(
        self,
        request: HybridRouteRequest,
        *,
        candidate: Candidate,
        deployment_proof: DeploymentProof,
        scope: Scope,
        now: datetime,
        recover: bool = False,
    ) -> HybridRouteOutcome:
        self._preflight_request(
            request,
            candidate=candidate,
            proof=deployment_proof,
            scope=scope,
            now=now,
        )
        claim = (
            self.store.recover(request, self.policy, now=now)
            if recover
            else self.store.claim(request, now=now)
        )
        if not claim.created:
            assert claim.outcome is not None
            if claim.outcome.state is HybridRouteState.COMPLETED:
                plan = self.store.prepared_validation(request.route_id)
                if self._digest(plan) != claim.outcome.validation_plan_digest:
                    raise HybridRouteRejected("prepared Hybrid Validation integrity failed")
            return claim.outcome
        if now >= request.deadline:
            return self._terminal(
                request,
                claim,
                state=HybridRouteState.TIMED_OUT,
                reason_code="hybrid_route_deadline_elapsed",
                now=now,
            )
        started = self.monotonic()
        try:
            endpoint = self.endpoint_provider.resolve(request.endpoint_reference)
            self._admit_endpoint(request, endpoint=endpoint, scope=scope)
            plan = self._validation_plan(
                request,
                endpoint_url=endpoint.url,
                candidate=candidate,
                scope=scope,
            )
        except (LiveEndpointUnavailable, ValueError):
            return self._terminal(
                request,
                claim,
                state=HybridRouteState.FAILED,
                reason_code="hybrid_endpoint_admission_failed",
                now=now,
            )
        if self.monotonic() - started > self.policy.materialization_timeout_seconds:
            return self._terminal(
                request,
                claim,
                state=HybridRouteState.TIMED_OUT,
                reason_code="hybrid_route_budget_elapsed",
                now=now,
            )
        plan_digest = self._digest(plan)
        outcome = HybridRouteOutcome(
            route_id=request.route_id,
            state=HybridRouteState.COMPLETED,
            attempt=claim.attempt,
            validation_plan_id=plan.plan_id,
            validation_plan_digest=plan_digest,
            endpoint_reference_id=request.endpoint_reference.reference_id,
            endpoint_url_digest=request.endpoint_url_digest,
            reason_code="hybrid_validation_plan_prepared",
            cleanup_complete=True,
            completed_at=now,
        )
        self.store.complete(outcome, validation_plan=plan)
        return outcome

    def _preflight_request(self, request, *, candidate, proof, scope, now):
        self._preflight_source(candidate=candidate, proof=proof, scope=scope, now=now)
        if (
            request.candidate_id != candidate.candidate_id
            or request.candidate_digest != self._digest(candidate)
            or request.source_target_id != candidate.target_id
            or request.source_target_version != candidate.target_version
            or request.source_manifest_digest != proof.source_manifest_digest
            or request.live_target_id != proof.live_target_id
            or request.deployment_proof_id != proof.proof_id
            or request.deployment_proof_digest != self._digest(proof)
            or request.endpoint_url_digest != proof.endpoint_url_digest
            or request.scope_id != scope.scope_id
            or request.scope_version != scope.version
            or request.route_policy_id != self.policy.policy_id
            or request.test_class not in scope.allowed_test_classes
            or request.deadline > min(scope.valid_until, proof.expires_at)
        ):
            raise HybridRouteRejected("Hybrid Route authoritative provenance failed")

    @staticmethod
    def _preflight_source(*, candidate, proof, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or candidate.state is not CandidateState.PROPOSED
            or candidate.scope_id != scope.scope_id
            or candidate.scope_version != scope.version
            or proof.source_target_id != candidate.target_id
            or proof.source_target_version != candidate.target_version
            or not proof.attested_at <= now < proof.expires_at
        ):
            raise HybridRouteRejected("Hybrid Route requires current authorized source inputs")

    @staticmethod
    def _admit_endpoint(request, *, endpoint, scope):
        if endpoint.url_digest != request.endpoint_url_digest:
            raise HybridRouteRejected("Live Endpoint digest does not match Deployment Proof")
        if not any(
            item.host.lower() == endpoint.host
            and endpoint.port in item.ports
            and endpoint.scheme in item.schemes
            for item in scope.network_targets
        ):
            raise HybridRouteRejected("Live Endpoint is outside Scope")

    def _validation_plan(self, request, *, endpoint_url, candidate, scope):
        registry = self.tool_registry
        runner_profile_values = validation_profile(
            image_digest=self.policy.validation_image_digest,
            snapshot_id=request.source_manifest_digest,
        ).model_dump(mode="python")
        runner_profile_values["allowed_tools"] = frozenset({"sandbox.test"})
        runner_profile = SandboxProfile.model_validate(runner_profile_values)
        runner_task = self._task(
            request,
            candidate=candidate,
            scope=scope,
            profile=runner_profile,
            registry_digest=registry.digest,
            allowed_tools=runner_profile.allowed_tools,
            tool_calls=1,
            key_suffix="runner-task",
        )
        runner_request = SandboxRunRequest(
            task=runner_task,
            profile=runner_profile,
            invocation=ToolInvocation(
                tool_id="sandbox.test",
                arguments=(f"hybrid-route:{request.route_id}",),
                working_directory="source",
            ),
            environment={"VULNLOOM_TASK_ID": str(runner_task.task_id)},
            idempotency_key=f"{request.idempotency_key}:runner",
        )
        broker_profile = validation_profile(
            image_digest=self.policy.validation_image_digest,
            snapshot_id=request.source_manifest_digest,
            network_grants=(
                NetworkGrant(
                    host=self._endpoint_host(endpoint_url),
                    ports=frozenset({self._endpoint_port(endpoint_url)}),
                    schemes=frozenset({self._endpoint_scheme(endpoint_url)}),
                ),
            ),
        )
        broker_task = self._task(
            request,
            candidate=candidate,
            scope=scope,
            profile=broker_profile,
            registry_digest=registry.digest,
            allowed_tools=frozenset({"http.request"}),
            tool_calls=1,
            key_suffix="broker-task",
        )
        call = BrokerCall(
            task=broker_task,
            profile=broker_profile,
            tool_id="http.request",
            http=HttpRequestPlan(
                method=HttpMethod.GET,
                url=endpoint_url,
                test_class=request.test_class,
                headers=(),
                credential_ref=None,
                body_ref=None,
                body_bytes=0,
                follow_redirects=False,
                limits=HttpLimits(
                    connect_seconds=self.policy.connect_seconds,
                    read_seconds=self.policy.read_seconds,
                    total_seconds=self.policy.total_seconds,
                    max_response_bytes=self.policy.max_response_bytes,
                    max_redirects=0,
                    max_requests=1,
                ),
            ),
            idempotency_key=f"{request.idempotency_key}:broker",
        )
        assertion = HttpResponseAssertion.create(
            call_id=call.call_id,
            expected_status_code=request.expected_status_code,
            expected_body_sha256=request.expected_body_sha256,
            match_result=ValidationResult.REPRODUCED,
        )
        return ValidationPlan.create(
            candidate_id=candidate.candidate_id,
            candidate_digest=request.candidate_digest,
            target_id=candidate.target_id,
            target_version=candidate.target_version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            selected_by=request.selected_by,
            selected_at=request.created_at,
            selection_reason="Hybrid route bound Source Candidate to exact deployed endpoint",
            runner_request=runner_request,
            broker_calls=(call,),
            http_assertion=assertion,
            idempotency_key=f"{request.idempotency_key}:validation",
        )

    def _task(
        self,
        request,
        *,
        candidate,
        scope,
        profile,
        registry_digest,
        allowed_tools,
        tool_calls,
        key_suffix,
    ):
        return TaskEnvelope(
            engagement_id=scope.engagement_id,
            target_id=candidate.target_id,
            target_version=candidate.target_version,
            scope_id=scope.scope_id,
            worker_role=WorkerRole.VALIDATOR,
            scope_version=scope.version,
            policy_digest=PolicyEngine(scope).policy_digest,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            tool_registry_digest=registry_digest,
            input_refs=(
                f"candidate:{request.candidate_digest}",
                f"deployment-proof:{request.deployment_proof_id}",
                f"endpoint-digest:{request.endpoint_url_digest}",
            ),
            allowed_tools=allowed_tools,
            budget=TaskBudget(
                wall_seconds=self.policy.runner_wall_seconds,
                model_tokens=0,
                tool_calls=tool_calls,
            ),
            deadline=request.deadline,
            idempotency_key=f"{request.idempotency_key}:{key_suffix}",
        )

    def _terminal(self, request, claim, *, state, reason_code, now):
        outcome = HybridRouteOutcome(
            route_id=request.route_id,
            state=state,
            attempt=claim.attempt,
            endpoint_reference_id=request.endpoint_reference.reference_id,
            endpoint_url_digest=request.endpoint_url_digest,
            reason_code=reason_code,
            cleanup_complete=True,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome

    @staticmethod
    def _endpoint_scheme(url: str) -> str:
        return url.split(":", 1)[0]

    @staticmethod
    def _endpoint_host(url: str) -> str:
        return urlsplit(url).hostname or ""

    @staticmethod
    def _endpoint_port(url: str) -> int:
        parsed = urlsplit(url)
        return parsed.port or (443 if parsed.scheme == "https" else 80)

    @staticmethod
    def _digest(value) -> str:
        return canonical_digest(value.model_dump(mode="python"))
