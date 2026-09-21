"""Trusted offline reducer for one authoritative sealed OpenAPI GET."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .models import ReconOutcome, RedTeamActionKind
from .openapi_models import (
    OpenApiDocumentObservation,
    OpenApiDocumentObservationOutcome,
    OpenApiDocumentObservationPlan,
    OpenApiHttpMethod,
    OpenApiObservationLimits,
    OpenApiPathDiscovery,
)
from .openapi_store import OpenApiObservationStore
from .seed_models import EndpointReconOutcomeKind
from .seed_store import EndpointReconStore
from .store import RedTeamStore


class OpenApiObservationRejected(ValueError):
    pass


class OpenApiObservationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise OpenApiObservationTimedOut("OpenAPI observation timed out")


class OpenApiObservationService:
    _METHODS = {item.value.lower(): item for item in OpenApiHttpMethod}

    def __init__(
        self,
        *,
        red_team_store: RedTeamStore,
        endpoint_recon_store: EndpointReconStore,
        observation_store: OpenApiObservationStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.red_team_store = red_team_store
        self.endpoint_recon_store = endpoint_recon_store
        self.observation_store = observation_store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        endpoint_recon_plan_id: str,
        scope: Scope,
        limits: OpenApiObservationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> OpenApiDocumentObservationPlan:
        source = self._source(endpoint_recon_plan_id, scope=scope, now=now)
        stop_at = min(deadline, scope.valid_until, source["flow"].deadline)
        if stop_at <= now:
            raise OpenApiObservationRejected("OpenAPI observation deadline is invalid")
        web = source["observation"].web_response
        assert web is not None
        return OpenApiDocumentObservationPlan.create(
            endpoint_recon_plan_id=endpoint_recon_plan_id,
            flow_plan_id=source["flow"].plan_id,
            source_checkpoint_id=source["checkpoint"].checkpoint_id,
            source_observation_id=source["observation"].observation_id,
            web_response_snapshot_id=web.snapshot_id,
            evidence_ref=web.evidence_refs[0],
            document_body_sha256=web.response_body_sha256,
            target_id=source["flow"].target.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: OpenApiDocumentObservationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> OpenApiDocumentObservationOutcome:
        authoritative = OpenApiDocumentObservationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        observation = self._observe(authoritative, scope=scope, now=now)
        claim = self.observation_store.claim(authoritative, now=now)
        if not claim.created:
            if claim.outcome is None or claim.outcome.observation != observation:
                raise OpenApiObservationRejected(
                    "completed OpenAPI observation outcome drifted"
                )
            return claim.outcome
        return self._complete(
            authoritative,
            observation,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def recover(
        self,
        plan: OpenApiDocumentObservationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> OpenApiDocumentObservationOutcome:
        authoritative = OpenApiDocumentObservationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        observation = self._observe(authoritative, scope=scope, now=now)
        claim = self.observation_store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            observation,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def _complete(self, plan, observation, *, attempt, scope, now):
        self._plan_binding(plan, scope=scope, now=now)
        if not self.evidence_store.contains(plan.evidence_ref):
            raise OpenApiObservationRejected(
                "OpenAPI source Evidence changed before completion"
            )
        outcome = OpenApiDocumentObservationOutcome(
            plan_id=plan.plan_id,
            observation=observation,
            attempt=attempt,
        )
        self.observation_store.complete(outcome, completed_at=now)
        return outcome

    def _observe(self, plan, *, scope, now):
        self._plan_binding(plan, scope=scope, now=now)
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        text = self.evidence_store.read_text_ref(plan.evidence_ref)
        body = self._document_body(text)
        if len(body.encode("utf-8")) > plan.limits.max_document_bytes:
            raise OpenApiObservationRejected("OpenAPI document exceeds its byte budget")
        deadline.check()
        document = self._load_json(body)
        self._bounded_tree(document, plan.limits, deadline)
        version = document.get("openapi")
        if not isinstance(version, str):
            raise OpenApiObservationRejected("OpenAPI 3.x version is missing")
        paths_value = document.get("paths")
        if not isinstance(paths_value, dict) or not paths_value:
            raise OpenApiObservationRejected("OpenAPI paths object is missing")
        if len(paths_value) > plan.limits.max_paths:
            raise OpenApiObservationRejected("OpenAPI path budget exceeded")
        servers = document.get("servers", [])
        if not isinstance(servers, list) or len(servers) > plan.limits.max_servers:
            raise OpenApiObservationRejected("OpenAPI server metadata budget exceeded")
        discoveries: list[OpenApiPathDiscovery] = []
        operation_count = 0
        for path_template in sorted(paths_value):
            deadline.check()
            path_item = paths_value[path_template]
            if not isinstance(path_template, str) or not isinstance(path_item, dict):
                raise OpenApiObservationRejected("OpenAPI path entry is invalid")
            methods: list[OpenApiHttpMethod] = []
            for name, value in path_item.items():
                method = self._METHODS.get(str(name).lower())
                if method is None:
                    continue
                if not isinstance(value, dict):
                    raise OpenApiObservationRejected("OpenAPI operation entry is invalid")
                methods.append(method)
            if not methods:
                raise OpenApiObservationRejected(
                    "OpenAPI path has no bounded HTTP operation"
                )
            operation_count += len(methods)
            if operation_count > plan.limits.max_operations:
                raise OpenApiObservationRejected("OpenAPI operation budget exceeded")
            try:
                discoveries.append(
                    OpenApiPathDiscovery.create(
                        path_template=path_template,
                        methods=tuple(methods),
                    )
                )
            except ValueError as exc:
                raise OpenApiObservationRejected(
                    "OpenAPI path template is not admissible"
                ) from exc
        references = self._reference_count(document, deadline)
        deadline.check()
        try:
            return OpenApiDocumentObservation.create(
                plan_id=plan.plan_id,
                endpoint_recon_plan_id=plan.endpoint_recon_plan_id,
                source_observation_id=plan.source_observation_id,
                web_response_snapshot_id=plan.web_response_snapshot_id,
                evidence_ref=plan.evidence_ref,
                document_body_sha256=plan.document_body_sha256,
                openapi_version=version,
                paths=tuple(
                    sorted(discoveries, key=lambda item: item.discovery_id)
                ),
                operation_count=operation_count,
                server_entries_ignored=len(servers),
                reference_entries_ignored=references,
                observed_at=plan.created_at,
            )
        except ValueError as exc:
            raise OpenApiObservationRejected(
                "OpenAPI document observation could not be sealed"
            ) from exc

    def _plan_binding(self, plan, *, scope, now):
        if not plan.created_at <= now < plan.deadline:
            raise OpenApiObservationRejected("OpenAPI observation plan is not active")
        source = self._source(plan.endpoint_recon_plan_id, scope=scope, now=now)
        web = source["observation"].web_response
        assert web is not None
        if (
            source["flow"].plan_id != plan.flow_plan_id
            or source["checkpoint"].checkpoint_id != plan.source_checkpoint_id
            or source["observation"].observation_id != plan.source_observation_id
            or web.snapshot_id != plan.web_response_snapshot_id
            or web.evidence_refs != (plan.evidence_ref,)
            or web.response_body_sha256 != plan.document_body_sha256
            or source["flow"].target.target_id != plan.target_id
            or scope.scope_id != plan.scope_id
            or scope.version != plan.scope_version
        ):
            raise OpenApiObservationRejected("OpenAPI observation binding drifted")

    def _source(self, endpoint_recon_plan_id, *, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise OpenApiObservationRejected(
                "OpenAPI observation requires a current approved Scope"
            )
        endpoint_plan = self.endpoint_recon_store.plan(endpoint_recon_plan_id)
        outcome = self.endpoint_recon_store.outcome(endpoint_recon_plan_id)
        flow = self.red_team_store.plan(endpoint_plan.flow_plan_id)
        checkpoint = self.red_team_store.latest(flow.plan_id)
        if (
            len(endpoint_plan.steps) != 1
            or endpoint_plan.steps[0].method != "GET"
            or outcome.outcome is not EndpointReconOutcomeKind.SUCCEEDED
            or not outcome.cleanup_complete
            or len(outcome.results) != 1
            or outcome.results[0].step_id != endpoint_plan.steps[0].step_id
            or outcome.results[0].web_response_snapshot_id is None
            or endpoint_plan.target_id != flow.target.target_id
            or endpoint_plan.scope_id != scope.scope_id
            or endpoint_plan.scope_version != scope.version
            or flow.rules.scope_id != scope.scope_id
            or flow.rules.scope_version != scope.version
            or flow.deadline > scope.valid_until
        ):
            raise OpenApiObservationRejected(
                "OpenAPI observation requires one authoritative sealed GET"
            )
        matches = []
        for observation_id in checkpoint.observation_ids:
            observation = self.red_team_store.observation(observation_id)
            web = observation.web_response
            if (
                web is not None
                and web.snapshot_id
                == outcome.results[0].web_response_snapshot_id
            ):
                matches.append(observation)
        if len(matches) != 1:
            raise OpenApiObservationRejected(
                "OpenAPI source Observation is unavailable or ambiguous"
            )
        observation = matches[0]
        action = self.red_team_store.action(observation.action_id)
        web = observation.web_response
        assert web is not None
        step = endpoint_plan.steps[0]
        if (
            observation.outcome is not ReconOutcome.SUCCEEDED
            or not observation.cleanup_complete
            or not observation.sensitive_data_redacted
            or action.kind is not RedTeamActionKind.HTTP_GET
            or action.plan_id != flow.plan_id
            or hashlib.sha256(action.target_url.encode()).hexdigest()
            != step.target_url_digest
            or web.plan_id != flow.plan_id
            or web.action_id != action.action_id
            or web.target_id != flow.target.target_id
            or web.scope_id != scope.scope_id
            or web.scope_version != scope.version
            or web.requested_url_digest != step.target_url_digest
            or web.final_url_digest != step.target_url_digest
            or web.snapshot_id != outcome.results[0].web_response_snapshot_id
            or outcome.results[0].response_body_sha256
            != web.response_body_sha256
            or outcome.results[0].response_bytes != web.response_bytes
            or web.evidence_refs != outcome.results[0].evidence_refs
            or len(web.evidence_refs) != 1
            or not self.evidence_store.contains(web.evidence_refs[0])
        ):
            raise OpenApiObservationRejected(
                "OpenAPI source provenance is invalid"
            )
        return {
            "endpoint_plan": endpoint_plan,
            "flow": flow,
            "checkpoint": checkpoint,
            "observation": observation,
        }

    @staticmethod
    def _document_body(text: str) -> str:
        stripped = text.lstrip()
        if stripped.startswith("{"):
            return stripped
        _, separator, body = text.partition("\n\n")
        if not separator or not body.lstrip().startswith("{"):
            raise OpenApiObservationRejected(
                "OpenAPI Evidence does not contain a JSON document"
            )
        return body.lstrip()

    @staticmethod
    def _load_json(body: str) -> dict[str, Any]:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise OpenApiObservationRejected(
                        "OpenAPI document contains duplicate object keys"
                    )
                result[key] = value
            return result

        try:
            value = json.loads(body, object_pairs_hook=unique_object)
        except OpenApiObservationRejected:
            raise
        except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
            raise OpenApiObservationRejected("OpenAPI JSON is invalid") from exc
        if not isinstance(value, dict):
            raise OpenApiObservationRejected("OpenAPI document root must be an object")
        return value

    @staticmethod
    def _bounded_tree(document, limits, deadline):
        stack = [(document, 1)]
        nodes = 0
        while stack:
            deadline.check()
            value, depth = stack.pop()
            nodes += 1
            if nodes > limits.max_nodes or depth > limits.max_depth:
                raise OpenApiObservationRejected(
                    "OpenAPI document structure budget exceeded"
                )
            if isinstance(value, dict):
                stack.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                stack.extend((item, depth + 1) for item in value)

    @staticmethod
    def _reference_count(document, deadline: _Deadline) -> int:
        count = 0
        stack = [document]
        while stack:
            deadline.check()
            value = stack.pop()
            if isinstance(value, dict):
                count += int("$ref" in value)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        return count
