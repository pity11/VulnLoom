"""Trusted offline materializer for sealed-GET Evidence Assertions."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .assertion_materialization_models import (
    REDACTION_SENTINEL,
    SENSITIVE_ASSERTION_CLASSIFIER_DIGEST,
    SENSITIVE_FIELD_NAMES,
    EvidenceAssertionMaterialization,
    EvidenceAssertionMaterializationLimits,
    EvidenceAssertionMaterializationOutcome,
    EvidenceAssertionMaterializationPlan,
)
from .assertion_materialization_store import EvidenceAssertionMaterializationStore
from .evidence_requirement_models import (
    EvidenceAssertion,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
    VulnerabilityEvidenceRequirement,
)
from .models import ReconOutcome, RedTeamActionKind
from .seed_models import EndpointReconOutcomeKind
from .seed_store import EndpointReconStore
from .store import RedTeamStore


class EvidenceAssertionMaterializationRejected(ValueError):
    pass


class EvidenceAssertionMaterializationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise EvidenceAssertionMaterializationTimedOut(
                "Evidence Assertion materialization timed out"
            )


class EvidenceAssertionMaterializationService:
    _FIXED_FACTS = (
        (
            EvidenceRequirementStage.OBSERVATION,
            EvidenceFactKind.SEALED_GET_SUCCEEDED,
            "control-plane:sealed-get-v1",
        ),
        (
            EvidenceRequirementStage.OBSERVATION,
            EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
            "control-plane:sealed-get-v1",
        ),
        (
            EvidenceRequirementStage.VALIDATION,
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
            "validator:sealed-get-materializer-v1",
        ),
        (
            EvidenceRequirementStage.CLEANUP,
            EvidenceFactKind.NO_STATE_CHANGE_PROVEN,
            "control-plane:sealed-get-v1",
        ),
        (
            EvidenceRequirementStage.CLEANUP,
            EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN,
            "control-plane:sealed-get-v1",
        ),
    )

    def __init__(
        self,
        *,
        red_team_store: RedTeamStore,
        endpoint_recon_store: EndpointReconStore,
        materialization_store: EvidenceAssertionMaterializationStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.red_team_store = red_team_store
        self.endpoint_recon_store = endpoint_recon_store
        self.materialization_store = materialization_store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        endpoint_recon_plan_id: str,
        scope: Scope,
        limits: EvidenceAssertionMaterializationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> EvidenceAssertionMaterializationPlan:
        source = self._source(endpoint_recon_plan_id, scope=scope, now=now)
        stop_at = min(deadline, scope.valid_until, source["flow"].deadline)
        if stop_at <= now:
            raise EvidenceAssertionMaterializationRejected(
                "Evidence Assertion materialization deadline is invalid"
            )
        web = source["observation"].web_response
        assert web is not None
        return EvidenceAssertionMaterializationPlan.create(
            requirement_id=VulnerabilityEvidenceRequirement.create().requirement_id,
            endpoint_recon_plan_id=endpoint_recon_plan_id,
            flow_plan_id=source["flow"].plan_id,
            source_checkpoint_id=source["checkpoint"].checkpoint_id,
            source_observation_id=source["observation"].observation_id,
            web_response_snapshot_id=web.snapshot_id,
            requested_url_digest=source["endpoint_plan"].steps[0].target_url_digest,
            evidence_ref=web.evidence_refs[0],
            response_body_sha256=web.response_body_sha256,
            target_id=source["flow"].target.target_id,
            target_version=source["flow"].plan_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            classifier_digest=SENSITIVE_ASSERTION_CLASSIFIER_DIGEST,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: EvidenceAssertionMaterializationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> EvidenceAssertionMaterializationOutcome:
        authoritative = EvidenceAssertionMaterializationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        materialization = self._materialize(authoritative, scope=scope, now=now)
        claim = self.materialization_store.claim(authoritative, now=now)
        if not claim.created:
            if claim.outcome is None or claim.outcome.materialization != materialization:
                raise EvidenceAssertionMaterializationRejected(
                    "completed Assertion materialization outcome drifted"
                )
            return claim.outcome
        return self._complete(
            authoritative,
            materialization,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def recover(
        self,
        plan: EvidenceAssertionMaterializationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> EvidenceAssertionMaterializationOutcome:
        authoritative = EvidenceAssertionMaterializationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        materialization = self._materialize(authoritative, scope=scope, now=now)
        claim = self.materialization_store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            materialization,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def _complete(self, plan, materialization, *, attempt, scope, now):
        self._plan_binding(plan, scope=scope, now=now)
        if not self.evidence_store.contains(plan.evidence_ref):
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source Evidence changed before completion"
            )
        outcome = EvidenceAssertionMaterializationOutcome(
            plan_id=plan.plan_id,
            materialization=materialization,
            attempt=attempt,
        )
        self.materialization_store.complete(outcome, completed_at=now)
        return outcome

    def _materialize(self, plan, *, scope, now):
        self._plan_binding(plan, scope=scope, now=now)
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        text = self.evidence_store.read_text_ref(plan.evidence_ref)
        body = self._document_body(text)
        encoded = body.encode("utf-8")
        if len(encoded) > plan.limits.max_document_bytes:
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source document exceeds its byte budget"
            )
        if hashlib.sha256(encoded).hexdigest() != plan.response_body_sha256:
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source body digest is invalid"
            )
        document = self._load_json(body)
        node_count, matched_count = self._inspect(
            document, plan.limits, deadline
        )
        presence = (
            EvidenceFactVerdict.SUPPORTED
            if matched_count
            else EvidenceFactVerdict.INCONCLUSIVE
        )
        assertions = [
            EvidenceAssertion.create(
                requirement_id=plan.requirement_id,
                stage=stage,
                fact=fact,
                verdict=EvidenceFactVerdict.SUPPORTED,
                evidence_refs=(plan.evidence_ref,),
                producer_ref=producer,
                context_id=plan.plan_id,
                observed_at=plan.created_at,
            )
            for stage, fact, producer in self._FIXED_FACTS
        ]
        assertions.append(
            EvidenceAssertion.create(
                requirement_id=plan.requirement_id,
                stage=EvidenceRequirementStage.OBSERVATION,
                fact=EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
                verdict=presence,
                evidence_refs=(plan.evidence_ref,),
                producer_ref="control-plane:sealed-get-v1",
                context_id=plan.plan_id,
                observed_at=plan.created_at,
            )
        )
        deadline.check()
        return EvidenceAssertionMaterialization.create(
            plan_id=plan.plan_id,
            requirement_id=plan.requirement_id,
            source_observation_id=plan.source_observation_id,
            web_response_snapshot_id=plan.web_response_snapshot_id,
            evidence_ref=plan.evidence_ref,
            response_body_sha256=plan.response_body_sha256,
            classifier_digest=plan.classifier_digest,
            assertions=tuple(sorted(assertions, key=lambda item: item.assertion_id)),
            inspected_node_count=node_count,
            matched_field_count=matched_count,
            sensitive_data_presence=presence,
            materialized_at=plan.created_at,
        )

    @staticmethod
    def _document_body(text: str) -> str:
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            return text
        _, separator, body = text.partition("\n\n")
        if not separator or not body.lstrip().startswith(("{", "[")):
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source Evidence does not contain JSON"
            )
        return body

    @staticmethod
    def _load_json(body: str) -> Any:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise EvidenceAssertionMaterializationRejected(
                        "Assertion source JSON contains duplicate keys"
                    )
                result[key] = value
            return result

        try:
            value = json.loads(body, object_pairs_hook=unique_object)
        except EvidenceAssertionMaterializationRejected:
            raise
        except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source JSON is invalid"
            ) from exc
        if not isinstance(value, (dict, list)):
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source JSON root must be structured"
            )
        return value

    @staticmethod
    def _inspect(document, limits, deadline):
        sensitive_names = frozenset(SENSITIVE_FIELD_NAMES)
        stack = [(document, 1)]
        nodes = 0
        keys = 0
        matched = 0
        while stack:
            deadline.check()
            value, depth = stack.pop()
            nodes += 1
            if nodes > limits.max_nodes or depth > limits.max_depth:
                raise EvidenceAssertionMaterializationRejected(
                    "Assertion source structure budget exceeded"
                )
            if isinstance(value, dict):
                keys += len(value)
                if keys > limits.max_object_keys:
                    raise EvidenceAssertionMaterializationRejected(
                        "Assertion source object-key budget exceeded"
                    )
                for name, item in value.items():
                    if not isinstance(name, str):
                        raise EvidenceAssertionMaterializationRejected(
                            "Assertion source object key is invalid"
                        )
                    if name.lower() in sensitive_names:
                        if item == REDACTION_SENTINEL:
                            matched += 1
                        elif item is not None and item != "":
                            raise EvidenceAssertionMaterializationRejected(
                                "sensitive-looking Evidence value is not redacted"
                            )
                    stack.append((item, depth + 1))
            elif isinstance(value, list):
                stack.extend((item, depth + 1) for item in value)
        return nodes, matched

    def _plan_binding(self, plan, *, scope, now):
        if (
            not plan.created_at <= now < plan.deadline
            or plan.requirement_id
            != VulnerabilityEvidenceRequirement.create().requirement_id
            or plan.classifier_digest != SENSITIVE_ASSERTION_CLASSIFIER_DIGEST
        ):
            raise EvidenceAssertionMaterializationRejected(
                "Evidence Assertion materialization plan is not active"
            )
        source = self._source(plan.endpoint_recon_plan_id, scope=scope, now=now)
        web = source["observation"].web_response
        assert web is not None
        if (
            source["flow"].plan_id != plan.flow_plan_id
            or source["checkpoint"].checkpoint_id != plan.source_checkpoint_id
            or source["observation"].observation_id != plan.source_observation_id
            or web.snapshot_id != plan.web_response_snapshot_id
            or source["endpoint_plan"].steps[0].target_url_digest
            != plan.requested_url_digest
            or web.evidence_refs != (plan.evidence_ref,)
            or web.response_body_sha256 != plan.response_body_sha256
            or source["flow"].target.target_id != plan.target_id
            or source["flow"].plan_id != plan.target_version
            or scope.scope_id != plan.scope_id
            or scope.version != plan.scope_version
        ):
            raise EvidenceAssertionMaterializationRejected(
                "Evidence Assertion materialization binding drifted"
            )

    def _source(self, endpoint_recon_plan_id, *, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
        ):
            raise EvidenceAssertionMaterializationRejected(
                "Assertion materialization requires a current read-only approved Scope"
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
            raise EvidenceAssertionMaterializationRejected(
                "Assertion materialization requires one authoritative sealed GET"
            )
        matches = []
        for observation_id in checkpoint.observation_ids:
            observation = self.red_team_store.observation(observation_id)
            web = observation.web_response
            if (
                web is not None
                and web.snapshot_id == outcome.results[0].web_response_snapshot_id
            ):
                matches.append(observation)
        if len(matches) != 1:
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source Observation is unavailable or ambiguous"
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
            or outcome.results[0].response_body_sha256 != web.response_body_sha256
            or outcome.results[0].response_bytes != web.response_bytes
            or web.evidence_refs != outcome.results[0].evidence_refs
            or len(web.evidence_refs) != 1
            or not self.evidence_store.contains(web.evidence_refs[0])
        ):
            raise EvidenceAssertionMaterializationRejected(
                "Assertion source provenance is invalid"
            )
        return {
            "endpoint_plan": endpoint_plan,
            "flow": flow,
            "checkpoint": checkpoint,
            "observation": observation,
        }
