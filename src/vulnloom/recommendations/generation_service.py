"""Approved one-shot model generation over a minimal Candidate projection."""

from uuid import NAMESPACE_URL, uuid5

from vulnloom.adapters.model_credentials import ModelCredentialUnavailable
from vulnloom.agent_runtime.context import (
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextSource,
    AgentContextSourceKind,
)
from vulnloom.agent_runtime.invocation_models import ModelInvocationResult
from vulnloom.agent_runtime.live_provider import SubprocessHttpsProviderAdapter
from vulnloom.agent_runtime.messages import AgentMessageRenderer
from vulnloom.agent_runtime.models import AgentRunLimits, AgentRunPlan, AgentStepRequest
from vulnloom.agent_runtime.provider_admission import AgentProviderEgressPurpose
from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.agent_runtime.transport import (
    AgentProviderTransportRejected,
    AgentProviderTransportTimedOut,
)
from vulnloom.analyzers.models import source_graph_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, CandidateState, utc_now
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.validation.models import candidate_content_digest

from .generation_models import (
    CandidateLocationProjection,
    CandidateRecommendationGenerationOutcome,
    CandidateRecommendationProjection,
    CandidateSignalProjection,
)
from .models import CandidateRecommendation
from .provider import (
    CandidateRecommendationCodec,
    CandidateRecommendationGenerationPlan,
    ProfileCandidateRecommendationCodec,
    RoutedCandidateRecommendationProviderConfig,
    recommendation_config,
)


def _digest(model):
    return canonical_digest(model.model_dump(mode="python"))


def recommendation_generation_approval_request(plan, scope):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.projection.target_id,
        action=ApprovalAction.USE_REAL_CREDENTIALS,
        action_digest=plan.plan_id,
        expected_side_effects=(
            "Send the exact minimal Candidate projection to the selected model Provider once.",
            "Consume provider tokens and store an unverified recommendation locally.",
        ),
        evidence_summary="Review the projection fields and selected Provider before approving.",
        policy_version=scope.version,
        expires_at=plan.deadline,
    )


class CandidateRecommendationGenerationService:
    def __init__(
        self,
        *,
        scope,
        graph_store,
        candidate_store,
        egress_store,
        store,
        credential_provider=None,
        resolver=None,
        process_runner=None,
        provider_config_factory=None,
        now=utc_now,
    ):
        self.scope = scope
        self.graphs, self.candidates = graph_store, candidate_store
        self.egress, self.store = egress_store, store
        self.credentials = credential_provider
        self.resolver, self.runner, self.now = resolver, process_runner, now
        self.provider_config_factory = provider_config_factory

    def _provider_config(self, *, grant_id, now, deadline):
        if self.provider_config_factory is None:
            return recommendation_config(grant_id)
        return self.provider_config_factory(
            grant_id=grant_id,
            now=now,
            deadline=deadline,
        )

    def projection(self, *, candidate_set_id, candidate_id):
        now = self.now()
        candidate_set = self.candidates.load(candidate_set_id)
        graph = self.graphs.load(candidate_set.source_graph_id)
        matches = tuple(
            item for item in candidate_set.candidates if item.candidate_id == candidate_id
        )
        if (
            self.scope.state.value != "approved"
            or not self.scope.valid_from <= now < self.scope.valid_until
            or candidate_set_digest(candidate_set) != candidate_set.candidate_set_id
            or source_graph_digest(graph) != graph.graph_id
            or candidate_set.source_graph_id != graph.graph_id
            or candidate_set.target_id != graph.target_id
            or candidate_set.target_version != graph.target_version
            or candidate_set.scope_id != self.scope.scope_id
            or candidate_set.scope_version != self.scope.version
            or graph.scope_id != self.scope.scope_id
            or graph.scope_version != self.scope.version
            or len(matches) != 1
            or matches[0].state is not CandidateState.PROPOSED
        ):
            raise ValueError("Candidate projection provenance rejected")
        candidate = matches[0]
        signals = {item.signal_id: item for item in graph.signals}
        if (
            len(signals) != len(graph.signals)
            or set(candidate.signal_ids) - signals.keys()
            or candidate.signal_ids != tuple(sorted(set(candidate.signal_ids)))
            or len(candidate.signal_ids) > 16
            or len(candidate.code_path) > 32
        ):
            raise ValueError("Candidate projection inputs rejected")
        return CandidateRecommendationProjection.create(
            candidate_set_id=candidate_set.candidate_set_id,
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate_content_digest(candidate),
            source_graph_id=graph.graph_id,
            target_id=candidate.target_id,
            target_version_digest=canonical_digest(candidate.target_version),
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            cwe=candidate.cwe,
            candidate_confidence=candidate.confidence,
            locations=tuple(
                CandidateLocationProjection(
                    index=index,
                    path_digest=canonical_digest(location.path),
                    line=location.line,
                )
                for index, location in enumerate(candidate.code_path)
            ),
            signals=tuple(
                CandidateSignalProjection(
                    signal_id=signal_id,
                    kind=signals[signal_id].kind,
                    rule_digest=canonical_digest(signals[signal_id].rule_id),
                    confidence=signals[signal_id].confidence,
                )
                for signal_id in sorted(candidate.signal_ids)
            ),
        )

    def prepare(self, *, candidate_set_id, candidate_id, grant_id, deadline, idempotency_key):
        now = self.now()
        projection = self.projection(candidate_set_id=candidate_set_id, candidate_id=candidate_id)
        config = self._provider_config(grant_id=grant_id, now=now, deadline=deadline)
        grant = self.egress.require_active(grant_id, admission=config.admission, now=now)
        if grant.purpose is not AgentProviderEgressPurpose.MODEL_INFERENCE or deadline > min(
            grant.expires_at, self.scope.valid_until
        ):
            raise ValueError("recommendation inference grant rejected")
        return CandidateRecommendationGenerationPlan.create(
            config=config,
            projection=projection,
            scope_digest=_digest(self.scope),
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def _preflight(self, plan, approval, network):
        plan = CandidateRecommendationGenerationPlan.model_validate(plan.model_dump())
        approval = ApprovalRequest.model_validate(approval.model_dump())
        now = self.now()
        if network is not True or self.credentials is None:
            raise ValueError("recommendation requires explicit model network and credentials")
        if not plan.created_at <= now < plan.deadline or plan.scope_digest != _digest(self.scope):
            raise ValueError("recommendation scope or time window changed")
        if plan.config != self._provider_config(
            grant_id=plan.config.registration.egress_grant_id,
            now=now,
            deadline=plan.deadline,
        ):
            raise ValueError("recommendation Provider configuration changed")
        if not (
            approval.is_valid_for(
                action=ApprovalAction.USE_REAL_CREDENTIALS, digest=plan.plan_id, now=now
            )
            and approval.engagement_id == self.scope.engagement_id
            and approval.target_id == plan.projection.target_id
            and approval.policy_version == self.scope.version
            and approval.decided_by
            and approval.decided_at
            and plan.created_at <= approval.decided_at <= now
        ):
            raise ValueError("recommendation requires exact human approval")
        grant = self.egress.require_active(
            plan.config.registration.egress_grant_id, admission=plan.config.admission, now=now
        )
        if grant.purpose is not AgentProviderEgressPurpose.MODEL_INFERENCE or plan.deadline > min(
            grant.expires_at, self.scope.valid_until
        ):
            raise ValueError("recommendation grant rejected")
        current = self.projection(
            candidate_set_id=plan.projection.candidate_set_id,
            candidate_id=plan.projection.candidate_id,
        )
        if current != plan.projection:
            raise ValueError("Candidate projection changed after approval")
        return plan, approval, current

    def execute(self, *, plan, approval, allow_provider_network=False):
        plan, approval, projection = self._preflight(plan, approval, allow_provider_network)
        cached = self.store.claim(plan, approval)
        if cached:
            if cached.transport.completed_at > self.now():
                raise ValueError("recommendation completion is in the future")
            return cached
        adapter = codec = None
        uncertain = False
        status, input_tokens, output_tokens = "rejected", 0, 0
        try:
            if (min(plan.deadline, approval.expires_at) - self.now()).total_seconds() <= 10:
                raise TimeoutError("recommendation execution budget exhausted")
            request, envelope = self._message(plan)
            codec_type = (
                ProfileCandidateRecommendationCodec
                if isinstance(plan.config, RoutedCandidateRecommendationProviderConfig)
                else CandidateRecommendationCodec
            )
            codec = codec_type(plan.config.codec, projection=projection)
            adapter = SubprocessHttpsProviderAdapter(
                registration=plan.config.registration,
                admission=plan.config.admission,
                credential_reference=plan.config.credential_reference,
                credential_provider=self.credentials,
                egress_store=self.egress,
                provider_codec=codec,
                resolver=self.resolver,
                process_runner=self.runner,
                now=self.now,
            )
            reply = adapter.complete(request, message_envelope=envelope)
            input_tokens, output_tokens = reply.input_tokens, reply.output_tokens
            if codec.response is not None and input_tokens + output_tokens <= 8192:
                status = "passed"
        except (TimeoutError, AgentProviderTransportTimedOut):
            status = "timed_out"
        except (AgentProviderTransportRejected, ModelCredentialUnavailable, ValueError):
            status = "rejected"
        except Exception:
            uncertain = True
        attempts = adapter.attempts if adapter else []
        receipts = adapter.receipts if adapter else []
        cleanup = not uncertain and (
            adapter is None or len(attempts) == len(adapter.transport_requests)
        )
        cleanup = cleanup and all(
            item.credential_released
            and item.request_body_released
            and item.raw_response_discarded
            and item.process_terminated
            and item.stderr_discarded
            for item in attempts
        )
        completed = self.now()
        if completed >= min(plan.deadline, approval.expires_at):
            status = "timed_out"
        if status == "passed" and (not cleanup or len(attempts) != 1 or len(receipts) != 1):
            status = "rejected"
        result_type = (
            ModelInvocationResult
            if isinstance(plan.config, RoutedCandidateRecommendationProviderConfig)
            else ProviderProbeResult
        )
        result_values = {
            "plan_id": plan.plan_id,
            "status": status,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "process_started": any(item.process_started for item in attempts),
            "cleanup_verified": cleanup,
            "attempt_digest": _digest(attempts[0]) if len(attempts) == 1 else None,
            "receipt_digest": _digest(receipts[0]) if len(receipts) == 1 else None,
            "completed_at": completed,
            "diagnostic": getattr(adapter, "diagnostic", None),
            "response_model": getattr(codec, "response_model", None),
        }
        if result_type is ModelInvocationResult:
            result_values["provider_id"] = plan.config.registration.provider_id
        transport = result_type.create(**result_values)
        response = codec.response if status == "passed" else None
        recommendation = None
        if response is not None:
            candidate_set = self.candidates.load(projection.candidate_set_id)
            candidate = next(
                item
                for item in candidate_set.candidates
                if item.candidate_id == projection.candidate_id
            )
            recommendation = CandidateRecommendation.create(
                candidate_set_id=projection.candidate_set_id,
                candidate_id=projection.candidate_id,
                candidate_digest=projection.candidate_digest,
                source_graph_id=projection.source_graph_id,
                target_id=projection.target_id,
                target_version_digest=projection.target_version_digest,
                scope_id=projection.scope_id,
                scope_version=projection.scope_version,
                supporting_signal_ids=candidate.signal_ids,
                cited_locations=tuple(
                    candidate.code_path[index] for index in response.cited_location_indexes
                ),
                priority=response.priority,
                rationale=response.rationale,
                review_questions=response.review_questions,
                producer_result_id=transport.result_id,
                producer_plan_id=plan.plan_id,
                producer_receipt_digest=transport.receipt_digest,
                created_at=completed,
            )
        outcome = CandidateRecommendationGenerationOutcome.create(
            plan_id=plan.plan_id,
            status="recommendation_ready" if status == "passed" else status,
            projection_id=projection.projection_id,
            transport=transport,
            response=response,
            recommendation=recommendation,
        )
        self.store.complete(outcome)
        return outcome

    def _message(self, plan):
        identity = uuid5(NAMESPACE_URL, "candidate-recommendation:" + plan.plan_id)
        ref = "observation:" + plan.projection.projection_id
        task = TaskEnvelope(
            task_id=identity,
            engagement_id=self.scope.engagement_id,
            target_id=plan.projection.target_id,
            scope_id=self.scope.scope_id,
            target_version=plan.projection.target_version_digest,
            scope_version=self.scope.version,
            worker_role=WorkerRole.REPORTER,
            policy_digest=plan.scope_digest,
            sandbox_profile_digest=plan.plan_id,
            tool_registry_digest=plan.plan_id,
            input_refs=(ref,),
            allowed_tools=frozenset(),
            budget=TaskBudget(wall_seconds=30, model_tokens=8192, tool_calls=0),
            deadline=plan.deadline,
            idempotency_key="candidate-recommendation:" + plan.plan_id,
        )
        context = AgentContextAssembler().assemble(
            task=task,
            sources=(
                AgentContextSource(
                    source_ref=ref,
                    kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                    text=plan.projection.model_dump_json(),
                ),
            ),
            limits=AgentContextLimits(),
            now=plan.created_at,
            deadline=plan.deadline,
        )
        run = AgentRunPlan.create(
            task=task,
            registration=plan.config.registration,
            limits=AgentRunLimits(max_steps=1, max_output_tokens_per_step=512, timeout_seconds=30),
            created_at=plan.created_at,
            deadline=plan.deadline,
            idempotency_key="candidate-recommendation:" + plan.plan_id,
            context_snapshot=context,
        )
        base = AgentStepRequest.create(plan=run, step=1, remaining_model_tokens=8192)
        envelope = AgentMessageRenderer().render(plan=run, snapshot=context, request=base)
        return AgentStepRequest.create(
            plan=run,
            step=1,
            remaining_model_tokens=8192,
            message_envelope_id=envelope.envelope_id,
        ), envelope
