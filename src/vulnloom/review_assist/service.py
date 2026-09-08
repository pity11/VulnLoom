"""One approved model call for commentary; no Tool Broker or domain-state writes."""

from uuid import NAMESPACE_URL, uuid5

from vulnloom.adapters.model_credentials import ModelCredentialUnavailable
from vulnloom.agent_runtime.context import (
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextSource,
    AgentContextSourceKind,
)
from vulnloom.agent_runtime.live_provider import SubprocessHttpsProviderAdapter
from vulnloom.agent_runtime.messages import AgentMessageRenderer
from vulnloom.agent_runtime.models import AgentRunLimits, AgentRunPlan, AgentStepRequest
from vulnloom.agent_runtime.provider_admission import AgentProviderEgressPurpose
from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.agent_runtime.transport import (
    AgentProviderTransportRejected,
    AgentProviderTransportTimedOut,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, utc_now
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole

from .models import CodeReviewOutcome
from .provider import CodeReviewCodec, CodeReviewPlan, review_config
from .source import select_snippet


def digest(model):
    return canonical_digest(model.model_dump())


def approval_request(plan, scope):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.snippet.target_id,
        action=ApprovalAction.USE_REAL_CREDENTIALS,
        action_digest=plan.plan_id,
        expected_side_effects=(
            "Send the exact redacted snippet in this plan to the CUC model once.",
            "Consume provider tokens and store unverified human-review commentary locally.",
        ),
        evidence_summary="Inspect all redacted lines and the model endpoint before approving.",
        policy_version=scope.version,
        expires_at=plan.deadline,
    )


class CodeReviewService:
    def __init__(
        self,
        *,
        ingestion,
        scope,
        egress_store,
        store,
        credential_provider=None,
        resolver=None,
        process_runner=None,
        now=utc_now,
    ):
        self.ingestion, self.scope = ingestion, scope
        self.egress, self.store = egress_store, store
        self.credentials = credential_provider
        self.resolver, self.runner, self.now = resolver, process_runner, now

    def prepare(
        self, *, snapshot_id, path, start_line, end_line, grant_id, deadline, idempotency_key
    ):
        now = self.now()
        snapshot = self.ingestion.load_snapshot(snapshot_id)
        snippet = select_snippet(
            ingestion=self.ingestion,
            snapshot=snapshot,
            scope=self.scope,
            path=path,
            start_line=start_line,
            end_line=end_line,
            now=now,
        )
        config = review_config(grant_id)
        grant = self.egress.require_active(grant_id, admission=config.admission, now=now)
        if grant.purpose is not AgentProviderEgressPurpose.MODEL_INFERENCE or deadline > min(
            grant.expires_at, self.scope.valid_until
        ):
            raise ValueError("review inference grant rejected")
        return CodeReviewPlan.create(
            config=config,
            snippet=snippet,
            scope_digest=digest(self.scope),
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def _preflight(self, plan, approval, path, network):
        plan = CodeReviewPlan.model_validate(plan.model_dump())
        approval = ApprovalRequest.model_validate(approval.model_dump())
        now = self.now()
        if network is not True or self.credentials is None:
            raise ValueError("review requires explicit model-network opt-in and credentials")
        if not plan.created_at <= now < plan.deadline or plan.scope_digest != digest(self.scope):
            raise ValueError("review scope or time window changed")
        if plan.config != review_config(plan.config.registration.egress_grant_id):
            raise ValueError("review provider configuration changed")
        if not (
            approval.is_valid_for(
                action=ApprovalAction.USE_REAL_CREDENTIALS, digest=plan.plan_id, now=now
            )
            and approval.engagement_id == self.scope.engagement_id
            and approval.target_id == plan.snippet.target_id
            and approval.policy_version == self.scope.version
            and approval.decided_by
            and approval.decided_at
            and plan.created_at <= approval.decided_at <= now
        ):
            raise ValueError("review requires exact human approval")
        grant = self.egress.require_active(
            plan.config.registration.egress_grant_id, admission=plan.config.admission, now=now
        )
        if grant.purpose is not AgentProviderEgressPurpose.MODEL_INFERENCE or plan.deadline > min(
            grant.expires_at, self.scope.valid_until
        ):
            raise ValueError("review grant purpose or window rejected")
        snapshot = self.ingestion.load_snapshot(plan.snippet.snapshot_id)
        selected = select_snippet(
            ingestion=self.ingestion,
            snapshot=snapshot,
            scope=self.scope,
            path=path,
            start_line=plan.snippet.lines[0].number,
            end_line=plan.snippet.lines[-1].number,
            now=now,
        )
        if selected != plan.snippet:
            raise ValueError("review input changed after approval")
        return plan, approval

    def execute(self, *, plan, approval, path, allow_provider_network=False):
        plan, approval = self._preflight(plan, approval, path, allow_provider_network)
        cached = self.store.claim(plan, approval)
        if cached:
            if cached.transport.completed_at > self.now():
                raise ValueError("review completion in the future")
            return cached
        adapter = None
        codec = None
        uncertain = False
        status, input_tokens, output_tokens = "rejected", 0, 0
        try:
            if (min(plan.deadline, approval.expires_at) - self.now()).total_seconds() <= 10:
                raise TimeoutError("review execution budget exhausted")
            request, envelope = self._message(plan)
            if (min(plan.deadline, approval.expires_at) - self.now()).total_seconds() <= 10:
                raise TimeoutError("review execution budget exhausted")
            codec = CodeReviewCodec(plan.config.codec, snippet=plan.snippet)
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
            if codec.review is not None and input_tokens + output_tokens <= 8192:
                status = "passed"
        except (TimeoutError, AgentProviderTransportTimedOut):
            status = "timed_out"
        except (AgentProviderTransportRejected, ModelCredentialUnavailable, ValueError):
            status = "rejected"
        except Exception:
            # No exception text, source text or raw response is persisted.
            uncertain = True
        attempts = adapter.attempts if adapter else []
        receipts = adapter.receipts if adapter else []
        cleanup = not uncertain and (
            adapter is None or len(attempts) == len(adapter.transport_requests)
        )
        cleanup = cleanup and all(
            a.credential_released
            and a.request_body_released
            and a.raw_response_discarded
            and a.process_terminated
            and a.stderr_discarded
            for a in attempts
        )
        completed = self.now()
        if completed >= min(plan.deadline, approval.expires_at):
            status = "timed_out"
        if status == "passed" and (not cleanup or len(attempts) != 1 or len(receipts) != 1):
            status = "rejected"
        transport = ProviderProbeResult.create(
            plan_id=plan.plan_id,
            status=status,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            process_started=any(a.process_started for a in attempts),
            cleanup_verified=cleanup,
            attempt_digest=digest(attempts[0]) if len(attempts) == 1 else None,
            receipt_digest=digest(receipts[0]) if len(receipts) == 1 else None,
            completed_at=completed,
            diagnostic=getattr(adapter, "diagnostic", None),
            response_model=getattr(codec, "response_model", None),
        )
        outcome = CodeReviewOutcome.create(
            plan_id=plan.plan_id,
            status="review_ready" if status == "passed" else status,
            transport=transport,
            review=codec.review if status == "passed" else None,
        )
        self.store.complete(outcome)
        return outcome

    def _message(self, plan):
        identity = uuid5(NAMESPACE_URL, "code-review:" + plan.plan_id)
        ref = "observation:" + plan.snippet.snippet_id
        task = TaskEnvelope(
            task_id=identity,
            engagement_id=self.scope.engagement_id,
            target_id=plan.snippet.target_id,
            scope_id=self.scope.scope_id,
            target_version=plan.snippet.file_digest,
            scope_version=self.scope.version,
            worker_role=WorkerRole.REPORTER,
            policy_digest=plan.scope_digest,
            sandbox_profile_digest=plan.plan_id,
            tool_registry_digest=plan.plan_id,
            input_refs=(ref,),
            allowed_tools=frozenset(),
            budget=TaskBudget(wall_seconds=30, model_tokens=8192, tool_calls=0),
            deadline=plan.deadline,
            idempotency_key="review:" + plan.plan_id,
        )
        context = AgentContextAssembler().assemble(
            task=task,
            sources=(
                AgentContextSource(
                    source_ref=ref,
                    kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                    text=plan.snippet.model_dump_json(),
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
            idempotency_key="review:" + plan.plan_id,
            context_snapshot=context,
        )
        base = AgentStepRequest.create(plan=run, step=1, remaining_model_tokens=8192)
        envelope = AgentMessageRenderer().render(plan=run, snapshot=context, request=base)
        return AgentStepRequest.create(
            plan=run, step=1, remaining_model_tokens=8192, message_envelope_id=envelope.envelope_id
        ), envelope
