"""An operator-initiated fixed provider test with no tool or research workflow dispatch."""

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from vulnloom.adapters.model_credentials import ModelCredentialProvider, ModelCredentialUnavailable
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import utc_now
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole

from .context import (
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextSource,
    AgentContextSourceKind,
)
from .live_provider import SubprocessHttpsProviderAdapter
from .messages import AgentMessageRenderer
from .models import AgentDecisionPayload, AgentRunLimits, AgentRunPlan, AgentStepRequest
from .provider_admission import AgentProviderEgressPurpose, AgentProviderEgressStore
from .provider_codec import OpenAIResponsesV1Codec
from .provider_probe_cuc import (
    CucChatProbeCodec,
    CucChatProbeCodecRegistration,
    CucChatStructuredProbeCodec,
    CucChatStructuredProbeCodecRegistration,
)
from .provider_probe_fixture import (
    CUC_PROBE_DIGEST,
    CUC_PROBE_TEXT,
    CUC_STRUCTURED_PROBE_DIGEST,
    CUC_STRUCTURED_PROBE_TEXT,
)
from .provider_probe_models import (
    PROBE_DIGEST,
    PROBE_SUMMARY,
    PROBE_TEXT,
    ProviderProbeConfig,
    ProviderProbePlan,
    ProviderProbeResult,
)
from .provider_probe_store import ProviderProbeStore
from .transport import AgentProviderTransportRejected, AgentProviderTransportTimedOut


def _digest(value):
    return canonical_digest(value.model_dump(mode="python"))


class ProviderProbeService:
    def __init__(
        self,
        *,
        config: ProviderProbeConfig,
        egress_store: AgentProviderEgressStore,
        credential_provider: ModelCredentialProvider,
        store: ProviderProbeStore,
        resolver=None,
        process_runner=None,
        now=utc_now,
    ):
        self.config = ProviderProbeConfig.model_validate(config.model_dump(mode="python"))
        self.egress_store = egress_store
        self.credential_provider = credential_provider
        self.store = store
        self.resolver = resolver
        self.process_runner = process_runner
        self.now = now

    def prepare(self, *, now: datetime, deadline: datetime, idempotency_key: str):
        config = ProviderProbeConfig.model_validate(self.config.model_dump(mode="python"))
        grant = self.egress_store.require_active(
            config.registration.egress_grant_id,
            admission=config.admission,
            now=now,
        )
        if grant.purpose is not AgentProviderEgressPurpose.MODEL_INFERENCE or not (
            now < deadline <= grant.expires_at
            and (deadline - now).total_seconds() > config.admission.limits.timeout_seconds
        ):
            raise ValueError("provider probe requires active inference authority and time budget")
        return ProviderProbePlan.create(
            config_digest=_digest(config),
            fixture_digest=CUC_STRUCTURED_PROBE_DIGEST
            if isinstance(config.codec, CucChatStructuredProbeCodecRegistration)
            else CUC_PROBE_DIGEST
            if isinstance(config.codec, CucChatProbeCodecRegistration)
            else PROBE_DIGEST,
            grant_id=grant.grant_id,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def execute(self, plan: ProviderProbePlan) -> ProviderProbeResult:
        plan = ProviderProbePlan.model_validate(plan.model_dump(mode="python"))
        now = self.now()
        expected = self.prepare(
            now=plan.created_at, deadline=plan.deadline, idempotency_key=plan.idempotency_key
        )
        if expected != plan or not plan.created_at <= now < plan.deadline:
            raise ValueError("provider probe plan or execution window drifted")
        self.egress_store.require_active(plan.grant_id, admission=self.config.admission, now=now)
        result = self.store.claim(plan)
        if result is not None:
            if result.completed_at > now:
                raise ValueError("provider probe completion is in the future")
            return result
        adapter = None
        codec = None
        status, input_tokens, output_tokens = "rejected", 0, 0
        uncertain_failure = False
        try:
            request, envelope = self._message(plan)
            if (
                plan.deadline - self.now()
            ).total_seconds() <= self.config.admission.limits.timeout_seconds:
                raise AgentProviderTransportTimedOut("provider probe time budget exhausted")
            codec = (
                CucChatStructuredProbeCodec(self.config.codec)
                if isinstance(self.config.codec, CucChatStructuredProbeCodecRegistration)
                else CucChatProbeCodec(self.config.codec)
                if isinstance(self.config.codec, CucChatProbeCodecRegistration)
                else OpenAIResponsesV1Codec(self.config.codec)
            )
            adapter = SubprocessHttpsProviderAdapter(
                registration=self.config.registration,
                admission=self.config.admission,
                credential_reference=self.config.credential_reference,
                credential_provider=self.credential_provider,
                egress_store=self.egress_store,
                provider_codec=codec,
                resolver=self.resolver,
                process_runner=self.process_runner,
                now=self.now,
            )
            reply = adapter.complete(request, message_envelope=envelope)
            decision = AgentDecisionPayload.model_validate(reply.structured_output)
            if reply.output_tokens > self.config.registration.max_output_tokens:
                raise ValueError("provider reported output over budget")
            input_tokens, output_tokens = reply.input_tokens, reply.output_tokens
            if (
                decision.kind.value == "complete"
                and decision.summary_digest == PROBE_SUMMARY
                and decision.tool_call is None
                and not decision.supporting_ref_digests
            ):
                status = "passed"
        except (AgentProviderTransportTimedOut, TimeoutError):
            status = "timed_out"
        except (AgentProviderTransportRejected, ModelCredentialUnavailable, ValueError):
            status = "rejected"
        except Exception:
            uncertain_failure = True
            # Provider errors may contain secrets or bodies. Never persist or print them.
            status = "rejected"
        completed_at = self.now()
        if completed_at >= plan.deadline:
            status = "timed_out"
        attempts = adapter.attempts if adapter else []
        receipts = adapter.receipts if adapter else []
        # A request without its final attempt has no trustworthy cleanup proof.
        # In particular, an invalid cleanup record must not pass via all([]).
        attempts_complete = adapter is None or len(attempts) == len(adapter.transport_requests)
        cleanup = not uncertain_failure and attempts_complete and all(
            a.credential_released
            and a.request_body_released
            and a.raw_response_discarded
            and a.process_terminated
            and a.stderr_discarded
            for a in attempts
        )
        if status == "passed" and (not cleanup or len(attempts) != 1 or len(receipts) != 1):
            status = "rejected"
        result = ProviderProbeResult.create(
            plan_id=plan.plan_id,
            status=status,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            process_started=any(a.process_started for a in attempts),
            cleanup_verified=cleanup,
            attempt_digest=_digest(attempts[0]) if len(attempts) == 1 else None,
            receipt_digest=_digest(receipts[0]) if len(receipts) == 1 else None,
            completed_at=completed_at,
            response_model=getattr(codec, "response_model", None),
            diagnostic=getattr(adapter, "diagnostic", None),
        )
        self.store.complete(result)
        return result

    def _message(self, plan):
        # Synthetic identities are derived from the probe only; no Target or Scope is loaded.
        identity = uuid5(NAMESPACE_URL, "vulnloom-provider-probe:" + plan.plan_id)
        fixture_digest = plan.fixture_digest
        fixture_text = {
            CUC_PROBE_DIGEST: CUC_PROBE_TEXT,
            CUC_STRUCTURED_PROBE_DIGEST: CUC_STRUCTURED_PROBE_TEXT,
            PROBE_DIGEST: PROBE_TEXT,
        }[fixture_digest]
        ref = "observation:" + fixture_digest
        task = TaskEnvelope(
            task_id=identity,
            engagement_id=identity,
            target_id=identity,
            scope_id=identity,
            target_version=fixture_digest,
            scope_version=1,
            worker_role=WorkerRole.REPORTER,
            policy_digest=fixture_digest,
            sandbox_profile_digest=fixture_digest,
            tool_registry_digest=fixture_digest,
            input_refs=(ref,),
            allowed_tools=frozenset(),
            budget=TaskBudget(wall_seconds=30, model_tokens=512, tool_calls=0),
            deadline=plan.deadline,
            idempotency_key="provider-probe:" + plan.plan_id,
        )
        snapshot = AgentContextAssembler().assemble(
            task=task,
            sources=(
                AgentContextSource(
                    source_ref=ref,
                    kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                    text=fixture_text,
                ),
            ),
            limits=AgentContextLimits(),
            now=plan.created_at,
            deadline=plan.deadline,
        )
        run = AgentRunPlan.create(
            task=task,
            registration=self.config.registration,
            limits=AgentRunLimits(
                max_steps=1,
                max_output_tokens_per_step=self.config.registration.max_output_tokens,
                timeout_seconds=30,
            ),
            created_at=plan.created_at,
            deadline=plan.deadline,
            idempotency_key="provider-probe:" + plan.plan_id,
            context_snapshot=snapshot,
        )
        base = AgentStepRequest.create(plan=run, step=1, remaining_model_tokens=512)
        envelope = AgentMessageRenderer().render(plan=run, snapshot=snapshot, request=base)
        return AgentStepRequest.create(
            plan=run, step=1, remaining_model_tokens=512, message_envelope_id=envelope.envelope_id
        ), envelope


def cuc_probe_admission():
    """Return the exact code-owned CUC endpoint/budget for independent operator review."""
    from vulnloom.adapters.model_credentials import ModelCredentialReference

    from .provider_process import SUBPROCESS_HTTPS_ADAPTER_DIGEST
    from .transport import AgentProviderTransportAdmission, AgentProviderTransportLimits

    reference = ModelCredentialReference.create(environment_variable="CUC_DEEPSEEK_API_KEY")
    return AgentProviderTransportAdmission.create_live_https(
        provider_id="cuc",
        hostname="openai.cuc.edu.cn",
        request_path="/v1/chat/completions",
        credential_reference_id=reference.reference_id,
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        limits=AgentProviderTransportLimits(
            max_request_bytes=32768,
            max_response_bytes=32768,
            timeout_seconds=10,
            max_requests_per_minute=1,
        ),
    )


def create_cuc_probe_config(*, grant_id: str, structured: bool = False) -> ProviderProbeConfig:
    """Bind a supplied grant; never issue it, read a key, or enable a shim."""
    from vulnloom.adapters.model_credentials import ModelCredentialReference

    from .models import AgentModelRegistration
    from .provider_process import SUBPROCESS_HTTPS_ADAPTER_DIGEST

    reference = ModelCredentialReference.create(environment_variable="CUC_DEEPSEEK_API_KEY")
    admission = cuc_probe_admission()
    codec = (
        CucChatStructuredProbeCodecRegistration.create()
        if structured
        else CucChatProbeCodecRegistration.create()
    )
    registration = AgentModelRegistration.create_subprocess_https(
        provider_id="cuc",
        model="cuc/deepseek",
        adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
        credential_reference_id=reference.reference_id,
        transport_admission_id=admission.admission_id,
        egress_grant_id=grant_id,
        provider_codec_id=codec.codec_id,
        supported_roles=(WorkerRole.REPORTER,),
        max_output_tokens=256,
    )
    return ProviderProbeConfig(
        registration=registration, admission=admission, credential_reference=reference, codec=codec
    )
