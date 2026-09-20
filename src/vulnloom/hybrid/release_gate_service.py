"""Fail-closed release qualification over authoritative Hybrid evidence."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, ScopeState

from .models import (
    DeploymentProof,
    HybridCheckKind,
    HybridConclusion,
    HybridRunState,
)
from .release_gate_models import (
    HybridReleaseDecision,
    HybridReleaseGateOutcome,
    HybridReleaseGatePlan,
    HybridReleaseGateResult,
    HybridReleaseGateState,
)
from .release_gate_store import HybridReleaseGateStore
from .store import HybridRecoveryRequired, HybridValidationStore


class HybridReleaseGateRejected(ValueError):
    pass


class HybridReleaseGateService:
    def __init__(
        self,
        *,
        hybrid_store: HybridValidationStore,
        release_gate_store: HybridReleaseGateStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.hybrid_store = hybrid_store
        self.release_gate_store = release_gate_store
        self.monotonic = monotonic

    def evaluate(
        self,
        plan: HybridReleaseGatePlan,
        *,
        deployment_proof: DeploymentProof,
        scope: Scope,
        now: datetime,
        recover: bool = False,
    ) -> HybridReleaseGateOutcome:
        chain, source_proof = self._preflight(
            plan,
            deployment_proof=deployment_proof,
            scope=scope,
            now=now,
        )
        claim = (
            self.release_gate_store.recover(plan, now=now)
            if recover
            else self.release_gate_store.claim(plan, now=now)
        )
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        if now >= plan.deadline:
            return self._terminal(
                plan,
                claim,
                state=HybridReleaseGateState.TIMED_OUT,
                reason_code="release_gate_deadline_elapsed",
                now=now,
            )
        started = self.monotonic()
        reasons = ()
        if chain.conclusion is not plan.policy.required_conclusion:
            reasons = ("hybrid_remediation_required",)
        if self.monotonic() - started > plan.policy.timeout_seconds:
            return self._terminal(
                plan,
                claim,
                state=HybridReleaseGateState.TIMED_OUT,
                reason_code="release_gate_budget_elapsed",
                now=now,
            )
        result = HybridReleaseGateResult.create(
            plan_id=plan.plan_id,
            hybrid_chain_id=chain.chain_id,
            decision=(
                HybridReleaseDecision.BLOCKED
                if reasons
                else HybridReleaseDecision.PASSED
            ),
            reason_codes=reasons,
            source_remediation_proof_id=(
                source_proof.proof_id if source_proof is not None else None
            ),
            evaluated_at=now,
        )
        return self._terminal(
            plan,
            claim,
            state=HybridReleaseGateState.COMPLETED,
            reason_code="release_gate_evaluated",
            now=now,
            result=result,
        )

    def _preflight(self, plan, *, deployment_proof, scope, now):
        try:
            HybridReleaseGatePlan.model_validate(plan.model_dump(mode="python"))
            DeploymentProof.model_validate(deployment_proof.model_dump(mode="python"))
        except ValueError as exc:
            raise HybridReleaseGateRejected(
                "Hybrid release gate typed input failed integrity validation"
            ) from exc
        if (
            scope.state is not ScopeState.APPROVED
            or now < plan.created_at
            or not scope.valid_from <= now < scope.valid_until
            or canonical_digest(scope.model_dump(mode="python")) != plan.scope_digest
            or scope.scope_id != plan.scope_id
            or scope.version != plan.scope_version
            or deployment_proof.proof_id != plan.deployment_proof_id
            or canonical_digest(deployment_proof.model_dump(mode="python"))
            != plan.deployment_proof_digest
            or not deployment_proof.attested_at <= now < deployment_proof.expires_at
        ):
            raise HybridReleaseGateRejected(
                "Hybrid release gate Scope or Deployment Proof is not current"
            )
        try:
            authoritative = self.hybrid_store.outcome_by_chain(plan.hybrid_chain_id)
        except HybridRecoveryRequired as exc:
            raise HybridReleaseGateRejected(
                "authoritative Hybrid release evidence is unavailable"
            ) from exc
        chain = authoritative.chain
        if chain is None or authoritative.state is not HybridRunState.COMPLETED:
            raise HybridReleaseGateRejected(
                "authoritative Hybrid release evidence is incomplete"
            )
        source_proof = authoritative.source_remediation_proof
        common_drift = (
            canonical_digest(chain.model_dump(mode="python")) != plan.hybrid_chain_digest
            or chain.deployment_proof_id != deployment_proof.proof_id
            or chain.source_target_id != deployment_proof.source_target_id
            or chain.source_target_version != deployment_proof.source_target_version
            or chain.source_manifest_digest != deployment_proof.source_manifest_digest
            or chain.live_target_id != deployment_proof.live_target_id
            or chain.endpoint_url_digest != deployment_proof.endpoint_url_digest
            or chain.source_target_id != plan.source_target_id
            or chain.source_target_version != plan.source_target_version
            or chain.source_manifest_digest != plan.source_manifest_digest
            or chain.live_target_id != plan.live_target_id
            or chain.endpoint_url_digest != plan.endpoint_url_digest
            or chain.scope_id != plan.scope_id
            or chain.scope_version != plan.scope_version
        )
        if common_drift:
            raise HybridReleaseGateRejected("Hybrid release gate provenance drifted")
        if chain.conclusion is HybridConclusion.REMEDIATED:
            if (
                chain.check_kind is not HybridCheckKind.REMEDIATION_RETEST
                or source_proof is None
                or chain.source_remediation_proof_id != source_proof.proof_id
                or source_proof.prior_chain_id != chain.prior_chain_id
                or source_proof.candidate_id != chain.candidate_id
                or source_proof.candidate_digest != chain.candidate_digest
                or source_proof.source_target_id != chain.source_target_id
                or source_proof.source_target_version != chain.source_target_version
                or source_proof.source_manifest_digest != chain.source_manifest_digest
                or source_proof.scope_id != chain.scope_id
                or source_proof.scope_version != chain.scope_version
                or source_proof.evidence_refs != chain.source_evidence_refs
            ):
                raise HybridReleaseGateRejected(
                    "Hybrid release gate remediation proof is inconsistent"
                )
        elif (
            chain.conclusion is not HybridConclusion.CONFIRMED
            or chain.check_kind is not HybridCheckKind.INITIAL
            or source_proof is not None
        ):
            raise HybridReleaseGateRejected(
                "Hybrid release gate chain conclusion is unsupported"
            )
        return chain, source_proof

    def _terminal(self, plan, claim, *, state, reason_code, now, result=None):
        outcome = HybridReleaseGateOutcome(
            plan_id=plan.plan_id,
            state=state,
            attempt=claim.attempt,
            result=result,
            reason_code=reason_code,
            cleanup_complete=True,
            completed_at=now,
        )
        self.release_gate_store.finish(outcome)
        return outcome
