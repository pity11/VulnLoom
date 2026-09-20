"""Fail-closed Hybrid admission over authoritative source and live facts."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from vulnloom.broker import BrokerStatus
from vulnloom.broker.models import url_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    Candidate,
    EvidenceBundle,
    Scope,
    ScopeState,
    ValidationResult,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.validation import ValidationPlan, ValidationStore

from .models import (
    DeploymentProof,
    HybridCheckKind,
    HybridConclusion,
    HybridEvidenceChain,
    HybridRunState,
    HybridValidationLimits,
    HybridValidationOutcome,
    HybridValidationPlan,
    SourceRemediationProof,
)
from .store import HybridValidationStore


class HybridValidationRejected(ValueError):
    pass


class HybridValidationService:
    def __init__(
        self,
        *,
        validation_store: ValidationStore,
        hybrid_store: HybridValidationStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.validation_store = validation_store
        self.hybrid_store = hybrid_store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        check_kind: HybridCheckKind,
        candidate: Candidate,
        deployment_proof: DeploymentProof,
        validation_plan: ValidationPlan,
        source_validation_plan: ValidationPlan | None = None,
        source_manifest_digest: str,
        source_evidence_refs: tuple[str, ...],
        scope: Scope,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
        prior_chain: HybridEvidenceChain | None = None,
        limits: HybridValidationLimits | None = None,
    ) -> HybridValidationPlan:
        self._scope(scope, now=created_at)
        if (
            deployment_proof.source_target_id != candidate.target_id
            or deployment_proof.source_target_version != candidate.target_version
            or deployment_proof.source_manifest_digest != source_manifest_digest
            or not deployment_proof.attested_at <= created_at < deployment_proof.expires_at
            or validation_plan.candidate_id != candidate.candidate_id
            or validation_plan.candidate_digest != self._digest(candidate)
            or validation_plan.target_id != candidate.target_id
            or validation_plan.target_version != candidate.target_version
            or validation_plan.scope_id != scope.scope_id
            or validation_plan.scope_version != scope.version
        ):
            raise HybridValidationRejected(
                "Hybrid source, deployment, or validation binding failed"
            )
        self._source_plan(
            check_kind=check_kind,
            source_plan=source_validation_plan,
            live_plan=validation_plan,
            candidate=candidate,
            scope=scope,
        )
        self._prior(
            check_kind=check_kind,
            prior=prior_chain,
            candidate=candidate,
            proof=deployment_proof,
            scope=scope,
        )
        exact_calls = tuple(
            call
            for call in validation_plan.broker_calls
            if call.http is not None
            and url_digest(call.http.url) == deployment_proof.endpoint_url_digest
        )
        if len(exact_calls) != 1:
            raise HybridValidationRejected(
                "Hybrid validation must route exactly one call to the deployed endpoint"
            )
        expected = (
            ValidationResult.REPRODUCED
            if check_kind is HybridCheckKind.INITIAL
            else ValidationResult.NOT_REPRODUCED
        )
        canonical_source_refs = tuple(sorted(set(source_evidence_refs)))
        values = {
            "check_kind": check_kind,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": self._digest(candidate),
            "source_target_id": candidate.target_id,
            "source_target_version": candidate.target_version,
            "source_manifest_digest": source_manifest_digest,
            "live_target_id": deployment_proof.live_target_id,
            "endpoint_url_digest": deployment_proof.endpoint_url_digest,
            "deployment_proof_id": deployment_proof.proof_id,
            "deployment_proof_digest": self._digest(deployment_proof),
            "source_validation_plan_id": (
                source_validation_plan.plan_id if source_validation_plan else None
            ),
            "validation_plan_id": validation_plan.plan_id,
            "source_evidence_refs": canonical_source_refs,
            "expected_result": expected,
            "prior_chain_id": prior_chain.chain_id if prior_chain else None,
            "scope_id": scope.scope_id,
            "scope_version": scope.version,
            "limits": limits or HybridValidationLimits(),
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        return HybridValidationPlan.create(**values)

    def execute(
        self,
        plan: HybridValidationPlan,
        *,
        candidate: Candidate,
        deployment_proof: DeploymentProof,
        scope: Scope,
        now: datetime,
        prior_chain: HybridEvidenceChain | None = None,
        recover: bool = False,
    ) -> HybridValidationOutcome:
        _, validation, source_validation, http_refs = self._preflight(
            plan,
            candidate=candidate,
            deployment_proof=deployment_proof,
            scope=scope,
            now=now,
            prior_chain=prior_chain,
        )
        claim = (
            self.hybrid_store.recover(plan, now=now)
            if recover
            else self.hybrid_store.claim(plan, now=now)
        )
        if not claim.created:
            assert claim.outcome is not None
            if claim.outcome.chain is not None and any(
                not self.evidence_store.contains(ref)
                for ref in claim.outcome.chain.evidence_bundle.evidence_refs
            ):
                raise HybridValidationRejected(
                    "completed Hybrid Evidence Chain integrity failed"
                )
            return claim.outcome
        if now >= plan.deadline:
            return self._terminal(
                plan,
                claim,
                state=HybridRunState.TIMED_OUT,
                reason_code="hybrid_deadline_elapsed",
                now=now,
            )
        started = self.monotonic()
        all_refs = {
            *plan.source_evidence_refs,
            deployment_proof.attestation_evidence_ref,
            *http_refs,
        }
        if any(not self.evidence_store.contains(ref) for ref in all_refs):
            return self._terminal(
                plan,
                claim,
                state=HybridRunState.FAILED,
                reason_code="evidence_integrity_failed",
                now=now,
            )
        if self.monotonic() - started > plan.limits.timeout_seconds:
            return self._terminal(
                plan,
                claim,
                state=HybridRunState.TIMED_OUT,
                reason_code="hybrid_budget_elapsed",
                now=now,
            )
        bundle = EvidenceBundle(
            candidate_id=candidate.candidate_id,
            evidence_refs=tuple(sorted(all_refs)),
            sealed_at=now,
        )
        source_proof = None
        if source_validation is not None:
            assert plan.prior_chain_id is not None
            source_proof = SourceRemediationProof.create(
                prior_chain_id=plan.prior_chain_id,
                candidate_id=candidate.candidate_id,
                candidate_digest=plan.candidate_digest,
                source_target_id=plan.source_target_id,
                source_target_version=plan.source_target_version,
                source_manifest_digest=plan.source_manifest_digest,
                validation_plan_id=source_validation.plan_id,
                validation_run_id=source_validation.validation_run.run_id,
                evidence_refs=plan.source_evidence_refs,
                scope_id=plan.scope_id,
                scope_version=plan.scope_version,
                sealed_at=now,
            )
        chain = HybridEvidenceChain.create(
            plan_id=plan.plan_id,
            check_kind=plan.check_kind,
            conclusion=(
                HybridConclusion.CONFIRMED
                if plan.check_kind is HybridCheckKind.INITIAL
                else HybridConclusion.REMEDIATED
            ),
            candidate_id=candidate.candidate_id,
            candidate_digest=plan.candidate_digest,
            source_target_id=plan.source_target_id,
            source_target_version=plan.source_target_version,
            source_manifest_digest=plan.source_manifest_digest,
            live_target_id=plan.live_target_id,
            endpoint_url_digest=plan.endpoint_url_digest,
            deployment_proof_id=plan.deployment_proof_id,
            source_remediation_proof_id=(source_proof.proof_id if source_proof else None),
            validation_plan_id=plan.validation_plan_id,
            validation_run_id=validation.validation_run.run_id,
            prior_chain_id=plan.prior_chain_id,
            source_evidence_refs=plan.source_evidence_refs,
            deployment_evidence_ref=deployment_proof.attestation_evidence_ref,
            http_evidence_refs=http_refs,
            evidence_bundle=bundle,
            scope_id=plan.scope_id,
            scope_version=plan.scope_version,
            sealed_at=now,
        )
        return self._terminal(
            plan,
            claim,
            state=HybridRunState.COMPLETED,
            reason_code="hybrid_evidence_chain_sealed",
            now=now,
            chain=chain,
            source_remediation_proof=source_proof,
        )

    def _preflight(self, plan, *, candidate, deployment_proof, scope, now, prior_chain):
        self._scope(scope, now=now)
        self._prior(
            check_kind=plan.check_kind,
            prior=prior_chain,
            candidate=candidate,
            proof=deployment_proof,
            scope=scope,
        )
        try:
            validation_plan, validation = self.validation_store.load_completed(
                plan.validation_plan_id
            )
        except (ValueError, RuntimeError) as exc:
            raise HybridValidationRejected(
                "authoritative completed dynamic Validation is unavailable"
            ) from exc
        source_validation = None
        if plan.source_validation_plan_id is not None:
            try:
                source_plan, source_validation = self.validation_store.load_completed(
                    plan.source_validation_plan_id
                )
            except (ValueError, RuntimeError) as exc:
                raise HybridValidationRejected(
                    "authoritative completed source remediation Validation is unavailable"
                ) from exc
            self._source_validation(
                plan,
                source_plan=source_plan,
                source_validation=source_validation,
                candidate=candidate,
            )
        if (
            plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != self._digest(candidate)
            or plan.source_target_id != candidate.target_id
            or plan.source_target_version != candidate.target_version
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.deployment_proof_id != deployment_proof.proof_id
            or plan.deployment_proof_digest != self._digest(deployment_proof)
            or plan.source_manifest_digest != deployment_proof.source_manifest_digest
            or plan.live_target_id != deployment_proof.live_target_id
            or plan.endpoint_url_digest != deployment_proof.endpoint_url_digest
            or not deployment_proof.attested_at <= now < deployment_proof.expires_at
            or validation_plan.candidate_id != candidate.candidate_id
            or validation_plan.candidate_digest != plan.candidate_digest
            or validation.candidate.candidate_id != candidate.candidate_id
            or validation.validation_run.candidate_id != candidate.candidate_id
            or validation.verdict.result is not plan.expected_result
            or validation.validation_run.result is not plan.expected_result
            or validation.evidence_bundle is None
        ):
            raise HybridValidationRejected("Hybrid authoritative provenance failed")
        http_refs = self._http_evidence(
            plan, validation_plan=validation_plan, validation=validation
        )
        return validation_plan, validation, source_validation, http_refs

    @staticmethod
    def _source_plan(*, check_kind, source_plan, live_plan, candidate, scope) -> None:
        if check_kind is HybridCheckKind.INITIAL:
            if source_plan is not None:
                raise HybridValidationRejected(
                    "initial Hybrid validation cannot bind a source remediation Validation"
                )
            return
        if (
            source_plan is None
            or source_plan.plan_id == live_plan.plan_id
            or source_plan.candidate_id != candidate.candidate_id
            or source_plan.candidate_digest != HybridValidationService._digest(candidate)
            or source_plan.target_id != candidate.target_id
            or source_plan.target_version != candidate.target_version
            or source_plan.scope_id != scope.scope_id
            or source_plan.scope_version != scope.version
            or source_plan.broker_calls
            or source_plan.http_assertion is not None
        ):
            raise HybridValidationRejected(
                "Hybrid remediation requires an independent network-free source Validation"
            )

    @staticmethod
    def _source_validation(plan, *, source_plan, source_validation, candidate) -> None:
        source_refs = tuple(sorted(set(source_validation.verdict.evidence_refs)))
        if (
            source_plan.plan_id != plan.source_validation_plan_id
            or source_plan.candidate_id != candidate.candidate_id
            or source_plan.candidate_digest != plan.candidate_digest
            or source_plan.target_id != plan.source_target_id
            or source_plan.target_version != plan.source_target_version
            or source_plan.scope_id != plan.scope_id
            or source_plan.scope_version != plan.scope_version
            or source_plan.broker_calls
            or source_plan.http_assertion is not None
            or source_validation.candidate.candidate_id != candidate.candidate_id
            or source_validation.validation_run.candidate_id != candidate.candidate_id
            or source_validation.verdict.result is not ValidationResult.NOT_REPRODUCED
            or source_validation.validation_run.result is not ValidationResult.NOT_REPRODUCED
            or source_validation.evidence_bundle is None
            or source_validation.evidence_bundle.evidence_refs != source_refs
            or source_refs != plan.source_evidence_refs
        ):
            raise HybridValidationRejected(
                "Hybrid source remediation authoritative provenance failed"
            )

    @staticmethod
    def _scope(scope: Scope, *, now: datetime) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise HybridValidationRejected("Hybrid validation requires current approved Scope")

    def _prior(self, *, check_kind, prior, candidate, proof, scope) -> None:
        if check_kind is HybridCheckKind.INITIAL:
            if prior is not None:
                raise HybridValidationRejected(
                    "initial Hybrid validation cannot bind a prior chain"
                )
            return
        if (
            prior is None
            or prior.conclusion is not HybridConclusion.CONFIRMED
            or prior.source_target_id != candidate.target_id
            or prior.source_target_version == candidate.target_version
            or prior.live_target_id != proof.live_target_id
            or prior.endpoint_url_digest != proof.endpoint_url_digest
            or prior.scope_id != scope.scope_id
        ):
            raise HybridValidationRejected("Hybrid remediation retest lineage is invalid")
        try:
            authoritative = self.hybrid_store.outcome(prior.plan_id)
        except RuntimeError as exc:
            raise HybridValidationRejected(
                "Hybrid remediation retest prior chain is not authoritative"
            ) from exc
        if authoritative.chain != prior or authoritative.state is not HybridRunState.COMPLETED:
            raise HybridValidationRejected(
                "Hybrid remediation retest prior chain is not authoritative"
            )

    @staticmethod
    def _http_evidence(plan, *, validation_plan, validation) -> tuple[str, ...]:
        calls = {
            call.call_id: call
            for call in validation_plan.broker_calls
            if call.http is not None and url_digest(call.http.url) == plan.endpoint_url_digest
        }
        matches = tuple(
            result
            for result in validation.broker_results
            if result.call_id in calls
            and result.status is BrokerStatus.COMPLETED
            and result.http is not None
            and result.http.final_url_digest == plan.endpoint_url_digest
        )
        if len(calls) != 1 or len(matches) != 1:
            raise HybridValidationRejected("dynamic Validation did not prove the exact endpoint")
        refs = tuple(sorted(set(matches[0].http.evidence_refs)))
        if not refs or len(refs) > plan.limits.max_http_evidence_refs:
            raise HybridValidationRejected("Hybrid HTTP Evidence budget is invalid")
        return refs

    def _terminal(
        self,
        plan,
        claim,
        *,
        state,
        reason_code,
        now,
        chain=None,
        source_remediation_proof=None,
    ):
        outcome = HybridValidationOutcome(
            plan_id=plan.plan_id,
            state=state,
            attempt=claim.attempt,
            chain=chain,
            source_remediation_proof=source_remediation_proof,
            reason_code=reason_code,
            cleanup_complete=True,
            completed_at=now,
        )
        self.hybrid_store.finish(outcome)
        return outcome

    @staticmethod
    def _digest(value) -> str:
        return canonical_digest(value.model_dump(mode="python"))
