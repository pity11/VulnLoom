"""Provider-neutral CI projection for Hybrid release gate outcomes."""

from __future__ import annotations

from datetime import datetime

from vulnloom.domain.models import Scope

from .models import DeploymentProof
from .release_gate_models import (
    HybridCiGateResponse,
    HybridCiGateStatus,
    HybridReleaseDecision,
    HybridReleaseGatePlan,
    HybridReleaseGateState,
)
from .release_gate_service import HybridReleaseGateRejected, HybridReleaseGateService
from .release_gate_store import HybridReleaseGateConflict, HybridReleaseGateRecoveryRequired


class HybridCiGateAdapter:
    """Map trusted gate evaluation to stable CI exit semantics without leaking inputs."""

    def __init__(self, service: HybridReleaseGateService):
        self.service = service

    def evaluate(
        self,
        plan: HybridReleaseGatePlan,
        *,
        deployment_proof: DeploymentProof,
        scope: Scope,
        now: datetime,
        recover: bool = False,
    ) -> HybridCiGateResponse:
        try:
            outcome = self.service.evaluate(
                plan,
                deployment_proof=deployment_proof,
                scope=scope,
                now=now,
                recover=recover,
            )
        except HybridReleaseGateRejected:
            return self._error(plan.plan_id, "release_gate_input_rejected")
        except HybridReleaseGateConflict:
            return self._error(plan.plan_id, "release_gate_idempotency_conflict")
        except HybridReleaseGateRecoveryRequired:
            return self._error(plan.plan_id, "release_gate_recovery_required")
        if outcome.state is not HybridReleaseGateState.COMPLETED:
            return self._error(plan.plan_id, outcome.reason_code)
        assert outcome.result is not None
        if outcome.result.decision is HybridReleaseDecision.PASSED:
            return HybridCiGateResponse(
                status=HybridCiGateStatus.PASS,
                exit_code=0,
                plan_id=plan.plan_id,
                result_id=outcome.result.result_id,
                reason_codes=(),
            )
        return HybridCiGateResponse(
            status=HybridCiGateStatus.BLOCK,
            exit_code=1,
            plan_id=plan.plan_id,
            result_id=outcome.result.result_id,
            reason_codes=outcome.result.reason_codes,
        )

    @staticmethod
    def _error(plan_id: str, reason_code: str) -> HybridCiGateResponse:
        return HybridCiGateResponse(
            status=HybridCiGateStatus.ERROR,
            exit_code=2,
            plan_id=plan_id,
            reason_codes=(reason_code,),
        )
