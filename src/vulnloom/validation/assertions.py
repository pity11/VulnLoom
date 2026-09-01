"""Deterministic verdict adapters over trusted, typed validation observations."""

from __future__ import annotations

from vulnloom.broker import BrokerResult, BrokerStatus, pinned_http_tool_registry
from vulnloom.domain.models import ValidationResult
from vulnloom.runners import SandboxRunResult

from .models import ValidationPlan, ValidationVerdict


class DeterministicHttpJudge:
    """Compare one exact precommitted HTTP status/body digest assertion."""

    def __init__(self, *, trusted_registry_digest: str | None = None):
        self.trusted_registry_digest = trusted_registry_digest or pinned_http_tool_registry().digest

    def evaluate(
        self,
        *,
        plan: ValidationPlan,
        runner_result: SandboxRunResult,
        broker_results: tuple[BrokerResult, ...],
        evidence_refs: tuple[str, ...],
    ) -> ValidationVerdict:
        assertion = plan.http_assertion
        if assertion is None:
            return ValidationVerdict(
                result=ValidationResult.INCONCLUSIVE,
                rationale_code="http_assertion_not_configured",
                evidence_refs=evidence_refs,
            )
        result = next(
            (item for item in broker_results if item.call_id == assertion.call_id),
            None,
        )
        if result is None or result.status is not BrokerStatus.COMPLETED or result.http is None:
            return ValidationVerdict(
                result=ValidationResult.INCONCLUSIVE,
                rationale_code="http_assertion_call_not_completed",
                evidence_refs=evidence_refs,
            )
        if result.registry_digest != self.trusted_registry_digest:
            return ValidationVerdict(
                result=ValidationResult.INCONCLUSIVE,
                rationale_code="http_assertion_untrusted_registry",
                evidence_refs=result.http.evidence_refs,
            )
        matched = (
            result.http.status_code == assertion.expected_status_code
            and result.http.response_body_sha256 == assertion.expected_body_sha256
        )
        return ValidationVerdict(
            result=assertion.match_result if matched else ValidationResult.INCONCLUSIVE,
            rationale_code=(
                "http_response_assertion_matched"
                if matched
                else "http_response_assertion_mismatched"
            ),
            evidence_refs=result.http.evidence_refs,
        )
