from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnloom.agent_runtime import ModelInvocationResult
from vulnloom.agent_runtime.provider_diagnostics import ProviderDiagnostic

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _passed():
    return ModelInvocationResult.create(
        plan_id="a" * 64,
        provider_id="alpha",
        status="passed",
        input_tokens=3,
        output_tokens=2,
        process_started=True,
        cleanup_verified=True,
        attempt_digest="b" * 64,
        receipt_digest="c" * 64,
        completed_at=NOW,
        diagnostic=ProviderDiagnostic(
            failure_stage=None,
            error_code=None,
            http_status=200,
            network_opened=True,
            captured_response_bytes=128,
            tls_version="TLSv1.3",
        ),
        response_model="model-a",
    )


def test_model_invocation_result_is_sealed_and_round_trips():
    result = _passed()

    assert ModelInvocationResult.model_validate_json(result.model_dump_json()) == result
    with pytest.raises(ValidationError, match="digest mismatch"):
        ModelInvocationResult.model_validate(
            {**result.model_dump(), "output_tokens": result.output_tokens + 1}
        )


@pytest.mark.parametrize(
    "update",
    [
        {"cleanup_verified": False},
        {"receipt_digest": None},
        {"response_model": None},
        {
            "diagnostic": ProviderDiagnostic(
                failure_stage="http_status",
                error_code="http_non_200",
                http_status=401,
                network_opened=True,
                captured_response_bytes=0,
                tls_version="TLSv1.3",
            )
        },
    ],
)
def test_passed_model_invocation_requires_identity_and_cleanup_proof(update):
    result = _passed()
    values = {**result.model_dump(exclude={"result_id"}), **update}

    with pytest.raises(ValidationError):
        ModelInvocationResult.create(**values)
