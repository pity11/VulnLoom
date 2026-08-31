from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnloom.adapters import (
    EnvironmentModelCredentialProvider,
    ModelCredentialReference,
    ModelCredentialUnavailable,
)
from vulnloom.adapters.models import ModelProviderConfig
from vulnloom.domain.models import Candidate
from vulnloom.runners.environment import (
    UnsafeEnvironmentName,
    UnsafeEnvironmentValue,
    build_worker_environment,
)


def test_worker_environment_starts_empty_and_does_not_inherit_parent(monkeypatch):
    monkeypatch.setenv("VULNLOOM_MODEL_API_KEY", "super-secret")
    worker = build_worker_environment({"VULNLOOM_TASK_ID": "task-7"})
    assert worker["VULNLOOM_TASK_ID"] == "task-7"
    assert "VULNLOOM_MODEL_API_KEY" not in worker
    assert "PATH" not in worker


def test_worker_environment_rejects_explicit_secret():
    with pytest.raises(UnsafeEnvironmentName, match="cannot enter Worker"):
        build_worker_environment({"OPENAI_API_KEY": "secret"})


def test_worker_environment_rejects_fixed_names_and_unsafe_values():
    with pytest.raises(UnsafeEnvironmentName, match="cannot be overridden"):
        build_worker_environment({"LANG": "en_US.UTF-8"})
    with pytest.raises(UnsafeEnvironmentValue, match="safety limits"):
        build_worker_environment({"VULNLOOM_INPUT": "bad\x00value"})


def test_model_key_is_leased_only_by_control_plane():
    reference = ModelCredentialReference.create(
        environment_variable="VULNLOOM_TEST_MODEL_KEY"
    )
    config = ModelProviderConfig(
        provider_id="openai-compatible",
        base_url="https://models.example/v1",
        model="research-model",
        credential_reference=reference,
    )
    provider = EnvironmentModelCredentialProvider(
        {"VULNLOOM_TEST_MODEL_KEY": "secret-value", "UNRELATED_SECRET": "hidden"},
        allowed_references=(reference,),
    )
    lease = provider.acquire(reference)
    with lease:
        assert bytes(lease.view()) == b"secret-value"
    assert lease.released
    assert lease.zeroed
    with pytest.raises(ModelCredentialUnavailable, match="released"):
        lease.view()
    assert "secret-value" not in config.model_dump_json()
    assert "hidden" not in config.model_dump_json()


def test_model_credential_provider_rejects_unregistered_reference():
    allowed = ModelCredentialReference.create(environment_variable="ALLOWED_MODEL_KEY")
    denied = ModelCredentialReference.create(environment_variable="UNRELATED_SECRET")
    provider = EnvironmentModelCredentialProvider(
        {"ALLOWED_MODEL_KEY": "allowed", "UNRELATED_SECRET": "hidden"},
        allowed_references=(allowed,),
    )

    with pytest.raises(ModelCredentialUnavailable, match="not allowed"):
        provider.acquire(denied)


@pytest.mark.parametrize("secret", ["", "bad\x00secret", "x" * 16_385])
def test_model_credential_provider_rejects_invalid_secret_values(secret):
    reference = ModelCredentialReference.create(environment_variable="MODEL_KEY")
    provider = EnvironmentModelCredentialProvider(
        {"MODEL_KEY": secret}, allowed_references=(reference,)
    )

    with pytest.raises(ModelCredentialUnavailable, match="unavailable|invalid"):
        provider.acquire(reference)


def test_model_credential_provider_requires_a_nonempty_unique_allowlist():
    reference = ModelCredentialReference.create(environment_variable="MODEL_KEY")
    with pytest.raises(ValueError, match="non-empty and unique"):
        EnvironmentModelCredentialProvider({}, allowed_references=())
    with pytest.raises(ValueError, match="non-empty and unique"):
        EnvironmentModelCredentialProvider(
            {}, allowed_references=(reference, reference)
        )


def test_candidate_signal_references_are_content_digests(candidate):
    assert candidate.signal_ids == ("d" * 64,)
    with pytest.raises(ValidationError):
        Candidate.model_validate({**candidate.model_dump(), "signal_ids": ("not-a-digest",)})
