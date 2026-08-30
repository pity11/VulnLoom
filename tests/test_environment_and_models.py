from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnloom.adapters.models import ModelProviderConfig
from vulnloom.domain.models import Candidate
from vulnloom.runners.environment import UnsafeEnvironmentName, build_worker_environment


def test_worker_environment_starts_empty_and_does_not_inherit_parent(monkeypatch):
    monkeypatch.setenv("VULNLOOM_MODEL_API_KEY", "super-secret")
    worker = build_worker_environment({"VULNLOOM_TASK_ID": "task-7"})
    assert worker["VULNLOOM_TASK_ID"] == "task-7"
    assert "VULNLOOM_MODEL_API_KEY" not in worker
    assert "PATH" not in worker


def test_worker_environment_rejects_explicit_secret():
    with pytest.raises(UnsafeEnvironmentName, match="cannot enter Worker"):
        build_worker_environment({"OPENAI_API_KEY": "secret"})


def test_model_key_is_resolved_only_by_control_plane(monkeypatch):
    config = ModelProviderConfig(
        provider_id="openai-compatible",
        base_url="https://models.example/v1",
        model="research-model",
        api_key_env="VULNLOOM_TEST_MODEL_KEY",
    )
    with pytest.raises(RuntimeError, match="not set"):
        config.resolve_api_key()
    monkeypatch.setenv("VULNLOOM_TEST_MODEL_KEY", "secret-value")
    assert config.resolve_api_key() == "secret-value"
    assert "secret-value" not in config.model_dump_json()


def test_candidate_signal_references_are_content_digests(candidate):
    assert candidate.signal_ids == ("d" * 64,)
    with pytest.raises(ValidationError):
        Candidate.model_validate({**candidate.model_dump(), "signal_ids": ("not-a-digest",)})
