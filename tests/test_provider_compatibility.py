from __future__ import annotations

import pytest

from vulnloom.agent_runtime import (
    CucChatCompatibilityBaseline,
    CucChatCompatibilityDrift,
)


def test_admitted_cuc_chat_path_matches_the_frozen_migration_baseline():
    baseline = CucChatCompatibilityBaseline.create()

    baseline.assert_current()


def test_cuc_chat_baseline_rejects_content_or_digest_drift():
    baseline = CucChatCompatibilityBaseline.create()

    with pytest.raises(ValueError, match="content drifted"):
        CucChatCompatibilityBaseline.model_validate(
            {
                **baseline.model_dump(mode="python"),
                "pong_request_digest": "f" * 64,
            }
        )
    with pytest.raises(ValueError, match="digest mismatch"):
        CucChatCompatibilityBaseline.model_validate(
            {
                **baseline.model_dump(mode="python"),
                "baseline_id": "f" * 64,
            }
        )


def test_cuc_chat_baseline_fails_closed_on_legacy_registration_drift(monkeypatch):
    baseline = CucChatCompatibilityBaseline.create()
    monkeypatch.setattr(
        "vulnloom.agent_runtime.provider_compatibility.CUC_PROBE_CODEC_DIGEST",
        "f" * 64,
    )

    with pytest.raises(CucChatCompatibilityDrift):
        baseline.assert_current()
