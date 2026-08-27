from __future__ import annotations

import json
from datetime import timedelta

import pytest

from vulnloom.cli import main
from vulnloom.domain.models import Scope, utc_now


def test_cli_create_and_status(tmp_path, capsys):
    db = tmp_path / "events.db"
    assert (
        main(
            [
                "--db",
                str(db),
                "engagement-create",
                "--name",
                "Authorized lab",
                "--authority",
                "contract-42",
                "--idempotency-key",
                "engagement:test",
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    engagement_id = created["event"]["engagement_id"]

    assert main(["--db", str(db), "status", "--engagement-id", engagement_id]) == 0
    events = json.loads(capsys.readouterr().out)
    assert [event["event_type"] for event in events] == ["EngagementCreated"]


def test_cli_approves_valid_scope(tmp_path, capsys, approved_scope):
    db = tmp_path / "events.db"
    scope_file = tmp_path / "scope.json"
    current = utc_now()
    values = approved_scope.model_dump(mode="python")
    values.update(
        {
            "state": "draft",
            "approved_by": None,
            "approved_at": None,
            "valid_from": current - timedelta(hours=1),
            "valid_until": current + timedelta(hours=1),
        }
    )
    draft = Scope.model_validate(values)
    scope_file.write_text(draft.model_dump_json(), encoding="utf-8")
    assert (
        main(
            [
                "--db",
                str(db),
                "scope-approve",
                "--file",
                str(scope_file),
                "--approver",
                "security-owner",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["event"]["payload"]["state"] == "approved"


def test_cli_refuses_expired_scope(tmp_path, approved_scope):
    scope_file = tmp_path / "scope.json"
    expired = approved_scope.model_copy(
        update={
            "valid_from": utc_now() - timedelta(days=2),
            "valid_until": utc_now() - timedelta(days=1),
        }
    )
    scope_file.write_text(expired.model_dump_json(), encoding="utf-8")
    with pytest.raises(SystemExit, match="outside its validity"):
        main(
            [
                "--db",
                str(tmp_path / "events.db"),
                "scope-approve",
                "--file",
                str(scope_file),
                "--approver",
                "reviewer",
            ]
        )
