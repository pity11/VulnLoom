from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import pytest

from vulnloom.cli import main
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, utc_now
from vulnloom.storage import (
    AuditIntegrityError,
    EventStore,
    FileAuditCheckpointStore,
    control_plane_audit_stream_id,
)


def test_cli_scope_event_uses_checkpointed_authoritative_path(
    tmp_path, capsys, approved_scope
):
    database = tmp_path / "events.db"
    checkpoints = tmp_path / "trusted-checkpoints"
    scope_file = tmp_path / "scope.json"
    current = utc_now()
    raw = approved_scope.model_dump(mode="python")
    raw.update(
        {
            "state": "draft",
            "approved_by": None,
            "approved_at": None,
            "valid_from": current - timedelta(hours=1),
            "valid_until": current + timedelta(hours=1),
        }
    )
    draft = Scope.model_validate(raw)
    scope_file.write_text(draft.model_dump_json(), encoding="utf-8")
    arguments = [
        "--db",
        str(database),
        "--audit-checkpoint-store",
        str(checkpoints),
        "scope-approve",
        "--file",
        str(scope_file),
        "--approver",
        "security-owner",
    ]

    assert main(arguments) == 0
    first = json.loads(capsys.readouterr().out)

    stream_id = control_plane_audit_stream_id(draft.engagement_id)
    checkpoint = FileAuditCheckpointStore(checkpoints).load(stream_id)
    assert checkpoint is not None and checkpoint.sequence == 1
    with EventStore(database) as store:
        projection = store.audit.projections(
            stream_id,
            trusted_checkpoint=checkpoint,
            now=utc_now(),
        )[0]

    assert first["created"] is True
    assert projection.scope_id == draft.scope_id
    assert projection.scope_version == draft.version
    approved = Scope.model_validate(first["event"]["payload"])
    assert projection.policy_digest == canonical_digest(
        approved.model_dump(mode="python")
    )


def test_cli_status_rejects_database_rollback_against_custodied_checkpoint(
    tmp_path, capsys
):
    database = tmp_path / "events.db"
    checkpoints = tmp_path / "trusted-checkpoints"
    create = [
        "--db",
        str(database),
        "--audit-checkpoint-store",
        str(checkpoints),
        "engagement-create",
        "--name",
        "Authorized lab",
        "--authority",
        "contract-42",
        "--idempotency-key",
        "engagement:audit-test",
    ]
    assert main(create) == 0
    engagement_id = json.loads(capsys.readouterr().out)["event"]["engagement_id"]

    connection = sqlite3.connect(database)
    connection.execute("DELETE FROM domain_events")
    connection.execute("DELETE FROM authoritative_audit_records")
    connection.execute("DELETE FROM authoritative_audit_heads")
    connection.commit()
    connection.close()

    with pytest.raises(AuditIntegrityError, match="checkpoint_ahead_of_chain"):
        main(
            [
                "--db",
                str(database),
                "--audit-checkpoint-store",
                str(checkpoints),
                "status",
                "--engagement-id",
                engagement_id,
            ]
        )
