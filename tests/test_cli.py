from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest

from vulnloom.benchmark.pilot_readiness_fixture import PILOT_NOW, build_pilot_fixture
from vulnloom.cli import main
from vulnloom.domain.models import ArtifactKind, ArtifactScope, Scope, ScopeState, utc_now
from vulnloom.ingestion import IngestionError, IngestionService


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


def test_cli_runs_authorized_local_shadow_pilot_without_selecting_candidate(
    tmp_path, capsys, monkeypatch
):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(fixture.scope.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("vulnloom.cli.utc_now", lambda: PILOT_NOW)
    args = [
        "--store",
        str(fixture.target_store_root),
        "shadow-pilot-local",
        "--snapshot-id",
        fixture.snapshot.manifest.manifest_id,
        "--scope-file",
        str(scope_file),
        "--analysis-store",
        str(tmp_path / "analysis"),
        "--candidate-store",
        str(tmp_path / "candidates"),
        "--readiness-db",
        str(tmp_path / "readiness.db"),
        "--readiness-store",
        str(tmp_path / "readiness"),
    ]

    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["mode"] == "authorized_local_shadow_pilot"
    assert first["gate_status"] == "passed"
    assert first["candidate_count"] == 5
    assert first["selected_candidate_ids"] == []
    assert {item["state"] for item in first["candidates"]} == {"proposed"}
    assert Path(first["graph_path"]).is_file()
    assert Path(first["candidate_set_path"]).is_file()
    assert not (tmp_path / "validation.db").exists()

    assert main(args) == 0
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["plan_id"] == first["plan_id"]
    assert repeated["graph_created"] is False
    assert repeated["candidate_set_created"] is False

    selection_args = [
        "--store",
        str(fixture.target_store_root),
        "pilot-candidate-select-local",
        "--readiness-plan-id",
        first["plan_id"],
        "--candidate-set-id",
        first["candidate_set_id"],
        "--candidate-id",
        first["candidates"][0]["candidate_id"],
        "--scope-file",
        str(scope_file),
        "--reviewer",
        "human-reviewer",
        "--decided-at",
        PILOT_NOW.isoformat(),
        "--analysis-store",
        str(tmp_path / "analysis"),
        "--candidate-store",
        str(tmp_path / "candidates"),
        "--readiness-db",
        str(tmp_path / "readiness.db"),
        "--readiness-store",
        str(tmp_path / "readiness"),
        "--selection-db",
        str(tmp_path / "selections.db"),
    ]
    assert main(selection_args) == 0
    selected = json.loads(capsys.readouterr().out)
    assert selected["mode"] == "human_pilot_candidate_selection"
    assert selected["candidate_state"] == "proposed"
    assert selected["validation_planned"] is False
    assert selected["record"]["candidate_id"] == first["candidates"][0]["candidate_id"]


def test_cli_shadow_pilot_rejects_revoked_scope_before_output(tmp_path, monkeypatch):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        fixture.scope.model_copy(update={"state": ScopeState.REVOKED}).model_dump_json(),
        encoding="utf-8",
    )
    monkeypatch.setattr("vulnloom.cli.utc_now", lambda: PILOT_NOW)
    with pytest.raises(IngestionError, match="approved"):
        main(
            [
                "--store",
                str(fixture.target_store_root),
                "shadow-pilot-local",
                "--snapshot-id",
                fixture.snapshot.manifest.manifest_id,
                "--scope-file",
                str(scope_file),
                "--readiness-db",
                str(tmp_path / "readiness.db"),
                "--readiness-store",
                str(tmp_path / "readiness"),
            ]
        )
    assert not (tmp_path / "readiness.db").exists()


def test_cli_shadow_pilot_rejects_unadmitted_quality_baseline(tmp_path, monkeypatch):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(fixture.scope.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("vulnloom.cli.utc_now", lambda: PILOT_NOW)
    monkeypatch.setattr("vulnloom.cli._ADMITTED_M9_4_RESULT_ID", "0" * 64)

    with pytest.raises(SystemExit, match="unadmitted quality baseline"):
        main(
            [
                "--store",
                str(fixture.target_store_root),
                "shadow-pilot-local",
                "--snapshot-id",
                fixture.snapshot.manifest.manifest_id,
                "--scope-file",
                str(scope_file),
                "--readiness-db",
                str(tmp_path / "readiness.db"),
            ]
        )
    assert not (tmp_path / "readiness.db").exists()


def test_cli_shadow_pilot_accepts_safe_snapshot_without_candidates(
    tmp_path, capsys, approved_scope
):
    archive = tmp_path / "safe.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "app.py",
            """from flask import Flask
app = Flask(__name__)
@app.get('/item/<item_id>')
def item(item_id):
    value = Item.query.get(item_id)
    if value.owner_id != current_user.id:
        raise PermissionError()
    return value
""",
        )
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    scope = approved_scope.model_copy(
        update={
            "artifacts": (
                ArtifactScope(
                    kind=ArtifactKind.SOURCE_ARCHIVE,
                    sha256=digest,
                    source_name=archive.name,
                ),
            )
        }
    )
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(scope.model_dump_json(), encoding="utf-8")
    target_store = tmp_path / "targets"
    snapshot = IngestionService(target_store).ingest_archive(archive, scope=scope)

    assert (
        main(
            [
                "--store",
                str(target_store),
                "shadow-pilot-local",
                "--snapshot-id",
                snapshot.manifest.manifest_id,
                "--scope-file",
                str(scope_file),
                "--analysis-store",
                str(tmp_path / "analysis"),
                "--candidate-store",
                str(tmp_path / "candidates"),
                "--readiness-db",
                str(tmp_path / "readiness.db"),
                "--readiness-store",
                str(tmp_path / "readiness"),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["gate_status"] == "passed"
    assert output["candidate_count"] == 0
    assert output["candidates"] == []
    assert output["selected_candidate_ids"] == []


def test_cli_ingests_scoped_archive_idempotently(tmp_path, capsys, approved_scope):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("app.py", "pass\n")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    scope = approved_scope.model_copy(
        update={
            "artifacts": (
                ArtifactScope(
                    kind=ArtifactKind.SOURCE_ARCHIVE,
                    sha256=digest,
                    source_name=archive.name,
                ),
            )
        }
    )
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(scope.model_dump_json(), encoding="utf-8")
    quarantine_args = [
        "--db",
        str(tmp_path / "events.db"),
        "--store",
        str(tmp_path / "targets"),
        "artifact-quarantine",
        "--engagement-id",
        str(scope.engagement_id),
        "--source",
        str(archive),
    ]
    assert main(quarantine_args) == 0
    quarantined = json.loads(capsys.readouterr().out)
    assert quarantined["event"]["event_type"] == "ArtifactQuarantined"
    assert quarantined["event"]["payload"]["artifact_id"] == digest

    args = [
        "--db",
        str(tmp_path / "events.db"),
        "--store",
        str(tmp_path / "targets"),
        "target-ingest-archive",
        "--scope-file",
        str(scope_file),
        "--source",
        str(archive),
    ]

    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["created"] is True
    assert first["event"]["event_type"] == "TargetIngested"

    assert main(args) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["created"] is False


def test_cli_builds_source_graph_and_records_summary_idempotently(tmp_path, capsys, approved_scope):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "app.py",
            """from flask import Flask
app = Flask(__name__)
@app.get('/hello/<name>')
def hello(name):
    return open(name).read()
""",
        )
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    scope = approved_scope.model_copy(
        update={
            "artifacts": (
                ArtifactScope(
                    kind=ArtifactKind.SOURCE_ARCHIVE,
                    sha256=digest,
                    source_name=archive.name,
                ),
            )
        }
    )
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(scope.model_dump_json(), encoding="utf-8")
    db = tmp_path / "events.db"
    target_store = tmp_path / "targets"
    ingest_args = [
        "--db",
        str(db),
        "--store",
        str(target_store),
        "target-ingest-archive",
        "--scope-file",
        str(scope_file),
        "--source",
        str(archive),
    ]
    assert main(ingest_args) == 0
    ingested = json.loads(capsys.readouterr().out)
    manifest_id = ingested["event"]["payload"]["manifest"]["manifest_id"]
    map_args = [
        "--db",
        str(db),
        "--store",
        str(target_store),
        "source-map",
        "--snapshot-id",
        manifest_id,
        "--scope-file",
        str(scope_file),
        "--analysis-store",
        str(tmp_path / "analysis"),
    ]

    assert main(map_args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["graph_created"] is True
    assert first["event_created"] is True
    assert first["graph"]["routes"] == 1
    assert first["graph"]["signals"] == 1
    assert first["graph"]["scope_id"] == str(scope.scope_id)
    assert first["graph"]["scope_version"] == scope.version
    assert first["graph"]["graph_ref"].endswith(".json")
    assert Path(first["graph_path"]).is_file()

    assert main(map_args) == 0
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["graph_created"] is False
    assert repeated["event_created"] is False

    candidate_args = [
        "--db",
        str(db),
        "candidate-generate",
        "--graph-id",
        first["graph"]["graph_id"],
        "--scope-file",
        str(scope_file),
        "--analysis-store",
        str(tmp_path / "analysis"),
        "--candidate-store",
        str(tmp_path / "candidates"),
    ]
    assert main(candidate_args) == 0
    generated = json.loads(capsys.readouterr().out)
    assert generated["candidate_set_created"] is True
    assert generated["event_created"] is True
    assert generated["candidate_set"]["candidates"] == 1
    assert Path(generated["candidate_set_path"]).is_file()

    assert main(candidate_args) == 0
    repeated_candidates = json.loads(capsys.readouterr().out)
    assert repeated_candidates["candidate_set_created"] is False
    assert repeated_candidates["event_created"] is False
