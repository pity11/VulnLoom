from __future__ import annotations

import os
from pathlib import Path

import pytest

from vulnloom.benchmark import (
    TrivyDatabaseLimits,
    TrivyDatabaseRejected,
    inspect_trivy_database,
    verify_trivy_database,
)


def _database(tmp_path: Path, request) -> Path:
    root = tmp_path / "database"
    database = root / "db"
    database.mkdir(parents=True)
    (database / "metadata.json").write_text('{"Version":2,"UpdatedAt":"sealed"}')
    (database / "trivy.db").write_bytes(b"sealed-trivy-database")
    for path in (database / "metadata.json", database / "trivy.db", database, root):
        path.chmod(0o444 if path.is_file() else 0o555)

    def restore_permissions() -> None:
        for path in (root, database, database / "metadata.json", database / "trivy.db"):
            if path.exists() and not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)

    request.addfinalizer(restore_permissions)
    return root


def test_trivy_database_snapshot_is_content_addressed_and_verifiable(tmp_path, request):
    root = _database(tmp_path, request)
    first = inspect_trivy_database(root, tool_version="0.73.0")
    second = inspect_trivy_database(root, tool_version="0.73.0")

    assert first == second
    assert len(first.snapshot_id) == 64
    assert tuple(item.path for item in first.files) == (
        "db/metadata.json",
        "db/trivy.db",
    )
    verify_trivy_database(root, first)


def test_trivy_database_rejects_writable_extra_and_symlink_entries(tmp_path, request):
    root = _database(tmp_path, request)
    (root / "db").chmod(0o755)
    with pytest.raises(TrivyDatabaseRejected, match="read-only"):
        inspect_trivy_database(root, tool_version="0.73.0")

    (root / "db").chmod(0o555)
    root.chmod(0o755)
    (root / "extra").write_text("not admitted")
    (root / "extra").chmod(0o444)
    root.chmod(0o555)
    with pytest.raises(TrivyDatabaseRejected, match="unexpected or missing"):
        inspect_trivy_database(root, tool_version="0.73.0")

    root.chmod(0o755)
    (root / "extra").unlink()
    os.symlink(root / "db" / "metadata.json", root / "link")
    root.chmod(0o555)
    with pytest.raises(TrivyDatabaseRejected, match="symbolic links"):
        inspect_trivy_database(root, tool_version="0.73.0")
    root.chmod(0o755)
    (root / "link").unlink()
    root.chmod(0o555)


def test_trivy_database_rejects_schema_size_and_content_drift(tmp_path, request):
    root = _database(tmp_path, request)
    snapshot = inspect_trivy_database(root, tool_version="0.73.0")

    with pytest.raises(TrivyDatabaseRejected, match="size"):
        inspect_trivy_database(
            root,
            tool_version="0.73.0",
            limits=TrivyDatabaseLimits(max_database_bytes=4),
        )
    with pytest.raises(TrivyDatabaseRejected, match="timed out"):
        inspect_trivy_database(
            root,
            tool_version="0.73.0",
            limits=TrivyDatabaseLimits(timeout_seconds=1e-12),
        )

    database = root / "db"
    database.chmod(0o755)
    payload = database / "trivy.db"
    payload.chmod(0o644)
    payload.write_bytes(b"changed")
    payload.chmod(0o444)
    database.chmod(0o555)
    with pytest.raises(TrivyDatabaseRejected, match="no longer matches"):
        verify_trivy_database(root, snapshot)

    database.chmod(0o755)
    metadata = database / "metadata.json"
    metadata.chmod(0o644)
    metadata.write_text('{"Version":1}')
    metadata.chmod(0o444)
    database.chmod(0o555)
    with pytest.raises(TrivyDatabaseRejected, match="schema version"):
        inspect_trivy_database(root, tool_version="0.73.0")
