from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from vulnloom.runners import codeql_query_wrapper as wrapper


def _sealed_inputs(tmp_path: Path) -> tuple[Path, Path]:
    database = tmp_path / "analyzer-data" / "database"
    queries = tmp_path / "analyzer-data" / "queries"
    database.mkdir(parents=True)
    queries.mkdir()
    (database / "codeql-database.yml").write_text("primaryLanguage: python\n")
    (database / "db-python").write_bytes(b"database")
    query = queries / "security.qls"
    query.write_text("- queries: .\n")
    for path in sorted((tmp_path / "analyzer-data").rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    (tmp_path / "analyzer-data").chmod(0o555)
    return database, query


def _arguments(database: Path, query: Path) -> tuple[str, ...]:
    files = tuple(path for path in database.rglob("*") if path.is_file())
    directories = tuple(path for path in database.rglob("*") if path.is_dir())
    return (
        "--query",
        str(query),
        "--max-files",
        str(len(files)),
        "--max-entries",
        str(len(files) + len(directories)),
        "--max-database-bytes",
        str(sum(path.stat().st_size for path in files)),
        "--max-output-bytes",
        "4096",
        "--timeout-seconds",
        "30",
    )


def test_wrapper_copies_to_bounded_output_and_streams_only_completed_sarif(
    tmp_path, monkeypatch, capsysbinary
):
    database, query = _sealed_inputs(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    codeql = tmp_path / "codeql"
    codeql.write_bytes(b"fixture")
    monkeypatch.setattr(wrapper, "CODEQL_PATH", codeql)
    monkeypatch.setattr(wrapper, "SOURCE_DATABASE", database)
    monkeypatch.setattr(wrapper, "QUERY_ROOT", query.parent)
    monkeypatch.setattr(wrapper, "WORKING_DATABASE", output / "codeql-database")
    monkeypatch.setattr(wrapper, "SARIF_PATH", output / "codeql-output.sarif")
    sarif = b'{"version":"2.1.0","runs":[]}'

    def fake_run(arguments, **options):
        assert arguments[:3] == (str(codeql), "database", "analyze")
        assert "--no-sarif-add-file-contents" in arguments
        assert "--no-sarif-add-snippets" in arguments
        assert options["env"] == {
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TMPDIR": "/tmp",
        }
        wrapper.SARIF_PATH.write_bytes(sarif)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    assert wrapper.main(_arguments(database, query)) == 0
    assert capsysbinary.readouterr().out == sarif
    assert (wrapper.WORKING_DATABASE / "db-python").read_bytes() == b"database"


def test_wrapper_refuses_symlink_limit_drift_and_never_invokes_codeql(tmp_path, monkeypatch):
    database, query = _sealed_inputs(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    database.chmod(0o755)
    os.symlink("db-python", database / "linked")
    database.chmod(0o555)
    monkeypatch.setattr(wrapper, "SOURCE_DATABASE", database)
    monkeypatch.setattr(wrapper, "QUERY_ROOT", query.parent)
    monkeypatch.setattr(wrapper, "WORKING_DATABASE", output / "codeql-database")
    monkeypatch.setattr(wrapper, "SARIF_PATH", output / "codeql-output.sarif")
    invoked = False

    def forbidden(*args, **kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError("CodeQL must not run")

    monkeypatch.setattr(wrapper.subprocess, "run", forbidden)
    arguments = list(_arguments(database, query))
    arguments[arguments.index("--max-files") + 1] = "99"

    assert wrapper.main(tuple(arguments)) == 70
    assert not invoked


def test_wrapper_rejects_unsafe_paths_empty_output_and_expired_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(wrapper, "QUERY_ROOT", tmp_path / "queries")
    with pytest.raises(wrapper.CodeQLWrapperRejected, match="query path"):
        wrapper._safe_query(str(tmp_path / "outside.qls"))
    with pytest.raises(wrapper.CodeQLWrapperRejected, match="unsafe path"):
        wrapper._safe_name("bad\nname")
    with pytest.raises(wrapper.CodeQLWrapperRejected, match="timed out"):
        wrapper._deadline(0)
    empty = tmp_path / "empty.sarif"
    empty.touch()
    with pytest.raises(wrapper.CodeQLWrapperRejected, match="empty or oversized"):
        wrapper._stream_regular(empty, max_bytes=16, deadline=time.monotonic() + 1)


def test_wrapper_rejects_writable_or_inexact_database_copy(tmp_path):
    database = tmp_path / "database"
    database.mkdir()
    payload = database / "db"
    payload.write_bytes(b"db")
    destination = tmp_path / "copy"
    with pytest.raises(wrapper.CodeQLWrapperRejected, match="root is unsafe"):
        wrapper._copy_database(
            database,
            destination,
            max_files=1,
            max_entries=1,
            max_bytes=2,
            deadline=time.monotonic() + 1,
        )

    database.chmod(0o555)
    payload.chmod(0o444)
    with pytest.raises(wrapper.CodeQLWrapperRejected, match="sealed copy limits"):
        wrapper._copy_database(
            database,
            destination,
            max_files=2,
            max_entries=1,
            max_bytes=2,
            deadline=time.monotonic() + 1,
        )
