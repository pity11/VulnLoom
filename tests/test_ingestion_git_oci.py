from __future__ import annotations

import hashlib
import os
import subprocess

import pytest

from vulnloom.domain.models import ArtifactKind, ArtifactScope, RepositoryScope
from vulnloom.ingestion import IngestionError, IngestionService
from vulnloom.ingestion import service as ingestion_module


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    (repo / "app.py").write_text("print('not executed')\n")
    os.chmod(repo / "app.py", 0o755)
    (repo / "Dockerfile").write_text("FROM scratch\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fixture")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_local_git_commit_is_materialized_without_git_metadata(tmp_path, approved_scope):
    repo, commit = _repository(tmp_path)
    repository_url = "https://example.test/source.git"
    scope = approved_scope.model_copy(
        update={"repositories": (RepositoryScope(url=repository_url, commit=commit),)}
    )

    snapshot = IngestionService(tmp_path / "store").ingest_git(
        repo,
        repository_url=repository_url,
        commit=commit,
        scope=scope,
    )

    root = tmp_path / "store" / snapshot.root_ref
    assert snapshot.target.version == commit
    assert not (root / ".git").exists()
    assert (root / "app.py").read_text() == "print('not executed')\n"
    assert (root / "app.py").stat().st_mode & 0o111 == 0
    assert {item.category.value for item in snapshot.manifest.files} == {"source", "dockerfile"}


def test_git_symlink_is_rejected_and_snapshot_is_cleaned(tmp_path, approved_scope):
    repo, _ = _repository(tmp_path)
    (repo / "link").symlink_to("/etc/passwd")
    _git(repo, "add", "link")
    _git(repo, "commit", "-m", "symlink")
    commit = _git(repo, "rev-parse", "HEAD")
    repository_url = "https://example.test/source.git"
    scope = approved_scope.model_copy(
        update={"repositories": (RepositoryScope(url=repository_url, commit=commit),)}
    )
    store = tmp_path / "store"

    with pytest.raises(IngestionError, match="symlink"):
        IngestionService(store).ingest_git(
            repo, repository_url=repository_url, commit=commit, scope=scope
        )
    assert list((store / "snapshots").iterdir()) == []


def test_git_source_symlink_and_scope_commit_mismatch_are_rejected(tmp_path, approved_scope):
    repo, commit = _repository(tmp_path)
    link = tmp_path / "repo-link"
    link.symlink_to(repo, target_is_directory=True)
    repository_url = "https://example.test/source.git"
    scope = approved_scope.model_copy(
        update={"repositories": (RepositoryScope(url=repository_url, commit=commit),)}
    )
    service = IngestionService(tmp_path / "store")
    with pytest.raises(IngestionError, match="non-symlink"):
        service.ingest_git(link, repository_url=repository_url, commit=commit, scope=scope)
    with pytest.raises(IngestionError, match="approved Scope"):
        service.ingest_git(
            repo,
            repository_url=repository_url,
            commit="0" * 40,
            scope=scope,
        )


def test_oci_registration_requires_exact_scope_and_digest(tmp_path, approved_scope):
    image_ref = "ghcr.io/example/app"
    digest_hex = hashlib.sha256(b"manifest").hexdigest()
    scope = approved_scope.model_copy(
        update={
            "artifacts": (
                ArtifactScope(
                    kind=ArtifactKind.OCI_IMAGE,
                    sha256=digest_hex,
                    source_name=image_ref,
                ),
            )
        }
    )
    service = IngestionService(tmp_path / "store")

    snapshot = service.register_oci_image(image_ref, f"sha256:{digest_hex}", scope=scope)
    assert snapshot.target.version == f"sha256:{digest_hex}"
    assert snapshot.root_ref is None
    assert snapshot.manifest.files == ()

    with pytest.raises(IngestionError, match="sha256"):
        service.register_oci_image(image_ref, "latest", scope=scope)
    with pytest.raises(IngestionError, match="approved Scope"):
        service.register_oci_image("ghcr.io/example/other", f"sha256:{digest_hex}", scope=scope)


def test_git_subprocess_environment_does_not_inherit_parent_secret(tmp_path, monkeypatch):
    captured = {}

    class Result:
        returncode = 0
        stdout = b"ok"
        stderr = b""

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        return Result()

    monkeypatch.setenv("VULNLOOM_MODEL_API_KEY", "must-not-leak")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(ingestion_module.shutil, "which", lambda _: "/usr/bin/git")
    service = IngestionService(tmp_path / "store")

    output = service._git_bytes(
        tmp_path,
        ["status"],
        ingestion_module._Deadline(1),
    )

    assert output == b"ok"
    assert "VULNLOOM_MODEL_API_KEY" not in captured["env"]
    assert "PATH" not in captured["env"]
    assert captured["command"][:2] == ["/usr/bin/git", "--no-replace-objects"]


def test_git_timeout_is_closed_and_leaves_no_snapshot(tmp_path, approved_scope, monkeypatch):
    repo, commit = _repository(tmp_path)
    repository_url = "https://example.test/source.git"
    scope = approved_scope.model_copy(
        update={"repositories": (RepositoryScope(url=repository_url, commit=commit),)}
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="git", timeout=1)
        ),
    )
    store = tmp_path / "store"

    with pytest.raises(IngestionError, match="timed out"):
        IngestionService(store).ingest_git(
            repo, repository_url=repository_url, commit=commit, scope=scope
        )
    assert list((store / "snapshots").iterdir()) == []
