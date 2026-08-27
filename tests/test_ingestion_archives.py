from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest

from vulnloom.domain.models import ArtifactKind, ArtifactScope, ScopeState
from vulnloom.ingestion import IngestionError, IngestionLimits, IngestionService


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scope_for(path, approved_scope, kind=ArtifactKind.SOURCE_ARCHIVE, name=None):
    artifact = ArtifactScope(
        kind=kind,
        sha256=_sha256(path),
        source_name=name or path.name,
    )
    return approved_scope.model_copy(update={"artifacts": (artifact,)})


def test_zip_is_quarantined_and_materialized_as_immutable_snapshot(tmp_path, approved_scope):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("app/main.py", "print('never executed')\n")
        handle.writestr("deploy/k8s/deployment.yaml", "kind: Deployment\n")
        handle.writestr("infra/main.tf", 'resource "x" "y" {}\n')
        handle.writestr("charts/app/Chart.yaml", "name: app\n")
        handle.writestr("charts/app/templates/service.yaml", "kind: Service\n")
    scope = _scope_for(archive, approved_scope)
    store = tmp_path / "store"

    snapshot = IngestionService(store).ingest_archive(archive, scope=scope)

    assert snapshot.target.version == _sha256(archive)
    assert snapshot.manifest.total_size > 0
    assert {item.category.value for item in snapshot.manifest.files} >= {
        "source",
        "kubernetes",
        "terraform",
        "helm",
    }
    helm_paths = {item.path for item in snapshot.manifest.files if item.category.value == "helm"}
    assert "charts/app/templates/service.yaml" in helm_paths
    root = store / snapshot.root_ref
    assert (root / "app/main.py").read_text() == "print('never executed')\n"
    assert stat.S_IMODE((root / "app/main.py").stat().st_mode) == 0o400
    assert (store / snapshot.artifact.quarantine_ref).exists()
    assert not any(path.name.startswith("snapshot-") for path in (store / "snapshots").iterdir())

    repeated = IngestionService(store).ingest_archive(archive, scope=scope)
    assert repeated == snapshot


@pytest.mark.parametrize("member", ["../escape.py", "/absolute.py", "C:/windows.py", "a\\b.py"])
def test_zip_path_escape_is_rejected_and_partial_snapshot_is_cleaned(
    tmp_path, approved_scope, member
):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(member, "bad")
    scope = _scope_for(archive, approved_scope)
    store = tmp_path / "store"

    with pytest.raises(IngestionError, match="path|invalid"):
        IngestionService(store).ingest_archive(archive, scope=scope)

    assert list((store / "snapshots").iterdir()) == []
    assert len(list((store / "quarantine").glob("*.blob"))) == 1
    assert not (tmp_path / "escape.py").exists()


def test_zip_symlink_is_rejected(tmp_path, approved_scope):
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(info, "../../outside")
    scope = _scope_for(archive, approved_scope)

    with pytest.raises(IngestionError, match="symlink"):
        IngestionService(tmp_path / "store").ingest_archive(archive, scope=scope)


def test_zip_special_file_is_rejected(tmp_path, approved_scope):
    archive = tmp_path / "fifo.zip"
    info = zipfile.ZipInfo("pipe")
    info.create_system = 3
    info.external_attr = (stat.S_IFIFO | 0o600) << 16
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(info, "")
    scope = _scope_for(archive, approved_scope)

    with pytest.raises(IngestionError, match="non-regular"):
        IngestionService(tmp_path / "store").ingest_archive(archive, scope=scope)


def test_tar_symlink_and_device_like_members_are_rejected(tmp_path, approved_scope):
    archive = tmp_path / "symlink.tar"
    with tarfile.open(archive, "w") as handle:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        handle.addfile(info)
    scope = _scope_for(archive, approved_scope)

    with pytest.raises(IngestionError, match="non-regular"):
        IngestionService(tmp_path / "store").ingest_archive(archive, scope=scope)


def test_tar_path_escape_is_rejected(tmp_path, approved_scope):
    archive = tmp_path / "escape.tar"
    content = b"bad"
    with tarfile.open(archive, "w") as handle:
        info = tarfile.TarInfo("../escape")
        info.size = len(content)
        handle.addfile(info, io.BytesIO(content))
    scope = _scope_for(archive, approved_scope)

    with pytest.raises(IngestionError, match="escapes snapshot"):
        IngestionService(tmp_path / "store").ingest_archive(archive, scope=scope)


def test_duplicate_casefolded_paths_are_rejected(tmp_path, approved_scope):
    archive = tmp_path / "collision.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("Config.yml", "a")
        handle.writestr("config.yml", "b")
    scope = _scope_for(archive, approved_scope)

    with pytest.raises(IngestionError, match="duplicate normalized"):
        IngestionService(tmp_path / "store").ingest_archive(archive, scope=scope)


def test_file_count_single_size_total_and_ratio_limits_are_enforced(tmp_path, approved_scope):
    count_archive = tmp_path / "count.zip"
    with zipfile.ZipFile(count_archive, "w") as handle:
        handle.writestr("a", "1")
        handle.writestr("b", "2")
    count_scope = _scope_for(count_archive, approved_scope)
    with pytest.raises(IngestionError, match="member count"):
        IngestionService(tmp_path / "count-store", IngestionLimits(max_files=1)).ingest_archive(
            count_archive, scope=count_scope
        )

    size_archive = tmp_path / "size.zip"
    with zipfile.ZipFile(size_archive, "w") as handle:
        handle.writestr("large", b"x" * 20)
    size_scope = _scope_for(size_archive, approved_scope)
    with pytest.raises(IngestionError, match="single-file"):
        IngestionService(
            tmp_path / "size-store", IngestionLimits(max_single_file_bytes=10)
        ).ingest_archive(size_archive, scope=size_scope)

    total_archive = tmp_path / "total.zip"
    with zipfile.ZipFile(total_archive, "w") as handle:
        handle.writestr("first", b"x" * 8)
        handle.writestr("second", b"y" * 8)
    total_scope = _scope_for(total_archive, approved_scope)
    with pytest.raises(IngestionError, match="expanded size"):
        IngestionService(
            tmp_path / "total-store",
            IngestionLimits(max_single_file_bytes=10, max_total_bytes=12),
        ).ingest_archive(total_archive, scope=total_scope)

    ratio_archive = tmp_path / "ratio.zip"
    with zipfile.ZipFile(ratio_archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("bomb", b"0" * 10_000)
    ratio_scope = _scope_for(ratio_archive, approved_scope)
    with pytest.raises(IngestionError, match="ratio"):
        IngestionService(
            tmp_path / "ratio-store", IngestionLimits(max_compression_ratio=2)
        ).ingest_archive(ratio_archive, scope=ratio_scope)


def test_digest_mismatch_scope_rejects_materialization_but_preserves_quarantine(
    tmp_path, approved_scope
):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("app.py", "pass")
    wrong = ArtifactScope(
        kind=ArtifactKind.SOURCE_ARCHIVE,
        sha256="0" * 64,
        source_name=archive.name,
    )
    scope = approved_scope.model_copy(update={"artifacts": (wrong,)})
    store = tmp_path / "store"

    with pytest.raises(IngestionError, match="approved Scope"):
        IngestionService(store).ingest_archive(archive, scope=scope)

    assert len(list((store / "quarantine").glob("*.blob"))) == 1
    assert list((store / "snapshots").iterdir()) == []


def test_source_symlink_and_unsupported_file_are_rejected(tmp_path, approved_scope):
    plain = tmp_path / "plain.txt"
    plain.write_text("not an archive")
    link = tmp_path / "linked.zip"
    link.symlink_to(plain)
    service = IngestionService(tmp_path / "store")
    with pytest.raises(IngestionError, match="non-symlink"):
        service.ingest_archive(link, scope=approved_scope)

    scope = _scope_for(plain, approved_scope)
    with pytest.raises(IngestionError, match="unsupported"):
        service.ingest_archive(plain, scope=scope)


def test_unapproved_scope_cannot_materialize_artifact(tmp_path, approved_scope):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("app.py", "pass")
    draft = _scope_for(archive, approved_scope).model_copy(update={"state": ScopeState.DRAFT})
    store = tmp_path / "store"

    with pytest.raises(IngestionError, match="approved Scope"):
        IngestionService(store).ingest_archive(archive, scope=draft)
    assert len(list((store / "quarantine").glob("*.blob"))) == 1
    assert list((store / "snapshots").iterdir()) == []


def test_iac_bundle_kind_is_preserved(tmp_path, approved_scope):
    archive = tmp_path / "iac.tar.gz"
    content = b'resource "x" "y" {}\n'
    with tarfile.open(archive, "w:gz") as handle:
        info = tarfile.TarInfo("main.tf")
        info.size = len(content)
        handle.addfile(info, io.BytesIO(content))
    scope = _scope_for(archive, approved_scope, ArtifactKind.IAC_BUNDLE)

    snapshot = IngestionService(tmp_path / "store").ingest_archive(
        archive, scope=scope, kind=ArtifactKind.IAC_BUNDLE
    )
    assert snapshot.target.kind.value == "iac_bundle"
    assert snapshot.manifest.files[0].category.value == "terraform"


def test_tiny_deadline_cleans_temporary_quarantine_file(tmp_path, approved_scope):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("large.bin", os.urandom(2 * 1024 * 1024))
    scope = _scope_for(archive, approved_scope)
    store = tmp_path / "store"
    service = IngestionService(store, IngestionLimits(timeout_seconds=1e-12))

    with pytest.raises(IngestionError, match="timed out"):
        service.ingest_archive(archive, scope=scope)

    assert list((store / "quarantine").glob("incoming-*")) == []
    assert list((store / "snapshots").iterdir()) == []


def test_reused_quarantine_and_snapshot_are_integrity_checked(tmp_path, approved_scope):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("app.py", "pass\n")
    scope = _scope_for(archive, approved_scope)
    store = tmp_path / "store"
    service = IngestionService(store)
    snapshot = service.ingest_archive(archive, scope=scope)

    payload_file = store / snapshot.root_ref / "app.py"
    os.chmod(payload_file, 0o600)
    payload_file.write_text("tampered\n")
    with pytest.raises(IngestionError, match="integrity"):
        service.ingest_archive(archive, scope=scope)

    quarantine = store / snapshot.artifact.quarantine_ref
    os.chmod(quarantine, 0o600)
    quarantine.write_bytes(b"tampered")
    with pytest.raises(IngestionError, match="quarantine.*integrity"):
        service.ingest_archive(archive, scope=scope)


def test_concurrent_duplicate_imports_converge_on_one_snapshot(tmp_path, approved_scope):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("app.py", "pass\n")
    scope = _scope_for(archive, approved_scope)
    store = tmp_path / "store"

    def ingest():
        return IngestionService(store).ingest_archive(archive, scope=scope)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = tuple(pool.map(lambda _: ingest(), range(2)))

    assert first == second
    assert len(list((store / "snapshots").iterdir())) == 1
    assert not list((store / "snapshots").glob("snapshot-*"))
