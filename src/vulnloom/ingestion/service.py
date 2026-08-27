"""Quarantine and materialize immutable Target Snapshots.

The service never executes target code, never invokes a shell, and never uses
archive ``extractall``. All partial snapshot directories are removed on error;
the content-addressed quarantine object remains available for audit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import unicodedata
import zipfile
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field

from vulnloom.domain.models import (
    Artifact,
    ArtifactKind,
    DomainModel,
    Scope,
    ScopeState,
    SnapshotFile,
    StaticFileCategory,
    Target,
    TargetKind,
    TargetManifest,
    TargetSnapshot,
    utc_now,
)


class IngestionError(ValueError):
    """An input was rejected before a Target Snapshot could be created."""


class IngestionLimits(DomainModel):
    max_archive_bytes: int = Field(default=100 * 1024 * 1024, gt=0)
    max_files: int = Field(default=10_000, gt=0)
    max_single_file_bytes: int = Field(default=20 * 1024 * 1024, gt=0)
    max_total_bytes: int = Field(default=200 * 1024 * 1024, gt=0)
    max_compression_ratio: float = Field(default=100.0, gt=0)
    timeout_seconds: float = Field(default=60.0, gt=0, le=3600)


class _Deadline:
    def __init__(self, seconds: float):
        self.ends_at = time.monotonic() + seconds

    def check(self) -> None:
        if time.monotonic() >= self.ends_at:
            raise IngestionError("ingestion timed out")

    def remaining(self) -> float:
        self.check()
        return max(0.001, self.ends_at - time.monotonic())


class IngestionService:
    def __init__(self, root: Path, limits: IngestionLimits | None = None):
        self.root = root.resolve()
        self.quarantine = self.root / "quarantine"
        self.snapshots = self.root / "snapshots"
        self.limits = limits or IngestionLimits()
        self.quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.snapshots.mkdir(parents=True, exist_ok=True, mode=0o700)

    def ingest_archive(
        self,
        source: Path,
        *,
        scope: Scope,
        kind: ArtifactKind = ArtifactKind.SOURCE_ARCHIVE,
        now=None,
    ) -> TargetSnapshot:
        if kind not in {ArtifactKind.SOURCE_ARCHIVE, ArtifactKind.IAC_BUNDLE}:
            raise IngestionError("archive import only supports source_archive or iac_bundle")
        deadline = _Deadline(self.limits.timeout_seconds)
        artifact = self._quarantine_file(source, scope.engagement_id, kind, deadline)
        self._require_artifact_scope(scope, artifact, now or utc_now())
        return self._materialize_archive(artifact, scope, deadline)

    def quarantine_artifact(
        self,
        source: Path,
        *,
        engagement_id: UUID,
        kind: ArtifactKind = ArtifactKind.SOURCE_ARCHIVE,
    ) -> Artifact:
        if kind not in {ArtifactKind.SOURCE_ARCHIVE, ArtifactKind.IAC_BUNDLE}:
            raise IngestionError("quarantine only supports source_archive or iac_bundle")
        return self._quarantine_file(
            source,
            engagement_id,
            kind,
            _Deadline(self.limits.timeout_seconds),
        )

    def ingest_git(
        self,
        source: Path,
        *,
        repository_url: str,
        commit: str,
        scope: Scope,
        now=None,
    ) -> TargetSnapshot:
        deadline = _Deadline(self.limits.timeout_seconds)
        self._require_active_scope(scope, now or utc_now())
        if not any(
            repo.url == repository_url and repo.commit.lower() == commit.lower()
            for repo in scope.repositories
        ):
            raise IngestionError("repository URL and commit are not in approved Scope")
        source = source.absolute()
        try:
            source_stat = source.lstat()
        except FileNotFoundError as exc:
            raise IngestionError("Git source does not exist") from exc
        if not stat.S_ISDIR(source_stat.st_mode) or source.is_symlink():
            raise IngestionError("Git source must be a local, non-symlink directory")
        source = source.resolve()
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
            raise IngestionError("commit must be a hexadecimal object identifier")

        canonical = self._git_text(
            source, ["rev-parse", "--verify", f"{commit}^{{commit}}"], deadline
        ).strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", canonical):
            raise IngestionError("Git returned a non-canonical commit identifier")
        tree = self._git_bytes(
            source, ["ls-tree", "-r", "-z", "-l", "--full-tree", canonical], deadline
        )
        entries = self._parse_git_tree(tree)
        artifact_id = hashlib.sha256(f"git\0{repository_url}\0{canonical}".encode()).hexdigest()
        artifact = Artifact(
            artifact_id=artifact_id,
            engagement_id=scope.engagement_id,
            kind=ArtifactKind.GIT_REPOSITORY,
            source_name=source.name,
            source_ref=repository_url,
            original_size=sum(size for _, _, size in entries),
            detected_format="git",
        )
        target = Target(
            target_id=_target_id(scope.engagement_id, "git", repository_url, canonical),
            engagement_id=scope.engagement_id,
            kind=TargetKind.REPOSITORY,
            source_ref=repository_url,
            version=canonical,
        )
        return self._materialize_git(source, canonical, artifact, target, entries, deadline)

    def register_oci_image(
        self,
        image_ref: str,
        digest: str,
        *,
        scope: Scope,
        now=None,
    ) -> TargetSnapshot:
        self._require_active_scope(scope, now or utc_now())
        match = re.fullmatch(r"sha256:([0-9a-f]{64})", digest)
        if not match:
            raise IngestionError("OCI image must be pinned by a sha256 digest")
        artifact_id = match.group(1)
        allowed = any(
            item.kind is ArtifactKind.OCI_IMAGE
            and item.sha256 == artifact_id
            and item.source_name == image_ref
            for item in scope.artifacts
        )
        if not allowed:
            raise IngestionError("OCI image reference and digest are not in approved Scope")
        artifact = Artifact(
            artifact_id=artifact_id,
            engagement_id=scope.engagement_id,
            kind=ArtifactKind.OCI_IMAGE,
            source_name=image_ref,
            source_ref=image_ref,
            original_size=0,
            detected_format="oci-manifest",
        )
        target = Target(
            target_id=_target_id(scope.engagement_id, "oci", image_ref, digest),
            engagement_id=scope.engagement_id,
            kind=TargetKind.CONTAINER_IMAGE,
            source_ref=image_ref,
            version=digest,
        )
        manifest = self._make_manifest(artifact, target, ())
        temporary = Path(tempfile.mkdtemp(prefix="snapshot-", dir=self.snapshots))
        snapshot = TargetSnapshot(target=target, artifact=artifact, manifest=manifest)
        return self._commit_or_reuse_snapshot(temporary, snapshot)

    def _quarantine_file(
        self,
        source: Path,
        engagement_id: UUID,
        kind: ArtifactKind,
        deadline: _Deadline,
    ) -> Artifact:
        open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            source_fd = os.open(source, open_flags)
        except FileNotFoundError as exc:
            raise IngestionError("artifact source does not exist") from exc
        except OSError as exc:
            raise IngestionError("artifact source must be a regular, non-symlink file") from exc
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            os.close(source_fd)
            raise IngestionError("artifact source must be a regular, non-symlink file")
        if source_stat.st_size > self.limits.max_archive_bytes:
            os.close(source_fd)
            raise IngestionError("artifact exceeds maximum original size")

        fd, temp_name = tempfile.mkstemp(prefix="incoming-", dir=self.quarantine)
        digest = hashlib.sha256()
        copied = 0
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(source_fd, "rb") as reader, os.fdopen(fd, "wb") as writer:
                while chunk := reader.read(1024 * 1024):
                    deadline.check()
                    copied += len(chunk)
                    if copied > self.limits.max_archive_bytes:
                        raise IngestionError("artifact exceeds maximum original size")
                    digest.update(chunk)
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            artifact_id = digest.hexdigest()
            destination = self.quarantine / f"{artifact_id}.blob"
            if destination.exists():
                if (
                    self._hash_regular_file(destination, self.limits.max_archive_bytes)
                    != artifact_id
                ):
                    raise IngestionError("existing quarantine object failed integrity check")
                os.unlink(temp_name)
            else:
                os.replace(temp_name, destination)
            detected = self._detect_archive_format(destination)
            os.chmod(destination, 0o400)
            return Artifact(
                artifact_id=artifact_id,
                engagement_id=engagement_id,
                kind=kind,
                source_name=source.name,
                source_ref=f"local-artifact:{source.name}",
                original_size=copied,
                detected_format=detected,
                quarantine_ref=str(destination.relative_to(self.root)),
            )
        except Exception:
            with suppress(OSError):
                os.close(source_fd)
            if os.path.exists(temp_name):
                os.unlink(temp_name)
            raise

    @staticmethod
    def _detect_archive_format(path: Path) -> str:
        if zipfile.is_zipfile(path):
            return "zip"
        try:
            with tarfile.open(path, mode="r:*"):
                return "tar"
        except (tarfile.TarError, OSError) as exc:
            raise IngestionError("unsupported or malformed archive") from exc

    def _materialize_archive(
        self, artifact: Artifact, scope: Scope, deadline: _Deadline
    ) -> TargetSnapshot:
        target_kind = (
            TargetKind.IAC_BUNDLE
            if artifact.kind is ArtifactKind.IAC_BUNDLE
            else TargetKind.REPOSITORY
        )
        target = Target(
            target_id=_target_id(
                scope.engagement_id,
                artifact.kind.value,
                artifact.source_name,
                artifact.artifact_id,
            ),
            engagement_id=scope.engagement_id,
            kind=target_kind,
            source_ref=artifact.source_name,
            version=artifact.artifact_id,
        )
        temporary = Path(tempfile.mkdtemp(prefix="snapshot-", dir=self.snapshots))
        payload = temporary / "payload"
        payload.mkdir(mode=0o700)
        archive_path = self.root / (artifact.quarantine_ref or "")
        try:
            if artifact.detected_format == "zip":
                files = self._extract_zip(archive_path, payload, deadline)
            elif artifact.detected_format == "tar":
                files = self._extract_tar(archive_path, payload, deadline)
            else:
                raise IngestionError("unsupported archive format")
            manifest = self._make_manifest(artifact, target, files)
            snapshot = TargetSnapshot(
                target=target,
                artifact=artifact,
                manifest=manifest,
                root_ref=str(
                    (self.snapshots / manifest.manifest_id / "payload").relative_to(self.root)
                ),
            )
            return self._commit_or_reuse_snapshot(temporary, snapshot)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise

    def _extract_zip(
        self, archive: Path, destination: Path, deadline: _Deadline
    ) -> tuple[SnapshotFile, ...]:
        with zipfile.ZipFile(archive) as handle:
            infos = handle.infolist()
            if len(infos) > self.limits.max_files:
                raise IngestionError("archive exceeds maximum member count")
            planned = []
            seen: set[str] = set()
            total = 0
            for info in infos:
                deadline.check()
                path = self._safe_member_path(info.filename, seen)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise IngestionError(f"archive symlink is forbidden: {path}")
                if info.is_dir():
                    if mode not in {0, stat.S_IFDIR}:
                        raise IngestionError(f"non-directory archive member is forbidden: {path}")
                    continue
                if mode not in {0, stat.S_IFREG}:
                    raise IngestionError(f"non-regular archive member is forbidden: {path}")
                if info.flag_bits & 0x1:
                    raise IngestionError(f"encrypted archive member is forbidden: {path}")
                total = self._check_member_limits(len(planned) + 1, info.file_size, total)
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > self.limits.max_compression_ratio:
                    raise IngestionError(f"compression ratio exceeds limit: {path}")
                planned.append((info, path))
            self._check_overall_ratio(total, archive.stat().st_size)
            return tuple(
                self._write_stream(handle.open(info), destination, path, info.file_size, deadline)
                for info, path in planned
            )

    def _extract_tar(
        self, archive: Path, destination: Path, deadline: _Deadline
    ) -> tuple[SnapshotFile, ...]:
        with tarfile.open(archive, mode="r:*") as handle:
            seen: set[str] = set()
            total = 0
            output = []
            member_count = 0
            for member in handle:
                deadline.check()
                member_count += 1
                if member_count > self.limits.max_files:
                    raise IngestionError("archive exceeds maximum member count")
                path = self._safe_member_path(member.name, seen)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise IngestionError(f"non-regular archive member is forbidden: {path}")
                total = self._check_member_limits(len(output) + 1, member.size, total)
                stream = handle.extractfile(member)
                if stream is None:
                    raise IngestionError(f"archive member has no readable content: {path}")
                output.append(self._write_stream(stream, destination, path, member.size, deadline))
            self._check_overall_ratio(total, archive.stat().st_size)
            return tuple(output)

    def _safe_member_path(self, raw: str, seen: set[str]) -> str:
        if not raw or "\x00" in raw or "\\" in raw or re.match(r"^[A-Za-z]:", raw):
            raise IngestionError("archive contains an invalid member path")
        normalized = unicodedata.normalize("NFC", raw)
        path = PurePosixPath(normalized)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise IngestionError(f"archive path escapes snapshot: {raw}")
        canonical = path.as_posix().rstrip("/")
        collision_key = canonical.casefold()
        if collision_key in seen:
            raise IngestionError(f"archive contains a duplicate normalized path: {canonical}")
        seen.add(collision_key)
        return canonical

    def _check_member_limits(self, file_count: int, size: int, total: int) -> int:
        if file_count > self.limits.max_files:
            raise IngestionError("archive exceeds maximum file count")
        if size < 0 or size > self.limits.max_single_file_bytes:
            raise IngestionError("archive member exceeds maximum single-file size")
        total += size
        if total > self.limits.max_total_bytes:
            raise IngestionError("archive exceeds maximum expanded size")
        return total

    def _check_overall_ratio(self, expanded: int, original: int) -> None:
        if expanded / max(original, 1) > self.limits.max_compression_ratio:
            raise IngestionError("archive expansion ratio exceeds limit")

    def _write_stream(
        self,
        stream: BinaryIO,
        destination: Path,
        relative_path: str,
        expected_size: int,
        deadline: _Deadline,
    ) -> SnapshotFile:
        output = destination.joinpath(*PurePosixPath(relative_path).parts)
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        digest = hashlib.sha256()
        written = 0
        try:
            with stream, output.open("xb") as writer:
                os.chmod(output, 0o600)
                while chunk := stream.read(1024 * 1024):
                    deadline.check()
                    written += len(chunk)
                    if written > expected_size or written > self.limits.max_single_file_bytes:
                        raise IngestionError(
                            f"archive member expanded beyond declared size: {relative_path}"
                        )
                    digest.update(chunk)
                    writer.write(chunk)
            if written != expected_size:
                raise IngestionError(f"archive member size mismatch: {relative_path}")
            return SnapshotFile(
                path=relative_path,
                size=written,
                sha256=digest.hexdigest(),
                category=_classify_path(relative_path),
            )
        except Exception:
            if output.exists():
                output.unlink()
            raise

    def _materialize_git(
        self,
        source: Path,
        canonical: str,
        artifact: Artifact,
        target: Target,
        entries: tuple[tuple[str, str, int], ...],
        deadline: _Deadline,
    ) -> TargetSnapshot:
        temporary = Path(tempfile.mkdtemp(prefix="snapshot-", dir=self.snapshots))
        payload = temporary / "payload"
        payload.mkdir(mode=0o700)
        try:
            files = []
            for object_id, path, size in entries:
                content = self._git_bytes(source, ["cat-file", "blob", object_id], deadline)
                if len(content) != size:
                    raise IngestionError(f"Git blob size mismatch: {path}")
                files.append(self._write_bytes(content, payload, path))
            manifest = self._make_manifest(artifact, target, files)
            snapshot = TargetSnapshot(
                target=target,
                artifact=artifact,
                manifest=manifest,
                root_ref=str(
                    (self.snapshots / manifest.manifest_id / "payload").relative_to(self.root)
                ),
            )
            return self._commit_or_reuse_snapshot(temporary, snapshot)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise

    def _parse_git_tree(self, raw: bytes) -> tuple[tuple[str, str, int], ...]:
        entries = []
        seen: set[str] = set()
        total = 0
        for record in filter(None, raw.split(b"\x00")):
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, object_id, raw_size = metadata.split(b" ", 3)
                path = raw_path.decode("utf-8", "strict")
                size = int(raw_size)
            except (ValueError, UnicodeDecodeError) as exc:
                raise IngestionError("Git tree contains an invalid entry") from exc
            if object_type != b"blob" or mode in {b"120000", b"160000"}:
                raise IngestionError(f"Git symlink or submodule is forbidden: {path}")
            path = self._safe_member_path(path, seen)
            total = self._check_member_limits(len(entries) + 1, size, total)
            entries.append((object_id.decode("ascii"), path, size))
        return tuple(entries)

    def _git_bytes(self, source: Path, args: list[str], deadline: _Deadline) -> bytes:
        git = shutil.which("git")
        if not git:
            raise IngestionError("git executable is unavailable")
        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
        command = [git, "--no-replace-objects", "-C", str(source), *args]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                env=environment,
                timeout=deadline.remaining(),
            )
        except subprocess.TimeoutExpired as exc:
            raise IngestionError("Git ingestion timed out") from exc
        if result.returncode != 0:
            error = result.stderr.decode("utf-8", "replace").strip()
            raise IngestionError(f"Git object read failed: {error[:300]}")
        return result.stdout

    def _git_text(self, source: Path, args: list[str], deadline: _Deadline) -> str:
        return self._git_bytes(source, args, deadline).decode("ascii", "strict")

    def _commit_or_reuse_snapshot(
        self, temporary: Path, snapshot: TargetSnapshot
    ) -> TargetSnapshot:
        final = self.snapshots / snapshot.manifest.manifest_id
        if final.exists():
            shutil.rmtree(temporary)
            return self._load_existing_snapshot(final, snapshot)

        try:
            metadata = temporary / "snapshot.json"
            with metadata.open("x", encoding="utf-8") as handle:
                handle.write(snapshot.model_dump_json(indent=2))
                handle.write("\n")
            try:
                os.rename(temporary, final)
            except OSError:
                if not final.exists():
                    raise
                shutil.rmtree(temporary)
                return self._load_existing_snapshot(final, snapshot)
            self._seal_snapshot(final)
            return snapshot
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise

    def _load_existing_snapshot(self, final: Path, expected: TargetSnapshot) -> TargetSnapshot:
        try:
            existing = TargetSnapshot.model_validate_json(
                (final / "snapshot.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise IngestionError("existing snapshot metadata is invalid") from exc
        if (
            existing.manifest.manifest_id != expected.manifest.manifest_id
            or existing.artifact.artifact_id != expected.artifact.artifact_id
            or existing.target.version != expected.target.version
        ):
            raise IngestionError("existing snapshot identity mismatch")
        self._verify_snapshot_files(final, existing)
        return existing

    def _verify_snapshot_files(self, final: Path, snapshot: TargetSnapshot) -> None:
        if snapshot.root_ref is None:
            if snapshot.manifest.files:
                raise IngestionError("metadata-only snapshot unexpectedly lists files")
            return
        payload = (self.root / snapshot.root_ref).resolve()
        if payload != (final / "payload").resolve() or final not in payload.parents:
            raise IngestionError("existing snapshot root escapes its content directory")
        expected = {item.path: item for item in snapshot.manifest.files}
        observed: set[str] = set()
        for path in payload.rglob("*"):
            relative = path.relative_to(payload).as_posix()
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise IngestionError("existing snapshot file cannot be inspected") from exc
            if stat.S_ISDIR(mode):
                continue
            observed.add(relative)
            item = expected.get(relative)
            if item is None or not stat.S_ISREG(mode) or path.is_symlink():
                raise IngestionError("existing snapshot contains an unexpected file")
            if (
                path.stat().st_size != item.size
                or self._hash_regular_file(path, item.size) != item.sha256
            ):
                raise IngestionError(f"existing snapshot file failed integrity check: {relative}")
        if observed != set(expected):
            raise IngestionError("existing snapshot is missing a manifest file")

    @staticmethod
    def _hash_regular_file(path: Path, maximum: int) -> str:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise IngestionError("content-addressed object is not a regular file") from exc
        digest = hashlib.sha256()
        read = 0
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise IngestionError("content-addressed object is not a regular file")
            while chunk := handle.read(1024 * 1024):
                read += len(chunk)
                if read > maximum:
                    raise IngestionError("content-addressed object exceeds declared size")
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _seal_snapshot(root: Path) -> None:
        for current, directories, files in os.walk(root, topdown=False):
            for name in files:
                os.chmod(Path(current) / name, 0o400)
            for name in directories:
                os.chmod(Path(current) / name, 0o500)
        os.chmod(root, 0o500)

    @staticmethod
    def _write_bytes(content: bytes, destination: Path, relative_path: str) -> SnapshotFile:
        output = destination.joinpath(*PurePosixPath(relative_path).parts)
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with output.open("xb") as handle:
            os.chmod(output, 0o600)
            handle.write(content)
        return SnapshotFile(
            path=relative_path,
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            category=_classify_path(relative_path),
        )

    @staticmethod
    def _make_manifest(
        artifact: Artifact,
        target: Target,
        files: Iterable[SnapshotFile],
    ) -> TargetManifest:
        initial = tuple(sorted(files, key=lambda item: item.path))
        chart_roots = {
            PurePosixPath(item.path).parent
            for item in initial
            if PurePosixPath(item.path).name.casefold() == "chart.yaml"
        }
        ordered = tuple(
            item.model_copy(update={"category": StaticFileCategory.HELM})
            if any(
                PurePosixPath(item.path).is_relative_to(root / "templates") for root in chart_roots
            )
            else item
            for item in initial
        )
        payload = {
            "artifact_id": artifact.artifact_id,
            "target_version": target.version,
            "files": [item.model_dump(mode="json") for item in ordered],
        }
        manifest_id = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return TargetManifest(
            manifest_id=manifest_id,
            artifact_id=artifact.artifact_id,
            target_id=target.target_id,
            target_version=target.version,
            files=ordered,
            total_size=sum(item.size for item in ordered),
        )

    @staticmethod
    def _require_active_scope(scope: Scope, now) -> None:
        if scope.state is not ScopeState.APPROVED:
            raise IngestionError("target ingestion requires an approved Scope")
        if not scope.valid_from <= now < scope.valid_until:
            raise IngestionError("target ingestion is outside the Scope validity window")

    def _require_artifact_scope(self, scope: Scope, artifact: Artifact, now) -> None:
        self._require_active_scope(scope, now)
        if not any(
            item.kind is artifact.kind
            and item.sha256 == artifact.artifact_id
            and item.source_name == artifact.source_name
            for item in scope.artifacts
        ):
            raise IngestionError("artifact name, kind, and digest are not in approved Scope")


def _classify_path(path: str) -> StaticFileCategory:
    lowered = path.casefold()
    name = PurePosixPath(path).name.casefold()
    parts = {part.casefold() for part in PurePosixPath(path).parts}
    if name == "chart.yaml" or "templates" in parts and "charts" in parts:
        return StaticFileCategory.HELM
    if name.endswith(".tf") or name.endswith(".tf.json"):
        return StaticFileCategory.TERRAFORM
    if name == "dockerfile" or name.startswith("dockerfile."):
        return StaticFileCategory.DOCKERFILE
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return StaticFileCategory.COMPOSE
    if name.endswith((".yaml", ".yml")) and any(
        hint in lowered for hint in ("k8s", "kubernetes", "manifest", "deployment", "service")
    ):
        return StaticFileCategory.KUBERNETES
    if name.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".php", ".rb")):
        return StaticFileCategory.SOURCE
    if name.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".env.example")):
        return StaticFileCategory.CONFIG
    if name.endswith((".md", ".rst", ".txt")):
        return StaticFileCategory.DOCUMENTATION
    return StaticFileCategory.OTHER


def _target_id(engagement_id: UUID, kind: str, source_ref: str, version: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"vulnloom:{engagement_id}:{kind}:{source_ref}:{version}")
