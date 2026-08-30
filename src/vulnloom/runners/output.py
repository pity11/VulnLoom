"""Bounded immutable capture of attached sandbox stdout."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Protocol

from .models import SandboxOutput


class ContainerOutputAttacher(Protocol):
    def start_capture(
        self,
        container: str,
        timeout: float,
        destination: Path,
        max_bytes: int,
    ) -> int: ...


class RunnerOutputCaptureFailed(RuntimeError):
    pass


class RunnerOutputStore:
    """Capture bounded bytes, validate no-follow, then publish by digest."""

    def __init__(self, root: Path, *, max_output_bytes: int = 64 * 1024 * 1024):
        if max_output_bytes <= 0:
            raise ValueError("sandbox output size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.temporary = self.root / "capture-tmp"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.temporary.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_output_bytes = max_output_bytes

    def capture_attached(
        self,
        attacher: ContainerOutputAttacher,
        container: str,
        *,
        timeout: float,
    ) -> tuple[int, SandboxOutput]:
        directory = Path(tempfile.mkdtemp(prefix="sandbox-output-", dir=self.temporary))
        path = directory / "output.json"
        try:
            exit_code = attacher.start_capture(
                container,
                timeout,
                path,
                self.max_output_bytes,
            )
            if {item.name for item in directory.iterdir()} != {"output.json"}:
                raise RunnerOutputCaptureFailed("sandbox output capture created unexpected entries")
            return exit_code, self._publish(self._read_regular(path))
        except (TimeoutError, RunnerOutputCaptureFailed):
            raise
        except Exception as exc:
            raise RunnerOutputCaptureFailed("sandbox output capture failed") from exc
        finally:
            if directory.exists():
                shutil.rmtree(directory)

    def path(self, output: SandboxOutput) -> Path:
        self._verify(output)
        return self.root / output.content_ref

    def read(self, output: SandboxOutput) -> bytes:
        return self._verify(output)

    def _publish(self, content: bytes) -> SandboxOutput:
        digest = hashlib.sha256(content).hexdigest()
        output = SandboxOutput(
            object_id=digest,
            logical_name="output.json",
            size=len(content),
            sha256=digest,
            content_ref=f"objects/{digest}/output.json",
        )
        destination = self.objects / digest
        if destination.exists():
            self._verify(output)
            return output
        publishing = Path(tempfile.mkdtemp(prefix="sandbox-publish-", dir=self.objects))
        try:
            target = publishing / "output.json"
            with target.open("xb") as handle:
                handle.write(content)
            os.chmod(target, 0o400)
            os.chmod(publishing, 0o500)
            try:
                os.rename(publishing, destination)
            except FileExistsError:
                self._verify(output)
            self._verify(output)
            return output
        finally:
            if publishing.exists():
                os.chmod(publishing, 0o700)
                shutil.rmtree(publishing)

    def _verify(self, output: SandboxOutput) -> bytes:
        directory = self.objects / output.object_id
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise RunnerOutputCaptureFailed("sandbox output object is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or {item.name for item in directory.iterdir()} != {
            "output.json"
        }:
            raise RunnerOutputCaptureFailed("sandbox output object is unsafe")
        content = self._read_regular(self.root / output.content_ref)
        if len(content) != output.size or hashlib.sha256(content).hexdigest() != output.sha256:
            raise RunnerOutputCaptureFailed("sandbox output object integrity check failed")
        return content

    def _read_regular(self, path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise RunnerOutputCaptureFailed("platform cannot enforce no-follow output reads")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise RunnerOutputCaptureFailed("sandbox output is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size <= 0
                or metadata.st_size > self.max_output_bytes
            ):
                raise RunnerOutputCaptureFailed("sandbox output is not a bounded regular file")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(
                    descriptor,
                    min(1024 * 1024, self.max_output_bytes + 1 - total),
                )
                if not block:
                    break
                total += len(block)
                if total > self.max_output_bytes:
                    raise RunnerOutputCaptureFailed("sandbox output exceeds its size limit")
                chunks.append(block)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
