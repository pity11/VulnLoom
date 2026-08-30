"""Boundaries for optional, mature static-analysis engines."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from vulnloom.domain.models import SourceLocation, TargetSnapshot

from .models import SignalKind, StaticSignal
from .python_web import _digest


class AnalyzerAdapterError(RuntimeError):
    """An external analyzer failed closed or returned untrusted output."""


class SemgrepAdapter:
    """Run Semgrep with a locally trusted ruleset and a minimal environment.

    The adapter never downloads rules and never accepts an arbitrary config path
    from an agent. Callers select a name from the constructor-provided registry.
    """

    def __init__(
        self,
        executable: Path,
        rules: dict[str, Path],
        *,
        timeout_seconds: float = 120,
        max_target_bytes: int = 2 * 1024 * 1024,
        max_output_bytes: int = 5 * 1024 * 1024,
    ):
        if timeout_seconds <= 0 or max_target_bytes <= 0 or max_output_bytes <= 0:
            raise ValueError("Semgrep limits must be positive")
        self.executable = executable.absolute()
        self.rules = {name: path.absolute() for name, path in rules.items()}
        self.timeout_seconds = timeout_seconds
        self.max_target_bytes = max_target_bytes
        self.max_output_bytes = max_output_bytes

    def analyze(
        self,
        snapshot: TargetSnapshot,
        snapshot_root: Path,
        rule_set: str,
    ) -> tuple[StaticSignal, ...]:
        config = self.rules.get(rule_set)
        if config is None:
            raise AnalyzerAdapterError("unknown Semgrep rule set")
        executable = self._trusted_regular_file(self.executable, "executable")
        config = self._trusted_regular_file(config, "config")
        root = snapshot_root.resolve()
        if not root.is_dir():
            raise AnalyzerAdapterError("snapshot root is unavailable")
        command = [
            str(executable),
            "--json",
            "--config",
            str(config),
            "--metrics",
            "off",
            "--disable-version-check",
            "--no-git-ignore",
            "--max-target-bytes",
            str(self.max_target_bytes),
            "--max-memory",
            "512",
            str(root),
        ]
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        try:
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                completed = subprocess.run(
                    command,
                    cwd=root,
                    env=environment,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                stdout_size = stdout.tell()
                if stdout_size > self.max_output_bytes:
                    raise AnalyzerAdapterError("Semgrep output exceeds the configured limit")
                stdout.seek(0)
                encoded_output = stdout.read(self.max_output_bytes + 1)
                stderr.seek(0)
                encoded_error = stderr.read(1_024)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AnalyzerAdapterError("Semgrep execution failed or timed out") from exc
        if completed.returncode != 0:
            error = encoded_error.decode("utf-8", "replace").strip()
            raise AnalyzerAdapterError(f"Semgrep returned an analyzer error: {error[:300]}")
        try:
            payload = json.loads(encoded_output.decode("utf-8", "strict"))
            results = payload["results"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AnalyzerAdapterError("Semgrep returned invalid JSON") from exc
        if not isinstance(results, list):
            raise AnalyzerAdapterError("Semgrep results must be a list")
        signals = [self._signal(snapshot, root, result) for result in results]
        return tuple(sorted(signals, key=lambda item: item.signal_id))

    @staticmethod
    def _trusted_regular_file(path: Path, label: str) -> Path:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AnalyzerAdapterError(f"Semgrep {label} is unavailable or unsafe") from exc
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise AnalyzerAdapterError(f"Semgrep {label} is unavailable or unsafe")
        resolved = path.resolve()
        try:
            resolved_metadata = resolved.stat()
        except OSError as exc:
            raise AnalyzerAdapterError(f"Semgrep {label} is unavailable or unsafe") from exc
        if (metadata.st_dev, metadata.st_ino) != (
            resolved_metadata.st_dev,
            resolved_metadata.st_ino,
        ):
            raise AnalyzerAdapterError(f"Semgrep {label} changed during validation")
        if label == "executable" and not os.access(resolved, os.X_OK):
            raise AnalyzerAdapterError("Semgrep executable is unavailable or unsafe")
        return resolved

    @staticmethod
    def _signal(snapshot: TargetSnapshot, root: Path, result: object) -> StaticSignal:
        if not isinstance(result, dict):
            raise AnalyzerAdapterError("Semgrep result must be an object")
        try:
            rule_id = str(result["check_id"])
            raw_path = Path(str(result["path"]))
            line = int(result["start"]["line"])
            extra = result.get("extra", {})
            message = str(extra.get("message", "Semgrep rule matched"))
            severity = str(extra.get("severity", "INFO")).upper()
        except (KeyError, TypeError, ValueError) as exc:
            raise AnalyzerAdapterError("Semgrep result is missing required fields") from exc
        resolved = raw_path.resolve() if raw_path.is_absolute() else (root / raw_path).resolve()
        if resolved == root or root not in resolved.parents or line < 1:
            raise AnalyzerAdapterError("Semgrep result path escapes the snapshot")
        relative = PurePosixPath(resolved.relative_to(root).as_posix()).as_posix()
        safe_summary = " ".join(message.split())[:500] or "Semgrep rule matched"
        identity = {"adapter": "semgrep", "rule": rule_id, "path": relative, "line": line}
        confidence = {"ERROR": 0.86, "WARNING": 0.72}.get(severity, 0.6)
        return StaticSignal(
            signal_id=_digest(identity),
            target_id=snapshot.target.target_id,
            kind=SignalKind.EXTERNAL_ANALYZER,
            rule_id=f"semgrep:{rule_id}",
            summary=safe_summary,
            locations=(SourceLocation(path=relative, line=line),),
            confidence=confidence,
            limitations=("External rule match requires VulnLoom validation and disproof.",),
        )
