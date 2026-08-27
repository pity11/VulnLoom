"""Boundaries for optional, mature static-analysis engines."""

from __future__ import annotations

import json
import subprocess
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
        self.executable = executable.resolve()
        self.rules = {name: path.resolve() for name, path in rules.items()}
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
        if not self.executable.is_file() or self.executable.is_symlink():
            raise AnalyzerAdapterError("Semgrep executable is unavailable or unsafe")
        if not config.is_file() or config.is_symlink():
            raise AnalyzerAdapterError("Semgrep config is unavailable or unsafe")
        root = snapshot_root.resolve()
        if not root.is_dir():
            raise AnalyzerAdapterError("snapshot root is unavailable")
        command = [
            str(self.executable),
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
            completed = subprocess.run(
                command,
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AnalyzerAdapterError("Semgrep execution failed or timed out") from exc
        if completed.returncode != 0:
            raise AnalyzerAdapterError("Semgrep returned an analyzer error")
        if len(completed.stdout.encode("utf-8")) > self.max_output_bytes:
            raise AnalyzerAdapterError("Semgrep output exceeds the configured limit")
        try:
            payload = json.loads(completed.stdout)
            results = payload["results"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AnalyzerAdapterError("Semgrep returned invalid JSON") from exc
        if not isinstance(results, list):
            raise AnalyzerAdapterError("Semgrep results must be a list")
        signals = [self._signal(snapshot, root, result) for result in results]
        return tuple(sorted(signals, key=lambda item: item.signal_id))

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
