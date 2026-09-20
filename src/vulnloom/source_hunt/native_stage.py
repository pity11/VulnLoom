#!/usr/bin/python3
"""Minimal audited native R9 benchmark worker.

This module is copied into the opt-in test image. It uses only the standard
library, never opens a socket, and emits exactly one structured report on
stdout. The trusted host adapter validates the report before it can become
Evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

_PROTOCOL = "vulnloom.source-tool-report.v1"
_TRIGGER = b"VULNLOOM"


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _compile(source_root: Path, destination: Path) -> None:
    result = subprocess.run(
        (
            "/usr/bin/gcc",
            "-g",
            "-O1",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            str(source_root / "target.c"),
            str(source_root / "harness.c"),
            "-o",
            str(destination),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp"},
    )
    if result.returncode != 0:
        raise RuntimeError("native benchmark compilation failed")


def _run(binary: Path, content: bytes) -> subprocess.CompletedProcess[bytes]:
    descriptor, name = tempfile.mkstemp(prefix="vulnloom-pov-", dir="/tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        return subprocess.run(
            (str(binary), name),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
            env={
                "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1",
                "HOME": "/tmp",
                "PATH": "/usr/bin:/bin",
                "TMPDIR": "/tmp",
            },
        )
    finally:
        os.unlink(name)


def _coverage(result: subprocess.CompletedProcess[bytes]) -> int:
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("COVERAGE:"):
            return int(line.split(":", 1)[1])
    return 0


def _require_asan_crash(result: subprocess.CompletedProcess[bytes]) -> None:
    stderr = result.stderr.decode("utf-8", "replace")
    if (
        result.returncode == 0
        or "AddressSanitizer" not in stderr
        or "heap-buffer-overflow" not in stderr
        or "parse_packet" not in stderr
    ):
        raise RuntimeError("native benchmark did not produce the admitted ASAN crash")


def _signature() -> dict[str, object]:
    values: dict[str, object] = {
        "sanitizer": "address",
        "signal": "abort",
        "failure_class": "heap-buffer-overflow",
        "frames": [
            {
                "module": "benchmark",
                "symbol": "parse_packet",
                "source_path": "target.c",
                "source_line": 12,
            },
            {
                "module": "benchmark",
                "symbol": "main",
                "source_path": "harness.c",
                "source_line": 31,
            },
        ],
    }
    return {"fingerprint": _digest(values), **values}


def _execute_stage(stage: str, source_root: Path) -> tuple[int, bool]:
    binary = Path("/workspace/output/vulnloom-native-benchmark")
    _compile(source_root, binary)
    if stage == "build":
        return 0, False
    if stage == "harness":
        result = _run(binary, b"")
        if result.returncode != 0 or _coverage(result) != 0:
            raise RuntimeError("native benchmark harness smoke test failed")
        return 0, False
    if stage == "fuzz":
        corpus = b""
        seen = {0}
        for expected in _TRIGGER:
            best = corpus
            best_coverage = len(corpus)
            for candidate_byte in range(32, 127):
                candidate = corpus + bytes((candidate_byte,))
                result = _run(binary, candidate)
                coverage = _coverage(result)
                if coverage > best_coverage:
                    best = candidate
                    best_coverage = coverage
                    seen.add(coverage)
                if candidate_byte == expected and coverage == len(candidate):
                    break
            corpus = best
        result = _run(binary, corpus)
        _require_asan_crash(result)
        return len(seen), False
    result = _run(binary, _TRIGGER)
    _require_asan_crash(result)
    return 0, stage == "pov_replay"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=(_PROTOCOL,), required=True)
    parser.add_argument(
        "--stage",
        choices=("build", "harness", "fuzz", "sanitizer", "pov_replay"),
        required=True,
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("registration_id")
    parser.add_argument("input_digest")
    parser.add_argument("adapter_digest")
    parser.add_argument("tool_version")
    args = parser.parse_args(argv)
    if (
        not args.source_root.is_dir()
        or len(args.registration_id) != 64
        or len(args.input_digest) != 64
        or len(args.adapter_digest) != 64
    ):
        raise SystemExit(2)
    coverage_edges, pov_reproduced = _execute_stage(args.stage, args.source_root)
    crash_stage = args.stage in {"fuzz", "sanitizer", "pov_replay"}
    report = {
        "protocol": _PROTOCOL,
        "registration_id": args.registration_id,
        "toolchain": "native_coverage_asan",
        "tool_version": args.tool_version,
        "adapter_digest": args.adapter_digest,
        "stage": args.stage,
        "input_digest": args.input_digest,
        "output_digest": _digest(
            {"stage": args.stage, "input_digest": args.input_digest}
        ),
        "coverage_edges": coverage_edges,
        "crash_input_digest": hashlib.sha256(_TRIGGER).hexdigest() if crash_stage else None,
        "crash_signature": _signature() if crash_stage else None,
        "pov_reproduced": pov_reproduced,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
