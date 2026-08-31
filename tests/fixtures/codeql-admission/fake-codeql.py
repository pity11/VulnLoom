#!/usr/bin/env python3
"""Admission fixture: mimic the fixed CodeQL write/SARIF boundary without target build."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(arguments: list[str]) -> int:
    if arguments[:2] != ["database", "analyze"] or len(arguments) < 4:
        return 64
    database = Path(arguments[2])
    output_argument = next((item for item in arguments if item.startswith("--output=")), None)
    if output_argument is None or database != Path("/workspace/output/codeql-database"):
        return 64
    results = database / "results"
    results.mkdir()
    (results / "write-proof.bqrs").write_bytes(b"bounded-copy-only")
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL admission fixture",
                        "rules": [
                            {
                                "id": "py/unsafe-example",
                                "properties": {"tags": ["external/cwe/cwe-79"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/unsafe-example",
                        "level": "error",
                        "message": {"text": "admission-private-message"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "deploy.yaml"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    Path(output_argument.split("=", 1)[1]).write_text(
        json.dumps(document, separators=(",", ":")),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
