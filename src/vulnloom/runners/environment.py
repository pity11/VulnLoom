"""Build Worker environments from an explicit, secret-free allowlist."""

from __future__ import annotations

import re
from collections.abc import Mapping


class UnsafeEnvironmentName(ValueError):
    pass


class UnsafeEnvironmentValue(ValueError):
    pass


_SENSITIVE = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|COOKIE|AUTH|API_?KEY|PRIVATE_?KEY|"
    r"AWS_|AZURE_|GOOGLE_|GITHUB_|GITLAB_|DOCKER_|SSH_)",
    re.IGNORECASE,
)


def build_worker_environment(explicit: Mapping[str, str]) -> dict[str, str]:
    """Return a new environment; never merge with ``os.environ``."""
    output = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    total_bytes = 0
    for name, value in explicit.items():
        if name in output:
            raise UnsafeEnvironmentName(f"fixed Worker variable cannot be overridden: {name}")
        if _SENSITIVE.search(name):
            raise UnsafeEnvironmentName(f"credential-like variable cannot enter Worker: {name}")
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            raise UnsafeEnvironmentName(f"invalid environment variable name: {name}")
        encoded_size = len(value.encode("utf-8"))
        total_bytes += len(name) + encoded_size + 1
        if "\x00" in value or encoded_size > 16_384 or total_bytes > 65_536:
            raise UnsafeEnvironmentValue("Worker environment value exceeds safety limits")
        output[name] = value
    return output
