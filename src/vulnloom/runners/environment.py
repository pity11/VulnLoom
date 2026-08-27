"""Build Worker environments from an explicit, secret-free allowlist."""

from __future__ import annotations

import re
from collections.abc import Mapping


class UnsafeEnvironmentName(ValueError):
    pass


_SENSITIVE = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|COOKIE|AUTH|API_?KEY|PRIVATE_?KEY|"
    r"AWS_|AZURE_|GOOGLE_|GITHUB_|GITLAB_|DOCKER_|SSH_)",
    re.IGNORECASE,
)


def build_worker_environment(explicit: Mapping[str, str]) -> dict[str, str]:
    """Return a new environment; never merge with ``os.environ``."""
    output = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for name, value in explicit.items():
        if _SENSITIVE.search(name):
            raise UnsafeEnvironmentName(f"credential-like variable cannot enter Worker: {name}")
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            raise UnsafeEnvironmentName(f"invalid environment variable name: {name}")
        output[name] = value
    return output
