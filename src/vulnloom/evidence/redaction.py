"""Conservative redaction before logs, indexes, or model context."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


class Redactor:
    policy_name = "builtin-v2"
    placeholder = "[REDACTED]"
    _secret_keys = re.compile(
        r"^(authorization|proxy-authorization|cookie|set-cookie|token|access_token|"
        r"refresh_token|api[_-]?key|secret|password|passwd|private[_-]?key)$",
        re.IGNORECASE,
    )
    _patterns = (
        re.compile(
            r'''(?i)(["'](?:authorization|cookie|token|access[_-]?token|api[_-]?key|secret|'''
            r'''password|passwd|private[_-]?key)["']\s*:\s*["'])[^"']+'''
        ),
        re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
        re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|password)\s*[=:]\s*)[^\s,;&]+"),
        re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    )

    def text(self, value: str) -> str:
        result = value
        for pattern in self._patterns:
            if pattern.groups:
                result = pattern.sub(lambda match: f"{match.group(1)}{self.placeholder}", result)
            else:
                result = pattern.sub(self.placeholder, result)
        return result

    def value(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {
                str(key): self.placeholder
                if self._secret_keys.match(str(key))
                else self.value(item)
                for key, item in value.items()
            }
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self.value(item) for item in value]
        return value
