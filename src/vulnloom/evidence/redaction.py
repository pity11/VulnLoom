"""Conservative redaction before logs, indexes, or model context."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import quote


class SensitiveDataRejected(ValueError):
    """Untrusted output could not be safely normalized and redacted."""


class Redactor:
    policy_name = "builtin-v3"
    placeholder = "[REDACTED]"
    _secret_keys = re.compile(
        r"^(authorization|proxy-authorization|cookie|set-cookie|token|access_token|"
        r"refresh_token|api[_-]?key|x-api-key|secret|client[_-]?secret|password|passwd|"
        r"private[_-]?key|credential|session|session[_-]?id|csrf|csrf[_-]?token)$",
        re.IGNORECASE,
    )
    _patterns = (
        re.compile(
            r'''(?i)(["'](?:authorization|cookie|token|access[_-]?token|api[_-]?key|'''
            r'''x-api-key|secret|client[_-]?secret|password|passwd|private[_-]?key|'''
            r'''credential|session(?:[_-]?id)?|csrf(?:[_-]?token)?)["']\s*:\s*["'])[^"']+'''
        ),
        re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
        re.compile(
            r"(?i)((?:api[_-]?key|x-api-key|access[_-]?token|client[_-]?secret|password|"
            r"credential|session(?:[_-]?id)?|csrf(?:[_-]?token)?)\s*[=:]\s*)[^\s,;&]+"
        ),
        re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    )

    def __init__(self, sensitive_values: Sequence[str] = ()):
        variants: set[str] = set()
        for value in sensitive_values:
            if not isinstance(value, str) or not 8 <= len(value.encode("utf-8")) <= 16_384:
                raise ValueError("sensitive values must contain 8 to 16384 UTF-8 bytes")
            if "\x00" in value:
                raise ValueError("sensitive values cannot contain NUL")
            encoded = value.encode("utf-8")
            variants.update(
                {
                    value,
                    quote(value, safe=""),
                    base64.b64encode(encoded).decode("ascii"),
                    base64.urlsafe_b64encode(encoded).decode("ascii"),
                    base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
                    encoded.hex(),
                    encoded.hex().upper(),
                    json.dumps(value, ensure_ascii=True)[1:-1],
                }
            )
        self._sensitive_variants = tuple(
            sorted((item for item in variants if item), key=len, reverse=True)
        )

    def text(self, value: str) -> str:
        result = value
        for sensitive in self._sensitive_variants:
            result = result.replace(sensitive, self.placeholder)
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
        if isinstance(value, (bytes, bytearray)):
            try:
                return self.text(bytes(value).decode("utf-8", "strict"))
            except UnicodeDecodeError:
                raise SensitiveDataRejected(
                    "binary sensitive data cannot enter a structured sink"
                ) from None
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self.value(item) for item in value]
        return value

    def is_safe_text(self, value: str) -> bool:
        return self.text(value) == value


class BoundedRedactionBuffer:
    """Accumulate fragmented UTF-8 output, then redact once across chunk boundaries."""

    def __init__(
        self,
        redactor: Redactor | None = None,
        *,
        max_input_bytes: int,
        max_output_bytes: int | None = None,
    ):
        if max_input_bytes <= 0 or (
            max_output_bytes is not None and max_output_bytes <= 0
        ):
            raise ValueError("redaction buffer limits must be positive")
        self.redactor = redactor or Redactor()
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes or max_input_bytes
        self._buffer = bytearray()
        self._finalized = False

    def feed(self, chunks: Iterable[bytes] | bytes) -> None:
        if self._finalized:
            raise SensitiveDataRejected("redaction buffer is already finalized")
        values = (chunks,) if isinstance(chunks, bytes) else chunks
        for chunk in values:
            if not isinstance(chunk, bytes):
                self.close()
                raise SensitiveDataRejected("redaction chunks must be bytes")
            if len(self._buffer) + len(chunk) > self.max_input_bytes:
                self.close()
                raise SensitiveDataRejected("redaction input exceeds the byte limit")
            self._buffer.extend(chunk)

    def finalize(self) -> str:
        if self._finalized:
            raise SensitiveDataRejected("redaction buffer is already finalized")
        self._finalized = True
        try:
            try:
                decoded = bytes(self._buffer).decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise SensitiveDataRejected("redaction input is not valid UTF-8") from None
            redacted = self.redactor.text(decoded)
            if len(redacted.encode("utf-8")) > self.max_output_bytes:
                raise SensitiveDataRejected("redacted output exceeds the byte limit")
            return redacted
        finally:
            self.close()

    def close(self) -> None:
        self._finalized = True
        self._buffer[:] = b"\x00" * len(self._buffer)
        self._buffer.clear()
