"""Immutable trusted tool capability registry."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from pydantic import ValidationError

from .models import (
    SideEffectMode,
    ToolRegistration,
)


class ToolRegistry:
    def __init__(self, registrations: Iterable[ToolRegistration]):
        try:
            entries = tuple(
                ToolRegistration.model_validate(item.model_dump(mode="python"))
                for item in registrations
            )
        except ValidationError as exc:
            raise ValueError("tool registry entry failed boundary validation") from exc
        by_id = {item.tool_id: item for item in entries}
        if len(by_id) != len(entries):
            raise ValueError("tool registry contains duplicate tool ids")
        self._entries = by_id
        payload = [
            item.model_dump(mode="json")
            for item in sorted(entries, key=lambda entry: entry.tool_id)
        ]
        self.digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def require(self, tool_id: str) -> ToolRegistration:
        try:
            return self._entries[tool_id]
        except KeyError as exc:
            raise ValueError("tool is not present in the trusted registry") from exc


def default_tool_registry() -> ToolRegistry:
    registration = ToolRegistration(
        tool_id="http.request",
        version="1",
        capability="http_request",
        allowed_profiles=frozenset({"validation"}),
        requires_network=True,
        accepts_credential_ref=True,
        side_effect_mode=SideEffectMode.CONDITIONAL,
        implementation_digest=hashlib.sha256(b"vulnloom:offline-http:v1").hexdigest(),
    )
    return ToolRegistry((registration,))
