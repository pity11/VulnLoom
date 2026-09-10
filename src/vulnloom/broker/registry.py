"""Immutable trusted tool capability registry."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest

from .implementation import (
    OFFLINE_HTTP_IMPLEMENTATION_DIGEST,
    OFFLINE_TLS_IMPLEMENTATION_DIGEST,
    PINNED_HTTP_IMPLEMENTATION_DIGEST,
    PINNED_TLS_IMPLEMENTATION_DIGEST,
)
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
            item.model_dump(mode="python")
            for item in sorted(entries, key=lambda entry: entry.tool_id)
        ]
        self.digest = canonical_digest(payload)

    def require(self, tool_id: str) -> ToolRegistration:
        try:
            return self._entries[tool_id]
        except KeyError as exc:
            raise ValueError("tool is not present in the trusted registry") from exc


def default_tool_registry() -> ToolRegistry:
    return _http_tool_registry(
        version="1", implementation_digest=OFFLINE_HTTP_IMPLEMENTATION_DIGEST
    )


def pinned_http_tool_registry() -> ToolRegistry:
    return _http_tool_registry(
        version="2", implementation_digest=PINNED_HTTP_IMPLEMENTATION_DIGEST
    )


def offline_tls_tool_registry() -> ToolRegistry:
    return _tls_tool_registry(
        version="1", implementation_digest=OFFLINE_TLS_IMPLEMENTATION_DIGEST
    )


def pinned_tls_tool_registry() -> ToolRegistry:
    return _tls_tool_registry(
        version="2", implementation_digest=PINNED_TLS_IMPLEMENTATION_DIGEST
    )


def _http_tool_registry(*, version: str, implementation_digest: str) -> ToolRegistry:
    registration = ToolRegistration(
        tool_id="http.request",
        version=version,
        capability="http_request",
        allowed_profiles=frozenset({"validation"}),
        requires_network=True,
        accepts_credential_ref=True,
        side_effect_mode=SideEffectMode.CONDITIONAL,
        implementation_digest=implementation_digest,
    )
    return ToolRegistry((registration,))


def _tls_tool_registry(*, version: str, implementation_digest: str) -> ToolRegistry:
    return ToolRegistry(
        (
            ToolRegistration(
                tool_id="tls.inspect",
                version=version,
                capability="tls_inspect",
                allowed_profiles=frozenset({"validation"}),
                requires_network=True,
                accepts_credential_ref=False,
                side_effect_mode=SideEffectMode.READ_ONLY,
                implementation_digest=implementation_digest,
            ),
        )
    )
