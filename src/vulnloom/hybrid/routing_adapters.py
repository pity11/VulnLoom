"""Trusted adapters for resolving opaque Live Endpoint References."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from vulnloom.broker.models import url_digest

from .routing_models import LiveEndpointReference


class LiveEndpointUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ResolvedLiveEndpoint:
    """Transient endpoint material that must never cross the adapter boundary."""

    url: str
    scheme: str
    host: str
    port: int
    url_digest: str


class LiveEndpointProvider(Protocol):
    def resolve(self, reference: LiveEndpointReference) -> ResolvedLiveEndpoint: ...


class EnvironmentLiveEndpointProvider:
    def __init__(
        self,
        environment: Mapping[str, str],
        *,
        allowed_references: tuple[LiveEndpointReference, ...],
    ):
        references = {item.reference_id: item for item in allowed_references}
        if not references or len(references) != len(allowed_references):
            raise ValueError("Live Endpoint References must be non-empty and unique")
        self._environment = environment
        self._references = references

    def resolve(self, reference: LiveEndpointReference) -> ResolvedLiveEndpoint:
        if self._references.get(reference.reference_id) != reference:
            raise LiveEndpointUnavailable("Live Endpoint Reference is not allowed")
        raw = self._environment.get(reference.configuration_key)
        if (
            not raw
            or len(raw) > 2_048
            or not raw.isascii()
            or any(ord(character) <= 32 for character in raw)
            or "\\" in raw
        ):
            raise LiveEndpointUnavailable("referenced Live Endpoint is unavailable")
        try:
            parsed = urlsplit(raw)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise LiveEndpointUnavailable("referenced Live Endpoint is invalid") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "%" in parsed.path
            or "//" in parsed.path
            or any(part in {".", ".."} for part in parsed.path.split("/"))
        ):
            raise LiveEndpointUnavailable("referenced Live Endpoint is invalid")
        host = parsed.hostname.lower()
        rendered_host = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme == "https" else 80
        netloc = rendered_host if port == default_port else f"{rendered_host}:{port}"
        normalized = urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))
        if normalized != raw:
            raise LiveEndpointUnavailable("referenced Live Endpoint must be canonical")
        return ResolvedLiveEndpoint(
            url=normalized,
            scheme=parsed.scheme,
            host=host,
            port=port,
            url_digest=url_digest(normalized),
        )
