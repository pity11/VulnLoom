"""Passive asset-discovery adapter boundary and deterministic offline fake."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .asset_discovery_models import AssetDiscoveryBatch, AssetDiscoveryQuery


class AssetDiscoveryAdapterInterrupted(RuntimeError):
    pass


class AssetDiscoveryAdapter(Protocol):
    def discover(self, query: AssetDiscoveryQuery) -> AssetDiscoveryBatch: ...


class OfflineAssetDiscoveryAdapter:
    """Returns sealed fixtures only; it has no network or credential surface."""

    def __init__(
        self,
        batches: Mapping[str, AssetDiscoveryBatch | Exception],
    ) -> None:
        self._batches = dict(batches)
        self.calls: list[str] = []

    def discover(self, query: AssetDiscoveryQuery) -> AssetDiscoveryBatch:
        self.calls.append(query.query_id)
        result = self._batches.get(query.query_id)
        if result is None:
            raise AssetDiscoveryAdapterInterrupted(
                "offline asset-discovery fixture is unavailable"
            )
        if isinstance(result, Exception):
            raise result
        return AssetDiscoveryBatch.model_validate(result.model_dump(mode="python"))
