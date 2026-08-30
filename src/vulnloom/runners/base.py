"""Adapter contract implemented by offline and future concrete sandbox runners."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from .models import SandboxRunRequest, SandboxRunResult


@runtime_checkable
class SandboxRunner(Protocol):
    def execute(
        self,
        request: SandboxRunRequest,
        *,
        now: datetime,
    ) -> SandboxRunResult: ...
