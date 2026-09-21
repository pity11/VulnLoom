"""Adapter contract implemented by offline and future concrete sandbox runners."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Event
from typing import Protocol, runtime_checkable
from uuid import UUID

from .models import SandboxRunRequest, SandboxRunResult


class RunnerCancellationRequested(RuntimeError):
    """Trusted control plane requested cancellation of an active run."""


@dataclass(frozen=True)
class RunnerCancellation:
    """Run-bound, thread-safe cancellation signal with no execution authority."""

    run_id: UUID
    _requested: Event = field(default_factory=Event, init=False, repr=False, compare=False)

    @property
    def requested(self) -> bool:
        return self._requested.is_set()

    def cancel(self) -> None:
        self._requested.set()


@runtime_checkable
class SandboxRunner(Protocol):
    def execute(
        self,
        request: SandboxRunRequest,
        *,
        now: datetime,
        cancellation: RunnerCancellation | None = None,
    ) -> SandboxRunResult: ...
