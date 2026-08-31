"""Immutable registry for locally installed analyzer execution contracts."""

from __future__ import annotations

from collections.abc import Sequence

from vulnloom.domain.digests import canonical_digest
from vulnloom.runners import DockerTool

from .analyzer_execution_models import AnalyzerToolRegistration


class AnalyzerToolRegistry:
    def __init__(self, registrations: Sequence[AnalyzerToolRegistration]):
        registrations = tuple(
            AnalyzerToolRegistration.model_validate(item.model_dump(mode="python"))
            for item in registrations
        )
        self._registrations = {item.tool_id: item for item in registrations}
        if len(self._registrations) != len(registrations):
            raise ValueError("analyzer tool ids must be unique")
        analyzer_keys = {(item.analyzer, item.tool_version) for item in registrations}
        if len(analyzer_keys) != len(registrations):
            raise ValueError("analyzer kind and version registrations must be unique")
        self.digest = canonical_digest(
            tuple(
                item.model_dump(mode="python")
                for item in sorted(registrations, key=lambda value: value.tool_id)
            )
        )

    def get(self, tool_id: str) -> AnalyzerToolRegistration:
        try:
            return self._registrations[tool_id]
        except KeyError as exc:
            raise ValueError("analyzer tool is not registered") from exc

    @property
    def tool_ids(self) -> frozenset[str]:
        return frozenset(self._registrations)

    @property
    def docker_tools(self) -> tuple[DockerTool, ...]:
        """Materialize Docker entries only from the sealed exact argv."""
        return tuple(
            DockerTool(
                tool_id=item.tool_id,
                argv_prefix=item.argv,
                successful_exit_codes=(
                    frozenset({0, 2}) if item.analyzer.value == "kubesec" else frozenset({0})
                ),
            )
            for item in sorted(self._registrations.values(), key=lambda value: value.tool_id)
        )
