"""Provider-neutral product workflow dimensions."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import model_validator

from vulnloom.domain.models import DomainModel


class WorkflowKind(StrEnum):
    SOURCE_HUNT = "source_hunt"
    PRE_RELEASE_ACCEPTANCE = "pre_release_acceptance"
    PRODUCTION_TESTING = "production_testing"
    AUTHORIZED_RED_TEAM = "authorized_red_team"


class Visibility(StrEnum):
    BLACK_BOX = "black_box"
    GREY_BOX = "grey_box"
    WHITE_BOX = "white_box"
    HYBRID = "hybrid"


class ExecutionProfile(StrEnum):
    BENCHMARK = "benchmark"
    PRODUCTION_SAFE = "production_safe"
    PRE_RELEASE = "pre_release"
    RED_TEAM = "red_team"


class AutonomyLevel(StrEnum):
    MANUAL = "a0_manual"
    ASSISTED = "a1_assisted"
    BOUNDED_EXECUTION = "a2_bounded_execution"
    ADAPTIVE_FLOW = "a3_adaptive_flow"
    GOAL_DRIVEN_CAMPAIGN = "a4_goal_driven_campaign"


class WorkflowMode(DomainModel):
    workflow: WorkflowKind
    visibility: Visibility
    execution_profile: ExecutionProfile
    autonomy: AutonomyLevel

    @model_validator(mode="after")
    def compatible(self) -> Self:
        if self.workflow is WorkflowKind.AUTHORIZED_RED_TEAM and (
            self.execution_profile is not ExecutionProfile.RED_TEAM
            or self.visibility not in {Visibility.BLACK_BOX, Visibility.GREY_BOX}
        ):
            raise ValueError("Authorized Red Team requires black/grey-box red-team mode")
        if self.workflow is WorkflowKind.SOURCE_HUNT and (
            self.visibility not in {Visibility.WHITE_BOX, Visibility.HYBRID}
            or self.execution_profile
            not in {ExecutionProfile.BENCHMARK, ExecutionProfile.PRE_RELEASE}
        ):
            raise ValueError("Source Hunt mode is incompatible")
        if self.workflow is WorkflowKind.PRODUCTION_TESTING and (
            self.execution_profile is not ExecutionProfile.PRODUCTION_SAFE
        ):
            raise ValueError("Production testing requires production-safe execution")
        if self.workflow is WorkflowKind.PRE_RELEASE_ACCEPTANCE and (
            self.execution_profile is not ExecutionProfile.PRE_RELEASE
        ):
            raise ValueError("Pre-release acceptance requires pre-release execution")
        return self
