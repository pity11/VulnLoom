"""Typed contracts for deterministic, Evidence-backed report drafting."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    DomainModel,
    Report,
    ReportChannel,
    ReportSection,
    ReportSectionKind,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ReportDraftPlan(DomainModel):
    plan_id: Digest
    finding_id: UUID
    finding_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    channel: ReportChannel
    title: str = Field(min_length=1, max_length=512)
    sections: Annotated[tuple[ReportSection, ...], Field(min_length=6, max_length=32)]
    prepared_by: str = Field(min_length=1, max_length=256)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.plan_id != report_draft_plan_digest(self):
            raise ValueError("ReportDraftPlan content digest mismatch")
        if self.deadline <= self.created_at:
            raise ValueError("ReportDraftPlan deadline must be after creation")
        counts = {kind: 0 for kind in ReportSectionKind}
        for section in self.sections:
            counts[section.kind] += 1
        if any(
            counts[kind] != 1
            for kind in ReportSectionKind
            if kind is not ReportSectionKind.REPRODUCTION
        ) or counts[ReportSectionKind.REPRODUCTION] < 1:
            raise ValueError("ReportDraftPlan must contain every required section")
        if sum(len(section.text) for section in self.sections) > 65_536:
            raise ValueError("ReportDraftPlan narrative exceeds the configured limit")
        return self

    @classmethod
    def create(
        cls,
        *,
        finding_id: UUID,
        finding_digest: str,
        candidate_id: UUID,
        candidate_digest: str,
        evidence_bundle_id: UUID,
        evidence_bundle_digest: str,
        scope_id: UUID,
        scope_version: int,
        channel: ReportChannel,
        title: str,
        sections: tuple[ReportSection, ...],
        prepared_by: str,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> ReportDraftPlan:
        values = {
            "finding_id": finding_id,
            "finding_digest": finding_digest,
            "candidate_id": candidate_id,
            "candidate_digest": candidate_digest,
            "evidence_bundle_id": evidence_bundle_id,
            "evidence_bundle_digest": evidence_bundle_digest,
            "scope_id": scope_id,
            "scope_version": scope_version,
            "channel": channel,
            "title": title,
            "sections": sections,
            "prepared_by": prepared_by,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "sections": tuple(section.model_dump(mode="python") for section in sections),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def report_draft_plan_digest(plan: ReportDraftPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


def domain_object_digest(value: DomainModel) -> str:
    return canonical_digest(value.model_dump(mode="python"))


class ReportArtifact(DomainModel):
    report_digest: Digest
    markdown_sha256: Digest
    json_sha256: Digest
    markdown_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/report\.md$")
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/report\.json$")

    @model_validator(mode="after")
    def references_match_content_identity(self) -> Self:
        prefix = f"objects/{self.report_digest}"
        if self.markdown_ref != f"{prefix}/report.md" or self.json_ref != f"{prefix}/report.json":
            raise ValueError("Report artifact references do not match content identity")
        return self


class ReportOutcome(DomainModel):
    plan_id: Digest
    report: Report
    artifact: ReportArtifact
    completed_at: AwareDatetime
