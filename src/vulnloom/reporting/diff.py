"""Deterministic, redacted Report revision diffs."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, Report, ReportReviewStatus, ReportSectionKind
from vulnloom.evidence.redaction import Redactor

from .models import Digest, domain_object_digest


class ReportChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class ReportFieldChange(DomainModel):
    path: str = Field(pattern=r"^(title|sections\.[a-z_]+(?:\.[0-9]+)?)$")
    kind: ReportChangeKind
    before: str | None = Field(default=None, max_length=8192)
    after: str | None = Field(default=None, max_length=8192)
    before_evidence_refs: tuple[Digest, ...] = ()
    after_evidence_refs: tuple[Digest, ...] = ()


class ReportDiff(DomainModel):
    diff_id: Digest
    report_family_id: UUID
    from_report_id: UUID
    from_report_digest: Digest
    from_version: int = Field(ge=1)
    to_report_id: UUID
    to_report_digest: Digest
    to_version: int = Field(ge=2)
    changes: Annotated[tuple[ReportFieldChange, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def content_address_is_valid(self) -> Self:
        if self.diff_id != canonical_digest(
            self.model_dump(mode="python", exclude={"diff_id"})
        ):
            raise ValueError("ReportDiff content digest mismatch")
        return self


def diff_reports(previous: Report, current: Report) -> ReportDiff:
    redactor = Redactor()
    narrative = (
        previous.title,
        current.title,
        *(section.text for section in previous.sections),
        *(section.text for section in current.sections),
    )
    if any(redactor.text(value) != value for value in narrative):
        raise ValueError("Report diff refuses content that has not passed redaction")
    if (
        previous.report_family_id != current.report_family_id
        or previous.finding_id != current.finding_id
        or previous.candidate_id != current.candidate_id
        or previous.evidence_bundle_id != current.evidence_bundle_id
        or previous.target_version != current.target_version
        or previous.scope_id != current.scope_id
        or previous.scope_version != current.scope_version
        or previous.channel is not current.channel
        or previous.version + 1 != current.version
        or current.review_status is not ReportReviewStatus.DRAFT
    ):
        raise ValueError("Reports are not consecutive revisions of the same family")

    changes: list[ReportFieldChange] = []
    if previous.title != current.title:
        changes.append(
            ReportFieldChange(
                path="title",
                kind=ReportChangeKind.MODIFIED,
                before=previous.title,
                after=current.title,
            )
        )
    before_sections = _section_map(previous)
    after_sections = _section_map(current)
    for path in sorted(set(before_sections) | set(after_sections)):
        before = before_sections.get(path)
        after = after_sections.get(path)
        if before == after:
            continue
        if before is None:
            kind = ReportChangeKind.ADDED
        elif after is None:
            kind = ReportChangeKind.REMOVED
        else:
            kind = ReportChangeKind.MODIFIED
        changes.append(
            ReportFieldChange(
                path=path,
                kind=kind,
                before=before[0] if before else None,
                after=after[0] if after else None,
                before_evidence_refs=before[1] if before else (),
                after_evidence_refs=after[1] if after else (),
            )
        )
    if not changes:
        raise ValueError("a new Report revision must contain a reviewable change")
    values = {
        "report_family_id": current.report_family_id,
        "from_report_id": previous.report_id,
        "from_report_digest": domain_object_digest(previous),
        "from_version": previous.version,
        "to_report_id": current.report_id,
        "to_report_digest": domain_object_digest(current),
        "to_version": current.version,
        "changes": tuple(changes),
    }
    digest_values = {
        **values,
        "changes": tuple(change.model_dump(mode="python") for change in changes),
    }
    return ReportDiff(diff_id=canonical_digest(digest_values), **values)


def _section_map(report: Report) -> dict[str, tuple[str, tuple[str, ...]]]:
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    reproduction_index = 0
    for section in report.sections:
        if section.kind is ReportSectionKind.REPRODUCTION:
            reproduction_index += 1
            path = f"sections.{section.kind.value}.{reproduction_index}"
        else:
            path = f"sections.{section.kind.value}"
        result[path] = (section.text, section.evidence_refs)
    return result
