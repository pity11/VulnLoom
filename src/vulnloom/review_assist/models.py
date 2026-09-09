"""Sealed input, bounded commentary and explicit review-only outcomes."""

import unicodedata
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.agent_runtime.invocation_models import ModelInvocationResult
from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.evidence import Redactor
from vulnloom.runners.models import Digest

LineNumber = Annotated[int, Field(strict=True, ge=1, le=65536)]


def sealed_create(cls, field, values):
    partial = cls.model_construct(**{field: "0" * 64}, **values)
    digest = canonical_digest(partial.model_dump(exclude={field}))
    return cls(**{field: digest}, **values)


class ReviewLine(DomainModel):
    number: LineNumber
    text: str = Field(max_length=2048)

    @model_validator(mode="after")
    def safe(self) -> Self:
        if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} and c != "\t" for c in self.text):
            raise ValueError("review line control characters rejected")
        if Redactor().text(self.text) != self.text:
            raise ValueError("review line is not redacted")
        return self


class CodeReviewSnippet(DomainModel):
    snippet_id: Digest
    snapshot_id: Digest
    target_id: UUID
    path_digest: Digest
    file_digest: Digest
    redaction_policy: Literal["python-literals-comments-v1"] = "python-literals-comments-v1"
    lines: Annotated[tuple[ReviewLine, ...], Field(min_length=1, max_length=80)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        numbers = tuple(line.number for line in self.lines)
        if numbers != tuple(range(numbers[0], numbers[0] + len(numbers))):
            raise ValueError("review line numbers must be contiguous")
        if sum(len(line.text.encode()) for line in self.lines) > 12000:
            raise ValueError("review snippet over budget")
        if not any(line.text.strip() for line in self.lines):
            raise ValueError("empty review snippet")
        if self.snippet_id != canonical_digest(self.model_dump(exclude={"snippet_id"})):
            raise ValueError("review snippet digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault("redaction_policy", "python-literals-comments-v1")
        return sealed_create(cls, "snippet_id", values)


class CodeReviewComment(DomainModel):
    category: Literal["explanation", "review_suggestion"]
    text: str = Field(min_length=1, max_length=400)
    lines: Annotated[tuple[LineNumber, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def safe(self) -> Self:
        if tuple(sorted(set(self.lines))) != self.lines:
            raise ValueError("review references must be ordered and unique")
        if not self.text.strip() or any(
            unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in self.text
        ):
            raise ValueError("review text is empty or contains control characters")
        if Redactor().text(self.text) != self.text:
            raise ValueError("review output contains sensitive text")
        return self


class CodeReviewResponse(DomainModel):
    source_digest: Digest
    comments: Annotated[tuple[CodeReviewComment, ...], Field(min_length=1, max_length=4)]

    def require_references(self, snippet: CodeReviewSnippet) -> None:
        visible = {line.number for line in snippet.lines if line.text.strip()}
        if self.source_digest != snippet.snippet_id or any(
            not set(comment.lines) <= visible for comment in self.comments
        ):
            raise ValueError("review cites content outside the selected snippet")


class CodeReviewOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    status: Literal["review_ready", "rejected", "timed_out"]
    transport: ProviderProbeResult | ModelInvocationResult
    review: CodeReviewResponse | None = None
    requires_human_review: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = "review_ready" if self.transport.status == "passed" else self.transport.status
        if self.status != expected or self.plan_id != self.transport.plan_id:
            raise ValueError("review outcome transport binding mismatch")
        if (self.review is not None) != (self.status == "review_ready"):
            raise ValueError("review output is unavailable without a completed call")
        if self.review is not None and (
            self.transport.response_model is None
            or self.transport.input_tokens + self.transport.output_tokens > 8192
        ):
            raise ValueError("review identity or token budget rejected")
        if self.outcome_id != canonical_digest(self.model_dump(exclude={"outcome_id"})):
            raise ValueError("review outcome digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        values.setdefault("requires_human_review", True)
        return sealed_create(cls, "outcome_id", values)


class ReviewWindow(DomainModel):
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if not 10 < (self.deadline - self.created_at).total_seconds() <= 300:
            raise ValueError("review time window rejected")
        return self
