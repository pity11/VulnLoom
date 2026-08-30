"""Pure Report review and local-export state transitions."""

from __future__ import annotations

from enum import StrEnum

from vulnloom.domain.models import Report, ReportReviewStatus


class ReviewDecisionKind(StrEnum):
    APPROVE = "approve"
    REQUEST_CHANGES = "request_changes"
    REJECT = "reject"


class ReportTransitionRejected(ValueError):
    """A Report state transition violated the review workflow."""


def apply_review_decision(report: Report, decision: ReviewDecisionKind) -> Report:
    if report.review_status is not ReportReviewStatus.DRAFT:
        raise ReportTransitionRejected("only a draft Report can receive a review decision")
    target = {
        ReviewDecisionKind.APPROVE: ReportReviewStatus.HUMAN_APPROVED,
        ReviewDecisionKind.REQUEST_CHANGES: ReportReviewStatus.CHANGES_REQUESTED,
        ReviewDecisionKind.REJECT: ReportReviewStatus.REJECTED,
    }[decision]
    return report.model_copy(update={"review_status": target})


def mark_report_exported(report: Report) -> Report:
    if report.review_status is not ReportReviewStatus.HUMAN_APPROVED:
        raise ReportTransitionRejected("only a human-approved Report can be locally exported")
    return report.model_copy(update={"review_status": ReportReviewStatus.EXPORTED})
