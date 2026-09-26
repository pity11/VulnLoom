"""Pure Campaign Candidate lifecycle transition rules introduced by B5.7."""

from vulnloom.domain.models import CandidateState, ValidationResult


class CampaignCandidateTransitionRejected(ValueError):
    pass


def admit_campaign_candidate_validation(current: CandidateState) -> CandidateState:
    if current is not CandidateState.PROPOSED:
        raise CampaignCandidateTransitionRejected(
            "only a proposed Campaign Candidate may enter Validation Intake"
        )
    return CandidateState.VALIDATION_PENDING


def start_campaign_candidate_validation(current: CandidateState) -> CandidateState:
    if current is not CandidateState.VALIDATION_PENDING:
        raise CampaignCandidateTransitionRejected(
            "Campaign Candidate validation can only start from validation_pending"
        )
    return CandidateState.VALIDATION_RUNNING


def complete_campaign_candidate_validation(
    current: CandidateState, result: ValidationResult
) -> CandidateState:
    if current is not CandidateState.VALIDATION_RUNNING:
        raise CampaignCandidateTransitionRejected(
            "Campaign Candidate validation can only complete from validation_running"
        )
    return (
        CandidateState.VALIDATED
        if result is ValidationResult.REPRODUCED
        else CandidateState.INCONCLUSIVE
    )
