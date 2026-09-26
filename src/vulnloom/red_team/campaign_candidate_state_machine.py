"""Pure Campaign Candidate lifecycle transition rules introduced by B5.7."""

from vulnloom.domain.models import CandidateState


class CampaignCandidateTransitionRejected(ValueError):
    pass


def admit_campaign_candidate_validation(current: CandidateState) -> CandidateState:
    if current is not CandidateState.PROPOSED:
        raise CampaignCandidateTransitionRejected(
            "only a proposed Campaign Candidate may enter Validation Intake"
        )
    return CandidateState.VALIDATION_PENDING
