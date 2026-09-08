"""Model recommendations over existing Candidates, never Candidate creation."""

from .generation_models import (
    CandidateLocationProjection,
    CandidateRecommendationGenerationOutcome,
    CandidateRecommendationProjection,
    CandidateRecommendationResponse,
    CandidateSignalProjection,
)
from .generation_service import (
    CandidateRecommendationGenerationService,
    recommendation_generation_approval_request,
)
from .generation_store import CandidateRecommendationGenerationStore
from .models import (
    CandidateRecommendation,
    CandidateRecommendationAdmissionPlan,
    CandidateRecommendationRecord,
    RecommendationPriority,
)
from .provider import (
    CandidateRecommendationCodec,
    CandidateRecommendationCodecRegistration,
    CandidateRecommendationGenerationPlan,
    CandidateRecommendationProviderConfig,
)
from .service import CandidateRecommendationAdmissionService
from .store import CandidateRecommendationStore

__all__ = [
    "CandidateLocationProjection",
    "CandidateRecommendation",
    "CandidateRecommendationAdmissionPlan",
    "CandidateRecommendationAdmissionService",
    "CandidateRecommendationCodec",
    "CandidateRecommendationCodecRegistration",
    "CandidateRecommendationGenerationOutcome",
    "CandidateRecommendationGenerationPlan",
    "CandidateRecommendationGenerationService",
    "CandidateRecommendationGenerationStore",
    "CandidateRecommendationProjection",
    "CandidateRecommendationProviderConfig",
    "CandidateRecommendationRecord",
    "CandidateRecommendationResponse",
    "CandidateRecommendationStore",
    "CandidateSignalProjection",
    "RecommendationPriority",
    "recommendation_generation_approval_request",
]
