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
    ProfileCandidateRecommendationCodec,
    ProfileCandidateRecommendationCodecRegistration,
    RoutedCandidateRecommendationProviderConfig,
    routed_recommendation_config,
)
from .selection_models import (
    CandidateRecommendationSelectionCommand,
    CandidateRecommendationSelectionDecision,
    CandidateRecommendationSelectionRecord,
)
from .selection_service import CandidateRecommendationSelectionService
from .selection_store import CandidateRecommendationSelectionStore
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
    "CandidateRecommendationSelectionCommand",
    "CandidateRecommendationSelectionDecision",
    "CandidateRecommendationSelectionRecord",
    "CandidateRecommendationSelectionService",
    "CandidateRecommendationSelectionStore",
    "CandidateRecommendationStore",
    "CandidateSignalProjection",
    "RecommendationPriority",
    "ProfileCandidateRecommendationCodec",
    "ProfileCandidateRecommendationCodecRegistration",
    "RoutedCandidateRecommendationProviderConfig",
    "recommendation_generation_approval_request",
    "routed_recommendation_config",
]
