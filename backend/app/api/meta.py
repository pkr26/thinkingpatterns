"""Unauthenticated, non-personal server facts (client UI needs them to be
honest): the configured revelation threshold and whether the optional LLM
path exists at all. Contains no user data; same posture as /healthz."""

from __future__ import annotations

from fastapi import APIRouter, Request

from .. import __version__
from ..api.consents import SHARING_DISCLOSURE_VERSION
from ..schemas import MetaResponse
from ..services.llm import processing_policy_fingerprint

router = APIRouter(prefix="/meta", tags=["meta"])

# The API major version the canonical mount serves under ("/api/v1").
API_VERSION = "v1"


@router.get("", response_model=MetaResponse)
async def get_meta(request: Request) -> MetaResponse:
    settings = request.app.state.settings
    return MetaResponse(
        version=__version__,
        api_version=API_VERSION,
        unlock_days=settings.unlock_threshold_days,
        llm_available=bool(settings.llm_url),
        llm_provider_name=settings.llm_provider_name.strip() or None,
        llm_data_retention=settings.llm_data_retention.strip() or None,
        llm_policy_fingerprint=processing_policy_fingerprint(settings),
        sharing_available=bool(settings.therapist_sharing_enabled),
        sharing_disclosure_version=(
            SHARING_DISCLOSURE_VERSION if settings.therapist_sharing_enabled else None
        ),
        sharing_access_log_retention_days=(
            settings.access_log_retention_days if settings.therapist_sharing_enabled else None
        ),
    )
