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
    # L-31 (2026-09-20): when the LLM path is off, EVERY llm_* field must be
    # None — the provider/retention env vars are only validated (and only
    # meaningful) when a URL is configured, so an operator can legitimately
    # leave them populated on a deployment with MINDPATTERN_LLM_URL unset.
    # Serving them under llm_available=false was contract drift: clients
    # would render provider/retention consent copy for a path that cannot
    # run. processing_policy_fingerprint already returns None for an empty
    # URL, so it agrees by construction.
    llm_available = bool(settings.llm_url.strip())
    return MetaResponse(
        version=__version__,
        api_version=API_VERSION,
        unlock_days=settings.unlock_threshold_days,
        llm_available=llm_available,
        llm_provider_name=(settings.llm_provider_name.strip() or None) if llm_available else None,
        llm_data_retention=(settings.llm_data_retention.strip() or None) if llm_available else None,
        llm_policy_fingerprint=processing_policy_fingerprint(settings),
        sharing_available=bool(settings.therapist_sharing_enabled),
        sharing_disclosure_version=(
            SHARING_DISCLOSURE_VERSION if settings.therapist_sharing_enabled else None
        ),
        sharing_access_log_retention_days=(
            settings.access_log_retention_days if settings.therapist_sharing_enabled else None
        ),
    )
