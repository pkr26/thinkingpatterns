"""Unauthenticated, non-personal server facts (client UI needs them to be
honest): the configured revelation threshold and whether the optional LLM
path exists at all. Contains no user data; same posture as /healthz."""

from __future__ import annotations

from fastapi import APIRouter, Request

from .. import __version__
from ..schemas import MetaResponse

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
    )
