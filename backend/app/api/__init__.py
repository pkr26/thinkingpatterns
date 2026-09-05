"""Router assembly."""

from fastapi import APIRouter

from . import account, auth, entries, insights, meta


api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(entries.router)
api_router.include_router(insights.router)
api_router.include_router(account.router)
api_router.include_router(meta.router)
