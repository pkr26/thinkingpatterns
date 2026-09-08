"""Application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

import anyio
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import config
from .api import api_router
from .cache import FixedWindowCounter
from .db import build_engine, build_sessionmaker, init_models
from .middleware import HardeningMiddleware
from .security.enclave import InMemoryKeyStore

# Single source for the app version inside the code (pyproject.toml carries
# the same value for packaging; importlib.metadata is unusable because the
# package is never installed — the image and dev venv run from source).
APP_VERSION = "1.0.0"


def create_app(settings: config.Settings | None = None) -> FastAPI:
    settings = settings or config.settings
    is_development = settings.environment == "development"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # create_all is a dev/test convenience only. Outside development the
        # schema comes from `alembic upgrade head` (run by the image
        # entrypoint before uvicorn starts) — silently pre-creating the schema
        # here would leave the database without an alembic_version stamp and
        # break the first real migration with CREATE TABLE conflicts.
        if is_development:
            await init_models(app.state.engine)
        yield
        await app.state.engine.dispose()

    app = FastAPI(
        title="MindPattern API",
        version=APP_VERSION,
        description="Zero-knowledge personal pattern recognition for mental state.",
        lifespan=lifespan,
        # The interactive docs and schema are developer tooling: in any
        # non-development environment they would hand an attacker a complete
        # API map for nothing (fail closed: a typo'd MINDPATTERN_ENV keeps
        # them off, matching the config gates).
        docs_url="/docs" if is_development else None,
        redoc_url="/redoc" if is_development else None,
        openapi_url="/openapi.json" if is_development else None,
    )
    app.state.settings = settings
    app.state.engine = build_engine(settings.database_url)
    app.state.sessionmaker = build_sessionmaker(app.state.engine)
    app.state.key_store = InMemoryKeyStore()
    app.state.rate_counter = FixedWindowCounter()
    # Analysis (brain recomputes) is attacker-sized CPU work; a dedicated
    # limiter keeps it from occupying every worker thread that auth scrypt
    # and ordinary requests also need.
    app.state.analyze_limiter = anyio.CapacityLimiter(4)
    # Auth scrypt (N=2^16, ~64 MiB per hash) likewise gets its own small
    # limiter: a login flood must not be able to queue unbounded 64-MiB
    # allocations on the shared anyio thread pool.
    app.state.auth_limiter = anyio.CapacityLimiter(4)

    app.add_middleware(
        CORSMiddleware,
        # Empty by default — the mobile app is a native client and needs no
        # CORS; browser frontends set an explicit MINDPATTERN_CORS_ORIGINS
        # allowlist. Credentials stay off.
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Processing-Token"],
    )
    # Outermost: body-size cap + security headers on EVERY response (413s,
    # 500s included) + last-ditch exception handling.
    app.add_middleware(HardeningMiddleware, max_body_bytes=settings.max_body_bytes)

    @app.exception_handler(RequestValidationError)
    async def validation_no_echo(request: Request, exc: RequestValidationError):
        # FastAPI's default 422 echoes the offending `input` — for an
        # oversized blob field that is a 2x-bandwidth amplification vector.
        # Keep locations + messages, drop the input payload.
        return JSONResponse(
            status_code=422,
            content={"detail": [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]},
        )

    app.include_router(api_router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        return {"status": "ok", "version": APP_VERSION}

    return app


app = create_app()
