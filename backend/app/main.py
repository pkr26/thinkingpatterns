"""Application factory."""

from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager

import anyio
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, config, singleprocess
from .api import api_router, api_v1_router
from .cache import FixedWindowCounter
from .db import build_engine, build_sessionmaker, init_models
from .deps import DEFAULT_ERROR_CODES
from .metrics import MetricsMiddleware, MetricsRegistry
from .middleware import HardeningMiddleware
from .security.enclave import InMemoryKeyStore

# Distinct from alembic/env.py's migration lock (727272): this one is held
# for the app's LIFETIME, serializing deployments of the same database.
CROSS_HOST_ADVISORY_LOCK_ID = 727273


async def _acquire_cross_host_guard(engine) -> object | None:
    """Postgres-only: hold a session-scoped advisory lock for the app
    lifetime so a SECOND HOST on the same database refuses to boot.

    The 2026-09-16 single-process guard is an flock — per-HOST. A second
    host booted cleanly and silently fragmented every in-process
    guarantee (single-use sessions, rate limits, quota locks), returning
    without an error. The advisory lock makes the multi-host topology
    fail loudly at boot instead. SQLite (dev/test) has no advisory locks
    and no such topology: returns None. The held connection deliberately
    stays out of the pool for the app's lifetime (pool sizing accounts
    for one connection).
    """
    # getattr: test doubles may not carry a dialect; no dialect, no guard.
    dialect = getattr(engine, "dialect", None)
    if getattr(dialect, "name", "") != "postgresql":
        return None
    conn = await engine.connect()
    try:
        acquired = (await conn.exec_driver_sql(
            f"SELECT pg_try_advisory_lock({CROSS_HOST_ADVISORY_LOCK_ID})"
        )).scalar()
        if acquired:
            # The SELECT autobegins a transaction; close it. Session-level
            # advisory locks survive COMMIT, but a transaction held open
            # for the app lifetime leaves this connection "idle in
            # transaction" — pinning xmin and blocking vacuum on every
            # table. The CONNECTION stays open (out of the pool) for the
            # app lifetime; that part is deliberate.
            await conn.commit()
    except Exception:
        await conn.close()
        raise
    if not acquired:
        await conn.close()
        raise RuntimeError(
            "another host is already serving this database: the rate "
            "limiter, per-user locks, and processing-session keystore are "
            "all in-process (see singleprocess.py). One host per database; "
            "move shared counters/locks to Redis &c. before scaling out."
        )
    return conn


async def _release_cross_host_guard(conn: object | None) -> None:
    if conn is None:
        return
    try:
        await conn.exec_driver_sql(
            f"SELECT pg_advisory_unlock({CROSS_HOST_ADVISORY_LOCK_ID})"
        )
    except Exception:
        logger.warning("pg_advisory_unlock failed; disconnect releases the lock", exc_info=True)
    finally:
        await conn.close()

logger = logging.getLogger("mindpattern")

# Kept as an alias: older code/tests reference APP_VERSION on this module.
APP_VERSION = __version__

# access_log retention sweep cadence. The DELETE used to run only inside
# POST /therapist/pairing-codes (opportunistic housekeeping), so a
# steady-state deployment — no new pairings — never pruned and the table
# grew unbounded. The sweep runs the same shared statement (see
# api/therapist.py) once at startup and then daily.
ACCESS_LOG_SWEEP_INTERVAL_SECONDS = 24 * 60 * 60


async def _prune_access_log_once(app: FastAPI) -> None:
    """One access_log retention pass: the SAME statement the pairing-code
    path issues (api.therapist.access_log_prune_statement — imported at
    call time so both call sites provably share one definition)."""
    from .api.therapist import access_log_prune_statement
    from .models import utcnow

    async with app.state.sessionmaker() as session:
        await session.execute(access_log_prune_statement(utcnow()))
        await session.commit()


async def _access_log_retention_sweep(app: FastAPI) -> None:
    """Retention pass immediately, then every 24h. A failed pass logs and
    waits for the next cycle: retention lag must never take the app down."""
    while True:
        try:
            await _prune_access_log_once(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("access_log retention sweep failed; retrying next cycle")
        await asyncio.sleep(ACCESS_LOG_SWEEP_INTERVAL_SECONDS)


def _error_envelope(status_code: int, detail, code: str | None = None) -> dict:
    # detail is ALWAYS a human string — never the FastAPI default list of
    # {loc, msg, input} dicts (mobile parses it as a string, and input echo
    # is an amplification/leak vector).
    if not isinstance(detail, str) or not detail:
        detail = "request failed"
    return {"detail": detail, "code": code or DEFAULT_ERROR_CODES.get(status_code, "error")}


def create_app(settings: config.Settings | None = None) -> FastAPI:
    settings = settings or config.settings
    is_development = settings.environment == "development"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # The deployment contract is ONE process per instance: rate limits,
        # per-user locks, and the processing-session keystore are all
        # in-process. A second worker used to boot silently and fragment
        # every one of those guarantees (2026-09-16 red-team finding C1) —
        # now it refuses to start. Re-entrant within a process (tests).
        with singleprocess.single_process_guard(
            settings.token_secret, settings.database_url
        ):
            if settings.trust_proxy_headers:
                config.logger.warning(
                    "MINDPATTERN_TRUST_PROXY_HEADERS is on: rate-limit identity "
                    "comes from X-Forwarded-For. The origin MUST only be reachable "
                    "through a trusted proxy that appends its own observation — "
                    "direct client access with a spoofable header defeats per-IP "
                    "limits entirely (2026-09-16 red-team finding B2)."
                )
            # Cross-host guard (2026-09-17): the flock above is per-host;
            # on Postgres a session advisory lock closes the multi-HOST hole.
            boot_guard_conn = await _acquire_cross_host_guard(app.state.engine)
            sweep_task: asyncio.Task | None = None
            try:
                # create_all is a dev/test convenience only. Outside development
                # the schema comes from `alembic upgrade head` (run by the image
                # entrypoint before uvicorn starts) — silently pre-creating the
                # schema here would leave the database without an alembic_version
                # stamp and break the first real migration with CREATE TABLE
                # conflicts.
                if is_development:
                    await init_models(app.state.engine)
                # Started AFTER init_models so the first pass never races
                # schema creation. The app.state handle pins the task's
                # lifecycle to the lifespan for tests.
                sweep_task = asyncio.create_task(_access_log_retention_sweep(app))
                app.state.access_log_sweep_task = sweep_task
                yield
            finally:
                if sweep_task is not None:
                    sweep_task.cancel()
                    await asyncio.gather(sweep_task, return_exceptions=True)
                await _release_cross_host_guard(boot_guard_conn)
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
    app.state.engine = build_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
    )
    app.state.sessionmaker = build_sessionmaker(app.state.engine)
    app.state.key_store = InMemoryKeyStore()
    app.state.rate_counter = FixedWindowCounter()
    app.state.metrics = MetricsRegistry()
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
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        # X-Processing-Token drives recomputes; X-Account-Verifier is the
        # preferred DELETE /account re-auth transport — a browser client
        # could not send either in a cross-origin request without this.
        allow_headers=["Authorization", "Content-Type", "X-Processing-Token", "X-Account-Verifier"],
    )
    # Inside the hardening layer: aggregate status counters (no paths, no
    # user data — see app/metrics.py). Added BEFORE HardeningMiddleware so
    # Hardening stays outermost (security headers on every response).
    app.add_middleware(MetricsMiddleware, registry=app.state.metrics)
    # Outermost: body-size cap + security headers on EVERY response (413s,
    # 500s included) + last-ditch exception handling.
    app.add_middleware(
        HardeningMiddleware,
        max_body_bytes=settings.max_body_bytes,
        trust_proxy_headers=settings.trust_proxy_headers,
    )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_envelope(request: Request, exc: StarletteHTTPException):
        # Covers both fastapi.HTTPException (a subclass) and framework-raised
        # Starlette errors (unknown route 404s, 405s). ApiError instances
        # carry their own code; everything else gets the per-status default.
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_envelope(exc.status_code, exc.detail, getattr(exc, "code", None)),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_no_echo(request: Request, exc: RequestValidationError):
        # FastAPI's default 422 echoes the offending `input` — for an
        # oversized blob field that is a 2x-bandwidth amplification vector.
        # Report only WHICH fields failed and why (locations + pydantic's
        # messages carry no user input), as one human string.
        parts = []
        for e in exc.errors():
            loc = ".".join(str(part) for part in e.get("loc", ()) if part != "body")
            msg = e.get("msg", "invalid value")
            parts.append(f"{loc}: {msg}" if loc else msg)
        detail = "; ".join(parts)[:500] or "request validation failed"
        return JSONResponse(
            status_code=422,
            content=_error_envelope(422, detail),
        )

    # Canonical mount is /api/v1; the legacy /api mount serves the same
    # routers unversioned for existing clients (deprecated — /api/meta
    # reports api_version so clients can discover the canonical base).
    app.include_router(api_v1_router)
    app.include_router(api_router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        # Liveness only: no DB touch, so a wedged pool still reports the
        # process as alive (that's what /readyz is for).
        return {"status": "ok", "version": APP_VERSION}

    @app.get("/metrics", tags=["ops"])
    async def metrics_endpoint(request: Request):
        # Fail closed: without an explicitly configured token the endpoint
        # exists only in development; every other environment 404s. The
        # environment is read from app.state at request time (tests flip it
        # without rebuilding the app; the value changes nothing else here).
        live_settings: config.Settings = request.app.state.settings
        if not live_settings.metrics_token:
            if live_settings.environment != "development":
                raise StarletteHTTPException(status_code=404, detail="not found")
        else:
            provided = request.headers.get("authorization", "")
            # The token ALSO comes from the live settings: the create_app
            # closure's copy goes stale the moment app.state.settings is
            # replaced at runtime — the old, possibly-empty token would
            # stay accepted forever. compare_digest (UTF-8 encodings, the
            # account.py idiom): the comparison itself must not leak.
            expected = f"Bearer {live_settings.metrics_token}"
            if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
                raise StarletteHTTPException(
                    status_code=401, detail="metrics token required"
                )
        keystore_len = len(request.app.state.key_store)
        return PlainTextResponse(
            request.app.state.metrics.render(keystore_len),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/readyz", tags=["ops"])
    async def readyz(request: Request):
        try:
            async with request.app.state.sessionmaker() as session:
                await session.execute(text("SELECT 1"))
        except Exception:
            logger.exception("readiness check failed: database unreachable")
            return JSONResponse(
                status_code=503,
                content=_error_envelope(503, "database unavailable"),
            )
        return {"status": "ready", "version": APP_VERSION}

    return app


app = create_app()
