"""Shared fixtures: fresh app per test on in-memory SQLite, httpx client."""

from __future__ import annotations

import os

# The app fails closed: environment defaults to production, so importing
# app.config (module-level Settings.from_env()) without MINDPATTERN_ENV set
# refuses to boot. The test suite IS a development context — opt in
# explicitly, before any app module is imported.
os.environ.setdefault("MINDPATTERN_ENV", "development")

import pathlib

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings() -> Settings:
    s = Settings(environment="development")
    # CI can point the whole suite at a real database (e.g.
    # postgresql+asyncpg://...) via MINDPATTERN_TEST_DB_URL; the default is
    # the per-test in-memory SQLite. Row cleanup for the shared database
    # lives in the autouse fixture at the bottom of this file.
    s.database_url = _test_db_url() or "sqlite+aiosqlite://"
    s.token_secret = "test-secret-not-for-production"
    s.processing_session_ttl = 300
    s.unlock_threshold_days = 30
    s.auth_rate_limit = 10
    s.entries_rate_limit = 1000  # tests seed many entries quickly
    return s


@pytest_asyncio.fixture
async def app(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


# ---------------------------------------------------------------------------
# MINDPATTERN_TEST_DB_URL support (added 2026-09-07; default path unchanged)
# ---------------------------------------------------------------------------


def _test_db_url() -> str:
    """External test database URL, or "" for the in-memory default."""
    return os.environ.get("MINDPATTERN_TEST_DB_URL", "").strip()


@pytest_asyncio.fixture(autouse=True)
async def _shared_test_db_cleanup():
    """Wipe rows between tests when the suite runs against a SHARED database.

    The default in-memory SQLite gives every test a fresh database through
    the app fixture; an external URL (the Postgres CI job) does not, so rows
    would leak between tests. Children are deleted before parents to respect
    FK order; the schema itself is never dropped. Cheap no-op when the env
    var is unset.

    Safety rails: this DELETES EVERY ROW of every app table after each test,
    so a non-SQLite URL must name a database containing "test" (the CI
    contract uses .../mindpattern_test). Parallel pytest workers would need
    one database each — the CI job runs serially.

    L-42 (2026-09-20): a SQLite URL used to skip the name guard entirely,
    so pointing MINDPATTERN_TEST_DB_URL at a real existing sqlite FILE (a
    dev mindpattern.db, say) wiped it on the first test. A file-backed
    sqlite URL is now accepted only when the file does NOT exist yet, or
    lives under the system temp directory, or the destructive intent is
    explicit (MINDPATTERN_TEST_DB_ALLOW_EXISTING_SQLITE=1). In-memory
    sqlite (empty database component) stays always-allowed.
    """
    url = _test_db_url()
    if not url:
        yield
        return
    if not url.startswith("sqlite"):
        from urllib.parse import urlparse

        db_name = (urlparse(url).path or "").lstrip("/")
        if "test" not in db_name:
            raise RuntimeError(
                f"MINDPATTERN_TEST_DB_URL points at database {db_name!r}; the "
                "per-test cleanup deletes all rows, so only a throwaway "
                "database whose name contains 'test' is accepted"
            )
    elif not _existing_sqlite_file_is_allowed(url):
        from sqlalchemy.engine import make_url

        database = make_url(url).database or ""
        raise RuntimeError(
            f"MINDPATTERN_TEST_DB_URL points at existing sqlite file "
            f"{database!r}; the per-test cleanup deletes every row in it. "
            "Point at a throwaway file (not yet created), use a path under "
            "the temp directory, or set "
            "MINDPATTERN_TEST_DB_ALLOW_EXISTING_SQLITE=1 to opt in "
            "explicitly."
        )
    from app.db import build_engine
    from app.models import Base

    engine = build_engine(url)
    try:
        yield
    finally:
        async with engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                await conn.execute(table.delete())
        await engine.dispose()


def _existing_sqlite_file_is_allowed(url: str) -> bool:
    """Whether a sqlite test URL may point at an ALREADY-EXISTING file.

    In-memory databases (empty/``:memory:`` database component) are always
    fine. For file-backed URLs: a not-yet-created file is fine (the suite
    will create and own it), anything under tempfile.gettempdir() is
    conventionally scratch space, and everything else needs the explicit
    opt-in env var. Relative and absolute paths are both judged by their
    resolved absolute location, so ``./db.sqlite`` cannot sneak past a
    guard written for ``/abs/db.sqlite``.
    """
    import tempfile

    from sqlalchemy.engine import make_url

    database = make_url(url).database or ""
    if database in ("", ":memory:") or database.startswith(":memory:"):
        return True
    path = pathlib.Path(database)
    if not path.is_file():
        return True
    if os.environ.get("MINDPATTERN_TEST_DB_ALLOW_EXISTING_SQLITE", "").strip() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return True
    try:
        path = path.resolve()
        return str(path).startswith(str(pathlib.Path(tempfile.gettempdir()).resolve()) + os.sep)
    except OSError:  # unresolvable path — do not guess it is scratch space
        return False
