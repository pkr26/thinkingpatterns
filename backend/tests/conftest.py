"""Shared fixtures: fresh app per test on in-memory SQLite, httpx client."""

from __future__ import annotations

import asyncio
import os

# The app fails closed: environment defaults to production, so importing
# app.config (module-level Settings.from_env()) without MINDPATTERN_ENV set
# refuses to boot. The test suite IS a development context — opt in
# explicitly, before any app module is imported.
os.environ.setdefault("MINDPATTERN_ENV", "development")

import pathlib
import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as main_module
from app.config import Settings
from app.main import create_app

# Pin the test process to UTC (2026-09-21, simulation finding): the
# server's calendar is server-UTC everywhere (_utc_today, entry/measure
# date bounds, question pinning — the L-1/L-5 fixes), but many tests
# anchor on the emulated client's host-local ``date.today()``. On hosts
# west of UTC the local evening (00:00–07:00 UTC) puts that anchor a day
# BEHIND the server's calendar, so accounts registered "now" reject
# "yesterday"-dated entries (created_at is UTC) and question AADs miss —
# 12 spurious failures that never show on UTC CI. Aligning the process
# timezone with the server's is the same environment CI already runs
# under; this runs at conftest-import time, which pytest completes
# BEFORE any test module evaluates its module-level TODAY, and the app
# itself never reads local time (every clock is explicit-UTC).
os.environ["TZ"] = "UTC"
time.tzset()


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
async def app(settings, monkeypatch):
    application = create_app(settings)
    initial_purge_finished = asyncio.Event()
    purge_once = main_module._purge_deleted_account_once

    async def finish_initial_purge(app):
        try:
            return await purge_once(app)
        finally:
            if app is application:
                initial_purge_finished.set()

    monkeypatch.setattr(main_module, "_purge_deleted_account_once", finish_initial_purge)
    async with application.router.lifespan_context(application):
        # In-memory SQLite shares one connection across sessions. Finish the
        # boot-time maintenance read before test requests start writing, or
        # its session rollback can undo a concurrent registration transaction.
        # The production worker remains active for subsequent lifecycle tests.
        await asyncio.wait_for(initial_purge_finished.wait(), timeout=10)
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


@pytest.fixture(autouse=True)
def _authenticate_authorized_entry_fixture_inserts():
    """Direct ORM seeds model authorized historical imports, not hostile writes.

    Production never seals missing guards automatically. Tests exercising a
    genuinely unsealed insert opt out via `_skip_trusted_entry_fixture=True`;
    updates/raw SQL always bypass this helper so tampering remains observable.
    """
    from types import SimpleNamespace

    from sqlalchemy import event

    from app.api._audit import _effective_mac_keys
    from app.models import Entry
    from app.security.entry_guard import seal_entry_guard

    def seed_guard(mapper, connection, row):
        if getattr(row, "_skip_trusted_entry_fixture", False):
            return
        if row.aad_guard_mac is None and row.aad_guard_key_version is None:
            ring, version = _effective_mac_keys(None, None, None)
            seal_entry_guard(
                row,
                SimpleNamespace(audit_mac_keyring=ring, audit_mac_key_version=version),
                v2_bound=False,
            )

    event.listen(Entry, "before_insert", seed_guard)
    yield
    event.remove(Entry, "before_insert", seed_guard)
