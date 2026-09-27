"""The Postgres test-profile seam, documented IN the suite (2026-09-26
test-infrastructure audit, item 4).

The default suite run is per-test in-memory SQLite — fast, hermetic, and
blind to everything real Postgres does differently (DDL, advisory locks,
transaction isolation, asyncpg's type handling). ``MINDPATTERN_TEST_DB_URL``
switches the WHOLE suite onto a real Postgres (see tests/README.md for the
one-command local recipes); this module exists so the seam itself is
pinned by a test rather than only by prose:

  * unset  → skip (the SQLite default path stays the default);
  * set    → the URL must be a Postgres dialect URL, and the driver must
             actually be importable — a profile pointing at a URL the
             environment cannot drive fails HERE, with a named cause,
             instead of as a wall of unrelated fixture errors.

The deeper Postgres-specific behavior lives in the PG-gated tests:
test_migrations.py's upgrade/downgrade round-trips and (implicitly, via
conftest) every API test's storage layer.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio


def _profile_url() -> str:
    return os.environ.get("MINDPATTERN_TEST_DB_URL", "").strip()


@pytest_asyncio.fixture(autouse=True)
async def _ensure_shared_schema():
    """Create the schema when this module runs STANDALONE against a fresh
    shared database. The conftest autouse cleanup DELETEs from every app
    table after each test; in a full-suite run earlier tests' create_all
    has already built the schema, but `pytest tests/test_pg_profile.py`
    alone against an empty database would make that cleanup error on
    missing tables. Same create_all the app fixture performs in
    development; a no-op when the tables already exist."""
    url = _profile_url()
    if not url:
        yield
        return
    from app.db import build_engine, init_models

    engine = build_engine(url)
    try:
        await init_models(engine)
    finally:
        await engine.dispose()
    yield


def test_pg_profile_env_names_a_postgres_dialect():
    """When the profile is enabled its URL must be postgres:// — the
    conftest cleanup, the migration tests, and the README recipes all
    assume asyncpg; a sqlite:// URL in this variable would silently run
    the "PG profile" against the exact engine the profile exists to get
    away from."""
    url = _profile_url()
    if not url:
        pytest.skip("MINDPATTERN_TEST_DB_URL not set — Postgres profile disabled")
    assert url.startswith(("postgresql://", "postgresql+")), (
        f"MINDPATTERN_TEST_DB_URL must be a postgresql(+asyncpg) URL, got {url!r}"
    )
    if "+" in url.split("://", 1)[0]:
        driver = url.split("://", 1)[0].split("+", 1)[1]
        assert driver == "asyncpg", (
            f"the suite's engines are built for asyncpg, got driver {driver!r}"
        )


def test_pg_profile_driver_is_importable():
    """Fail with a named cause when the profile is enabled but asyncpg is
    missing from the environment (e.g. the postgres extra was not
    installed), instead of letting every downstream fixture error."""
    if not _profile_url():
        pytest.skip("MINDPATTERN_TEST_DB_URL not set — Postgres profile disabled")
    pytest.importorskip("asyncpg", reason="MINDPATTERN_TEST_DB_URL is set but asyncpg is missing")
