"""Alembic migration environment for the async SQLAlchemy engine.

Workflow (run from the backend/ directory):

    # Apply all pending migrations (the production upgrade path):
    MINDPATTERN_DB_URL=postgresql+asyncpg://... ../.venv/bin/alembic upgrade head

    # Generate the next migration after changing app/models.py:
    MINDPATTERN_DB_URL=sqlite+aiosqlite:///./scratch.db ../.venv/bin/alembic revision --autogenerate -m "..."
    # ...then REVIEW the generated file: autogenerate misses renames and
    # some constraint changes; edit it before committing.

    # Adopt an existing pre-migrations database (schema already matches
    # models.py because create_all built it): record it as current without
    # re-running DDL, then future revisions apply normally:
    MINDPATTERN_DB_URL=... ../.venv/bin/alembic stamp head

The URL is read straight from MINDPATTERN_DB_URL (falling back to the same
local SQLite default the app uses in development). app.config is deliberately
NOT imported: its import-time fail-closed gate (token secret, non-SQLite URL
outside development) would crash every migration command on an operator
machine, and migration tooling has no business needing a token secret. Both
dialects are handled: SQLite migrations run with render_as_batch=True (SQLite
cannot ALTER most things; batch mode rebuilds the table), PostgreSQL runs
plain DDL.

PostgreSQL concurrency: when several replicas first-boot at once against one
database (compose/swarm scale-out), their entrypoints can run ``alembic
upgrade head`` simultaneously. A session-level advisory lock serializes the
DDL; lock_timeout/statement_timeout make a blocked migration FAIL (the
orchestrator restarts the replica and it retries) instead of hanging the
boot forever. SQLite needs none of this (single-writer file databases).
"""

from __future__ import annotations

import asyncio
import logging
import os

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from app.models import Base

logger = logging.getLogger("mindpattern.alembic")

config = context.config

target_metadata = Base.metadata

# Arbitrary fixed key for the migration advisory lock (any int64; stable
# across releases so every replica's migration runner contends on it).
ADVISORY_LOCK_ID = 727272


def _database_url() -> str:
    # Same default as app.config.Settings.database_url, without importing the
    # fail-closed app config (see module docstring).
    return os.getenv("MINDPATTERN_DB_URL", "sqlite+aiosqlite:///./mindpattern.db")


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=_is_sqlite(url),
        # Autogenerate must SEE type and server-default drift, not just
        # added/dropped tables and columns (the L-33 class: a column whose
        # type or default silently diverged between models.py and a
        # revision). Both flags, both branches — the parity test in
        # backend/tests/test_migrations.py pins them.
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    is_postgres = connection.dialect.name == "postgresql"
    if is_postgres:
        # Bound every wait BEFORE taking the advisory lock: lock_timeout
        # covers the lock acquisition itself, statement_timeout any single
        # slow DDL statement.
        connection.exec_driver_sql("SET lock_timeout = '15s'")
        connection.exec_driver_sql("SET statement_timeout = '300s'")
        connection.exec_driver_sql(f"SELECT pg_advisory_lock({ADVISORY_LOCK_ID})")
    try:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
            # Same rationale as the offline branch above: without these two
            # flags, `alembic revision --autogenerate` (and the parity gate
            # that mirrors it) is blind to type/server-default drift.
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    finally:
        if is_postgres:
            try:
                connection.exec_driver_sql(f"SELECT pg_advisory_unlock({ADVISORY_LOCK_ID})")
            except Exception:  # the disconnect alone releases the lock
                logger.warning(
                    "pg_advisory_unlock failed; disconnect releases the lock", exc_info=True
                )


async def run_migrations_online() -> None:
    engine = create_async_engine(_database_url())
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
