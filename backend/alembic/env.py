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

The URL comes from app.config.Settings.from_env() — the same source the app
itself reads — so there is exactly one configuration path. Both dialects are
handled: SQLite migrations run with render_as_batch=True (SQLite cannot
ALTER most things; batch mode rebuilds the table), PostgreSQL runs plain DDL.
"""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import Settings
from app.models import Base

config = context.config

target_metadata = Base.metadata


def _database_url() -> str:
    return Settings.from_env().database_url


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
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(_database_url())
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
