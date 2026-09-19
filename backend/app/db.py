"""Async engine / session wiring (SQLite for tests+dev, PostgreSQL for prod).

Schema lifecycle: Alembic migrations (backend/alembic/, configured by
backend/alembic.ini) are the source of truth for schema change. The initial
revision reproduces exactly what ``init_models`` creates, so:

- fresh dev/test databases: ``init_models`` (create_all) builds the schema
  directly — no alembic round-trip in the 250+-test hot loop;
- production upgrade path: ``alembic upgrade head`` (see
  backend/alembic/README.md);
- databases created before migrations existed: adopt with
  ``alembic stamp head`` once, then ``alembic upgrade head`` thereafter.

After any change to app/models.py, generate the next revision with
``alembic revision --autogenerate`` and review it before committing —
create_all will NOT apply changes to existing databases.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from .models import Base

# Keep readiness independent of Alembic's CLI/runtime import path. Update
# this with the newest single Alembic head whenever a revision is added.
SCHEMA_HEAD = "a3f8d1e6c942"


def rowcount(result: Any) -> int:
    """rowcount of a DML execution() result.

    SQLAlchemy types AsyncSession.execute as returning Result, whose stubs
    carry no rowcount — but every DML execution returns a CursorResult at
    runtime on all three drivers here (aiosqlite, asyncpg, tests' doubles).
    getattr keeps the type-checkers honest without a cast at each site.
    """
    return int(getattr(result, "rowcount", 0))


def build_engine(
    database_url: str,
    *,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: int = 30,
) -> AsyncEngine:
    if database_url.startswith("sqlite"):
        # A single shared connection keeps in-memory SQLite alive across
        # sessions. No pool sizing args: aiosqlite + StaticPool has one
        # connection, and pool_size/max_overflow would break or mislead it.
        engine = create_async_engine(
            database_url,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            echo=False,
        )

        # SQLite ships with foreign keys OFF by default, which silently turns
        # every ondelete=CASCADE in models.py into decoration — orphan rows
        # (e.g. entries written by a request racing account deletion) commit
        # cleanly. Postgres enforces FKs natively; make SQLite match.
        @event.listens_for(engine.sync_engine, "connect")
        def _enable_sqlite_fk(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine
    # Production (asyncpg): bounded, env-tuned pool (MINDPATTERN_DB_POOL_*) —
    # the defaults otherwise come from SQLAlchemy and can't be sized for the
    # deployment. pool_pre_ping drops connections the server already closed.
    return create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
    )


def build_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_models(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
