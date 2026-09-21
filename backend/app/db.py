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
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, StaticPool

from .models import Base

# Keep readiness independent of Alembic's CLI/runtime import path. Update
# this with the newest single Alembic head whenever a revision is added.
SCHEMA_HEAD = "a3e7c9d5f1b2"


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
    statement_timeout_ms: int = 30_000,
    idle_in_transaction_timeout_ms: int = 300_000,
) -> AsyncEngine:
    if database_url.startswith("sqlite"):
        # Two SQLite topologies, deliberately different pools:
        #
        # :memory: keeps StaticPool — one shared connection is the only
        # thing keeping an in-memory database alive across sessions.  This
        # is the pytest topology only; the shared connection means two
        # concurrent transactions CAN interleave in ways a real deployment
        # never sees (e.g. the pairing-code claim race the 2026-09-19
        # round demonstrated), so concurrency invariants are pinned on the
        # FILE topology below, which matches production semantics.
        #
        # File-backed SQLite (dev servers, file-based test runs) gets a
        # connection PER CHECKOUT, matching production's per-session
        # connections. StaticPool here ran every concurrent transaction
        # over ONE DBAPI connection, interleaving their statement/commit
        # streams: two pairing-code grants racing on one "single-use" code
        # could BOTH pass the conditional claim UPDATE (rowcount 1 each)
        # and both create consent rows. The conditional UPDATE is sound
        # under per-connection isolation; it cannot close a race between
        # two sessions sharing one connection's transaction state. WAL
        # plus a busy timeout make concurrent writers block briefly like a
        # real server instead of failing fast with SQLITE_BUSY.
        database = make_url(database_url).database
        in_memory = not database or database == ":memory:"
        engine = create_async_engine(
            database_url,
            poolclass=StaticPool if in_memory else NullPool,
            connect_args={"check_same_thread": False},
            echo=False,
        )

        # SQLite ships with foreign keys OFF by default, which silently turns
        # every ondelete=CASCADE in models.py into decoration — orphan rows
        # (e.g. entries written by a request racing account deletion) commit
        # cleanly. Postgres enforces FKs natively; make SQLite match.
        @event.listens_for(engine.sync_engine, "connect")
        def _configure_sqlite(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            if not in_memory:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

        return engine
    # Production (asyncpg): bounded, env-tuned pool (MINDPATTERN_DB_POOL_*) —
    # the defaults otherwise come from SQLAlchemy and can't be sized for the
    # deployment. pool_pre_ping drops connections the server already closed.
    # server_settings timeouts (2026-09-21 audit B-3): statement_timeout
    # bounds each query; idle_in_transaction_session_timeout is the vacuum
    # guard — a transaction leaked open used to pin xmin until an operator
    # noticed. asyncpg takes these as STRING milliseconds.
    return create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        connect_args={
            "server_settings": {
                "statement_timeout": str(statement_timeout_ms),
                "idle_in_transaction_session_timeout": str(idle_in_transaction_timeout_ms),
            }
        },
    )


def build_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_models(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
