"""Async engine / session wiring (SQLite for tests+dev, PostgreSQL for prod)."""

from __future__ import annotations

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from .models import Base


def build_engine(database_url: str) -> AsyncEngine:
    if database_url.startswith("sqlite"):
        # A single shared connection keeps in-memory SQLite alive across sessions.
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
    return create_async_engine(database_url, echo=False, pool_pre_ping=True)


def build_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_models(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
