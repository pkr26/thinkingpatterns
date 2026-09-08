"""Migration tests: the alembic-built schema must match the models exactly,
and the app must boot and write against a migrated database.

These tests are synchronous on purpose: alembic/env.py drives the async
engine with ``asyncio.run()``, which cannot nest inside the pytest-asyncio
event loop.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.engine import Engine

from app.config import Settings
from app.main import create_app
from app.models import Base, Entry, User

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _upgrade_head(db_url: str, monkeypatch) -> None:
    monkeypatch.setenv("MINDPATTERN_DB_URL", db_url)
    command.upgrade(Config(str(BACKEND_DIR / "alembic.ini")), "head")


def _schema_snapshot(engine: Engine) -> dict:
    insp = inspect(engine)
    snapshot = {}
    for table in insp.get_table_names():
        if table == "alembic_version":
            continue
        snapshot[table] = {
            "columns": {
                c["name"]: (str(c["type"]), c["nullable"], bool(c["primary_key"]))
                for c in insp.get_columns(table)
            },
            "indexes": sorted(
                (i["name"], tuple(i["column_names"]), i["unique"])
                for i in insp.get_indexes(table)
            ),
            "uniques": sorted(
                (u["name"], tuple(u["column_names"]))
                for u in insp.get_unique_constraints(table)
            ),
            "fks": sorted(
                (
                    tuple(f["constrained_columns"]),
                    f["referred_table"],
                    tuple(f["referred_columns"]),
                    f["options"].get("ondelete"),
                )
                for f in insp.get_foreign_keys(table)
            ),
        }
    return snapshot


def test_migrations_reproduce_create_all_schema(tmp_path, monkeypatch):
    migrated = tmp_path / "migrated.db"
    _upgrade_head(f"sqlite+aiosqlite:///{migrated}", monkeypatch)

    reference = tmp_path / "reference.db"
    ref_engine = create_engine(f"sqlite:///{reference}")
    Base.metadata.create_all(ref_engine)

    mig_engine = create_engine(f"sqlite:///{migrated}")
    assert _schema_snapshot(mig_engine) == _schema_snapshot(ref_engine)
    # The schema diff above ignores the version table; assert the stamp too.
    with mig_engine.connect() as conn:
        rows = conn.exec_driver_sql("SELECT version_num FROM alembic_version").all()
    assert rows == [("73031d06d71b",)]
    mig_engine.dispose()
    ref_engine.dispose()


def test_autogenerate_against_migrated_head_is_empty(tmp_path, monkeypatch):
    """Model/migration parity: autogenerating against a database migrated to
    head must produce an EMPTY diff. If this fails, someone changed
    app/models.py without shipping a revision (or a revision's DDL does not
    match the models) — `alembic revision --autogenerate` would silently
    produce a spurious next migration.
    """
    migrated = tmp_path / "parity.db"
    _upgrade_head(f"sqlite+aiosqlite:///{migrated}", monkeypatch)

    engine = create_engine(f"sqlite:///{migrated}")
    with engine.connect() as conn:
        # render_as_batch matches alembic/env.py's SQLite configuration.
        ctx = MigrationContext.configure(conn, opts={"render_as_batch": True})
        diff = compare_metadata(ctx, Base.metadata)
    engine.dispose()
    assert diff == []


def test_app_boots_and_writes_on_migrated_database(tmp_path, monkeypatch):
    db_file = tmp_path / "migrated.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    _upgrade_head(db_url, monkeypatch)

    async def smoke() -> None:
        settings = Settings(
            environment="development", database_url=db_url, token_secret="test-secret-not-for-production"
        )
        application = create_app(settings)
        async with application.router.lifespan_context(application):
            async with application.state.sessionmaker() as session:
                user = User(username="mig-user", salt="s", verifier=b"v", scrypt_salt=b"k")
                session.add(user)
                await session.commit()
                session.add(Entry(user_id=user.id, client_entry_id="e1", blob=b"x", entry_date=user.created_at.date()))
                await session.commit()
                loaded = await session.scalar(select(User).where(User.username == "mig-user"))
                assert loaded is not None
                entries = (await session.scalars(select(Entry))).all()
                assert [e.client_entry_id for e in entries] == ["e1"]

    asyncio.run(smoke())
