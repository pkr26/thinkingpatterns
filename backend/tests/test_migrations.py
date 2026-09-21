"""Migration tests: the alembic-built schema must match the models exactly,
and the app must boot and write against a migrated database.

These tests are synchronous on purpose: alembic/env.py drives the async
engine with ``asyncio.run()``, which cannot nest inside the pytest-asyncio
event loop.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine

from app.config import Settings
from app.db import SCHEMA_HEAD, build_engine, build_sessionmaker, init_models
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
                (i["name"], tuple(i["column_names"]), i["unique"]) for i in insp.get_indexes(table)
            ),
            "uniques": sorted(
                (u["name"], tuple(u["column_names"])) for u in insp.get_unique_constraints(table)
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
    assert rows == [(SCHEMA_HEAD,)]
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
        # render_as_batch matches alembic/env.py's SQLite configuration —
        # and so do the comparison flags (2026-09-21, audit fix B-2): without
        # compare_type/compare_server_default the diff cannot SEE type or
        # default drift, the exact divergence class once fixed as L-33.
        ctx = MigrationContext.configure(
            conn,
            opts={
                "render_as_batch": True,
                "compare_type": True,
                "compare_server_default": True,
            },
        )
        diff = compare_metadata(ctx, Base.metadata)
    engine.dispose()
    assert diff == []


def test_alembic_env_sets_autogenerate_comparison_flags(tmp_path, monkeypatch):
    """The parity gate above only sees type/default drift if alembic/env.py
    hands the flags to context.configure — otherwise the OPERATOR path
    (`alembic revision --autogenerate`) stays blind even while the test
    passes. Spy on context.configure during a real env.py execution, in
    BOTH branches: the online one (a normal upgrade) and the offline one
    (`sql=True`, the `--sql` emit path).
    """
    from alembic import context as alembic_context

    recorded: list[dict] = []
    real_configure = alembic_context.configure

    def spy(*args, **kwargs):
        recorded.append(kwargs)
        return real_configure(*args, **kwargs)

    monkeypatch.setattr(alembic_context, "configure", spy)

    db_file = tmp_path / "flags.db"
    _upgrade_head(f"sqlite+aiosqlite:///{db_file}", monkeypatch)  # online branch
    assert recorded, "env.py never called context.configure during upgrade"
    for kwargs in recorded:
        assert kwargs.get("compare_type") is True, f"online branch: {kwargs}"
        assert kwargs.get("compare_server_default") is True, f"online branch: {kwargs}"

    recorded.clear()
    monkeypatch.setenv("MINDPATTERN_DB_URL", f"sqlite+aiosqlite:///{tmp_path / 'offline.db'}")
    # --sql mode (offline branch). Stop at the initial revision: later
    # revisions use batch_alter_table, and batch mode needs a live
    # connection to reflect — one revision is enough to prove the offline
    # configure call carries the flags.
    command.upgrade(Config(str(BACKEND_DIR / "alembic.ini")), "73031d06d71b", sql=True)
    assert recorded, "env.py never called context.configure in --sql mode"
    for kwargs in recorded:
        assert kwargs.get("compare_type") is True, f"offline branch: {kwargs}"
        assert kwargs.get("compare_server_default") is True, f"offline branch: {kwargs}"


def test_insights_unique_constraint_revision_roundtrips(tmp_path, monkeypatch):
    """upgrade head adds the constraint; downgrade to the initial revision
    removes it; upgrading again restores it (batch-mode table rebuild)."""
    db_file = tmp_path / "roundtrip.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    _upgrade_head(db_url, monkeypatch)

    engine = create_engine(f"sqlite:///{db_file}")
    uniques = inspect(engine).get_unique_constraints("insights")
    assert any(u["name"] == "uq_insights_user_kind_date" for u in uniques)
    engine.dispose()

    command.downgrade(Config(str(BACKEND_DIR / "alembic.ini")), "73031d06d71b")
    engine = create_engine(f"sqlite:///{db_file}")
    uniques = inspect(engine).get_unique_constraints("insights")
    assert not any(u["name"] == "uq_insights_user_kind_date" for u in uniques)
    engine.dispose()

    command.upgrade(Config(str(BACKEND_DIR / "alembic.ini")), "head")
    engine = create_engine(f"sqlite:///{db_file}")
    uniques = inspect(engine).get_unique_constraints("insights")
    assert any(u["name"] == "uq_insights_user_kind_date" for u in uniques)
    engine.dispose()


def test_consent_record_revision_roundtrips(tmp_path, monkeypatch):
    """The GDPR consent columns arrive at head, leave on downgrade to the
    previous revision, and come back on re-upgrade (batch-mode rebuild)."""
    db_file = tmp_path / "consent-roundtrip.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    _upgrade_head(db_url, monkeypatch)

    def consent_columns() -> set[str]:
        engine = create_engine(f"sqlite:///{db_file}")
        names = {c["name"] for c in inspect(engine).get_columns("users")}
        engine.dispose()
        return names

    assert {"llm_consent_at", "llm_consent_disclosure"} <= consent_columns()

    command.downgrade(Config(str(BACKEND_DIR / "alembic.ini")), "e930dbc4f001")
    assert not ({"llm_consent_at", "llm_consent_disclosure"} & consent_columns())

    command.upgrade(Config(str(BACKEND_DIR / "alembic.ini")), "head")
    assert {"llm_consent_at", "llm_consent_disclosure"} <= consent_columns()


def test_collection_snapshot_revision_migration_backfills_and_roundtrips(tmp_path, monkeypatch):
    """Existing accounts start at a usable zero marker and downgrade cleanly."""
    db_file = tmp_path / "collection-revisions.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MINDPATTERN_DB_URL", db_url)
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))

    # Seed an account on the immediately preceding deployed schema, then
    # prove the new non-null counters backfill rather than breaking upgrade.
    command.upgrade(cfg, "b9e6c4a7d812")
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            INSERT INTO users
                (id, username, salt, verifier, scrypt_salt, created_at,
                 is_active, token_epoch, llm_consent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "revision-migration-user",
                "revision-migration-user",
                "s",
                b"v",
                b"k",
                "2026-09-18T00:00:00+00:00",
                1,
                1,
                0,
            ),
        )
    engine.dispose()

    command.upgrade(cfg, "head")
    engine = create_engine(f"sqlite:///{db_file}")
    columns = {column["name"]: column for column in inspect(engine).get_columns("users")}
    assert {"entries_revision", "notes_revision"} <= columns.keys()
    assert not columns["entries_revision"]["nullable"]
    assert not columns["notes_revision"]["nullable"]
    with engine.connect() as conn:
        revisions = conn.exec_driver_sql(
            "SELECT entries_revision, notes_revision FROM users WHERE id = ?",
            ("revision-migration-user",),
        ).all()
    assert revisions == [(0, 0)]
    engine.dispose()

    command.downgrade(cfg, "b9e6c4a7d812")
    engine = create_engine(f"sqlite:///{db_file}")
    assert not (
        {"entries_revision", "notes_revision"}
        & {c["name"] for c in inspect(engine).get_columns("users")}
    )
    engine.dispose()
    command.upgrade(cfg, "head")


def test_app_boots_and_writes_on_migrated_database(tmp_path, monkeypatch):
    db_file = tmp_path / "migrated.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    _upgrade_head(db_url, monkeypatch)

    async def smoke() -> None:
        settings = Settings(
            environment="development",
            database_url=db_url,
            token_secret="test-secret-not-for-production",
        )
        application = create_app(settings)
        async with application.router.lifespan_context(application):
            async with application.state.sessionmaker() as session:
                user = User(username="mig-user", salt="s", verifier=b"v", scrypt_salt=b"k")
                session.add(user)
                await session.commit()
                session.add(
                    Entry(
                        user_id=user.id,
                        client_entry_id="e1",
                        blob=b"x",
                        entry_date=user.created_at.date(),
                    )
                )
                await session.commit()
                loaded = await session.scalar(select(User).where(User.username == "mig-user"))
                assert loaded is not None
                entries = (await session.scalars(select(Entry))).all()
                assert [e.client_entry_id for e in entries] == ["e1"]

    asyncio.run(smoke())


def test_utc_datetime_preserves_aware_offset_instant_on_sqlite():
    """SQLite removes timezone offsets from DateTime storage. UTCDateTime
    must normalize before that conversion, or a non-UTC aware value silently
    changes instant on a SQLite development/test round trip.
    """

    original = datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))

    async def round_trip() -> datetime:
        engine = build_engine("sqlite+aiosqlite://")
        try:
            await init_models(engine)
            sessionmaker = build_sessionmaker(engine)
            async with sessionmaker() as session:
                user = User(
                    username="offset-user",
                    salt="s",
                    verifier=b"v",
                    scrypt_salt=b"k",
                    created_at=original,
                )
                session.add(user)
                await session.commit()
                user_id = user.id
            async with sessionmaker() as session:
                loaded = await session.get(User, user_id)
                assert loaded is not None
                return loaded.created_at
        finally:
            await engine.dispose()

    assert asyncio.run(round_trip()) == original.astimezone(timezone.utc)


def test_undated_insight_unique_index_deduplicates_legacy_rows(tmp_path, monkeypatch):
    """The NULL-date partial index must preserve the newest historical
    pattern/brain row before enforcing its invariant on both fresh writes
    and old databases that predate the index.
    """

    db_file = tmp_path / "undated-insights.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MINDPATTERN_DB_URL", db_url)
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    command.upgrade(cfg, "d52c4e8f14a0")

    engine = create_engine(f"sqlite:///{db_file}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            INSERT INTO users
                (id, username, salt, verifier, scrypt_salt, created_at,
                 is_active, token_epoch, llm_consent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("user-1", "undated-user", "s", b"v", b"k", "2026-01-01T00:00:00+00:00", 1, 1, 0),
        )
        conn.exec_driver_sql(
            """
            INSERT INTO insights (id, user_id, kind, for_date, blob, created_at)
            VALUES (?, ?, ?, NULL, ?, ?)
            """,
            ("old", "user-1", "patterns", b"old", "2026-01-01T00:00:00+00:00"),
        )
        conn.exec_driver_sql(
            """
            INSERT INTO insights (id, user_id, kind, for_date, blob, created_at)
            VALUES (?, ?, ?, NULL, ?, ?)
            """,
            ("new", "user-1", "patterns", b"new", "2026-01-02T00:00:00+00:00"),
        )
    engine.dispose()

    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db_file}")
    with engine.begin() as conn:
        rows = conn.exec_driver_sql(
            "SELECT id, blob FROM insights WHERE user_id = ? AND kind = ? AND for_date IS NULL",
            ("user-1", "patterns"),
        ).all()
        assert rows == [("new", b"new")]
        conn.exec_driver_sql(
            """
            INSERT INTO insights (id, user_id, kind, for_date, blob, created_at)
            VALUES (?, ?, ?, NULL, ?, ?)
            """,
            ("brain-1", "user-1", "brain", b"state", "2026-01-02T00:00:00+00:00"),
        )
        with pytest.raises(IntegrityError):
            conn.exec_driver_sql(
                """
                INSERT INTO insights (id, user_id, kind, for_date, blob, created_at)
                VALUES (?, ?, ?, NULL, ?, ?)
                """,
                ("brain-2", "user-1", "brain", b"duplicate", "2026-01-03T00:00:00+00:00"),
            )
    assert any(
        index["name"] == "uq_insights_user_kind_undated" and index["unique"]
        for index in inspect(engine).get_indexes("insights")
    )
    engine.dispose()


def test_postgres_alembic_upgrade_head_and_current(monkeypatch):
    """The real migration path against real PostgreSQL: plain DDL, the
    advisory lock, batch mode OFF — everything the SQLite tests above
    cannot exercise. Skips everywhere except CI's backend-postgres job,
    which exports MINDPATTERN_TEST_DB_URL pointing at a throwaway database
    (the conftest autouse fixture refuses any database whose name lacks
    "test" before this test body ever runs)."""
    db_url = os.environ.get("MINDPATTERN_TEST_DB_URL", "").strip()
    if not db_url.startswith("postgresql"):
        pytest.skip("MINDPATTERN_TEST_DB_URL is not a PostgreSQL URL")
    monkeypatch.setenv("MINDPATTERN_DB_URL", db_url)

    from app.db import build_engine

    async def _reset_schema() -> None:
        # App tests sharing this database may already have create_all-built
        # the schema; drop it so `upgrade head` runs EVERY revision's DDL
        # for real instead of dying on the first CREATE TABLE.
        engine = build_engine(db_url)
        async with engine.begin() as conn:
            await conn.exec_driver_sql("DROP SCHEMA public CASCADE")
            await conn.exec_driver_sql("CREATE SCHEMA public")
        await engine.dispose()

    asyncio.run(_reset_schema())

    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    command.upgrade(cfg, "head")
    command.current(cfg)  # via the alembic API, as the deploy entrypoint does

    from alembic.script import ScriptDirectory

    heads = ScriptDirectory.from_config(cfg).get_heads()

    async def _stamp() -> list[str]:
        engine = build_engine(db_url)
        async with engine.connect() as conn:
            rows = (await conn.exec_driver_sql("SELECT version_num FROM alembic_version")).all()
        await engine.dispose()
        return [row[0] for row in rows]

    assert asyncio.run(_stamp()) == heads


def test_dated_insight_unique_constraint_deduplicates_before_enforcing(tmp_path, monkeypatch):
    """e930dbc4f001 must not rely on "duplicates cannot exist": a legacy
    duplicate pair (e.g. from a recompute race predating the per-user lock)
    is reduced to the row `_latest_insight()` selects before CREATE UNIQUE
    runs, so an upgrade never aborts mid-deploy. (2026-09-18 audit fix.)
    """

    db_file = tmp_path / "dated-insights.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MINDPATTERN_DB_URL", db_url)
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    command.upgrade(cfg, "73031d06d71b")

    engine = create_engine(f"sqlite:///{db_file}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            INSERT INTO users
                (id, username, salt, verifier, scrypt_salt, created_at,
                 is_active, token_epoch, llm_consent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("user-1", "dated-user", "s", b"v", b"k", "2026-01-01T00:00:00+00:00", 1, 1, 0),
        )
        # Two rows for the SAME (user, kind, for_date) with distinct
        # created_at: exactly what a pre-lock concurrent recompute could
        # have committed under delete-then-insert.
        for row_id, blob, created in (
            ("stale", b"stale", "2026-01-01T00:00:00+00:00"),
            ("fresh", b"fresh", "2026-01-02T00:00:00+00:00"),
            ("tie-a", b"a", "2026-01-02T00:00:00+00:00"),
        ):
            conn.exec_driver_sql(
                """
                INSERT INTO insights (id, user_id, kind, for_date, blob, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (row_id, "user-1", "question", "2026-01-03", blob, created),
            )
        # A different (user, kind, for_date) row must be untouched.
        conn.exec_driver_sql(
            """
            INSERT INTO insights (id, user_id, kind, for_date, blob, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("other", "user-1", "question", "2026-01-04", b"other", "2026-01-01T00:00:00+00:00"),
        )
    engine.dispose()

    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db_file}")
    with engine.begin() as conn:
        rows = conn.exec_driver_sql(
            "SELECT id FROM insights WHERE user_id = ? AND kind = ? AND for_date = ?",
            ("user-1", "question", "2026-01-03"),
        ).all()
        # created_at DESC, id DESC keeps "tie-a" (the tie broken by id),
        # matching _latest_insight()'s selection rule.
        assert rows == [("tie-a",)]
        survivors = conn.exec_driver_sql("SELECT id FROM insights ORDER BY id").all()
        assert survivors == [("other",), ("tie-a",)]
        with pytest.raises(IntegrityError):
            conn.exec_driver_sql(
                """
                INSERT INTO insights (id, user_id, kind, for_date, blob, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("dupe", "user-1", "question", "2026-01-03", b"x", "2026-02-01T00:00:00+00:00"),
            )
    engine.dispose()
