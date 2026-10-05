"""Executable ORM, migration and offline-bootstrap contracts.

Imports stay inside test calls so an unusable mutated model or revision is a
behavioral failure, rather than a failure to collect the oracle itself.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
import runpy
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
CONTRACT = ROOT / "tools/tests/fixtures/backend_schema_contract.json"


def model_contract():
    from sqlalchemy.dialects import postgresql, sqlite

    models = importlib.import_module("app.models")
    result = {}
    for table in models.Base.metadata.sorted_tables:
        columns = []
        for column in table.columns:
            default = None
            if column.default is not None:
                argument = column.default.arg
                if callable(argument):
                    value = argument(None)
                    if isinstance(value, datetime):
                        assert value.tzinfo is not None
                        assert value.utcoffset() == timedelta(0)
                        assert (
                            abs((datetime.now(timezone.utc) - value).total_seconds())
                            < 5
                        )
                        default = {"generated": "current UTC time"}
                    else:
                        assert isinstance(value, str) and re.fullmatch(
                            r"[0-9a-f]{32}", value
                        )
                        assert argument(None) != value, (
                            "separate rows need separate opaque IDs"
                        )
                        default = {"generated": "random opaque ID"}
                else:
                    default = {"value": argument}
            columns.append(
                {
                    "name": column.name,
                    "sqlite_type": str(column.type.compile(dialect=sqlite.dialect())),
                    "postgresql_type": str(
                        column.type.compile(dialect=postgresql.dialect())
                    ),
                    "nullable": column.nullable,
                    "primary_key": column.primary_key,
                    "default": default,
                    "server_default": str(column.server_default.arg)
                    if column.server_default
                    else None,
                }
            )
        constraints = []
        for constraint in table.constraints:
            value = {
                "kind": type(constraint).__name__,
                "name": constraint.name,
                "columns": [column.name for column in constraint.columns],
            }
            if hasattr(constraint, "elements"):
                value.update(
                    targets=[
                        element.target_fullname for element in constraint.elements
                    ],
                    ondelete=constraint.ondelete,
                    onupdate=constraint.onupdate,
                    deferrable=constraint.deferrable,
                    initially=constraint.initially,
                )
            if hasattr(constraint, "sqltext"):
                value["expression"] = str(constraint.sqltext)
            constraints.append(value)
        indexes = []
        for index in table.indexes:
            predicates = {}
            for dialect in ("sqlite", "postgresql"):
                predicate = index.dialect_options[dialect].get("where")
                predicates[dialect] = None if predicate is None else str(predicate)
            indexes.append(
                {
                    "name": index.name,
                    "unique": index.unique,
                    "columns": [column.name for column in index.columns],
                    "predicates": predicates,
                }
            )
        result[table.name] = {
            "columns": columns,
            "constraints": sorted(
                constraints, key=lambda value: json.dumps(value, sort_keys=True)
            ),
            "indexes": sorted(indexes, key=lambda value: value["name"]),
        }
    return result


def database_contract(engine):
    from sqlalchemy import inspect
    from sqlalchemy.sql.sqltypes import Integer

    inspector = inspect(engine)
    result = {}
    for table in inspector.get_table_names():
        if table == "alembic_version":
            continue
        primary_key = inspector.get_pk_constraint(table)
        primary_columns = set(primary_key["constrained_columns"])
        indexes = []
        for index in inspector.get_indexes(table):
            indexes.append(
                {
                    "name": index["name"],
                    "columns": index["column_names"],
                    "unique": bool(index["unique"]),
                    "predicates": {
                        name: str(value)
                        for name, value in index.get("dialect_options", {}).items()
                    },
                }
            )
        columns = [
            {
                "name": column["name"],
                "type": str(column["type"]),
                "nullable": column["nullable"],
                "default": (
                    column["default"].strip("'")
                    if isinstance(column["type"], Integer)
                    and isinstance(column["default"], str)
                    and re.fullmatch(r"'?[+-]?\d+'?", column["default"])
                    else column["default"]
                ),
                "primary_key": column["name"] in primary_columns,
                "timezone": getattr(column["type"], "timezone", None),
            }
            for column in inspector.get_columns(table)
        ]
        result[table] = {
            "columns": sorted(columns, key=lambda column: column["name"]),
            "primary_key": primary_key,
            "uniques": sorted(
                inspector.get_unique_constraints(table),
                key=lambda value: json.dumps(value, sort_keys=True),
            ),
            "checks": sorted(
                inspector.get_check_constraints(table),
                key=lambda value: json.dumps(value, sort_keys=True),
            ),
            "foreign_keys": sorted(
                inspector.get_foreign_keys(table),
                key=lambda value: json.dumps(value, sort_keys=True),
            ),
            "indexes": sorted(indexes, key=lambda value: value["name"]),
        }
    return result


def test_model_schema_and_row_defaults_match_the_deployed_contract(monkeypatch):
    from sqlalchemy import bindparam, column, select

    monkeypatch.syspath_prepend(str(BACKEND))
    assert model_contract() == json.loads(CONTRACT.read_text())
    models = importlib.import_module("app.models")
    assert models.ROLE_USER == "user"
    assert models.ROLE_THERAPIST == "therapist"
    assert (models.KEY_SCHEME_V1, models.KEY_SCHEME_V2) == ("v1", "v2")
    assert (models.KIND_PATTERNS, models.KIND_BRAIN, models.KIND_QUESTION) == (
        "patterns",
        "brain",
        "question",
    )
    value = datetime(
        2026, 1, 2, 12, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )
    expected = datetime(2026, 1, 2, 7, 0, tzinfo=timezone.utc)
    decorator = models.UTCDateTime()
    for operation in (decorator.process_bind_param, decorator.process_result_value):
        assert operation(None, None) is None
        assert operation(value, None) == expected
        assert operation(value.replace(tzinfo=None), None) == value.replace(
            tzinfo=timezone.utc
        )
    # Timestamp predicates occur on nearly every paginated account query. A
    # stateless timestamp adapter must leave SQLAlchemy's compilation cache usable.
    timestamp = column("created_at", models.UTCDateTime())
    statement = select(timestamp).where(timestamp >= bindparam("timestamp"))
    cache_key = statement._generate_cache_key()
    assert cache_key is not None


def test_complete_migration_upgrade_and_downgrade_preserve_runtime_schema(
    tmp_path, monkeypatch
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, event, inspect
    from sqlalchemy.engine import Engine

    monkeypatch.syspath_prepend(str(BACKEND))
    models = importlib.import_module("app.models")
    reference = create_engine(f"sqlite:///{tmp_path / 'reference.sqlite'}")
    migrated = create_engine(f"sqlite:///{tmp_path / 'migrated.sqlite'}")
    models.Base.metadata.create_all(reference)
    monkeypatch.setenv(
        "MINDPATTERN_DB_URL", f"sqlite+aiosqlite:///{tmp_path / 'migrated.sqlite'}"
    )
    configuration = Config(str(BACKEND / "alembic.ini"))
    user_pages = 0

    def bounded_empty_backfill(
        connection, cursor, statement, parameters, context, executemany
    ):
        nonlocal user_pages
        if "SELECT id, llm_consent_at" in statement:
            user_pages += 1
            # Both upgrades start with zero users. One exhausted query per
            # upgrade is sufficient; repeating it cannot discover another page.
            assert user_pages <= 2, "empty consent backfill must stop requesting pages"

    event.listen(Engine, "before_cursor_execute", bounded_empty_backfill)
    try:
        command.upgrade(configuration, "head")
        expected = database_contract(reference)
        assert database_contract(migrated) == expected
        with migrated.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT id, completed_at FROM entry_guard_bootstrap"
            ).all() == [(1, None)]
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version"
                ).scalar_one()
                == "f4a2d8c6b901"
            )
        command.downgrade(configuration, "base")
        assert inspect(migrated).get_table_names() == ["alembic_version"]
        command.upgrade(configuration, "head")
        assert database_contract(migrated) == expected
    finally:
        event.remove(Engine, "before_cursor_execute", bounded_empty_backfill)
        migrated.dispose()
        reference.dispose()


def test_offline_bootstrap_requires_attestation_and_releases_runtime_custody(
    monkeypatch, capsys
):
    from contextlib import contextmanager

    monkeypatch.syspath_prepend(str(BACKEND))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    module = importlib.import_module("bootstrap_entry_guards")
    events = []

    class Engine:
        async def dispose(self):
            events.append("dispose")

    engine = Engine()
    settings = SimpleNamespace(
        database_url="sqlite+aiosqlite://", token_secret="test-token"
    )
    monkeypatch.setattr(module.Settings, "from_env", lambda: settings)
    monkeypatch.setattr(module, "build_engine", lambda url: engine)
    monkeypatch.setattr(module, "build_sessionmaker", lambda value: "sessionmaker")

    @contextmanager
    def single_process_guard(secret, url):
        assert (secret, url) == (settings.token_secret, settings.database_url)
        events.append("process acquire")
        try:
            yield
        finally:
            events.append("process release")

    async def acquire(value):
        assert value is engine
        events.append("database acquire")
        return "database custody"

    async def release(value):
        events.append(("database release", value))

    async def bootstrap(factory, value):
        assert (factory, value) == ("sessionmaker", settings)
        events.append("bootstrap")
        return 7

    monkeypatch.setattr(module, "single_process_guard", single_process_guard)
    monkeypatch.setattr(module, "_acquire_cross_host_guard", acquire)
    monkeypatch.setattr(module, "_release_cross_host_guard", release)
    monkeypatch.setattr(module, "bootstrap_trusted_entries", bootstrap)
    monkeypatch.setattr(
        "sys.argv", ["bootstrap_entry_guards.py", "--trusted-bootstrap"]
    )
    asyncio.run(module.main())
    assert events == [
        "process acquire",
        "database acquire",
        "bootstrap",
        "process release",
        ("database release", "database custody"),
        "dispose",
    ]
    assert (
        capsys.readouterr().out
        == "Trusted entry bootstrap complete: 7 rows; ciphertext unchanged\n"
    )
    events.clear()
    monkeypatch.setattr("sys.argv", ["bootstrap_entry_guards.py"])
    import pytest

    with pytest.raises(SystemExit) as failure:
        asyncio.run(module.main())
    assert failure.value.code != 0
    assert events == []

    async def cannot_acquire(value):
        events.append("database acquire")
        raise RuntimeError("database custody unavailable")

    monkeypatch.setattr(module, "_acquire_cross_host_guard", cannot_acquire)
    monkeypatch.setattr(
        "sys.argv", ["bootstrap_entry_guards.py", "--trusted-bootstrap"]
    )
    with pytest.raises(RuntimeError, match="database custody unavailable"):
        asyncio.run(module.main())
    assert events == [
        "process acquire",
        "database acquire",
        "process release",
        ("database release", None),
        "dispose",
    ]
    completed = subprocess.run(
        [sys.executable, str(BACKEND / "bootstrap_entry_guards.py"), "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0
    assert "--trusted-bootstrap" in completed.stdout


def test_migration_environment_serializes_postgres_and_configures_both_modes(
    monkeypatch,
    caplog,
):
    from contextlib import contextmanager
    from unittest.mock import Mock

    from alembic import context

    monkeypatch.syspath_prepend(str(BACKEND))
    models = importlib.import_module("app.models")
    configure = Mock()
    migrations = Mock()

    @contextmanager
    def transaction():
        yield

    monkeypatch.setattr(context, "config", SimpleNamespace(), raising=False)
    monkeypatch.setattr(context, "is_offline_mode", lambda: True)
    monkeypatch.setattr(context, "configure", configure)
    monkeypatch.setattr(context, "begin_transaction", transaction)
    monkeypatch.setattr(context, "run_migrations", migrations)
    monkeypatch.setenv(
        "MINDPATTERN_DB_URL", "postgresql+asyncpg://localhost/mutation_test"
    )
    module = runpy.run_path(str(BACKEND / "alembic/env.py"))
    offline = configure.call_args.kwargs
    assert offline["url"] == "postgresql+asyncpg://localhost/mutation_test"
    assert offline["target_metadata"] is models.Base.metadata
    assert offline["literal_binds"] is True
    assert offline["dialect_opts"] == {"paramstyle": "named"}
    assert offline["render_as_batch"] is False
    assert offline["compare_type"] is True
    assert offline["compare_server_default"] is True
    monkeypatch.delenv("MINDPATTERN_DB_URL")
    assert module["_database_url"]() == "sqlite+aiosqlite:///./mindpattern.db"
    assert module["_is_sqlite"]("sqlite+aiosqlite:///private.sqlite")
    assert not module["_is_sqlite"]("postgresql+asyncpg://localhost/mutation_test")

    statements = []

    class Connection:
        dialect = SimpleNamespace(name="postgresql")

        def exec_driver_sql(self, statement):
            statements.append(statement)

        def commit(self):
            statements.append("COMMIT preamble")

    module["do_run_migrations"](Connection())
    assert statements == [
        "SET lock_timeout = '15s'",
        "SET statement_timeout = '300s'",
        "SELECT pg_advisory_lock(727272)",
        "COMMIT preamble",
        "SELECT pg_advisory_unlock(727272)",
    ]
    online = configure.call_args.kwargs
    assert online["target_metadata"] is models.Base.metadata
    assert online["render_as_batch"] is False
    assert online["compare_type"] is True
    assert online["compare_server_default"] is True
    assert migrations.call_count == 2

    class LostUnlockConnection(Connection):
        def exec_driver_sql(self, statement):
            super().exec_driver_sql(statement)
            if "pg_advisory_unlock" in statement:
                raise RuntimeError("connection lost before unlock")

    module["do_run_migrations"](LostUnlockConnection())
    warning = caplog.records[-1]
    assert warning.name == "mindpattern.alembic"
    assert warning.message == "pg_advisory_unlock failed; disconnect releases the lock"
    assert isinstance(warning.exc_info, tuple)
    assert isinstance(warning.exc_info[1], RuntimeError)

    class SQLiteConnection(Connection):
        dialect = SimpleNamespace(name="sqlite")

    statements.clear()
    module["do_run_migrations"](SQLiteConnection())
    assert statements == []
    assert configure.call_args.kwargs["render_as_batch"] is True

    events = []

    class AsyncConnection:
        async def __aenter__(self):
            events.append("connect")
            return self

        async def __aexit__(self, *args):
            events.append("disconnect")

        async def run_sync(self, callback):
            assert callback is module["do_run_migrations"]
            events.append("migrate")

    class AsyncEngine:
        def connect(self):
            return AsyncConnection()

        async def dispose(self):
            events.append("dispose")

    globals_ = module["run_migrations_online"].__globals__
    monkeypatch.setitem(globals_, "create_async_engine", lambda url: AsyncEngine())
    asyncio.run(module["run_migrations_online"]())
    assert events == ["connect", "migrate", "disconnect", "dispose"]


def test_postgresql_migrations_preserve_types_defaults_and_all_constraints(monkeypatch):
    import pytest
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    configured = os.environ.get("SCHEMA_MUTATION_POSTGRES_URL", "")
    if not configured:
        pytest.skip("dedicated PostgreSQL schema campaign URL is required")
    base = make_url(configured)
    # This explicit opt-in names a disposable test cluster. Queries only
    # create/drop fresh databases owned by this invocation, never the URL's DB.
    assert base.drivername == "postgresql+asyncpg"
    assert "test" in (base.database or "").lower()
    monkeypatch.syspath_prepend(str(BACKEND))
    models = importlib.import_module("app.models")
    prefix = f"mindpattern_schema_mutation_test_{os.getpid()}_{uuid4().hex[:10]}"
    names = [prefix + "_reference", prefix + "_migrated"]
    urls = [
        base.set(database=name).render_as_string(hide_password=False) for name in names
    ]

    async def administration(statement):
        import asyncpg

        url = base.set(database="postgres").render_as_string(hide_password=False)
        connection = await asyncpg.connect(
            url.replace("postgresql+asyncpg://", "postgresql://")
        )
        try:
            await connection.execute(statement)
        finally:
            await connection.close()

    async def schema(url, create=False):
        engine = create_async_engine(url)
        try:
            if create:
                async with engine.begin() as connection:
                    await connection.run_sync(models.Base.metadata.create_all)
            async with engine.connect() as connection:
                value = await connection.run_sync(database_contract)
                # PostgreSQL renders equivalent typed defaults with casts.
                # Compare the actual values rather than their dialect prose.
                for table in value.values():
                    for column in table["columns"]:
                        if column["default"] is not None:
                            column["default"] = (
                                await connection.exec_driver_sql(
                                    "SELECT " + str(column["default"])
                                )
                            ).scalar_one()
                return value
        finally:
            await engine.dispose()

    created = []
    try:
        for name in names:
            asyncio.run(administration(f'CREATE DATABASE "{name}"'))
            created.append(name)
        expected = asyncio.run(schema(urls[0], create=True))
        monkeypatch.setenv("MINDPATTERN_DB_URL", urls[1])
        command.upgrade(Config(str(BACKEND / "alembic.ini")), "head")
        assert asyncio.run(schema(urls[1])) == expected
    finally:
        for name in created:
            asyncio.run(
                administration(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            )


def test_legacy_quota_backfill_counts_each_owners_opaque_data(
    tmp_path, monkeypatch, request
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, event
    from sqlalchemy.engine import Engine

    monkeypatch.syspath_prepend(str(BACKEND))

    # Older SQLite installations supply LENGTH but not OCTET_LENGTH. This
    # capability fault exercises that supported fallback on a real database.
    def older_sqlite_functions(connection, record):
        def unavailable(value):
            raise RuntimeError("OCTET_LENGTH is unavailable on this SQLite runtime")

        connection.create_function("OCTET_LENGTH", 1, unavailable)

    event.listen(Engine, "connect", older_sqlite_functions)
    request.addfinalizer(
        lambda: event.remove(Engine, "connect", older_sqlite_functions)
    )
    database = tmp_path / "quota-backfill.sqlite"
    monkeypatch.setenv("MINDPATTERN_DB_URL", f"sqlite+aiosqlite:///{database}")
    configuration = Config(str(BACKEND / "alembic.ini"))
    command.upgrade(configuration, "b7c4e2f9a1d5")
    engine = create_engine(f"sqlite:///{database}")
    try:
        with engine.begin() as connection:
            for owner in ("a", "b", "c"):
                connection.exec_driver_sql(
                    "INSERT INTO users (id,username,salt,verifier,scrypt_salt,created_at,"
                    "is_active,token_epoch,llm_consent) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        owner,
                        owner,
                        "salt",
                        b"verifier",
                        b"scrypt",
                        "2026-01-01",
                        1,
                        1,
                        0,
                    ),
                )
            for identifier, owner, blob in (
                ("a1", "a", b"\x00\xffa"),
                ("a2", "a", b"more opaque bytes"),
                ("b1", "b", b"\x80\x81"),
            ):
                connection.exec_driver_sql(
                    "INSERT INTO entries (id,user_id,client_entry_id,blob,entry_date,received_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (identifier, owner, identifier, blob, "2026-01-01", "2026-01-02"),
                )
            for identifier, owner in (("m1", "a"), ("m2", "b"), ("m3", "b")):
                connection.exec_driver_sql(
                    "INSERT INTO measures (id,user_id,client_measure_id,blob,measure_date,received_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        identifier,
                        owner,
                        identifier,
                        b"opaque measure",
                        "2026-01-01",
                        "2026-01-02",
                    ),
                )
        command.upgrade(configuration, "c8d5f2b6a4e7")
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT id,entry_count,entry_blob_bytes,measure_count FROM users ORDER BY id"
            ).all() == [("a", 2, 20, 1), ("b", 1, 2, 2), ("c", 0, 0, 0)]
            assert (
                connection.exec_driver_sql(
                    "SELECT blob FROM entries WHERE id='a1'"
                ).scalar_one()
                == b"\x00\xffa"
            )
        command.downgrade(configuration, "b7c4e2f9a1d5")
        command.upgrade(configuration, "c8d5f2b6a4e7")
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT entry_count,entry_blob_bytes,measure_count FROM users WHERE id='a'"
            ).one() == (2, 20, 1)
    finally:
        engine.dispose()


def test_legacy_audit_timestamp_and_hash_are_portable(monkeypatch):
    import hashlib

    monkeypatch.syspath_prepend(str(BACKEND))
    module = runpy.run_path(
        str(BACKEND / "alembic/versions/c6e0b4f8a2d9_access_log_chain.py")
    )
    aware = datetime(
        2026, 1, 2, 12, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )
    canonical = "2026-01-02T07:00:00+00:00"
    assert module["_canonical_at"](aware) == canonical
    assert module["_canonical_at"](aware.isoformat()) == canonical
    assert (
        module["_canonical_at"](
            datetime(2026, 1, 2, 7, tzinfo=timezone.utc).replace(tzinfo=None)
        )
        == canonical
    )
    for previous in (None, "abc123"):
        expected = hashlib.sha256(
            json.dumps(
                [previous or "", "actor-é", "owner", "entrée", canonical],
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        assert (
            module["_entry_hash"](previous, "actor-é", "owner", "entrée", aware)
            == expected
        )


def test_independent_controls_backfill_historical_permissions_and_audio_owners(
    tmp_path, monkeypatch
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, event
    from sqlalchemy.engine import Engine

    monkeypatch.syspath_prepend(str(BACKEND))
    database = tmp_path / "independent-controls.sqlite"
    monkeypatch.setenv("MINDPATTERN_DB_URL", f"sqlite+aiosqlite:///{database}")
    configuration = Config(str(BACKEND / "alembic.ini"))
    command.upgrade(configuration, "d6a0c4e8b213")
    engine = create_engine(f"sqlite:///{database}")
    owner = "a" * 32
    granted = "2026-01-02T07:00:00+00:00"
    revoked = "2026-02-03T08:00:00+00:00"
    pages = 0

    def bounded_pages(connection, cursor, statement, parameters, context, executemany):
        nonlocal pages
        if "SELECT id, llm_consent_at" in statement:
            pages += 1
            assert pages <= 2, (
                "one small population needs one page and one exhaustion query"
            )

    try:
        with engine.begin() as connection:
            for identifier in (
                owner,
                "patient-b",
                "therapist-a",
                "therapist-b",
                "empty",
            ):
                connection.exec_driver_sql(
                    "INSERT INTO users (id,username,salt,verifier,scrypt_salt,created_at,"
                    "is_active,token_epoch,llm_consent) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        identifier,
                        "salt",
                        b"verifier",
                        b"scrypt",
                        granted,
                        1,
                        1,
                        0,
                    ),
                )
            connection.exec_driver_sql(
                "UPDATE users SET llm_consent_at=?,llm_consent_disclosure='llm-v3',"
                "llm_consent_policy='llm-policy',voice_consent_at=?,"
                "voice_consent_disclosure='voice-v2',voice_consent_policy='voice-policy' WHERE id=?",
                (granted, revoked, owner),
            )
            for identifier, patient, therapist, status, withdrawal, voice in (
                ("active", owner, "therapist-a", "active", None, 1),
                ("revoked", owner, "therapist-b", "revoked", revoked, 0),
                ("other", "patient-b", "therapist-a", "revoked", None, 1),
            ):
                connection.exec_driver_sql(
                    "INSERT INTO consents (id,user_id,therapist_id,status,scope,granted_at,revoked_at,"
                    "disclosure,share_voice) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        patient,
                        therapist,
                        status,
                        "full",
                        granted,
                        withdrawal,
                        "sharing-v4",
                        voice,
                    ),
                )
            for identifier, key in (
                ("valid", f"audio/{owner}/one.enc"),
                ("wrong-prefix", f"other/{owner}/two.enc"),
                ("wrong-owner-length", "audio/short/three.enc"),
            ):
                connection.exec_driver_sql(
                    "INSERT INTO audio_deletions (id,backend,storage_key,not_before) VALUES (?,?,?,?)",
                    (identifier, "local", key, granted),
                )
            connection.exec_driver_sql(
                "INSERT INTO access_log (id,actor_id,actor_role,user_id,action,at,chain_seq,prev_hash,entry_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                ("legacy", owner, "user", owner, "login", granted, 1, None, "0" * 64),
            )
        event.listen(Engine, "before_cursor_execute", bounded_pages)
        try:
            command.upgrade(configuration, "e1b7c9d3a5f2")
        finally:
            event.remove(Engine, "before_cursor_execute", bounded_pages)
        with engine.connect() as connection:
            rows = connection.exec_driver_sql(
                "SELECT user_id,kind,action,disclosure,policy,consent_id,share_voice,event_version,occurred_at "
                "FROM consent_events ORDER BY user_id,kind,consent_id,action"
            ).all()
            normalized = [
                tuple(row[:-1]) + (datetime.fromisoformat(row[-1]),) for row in rows
            ]
            assert normalized == [
                (
                    owner,
                    "llm",
                    "granted",
                    "llm-v3",
                    "llm-policy",
                    None,
                    None,
                    1,
                    datetime.fromisoformat(granted),
                ),
                (
                    owner,
                    "sharing",
                    "granted",
                    "sharing-v4",
                    None,
                    "active",
                    None,
                    1,
                    datetime.fromisoformat(granted),
                ),
                (
                    owner,
                    "sharing",
                    "granted",
                    "sharing-v4",
                    None,
                    "revoked",
                    None,
                    1,
                    datetime.fromisoformat(granted),
                ),
                (
                    owner,
                    "sharing",
                    "withdrawn",
                    "sharing-v4",
                    None,
                    "revoked",
                    0,
                    1,
                    datetime.fromisoformat(revoked),
                ),
                (
                    owner,
                    "voice",
                    "granted",
                    "voice-v2",
                    "voice-policy",
                    None,
                    None,
                    1,
                    datetime.fromisoformat(revoked),
                ),
                (
                    "patient-b",
                    "sharing",
                    "granted",
                    "sharing-v4",
                    None,
                    "other",
                    None,
                    1,
                    datetime.fromisoformat(granted),
                ),
            ]
            ids = (
                connection.exec_driver_sql("SELECT id FROM consent_events")
                .scalars()
                .all()
            )
            assert len(ids) == len(set(ids)) and all(
                re.fullmatch(r"[0-9a-f]{32}", value) for value in ids
            )
            assert connection.exec_driver_sql(
                "SELECT id,owner_id,created_at=not_before FROM audio_deletions ORDER BY id"
            ).all() == [
                ("valid", owner, 1),
                ("wrong-owner-length", None, 1),
                ("wrong-prefix", None, 1),
            ]
            assert connection.exec_driver_sql(
                "SELECT record_version,mac_key_version FROM access_log WHERE id='legacy'"
            ).one() == (1, 1)
            assert connection.exec_driver_sql(
                "SELECT user_id,head_seq,head_hash,first_retained_seq,first_retained_hash,state_version,"
                "mac_key_version,state_mac FROM audit_chain_state"
            ).one() == (owner, 1, "0" * 64, 1, "0" * 64, 1, 1, None)
    finally:
        engine.dispose()


def test_independent_controls_reject_excess_history_for_both_owner_dimensions(
    tmp_path, monkeypatch
):
    import pytest
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    monkeypatch.syspath_prepend(str(BACKEND))
    for dimension in ("user_id", "therapist_id"):
        database = tmp_path / f"history-{dimension}.sqlite"
        monkeypatch.setenv("MINDPATTERN_DB_URL", f"sqlite+aiosqlite:///{database}")
        configuration = Config(str(BACKEND / "alembic.ini"))
        command.upgrade(configuration, "d6a0c4e8b213")
        engine = create_engine(f"sqlite:///{database}")
        try:
            with engine.begin() as connection:
                identifiers = ["owner", *[f"other-{index}" for index in range(1001)]]
                connection.exec_driver_sql(
                    "INSERT INTO users (id,username,salt,verifier,scrypt_salt,created_at,"
                    "is_active,token_epoch,llm_consent) VALUES (?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            identifier,
                            identifier,
                            "salt",
                            b"v",
                            b"k",
                            "2026-01-01",
                            1,
                            1,
                            0,
                        )
                        for identifier in identifiers
                    ],
                )
                connection.exec_driver_sql(
                    "INSERT INTO consents (id,user_id,therapist_id,status,scope,granted_at) VALUES (?,?,?,?,?,?)",
                    [
                        (
                            f"consent-{index}",
                            "owner" if dimension == "user_id" else identifier,
                            "owner" if dimension == "therapist_id" else identifier,
                            "active",
                            "full",
                            "2026-01-02",
                        )
                        for index, identifier in enumerate(identifiers[1:])
                    ],
                )
            with pytest.raises(RuntimeError) as failure:
                command.upgrade(configuration, "e1b7c9d3a5f2")
            assert (
                str(failure.value)
                == "retained sharing history exceeds the supported 1000-row migration limit"
            )
            assert "consent_events" not in inspect(engine).get_table_names(), (
                "reject overflow before changing deployed data"
            )
        finally:
            engine.dispose()


def test_pairing_hardening_downgrade_restores_nonunique_lookup_index(
    tmp_path, monkeypatch
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    monkeypatch.syspath_prepend(str(BACKEND))
    database = tmp_path / "pairing-downgrade.sqlite"
    monkeypatch.setenv("MINDPATTERN_DB_URL", f"sqlite+aiosqlite:///{database}")
    configuration = Config(str(BACKEND / "alembic.ini"))
    command.upgrade(configuration, "d52c4e8f14a0")
    command.downgrade(configuration, "c41f8a92d5e7")
    engine = create_engine(f"sqlite:///{database}")
    try:
        indexes = inspect(engine).get_indexes("pairing_codes")
        index = next(
            value for value in indexes if value["name"] == "ix_pairing_codes_hash"
        )
        assert not index["unique"] and index["column_names"] == ["code_hash"]
        assert not inspect(engine).get_unique_constraints("pairing_codes")
    finally:
        engine.dispose()


def test_consent_backfill_processes_all_pages_and_voice_only_history(
    tmp_path, monkeypatch
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, event
    from sqlalchemy.engine import Engine

    monkeypatch.syspath_prepend(str(BACKEND))
    database = tmp_path / "paged-consent.sqlite"
    monkeypatch.setenv("MINDPATTERN_DB_URL", f"sqlite+aiosqlite:///{database}")
    configuration = Config(str(BACKEND / "alembic.ini"))
    command.upgrade(configuration, "d6a0c4e8b213")
    engine = create_engine(f"sqlite:///{database}")
    owners = [f"{index:032x}" for index in range(501)]
    pages = 0

    def bounded_pages(connection, cursor, statement, parameters, context, executemany):
        nonlocal pages
        if "SELECT id, llm_consent_at" in statement:
            pages += 1
            assert pages <= 3, "501 owners need two data pages and one exhaustion query"

    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO users (id,username,salt,verifier,scrypt_salt,created_at,"
                "is_active,token_epoch,llm_consent,voice_consent_at,voice_consent_disclosure,voice_consent_policy) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        owner,
                        owner,
                        "salt",
                        b"v",
                        b"k",
                        "2026-01-01",
                        1,
                        1,
                        0,
                        "2026-01-02",
                        "voice-v2",
                        "voice-policy",
                    )
                    for owner in owners
                ],
            )
        event.listen(Engine, "before_cursor_execute", bounded_pages)
        try:
            command.upgrade(configuration, "e1b7c9d3a5f2")
        finally:
            event.remove(Engine, "before_cursor_execute", bounded_pages)
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT user_id,kind,action,disclosure,policy FROM consent_events ORDER BY user_id"
            ).all() == [
                (owner, "voice", "granted", "voice-v2", "voice-policy")
                for owner in owners
            ]
    finally:
        engine.dispose()


def test_models_pass_the_existing_backend_static_typecheck_gate(tmp_path):
    """Static evidence is reported separately from runtime mutation kills."""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--no-incremental",
            "--cache-dir",
            str(tmp_path / "mypy"),
        ],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_deployment_revision_graph_exposes_one_unlabelled_chain(monkeypatch):
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    monkeypatch.syspath_prepend(str(BACKEND))
    scripts = ScriptDirectory.from_config(Config(str(BACKEND / "alembic.ini")))
    assert scripts.get_heads() == ["f4a2d8c6b901"]
    assert scripts.get_bases() == ["73031d06d71b"]
    revisions = list(scripts.walk_revisions())
    assert len(revisions) == 33
    # These are the public graph records consumed by Alembic's history and
    # branch commands. The deployment chain publishes no branch label,
    # including the empty label that can silently propagate to descendants.
    assert all(not revision.branch_labels for revision in revisions)
    assert all(not revision.is_branch_point for revision in revisions)
    assert all(not revision.is_merge_point for revision in revisions)
