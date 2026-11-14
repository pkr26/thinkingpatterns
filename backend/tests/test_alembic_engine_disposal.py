"""The Alembic engine must release its SQLite worker on every exit."""

import ast
import asyncio
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.parametrize("fail_migration", [False, True], ids=["success", "migration-failure"])
def test_migration_runner_disposes_engine_on_every_exit(tmp_path, fail_migration):
    env_path = Path(__file__).resolve().parents[1] / "alembic" / "env.py"
    tree = ast.parse(env_path.read_bytes(), filename=str(env_path))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_migrations_online"
    )
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "engine.sqlite"))

    def migrate(connection):
        connection.exec_driver_sql("SELECT 1")
        if fail_migration:
            raise RuntimeError("synthetic migration failure")

    namespace = {
        "create_async_engine": lambda _url: engine,
        "_database_url": lambda: "sqlite+aiosqlite://",
        "do_run_migrations": migrate,
    }
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(env_path), "exec"), namespace)
    existing = {thread.ident for thread in threading.enumerate() if thread.is_alive()}
    try:
        if fail_migration:
            with pytest.raises(RuntimeError, match="synthetic migration failure"):
                asyncio.run(namespace["run_migrations_online"]())
        else:
            asyncio.run(namespace["run_migrations_online"]())
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and any(
            thread.is_alive() and thread.ident not in existing for thread in threading.enumerate()
        ):
            time.sleep(0.05)
        remaining = [
            thread.name
            for thread in threading.enumerate()
            if thread.is_alive() and thread.ident not in existing
        ]
        assert remaining == [], f"migration exit retained worker threads: {remaining}"
    finally:
        # Keep the regression itself from leaking the engine when run against old code.
        asyncio.run(engine.dispose())
