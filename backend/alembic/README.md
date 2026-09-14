# Database migrations (Alembic)

Alembic is the schema-change path for real databases. `app.db.init_models`
still does `create_all`, but only with `MINDPATTERN_ENV=development` (dev/test
convenience; the deployed container migrates via its entrypoint instead), and
even then it only ever helps a *fresh* database — it silently ignores every
later change to `app/models.py`. Any column/table change MUST ship as a
revision here.

All commands run from `backend/`. The database URL is read from
`MINDPATTERN_DB_URL` (default: local SQLite `sqlite+aiosqlite:///./mindpattern.db`)
— no `sqlalchemy.url` in `alembic.ini` to drift. Migration tooling deliberately
does NOT import `app.config`: its import-time fail-closed gate (token secret,
non-SQLite URL outside development) would otherwise crash every alembic
command on an operator machine, and migrations do not need a token secret.

## Apply migrations (production upgrade path)

```sh
MINDPATTERN_DB_URL=postgresql+asyncpg://user:pass@host/db ../.venv/bin/alembic upgrade head
```

Run this at deploy time, before starting the new app version (the Docker
image's entrypoint does it automatically before uvicorn starts). SQLite dev
databases work the same way with `sqlite+aiosqlite:///./mindpattern.db`.

## Adopt a database created before migrations existed

Its schema already matches the initial revision (create_all built it), so
record that without re-running DDL:

```sh
MINDPATTERN_DB_URL=... ../.venv/bin/alembic stamp head
```

Then future `alembic upgrade head` runs apply only real changes.

## Add a new migration after changing app/models.py

```sh
MINDPATTERN_DB_URL=sqlite+aiosqlite:///./scratch.db ../.venv/bin/alembic revision --autogenerate -m "add foo column"
```

Autogenerate detects additions/removals/type changes but misses renames and
some constraint changes — always review the generated file, then delete
`scratch.db`. A parity check that the schema matches the models exactly:
autogenerate against a fully-migrated database must produce an empty diff.

## Notes

- env.py builds an **async** engine (`create_async_engine`) and runs
  migrations through `connection.run_sync`, matching the app's async stack.
- SQLite runs with `render_as_batch=True` (SQLite cannot ALTER most things;
  batch mode rebuilds tables when needed). PostgreSQL runs plain DDL. The
  initial revision is create-only and dialect-neutral.
- On PostgreSQL, migrations run under a session-level advisory lock
  (`pg_advisory_lock(727272)`) so concurrent first-boots of several replicas
  serialize instead of racing the same DDL; `lock_timeout=15s` /
  `statement_timeout=300s` make a blocked migration fail (the orchestrator
  retries the boot) instead of hanging forever. SQLite takes neither —
  single-writer file databases don't need it.
- A database adopted via `alembic stamp head` while head was the initial
  revision must be re-stamped: `stamp` only records "current", it does not
  apply later revisions — run `alembic upgrade head` to pick up
  `e930dbc4f001` (insights unique constraint) and beyond.
