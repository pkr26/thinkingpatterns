# Development guide

Commands below start at the repository root unless a block changes directory.
Use Python 3.12 or newer and Node.js 22 (see [.nvmrc](../.nvmrc)).

## Backend

```sh
cd backend
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.dev.lock.txt
MINDPATTERN_ENV=development uvicorn app.main:app --reload
```

Development mode permits SQLite and exposes the interactive API at
`http://localhost:8000/docs`. All other environments apply the production
startup checks. See the [configuration reference](configuration.md).

For an existing local database, apply migrations before starting the API:

```sh
cd backend
MINDPATTERN_DB_URL=sqlite+aiosqlite:///./mindpattern.db .venv/bin/alembic upgrade head
```

Development startup can create missing tables for a fresh database; it does
not upgrade an existing schema. Every schema change needs an Alembic revision.
For a database created before migrations existed, compare its schema to the
historical revisions and stamp only the verified matching revision. Follow the
[migration guide](../backend/alembic/README.md), including backup and upgrade
rehearsal, before changing an existing database.

## Browser clients

Run each client in its own terminal:

```sh
cd web
npm ci
npm run dev
```

```sh
cd portal
npm ci
npm run dev
```

Both Vite development servers proxy `/api` to the backend on port 8000.
Client configuration, deployment, and security details live in the
[patient client guide](../web/README.md) and
[therapist portal guide](../portal/README.md).

## Mobile

```sh
cd mobile
npm ci
npm run typecheck
npm run verify:native-release
```

Follow [mobile/README.md](../mobile/README.md) for Android/iOS prerequisites,
platform builds, Metro, and device verification. Native projects are committed;
dependency patches are applied and verified during installation.

## Docker and operations

The root `docker-compose.yml` is the production contract and requires immutable
API and backup images. For source builds, use the explicit development overlay:

```sh
docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.dev.yml up --build
```

First prepare the local image variables and file-mounted secrets described in
[deployment setup](../deploy/README.md). The development overlay supplies
local build definitions and a development audio store. Backups are opt-in via
`--profile backups`; retention and restore procedures are in the
[backup guide](../backup/README.md).

`/healthz` reports liveness. `/readyz` checks database availability and runtime
ownership/audit health. `/metrics` serves aggregate counters behind the
configured metrics bearer token; production disables it when no token is set.

## Synthetic demo data

The analysis threshold requires 30 distinct active days. The demo seeder creates
84 days of synthetic journal history using the real client key schedule and API.
Use a disposable database. Run these in separate terminals:

```sh
cd backend
MINDPATTERN_ENV=development MINDPATTERN_DB_URL=sqlite+aiosqlite:///./demo.db \
  .venv/bin/uvicorn app.main:app --port 8000
```

```sh
cd backend
.venv/bin/python scripts/seed_demo.py \
  --db-url sqlite+aiosqlite:///./demo.db \
  --username demo --password 'demo-patterns-2026'
```

Sign in with the synthetic account to inspect the resulting patterns. Additional
manual browser fixtures are documented in [e2e_gui/](../e2e_gui/README.md).

## Validation

Run backend checks with its virtual environment active:

```sh
cd backend
. .venv/bin/activate
ruff check .
ruff format --check .
python -m mypy
python -m pytest
python probe_brain.py
```

The full suite includes the cross-platform cryptographic vectors. The
`-m 'not slow'` selection is intended for mutation runs; it excludes the
expensive vector tests and is not a replacement for the full suite.

The same tests can use a disposable PostgreSQL database:

```sh
cd backend
MINDPATTERN_TEST_DB_URL=postgresql+asyncpg://user:password@localhost/mindpattern_test \
  .venv/bin/python -m pytest
```

The database name must include `test`. See [backend test documentation](../backend/tests/README.md)
for isolation and mutation-testing details.

For each of `web/`, `portal/`, and `mobile/`, run `npm run typecheck` and
`npm test`. Run `npm run build` for both browser clients. Mobile also provides
`npm run verify:vectors`, `npm run verify:native-release`, and
`npm run verify:dependency-patches`.

Run the repository tooling with the locked backend dependencies. Keep the
automatic mutation runner tests in a separate interpreter so their fork parent
does not inherit application modules imported by other tooling tests:

```sh
cd backend
.venv/bin/python -m pytest ../tools/tests/test_automatic_backend_mutation.py \
  ../tools/tests/test_automatic_http_contracts.py -q
.venv/bin/python -m pytest ../tools/tests \
  --ignore=../tools/tests/test_automatic_backend_mutation.py \
  --ignore=../tools/tests/test_automatic_http_contracts.py -q
MINDPATTERN_ENV=development .venv/bin/python -m pytest \
  ../redteam/automatic_backend_script_oracles.py -q
```

From the repository root, check documentation and API-reference links:

```sh
python3 tools/check-docs.py
```

Live browser-client drills require a running disposable development API. From
`web/`, set `LIVE_DRILL=1` and `LIVE_DRILL_ORIGIN` before running the tests
under `tests/live/`. Do not point synthetic drills at a real deployment.

[CI](../.github/workflows/ci.yml) owns the authoritative coverage floors and
runs the suite on Python 3.12/3.14 and PostgreSQL, browser builds, native builds,
shared vectors, authenticated backup restore, monitoring contracts, dependency
audits, and secret scanning. Scheduled workflows run the deeper red-team and
mutation campaigns; pull requests also have a scoped mutation gate.
