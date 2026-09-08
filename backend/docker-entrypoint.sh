#!/bin/sh
# Container entrypoint: migrate, then serve.
#
# The app only runs create_all in development (see app/main.py lifespan), so
# the schema MUST come from migrations here. `alembic upgrade head` is
# idempotent and reads MINDPATTERN_DB_URL directly (alembic/env.py); a
# database created by an old create_all-based deploy must first be adopted
# with `alembic stamp head` (see alembic/README.md).
set -eu

alembic upgrade head

# Flags documented in the Dockerfile: no access logs (they would record
# usernames and journal-write timestamps) and no --proxy-headers (rate
# limiting keys on the real peer unless a trusted proxy is configured).
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log
