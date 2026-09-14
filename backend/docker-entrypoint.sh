#!/bin/sh
# Container entrypoint: migrate, then serve.
#
# The app only runs create_all in development (see app/main.py lifespan), so
# the schema MUST come from migrations here. `alembic upgrade head` is
# idempotent and reads MINDPATTERN_DB_URL directly (alembic/env.py); a
# database created by an old create_all-based deploy must first be adopted
# with `alembic stamp head` (see alembic/README.md). Concurrent replicas are
# serialized by a Postgres advisory lock inside alembic/env.py.
set -eu

# Retry the migration: under compose/k8s a fresh Postgres can accept TCP
# before it accepts the migration's lock, and a crash-looping container is a
# worse failure mode than a few seconds of backoff. Persistent failures
# (bad URL, real lock contention) still abort after 5 attempts — the
# container must not start serving against an unmigrated schema.
attempt=1
max_attempts=5
until alembic upgrade head; do
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "entrypoint: alembic upgrade head failed $max_attempts times; aborting" >&2
    exit 1
  fi
  echo "entrypoint: migration attempt $attempt failed; retrying in 3s" >&2
  sleep 3
  attempt=$((attempt + 1))
done

# Flags documented in the Dockerfile: no access logs (they would record
# usernames and journal-write timestamps) and no --proxy-headers (rate
# limiting keys on the real peer unless a trusted proxy is configured).
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log
