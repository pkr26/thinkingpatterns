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

# Do not rely on Uvicorn's default proxy-header behavior: it can rewrite
# scope.client before HardeningMiddleware gets to verify the raw socket peer.
# The app implements its own explicit MINDPATTERN_TRUSTED_PROXY_IPS boundary,
# so proxy handling here must stay disabled even when Uvicorn changes its
# defaults. Access logs are also off because they can record identifiers and
# journal-write timing metadata. The hardening middleware limits a complete
# request-body read to 30 seconds, and this cap prevents a slow-body flood
# from consuming an unbounded number of ASGI tasks while those timers run.
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log --no-proxy-headers --limit-concurrency 100 --timeout-keep-alive 5
