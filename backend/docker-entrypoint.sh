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

# Database URL assembly (pentest 2026-09-29, MED-1): the db password is the
# one secret that cannot ride the app's `<VAR>_FILE` chain — alembic below
# and the app both want a complete MINDPATTERN_DB_URL, and compose cannot
# interpolate a secret FILE into an environment value, so it used to be
# interpolated raw from .env into the api's env where `docker inspect` (or
# /proc/<pid>/environ) could read it back. The api container now mounts the
# same postgres_password secret the db service reads, and the URL is built
# here, in-process: the password enters only this process's runtime
# environment, never the container's static configuration. An operator-set
# MINDPATTERN_DB_URL (dev overlay, custom deployments) always wins — this
# block never rewrites a value it was given.
if [ -z "${MINDPATTERN_DB_URL:-}" ] && [ -s /run/secrets/postgres_password ]; then
  db_password=$(cat /run/secrets/postgres_password)
  # Command substitution already strips trailing newlines; trim any other
  # trailing whitespace (a space, tab, or CR an editor or CRLF conversion
  # left behind) the same way — anything else would silently corrupt the
  # URL's password component. The value itself must stay hex-only
  # (openssl rand -hex 16); the entrypoint interpolates it verbatim, so
  # URL-reserved characters would break the connection string (2026-09-19
  # audit, L-86 — see the compose header).
  while :; do
    case "$db_password" in
      *[[:space:]]) db_password=${db_password%?} ;;
      *) break ;;
    esac
  done
  # 2026-10-01 audit LOW: hex-only is a hard contract here (the value is
  # interpolated verbatim into the URL); a non-hex password used to
  # produce a corrupt URL that crash-looped the API with an opaque error.
  case "$db_password" in
    ''|*[!0-9a-fA-F]*)
      echo "ERROR: postgres_password must be hex only (openssl rand -hex 16) — URL-reserved characters would corrupt MINDPATTERN_DB_URL" >&2
      exit 78 ;;
  esac
  export MINDPATTERN_DB_URL="postgresql+asyncpg://${POSTGRES_USER:-mindpattern}:${db_password}@db:5432/${POSTGRES_DB:-mindpattern}"
fi

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

# Explicit offline upgrade command only. This reuses the normal secret-file
# URL assembly and migration path, then exits without serving requests.
# Never automatically adopt missing entry guards during an ordinary boot.
if [ "${1:-}" = "--trusted-entry-bootstrap" ]; then
  exec python bootstrap_entry_guards.py --trusted-bootstrap
fi

# Do not rely on Uvicorn's default proxy-header behavior: it can rewrite
# scope.client before HardeningMiddleware gets to verify the raw socket peer.
# The app implements its own explicit MINDPATTERN_TRUSTED_PROXY_IPS boundary,
# so proxy handling here must stay disabled even when Uvicorn changes its
# defaults. Access logs are also off because they can record identifiers and
# journal-write timing metadata. The hardening middleware limits a complete
# request-body read to 30 seconds, and this cap prevents a slow-body flood
# from consuming an unbounded number of ASGI tasks while those timers run.
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log --no-proxy-headers --limit-concurrency 100 --timeout-keep-alive 5
