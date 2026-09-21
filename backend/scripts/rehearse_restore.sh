#!/usr/bin/env bash
# Backup RESTORE rehearsal (2026-09-17).
#
# The compose backup service writes encrypted pg_dump -Fc archives; the
# README says "rehearse pg_restore before you need it" — this script IS
# the rehearsal. It restores the newest dump into a THROWAWAY postgres
# container, asserts the expected schema is usable, reports the restored
# snapshot's row counts beside the live database, decrypts nothing to the
# HOST (it validates the backup KEY works by restoring an ENCRYPTED dump),
# and tears everything down. A backup is necessarily older than the live
# database after ordinary writes, so count differences are evidence of its
# recovery point — not a false "restore failed" verdict.
#
# Usage:
#   bash backend/scripts/rehearse_restore.sh [--env-file FILE]... [--dev] [--remote]
#
# `--env-file` is repeatable and is passed directly to `docker compose` — the
# script never sources an env artifact.  A production rehearsal can therefore
# safely combine an owner-only secrets file and the public release image-ref
# fragment.  `--dev` explicitly adds docker-compose.dev.yml for a local
# source-built stack.  Without it, the production compose contract is used.
#
# `--remote` rehearses the runbook's "Recovery when the HOST is gone" steps
# instead of the local volume: the off-site ciphertext is FETCHED through the
# backup-offsite overlay's one-shot mode into a throwaway host scratch dir
# (mounted at /restore, the container-side path of the documented commands),
# then authenticated, decrypted, and restored from there.  The
# BACKUP_OFFSITE_REMOTE / BACKUP_OFFSITE_RCLONE_CONFIG values must reach
# compose via one of the passed --env-file arguments (they are never read by
# this script itself).
#
# Needs: docker and the compose stack running (live counts come from `db`).
# Crypto tooling comes from the checked-in backup image; this rehearsal never
# installs packages at runtime.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
CALLER_DIR=$(pwd -P)
COMPOSE=(docker compose -f "$REPO_ROOT/docker-compose.yml")
REMOTE_MODE=0
FETCH_DIR=""

usage() {
  cat >&2 <<'EOF'
usage: bash backend/scripts/rehearse_restore.sh [--env-file FILE]... [--dev] [--remote]

Pass each Compose env file explicitly; files are forwarded as arguments and
are never sourced by this script. For production, pass the owner-only secrets
file first and the validated release image-ref asset second. Use --dev only
for a stack started with docker-compose.dev.yml. Use --remote to rehearse the
off-site (host-gone) recovery: fetch from the BACKUP_OFFSITE remote via the
overlay's one-shot mode, then verify/decrypt/restore through the /restore
container path, exactly as docs/INCIDENT_RUNBOOK.md documents it.
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file)
      [ "$#" -ge 2 ] || usage
      env_file=$2
      case "$env_file" in
        /*) ;;
        *) env_file="$CALLER_DIR/$env_file" ;;
      esac
      [ -f "$env_file" ] || {
        echo "compose env file does not exist: $env_file" >&2
        exit 66
      }
      COMPOSE+=(--env-file "$env_file")
      shift 2
      ;;
    --dev)
      COMPOSE+=(-f "$REPO_ROOT/docker-compose.dev.yml")
      shift
      ;;
    --remote)
      REMOTE_MODE=1
      shift
      ;;
    --help|-h)
      usage
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      ;;
  esac
done

# One trap for everything throwaway this script creates: the scratch Postgres
# container (SUFFIX, created below) and, in --remote mode, the host scratch
# dir holding the fetched ciphertext (FETCH_DIR, created below). The guards
# keep each half a no-op before its variable exists.
cleanup() {
  if [ -n "${SUFFIX:-}" ]; then
    docker rm -f "db-$SUFFIX" >/dev/null 2>&1 || true
  fi
  if [ -n "${FETCH_DIR:-}" ]; then
    rm -rf "$FETCH_DIR"
  fi
}
trap cleanup EXIT

cd "$REPO_ROOT"

# Read the live service's role/database rather than sourcing the env files or
# assuming their defaults. The script already requires this service to be up.
POSTGRES_USER=$("${COMPOSE[@]}" exec -T db sh -ceu 'printf "%s" "$POSTGRES_USER"')
POSTGRES_DB=$("${COMPOSE[@]}" exec -T db sh -ceu 'printf "%s" "$POSTGRES_DB"')
[ -n "$POSTGRES_USER" ] && [ -n "$POSTGRES_DB" ] || {
  echo "live compose database did not expose POSTGRES_USER/POSTGRES_DB" >&2
  exit 1
}
# Keep the restore target on the exact immutable Postgres image used by the
# compose service and CI.  A mutable `postgres:16-alpine` tag could otherwise
# make a rehearsal pass or fail for reasons unrelated to the stored archive.
POSTGRES_IMAGE="postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"

# Where the newest backup lives INSIDE the backup-service container, plus the
# extra `compose run` flags that make that true. Local mode: the compose
# pgbackups volume, already mounted at /backups (no extra flags). Remote
# mode: the fetched scratch dir mounted at /restore — the runbook's
# container-side path, deliberately not the host path (that confusion is the
# exact class of bug the remote rehearsal exists to catch).
SRC_DIR=/backups
BACKUP_RUN_ARGS=(--no-deps)

if [ "$REMOTE_MODE" = 1 ]; then
  echo "==> REMOTE rehearsal: fetching the newest ciphertext from the off-site store"
  FETCH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mindpattern-rehearse-remote.XXXXXX")
  echo "    fetched ciphertext scratch dir (host): $FETCH_DIR"
  # The runbook's host-gone step 3, verbatim in shape: the backup-offsite
  # overlay's one-shot fetch mode pulling the remote into a directory
  # mounted at /restore. BACKUP_OFFSITE_* interpolation comes from the
  # passed --env-file files, never from this script.
  "${COMPOSE[@]}" -f "$REPO_ROOT/deploy/backup-offsite/docker-compose.yml" \
    --profile backups-offsite run --rm -T \
    -v "$FETCH_DIR":/restore \
    -e BACKUP_OFFSITE_MODE=fetch -e BACKUP_FETCH_DIR=/restore backup-offsite \
    || {
      echo "off-site fetch failed — are BACKUP_OFFSITE_REMOTE / BACKUP_OFFSITE_RCLONE_CONFIG present in a passed --env-file?" >&2
      exit 1
    }
  # The runbook's step 4, host side: keep the FILE NAME and rebuild the
  # container-side path from it. A candidate without its sidecar is never a
  # restorable backup.
  NEWEST=""
  for f in $(ls -1t "$FETCH_DIR"/mindpattern-*.dump.enc 2>/dev/null || true); do
    [ -f "$f.hmac" ] && { NEWEST=$f; break; }
  done
  [ -n "$NEWEST" ] || {
    echo "no authenticated mindpattern-*.dump.enc + .hmac fetched from the off-site remote" >&2
    exit 1
  }
  SRC_DIR=/restore
  BACKUP_RUN_ARGS=(--no-deps -v "$FETCH_DIR":/restore)
else
  echo "==> locating the newest authenticated backup in the compose volume"
  # Run through the checked-in backup image/service rather than guessing the
  # Compose-generated volume name or pulling a mutable Alpine utility image.
  # A candidate without its sidecar is never a restorable backup.
  NEWEST=$("${COMPOSE[@]}" --profile backups run --rm --no-deps -T \
    --entrypoint sh backup -ceu '
    for f in $(ls -1t /backups/mindpattern-*.dump.enc 2>/dev/null || true); do
      test -f "$f.hmac" && { printf "%s" "$f"; exit 0; }
    done
    exit 0
  ')
  [ -n "$NEWEST" ] || { echo "no authenticated mindpattern-*.dump.enc + .hmac found in compose backup volume" >&2; exit 1; }
fi
FILE=$(basename "$NEWEST")
echo "==> newest backup: $FILE"

echo "==> authenticating then decrypting $FILE (to /dev/null in backup image)"
"${COMPOSE[@]}" --profile backups run --rm -T "${BACKUP_RUN_ARGS[@]}" \
  -e FILE="$FILE" -e SRC_DIR="$SRC_DIR" --entrypoint sh backup -ceu '
    mindpattern-backup-mac verify "$SRC_DIR/$FILE"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_KEY \
      < "$SRC_DIR/$FILE" > /dev/null
  ' || { echo "DECRYPTION FAILED — is BACKUP_KEY the backup service key?" >&2; exit 1; }

echo "==> proving the authentication tag rejects ciphertext tampering"
"${COMPOSE[@]}" --profile backups run --rm -T "${BACKUP_RUN_ARGS[@]}" \
  -e FILE="$FILE" -e SRC_DIR="$SRC_DIR" --entrypoint sh backup -ceu '
    cp "$SRC_DIR/$FILE" /tmp/tampered.dump.enc
    cp "$SRC_DIR/$FILE.hmac" /tmp/tampered.dump.enc.hmac
    printf x >> /tmp/tampered.dump.enc
    if mindpattern-backup-mac verify /tmp/tampered.dump.enc; then
      echo "tampered backup unexpectedly verified" >&2
      exit 1
    fi
  '

# Throwaway restore target: same major version as the live server, no
# published port, removed by the EXIT trap above.
SUFFIX="rehearse-$(date +%s)"
docker run --rm -d --name "db-$SUFFIX" \
  -e POSTGRES_PASSWORD=rehearse \
  "$POSTGRES_IMAGE" >/dev/null
ready=0
attempt=1
while [ "$attempt" -le 60 ]; do
  if docker exec "db-$SUFFIX" pg_isready -U postgres >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
  attempt=$((attempt + 1))
done
if [ "$ready" -ne 1 ]; then
  echo "throwaway Postgres did not become ready within 30 seconds; recent logs follow" >&2
  docker logs "db-$SUFFIX" >&2 || true
  exit 1
fi

# Verify and decrypt inside the checked-in backup image, then pipe straight
# into pg_restore in the throwaway database (decrypted bytes never touch the
# host disk). Verify MUST precede EVERY decrypt operation. -iter is pinned to
# the compose backup service's encryptor — the counts must match exactly or
# decryption fails closed.
"${COMPOSE[@]}" --profile backups run --rm -T "${BACKUP_RUN_ARGS[@]}" \
  -e FILE="$FILE" -e SRC_DIR="$SRC_DIR" --entrypoint sh backup -ceu '
    mindpattern-backup-mac verify "$SRC_DIR/$FILE"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_KEY \
      < "$SRC_DIR/$FILE"
  ' | docker exec -i "db-$SUFFIX" pg_restore -U postgres -d postgres --no-owner >/dev/null

echo "==> asserting the restored schema and reporting snapshot row counts"
# A count of arbitrary public tables is not a useful schema proof: extensions
# or unrelated application tables could satisfy it while an essential data
# table is absent. Check the actual application contract and require a
# stamped migration version before treating pg_restore as successful.
for t in users entries insights access_log alembic_version; do
  PRESENT=$(docker exec "db-$SUFFIX" psql -U postgres -tAc \
    "select to_regclass('public.$t')")
  [ "$PRESENT" = "$t" ] || {
    echo "restored DB is missing required table $t — restore incomplete" >&2
    exit 1
  }
done
RESTORED_VERSION=$(docker exec "db-$SUFFIX" psql -U postgres -tAc \
  "select version_num from alembic_version limit 1")
[ -n "$RESTORED_VERSION" ] || {
  echo "restored DB has no Alembic version — restore incomplete" >&2
  exit 1
}
echo "    alembic_version: $RESTORED_VERSION"

# Live counts come from the compose `db` service with the role the
# compose file defines (POSTGRES_USER=mindpattern; there is no `postgres`
# role and no mindpattern-db-1 container name to fall back on). Unreadable
# live counts are a script failure, not a SKIP.  The values are deliberately
# informational: a daily dump can be perfectly restorable while current
# production already contains later writes.
for t in users entries insights access_log; do
  LIVE=$("${COMPOSE[@]}" exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select count(*) from $t") || {
    echo "cannot read live count for $t — is the compose stack (service db) running?" >&2
    exit 1
  }
  RESTORED=$(docker exec "db-$SUFFIX" psql -U postgres -tAc "select count(*) from $t")
  echo "    $t: live=$LIVE restored=$RESTORED"
  if [ "$LIVE" != "$RESTORED" ]; then
    echo "    note: snapshot differs from current live data (expected when writes followed the dump)" >&2
  fi
done
if [ "$REMOTE_MODE" = 1 ]; then
  echo "==> REMOTE RESTORE REHEARSAL PASSED (off-site ciphertext fetched, authenticated, and restored into a stamped, usable schema; fetch scratch dir and throwaway DB torn down)"
else
  echo "==> RESTORE REHEARSAL PASSED (authenticated archive restored into a stamped, usable schema; throwaway DB torn down)"
fi
