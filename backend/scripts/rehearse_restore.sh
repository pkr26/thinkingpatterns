#!/usr/bin/env bash
# Backup RESTORE rehearsal (2026-09-17).
#
# The compose backup service writes encrypted pg_dump -Fc archives; the
# README says "rehearse pg_restore before you need it" — this script IS
# the rehearsal. It restores the newest dump into a THROWAWAY postgres
# container, asserts the schema and row counts match the live database,
# decrypts nothing to the HOST (it validates the backup KEY works by
# restoring an ENCRYPTED dump), and tears everything down. A row-count
# mismatch FAILS the rehearsal: a restore that does not reproduce the
# live counts is exactly the failure this script exists to catch.
#
# Usage:  bash backend/scripts/rehearse_restore.sh
# Needs:  docker, openssl, the same BACKUP_KEY the backup service uses,
#         and the compose stack running (live counts come from `db`).
set -euo pipefail

cd "$(dirname "$0")/../.."

# NOTE: keep apostrophes OUT of the ${VAR:?...} messages below — the
# macOS system bash (3.2) mis-parses them and refuses to run the script.
: "${BACKUP_KEY:?set BACKUP_KEY to the backup service key (it must be the SAME key)}"
VOLUME="${BACKUP_VOLUME:-pgbackups}"
# Live counts ride `docker compose exec db` (a unix-socket connection
# inside the container — no password) but the ROLE and DATABASE must
# match what docker-compose.yml's db service defines; the defaults are
# its defaults. Export overrides if your .env sets them.
POSTGRES_USER="${POSTGRES_USER:-mindpattern}"
POSTGRES_DB="${POSTGRES_DB:-mindpattern}"

echo "==> locating the newest backup in volume '$VOLUME'"
# The backup service writes /backups/mindpattern-<stamp>.dump.enc ONLY
# (docker-compose.yml); the old *.dump glob matched nothing it produced.
NEWEST=$(docker run --rm -v "$VOLUME:/backups" alpine sh -c \
  'ls -1t /backups/mindpattern-*.dump.enc 2>/dev/null | head -1 || true')
[ -n "$NEWEST" ] || { echo "no mindpattern-*.dump.enc found in volume $VOLUME" >&2; exit 1; }
FILE=$(basename "$NEWEST")
echo "==> newest backup: $FILE"

echo "==> key check: decrypting $FILE (to /dev/null in a throwaway container)"
docker run --rm \
  -v "$VOLUME:/backups" \
  -e BACKUP_KEY -e FILE="$FILE" \
  alpine sh -c '
    openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY \
      < "/backups/$FILE" > /dev/null
  ' || { echo "DECRYPTION FAILED — is BACKUP_KEY the backup service key?" >&2; exit 1; }

# Throwaway restore target: same major version as the live server, no
# published port, removed by the EXIT trap below.
SUFFIX="rehearse-$(date +%s)"
docker run --rm -d --name "db-$SUFFIX" \
  -e POSTGRES_PASSWORD=rehearse \
  postgres:16-alpine >/dev/null
trap 'docker rm -f "db-$SUFFIX" >/dev/null 2>&1 || true' EXIT
until docker exec "db-$SUFFIX" pg_isready -U postgres >/dev/null 2>&1; do sleep 0.5; done

# Decrypt inside a throwaway alpine and pipe straight into pg_restore in
# the throwaway database (the decrypted bytes never touch the host disk).
docker run --rm -i \
  -v "$VOLUME:/backups" -e BACKUP_KEY -e FILE="$FILE" \
  --link "db-$SUFFIX":db alpine sh -c '
    apk add --no-cache openssl >/dev/null
    openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY \
      < "/backups/$FILE"
  ' | docker exec -i "db-$SUFFIX" pg_restore -U postgres -d postgres --no-owner >/dev/null

echo "==> asserting the restored schema and row counts"
TABLES=$(docker exec "db-$SUFFIX" psql -U postgres -tAc \
  "select count(*) from information_schema.tables where table_schema='public'")
[ "$TABLES" -ge 5 ] || { echo "restored DB has only $TABLES public tables — restore incomplete" >&2; exit 1; }

# Live counts come from the compose `db` service with the role the
# compose file defines (POSTGRES_USER=mindpattern; there is no
# `postgres` role and no mindpattern-db-1 container name to fall back
# on). Unreadable live counts are a script failure, not a SKIP.
FAILED=0
for t in users entries insights access_log; do
  LIVE=$(docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select count(*) from $t") || {
    echo "cannot read live count for $t — is the compose stack (service db) running?" >&2
    exit 1
  }
  RESTORED=$(docker exec "db-$SUFFIX" psql -U postgres -tAc "select count(*) from $t")
  echo "    $t: live=$LIVE restored=$RESTORED"
  if [ "$LIVE" != "$RESTORED" ]; then
    echo "    FAIL: $t live=$LIVE restored=$RESTORED — the restore does not reproduce the live database (check the dump's timestamp)" >&2
    FAILED=1
  fi
done
if [ "$FAILED" -ne 0 ]; then
  echo "RESTORE REHEARSAL FAILED: row counts differ" >&2
  exit 1
fi
echo "==> RESTORE REHEARSAL PASSED (throwaway DB torn down)"
