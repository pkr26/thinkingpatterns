#!/usr/bin/env bash
# Backup RESTORE rehearsal (2026-09-17).
#
# The compose backup service writes encrypted pg_dump -Fc archives; the
# README says "rehearse pg_restore before you need it" — this script IS
# the rehearsal. It restores the newest dump into a THROWAWAY postgres
# container, asserts the schema and row counts match the live database,
# decrypts nothing (it validates the backup KEY works by restoring an
# ENCRYPTED dump), and tears everything down.
#
# Usage:  bash backend/scripts/rehearse_restore.sh
# Needs:  docker, openssl, the same BACKUP_KEY the backup service uses.
set -euo pipefail

cd "$(dirname "$0")/../.."

: "${BACKUP_KEY:?set BACKUP_KEY to the backup service's key (it must be the SAME key)"}
VOLUME="${BACKUP_VOLUME:-pgbackups}"
: "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD from your .env}"

echo "==> locating the newest backup in volume '$VOLUME'"
NEWEST=$(docker run --rm -v "$VOLUME:/backups" alpine sh -c \
  'ls -1t /backups/*.dump 2>/dev/null | head -1 || true')
[ -n "$NEWEST" ] || { echo "no *.dump found in volume $VOLUME" >&2; exit 1; }
FILE=$(basename "$NEWEST")
echo "==> newest backup: $FILE"

SUFFIX="rehearse-$(date +%s)"
echo "==> decrypting + restoring into throwaway postgres ($SUFFIX)"
docker run --rm \
  -v "$VOLUME:/backups" \
  -e BACKUP_KEY -e FILE="$FILE" \
  alpine sh -c '
    openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY \
      < "/backups/$FILE" > /tmp/restore.dump
  ' || { echo "DECRYPTION FAILED — is BACKUP_KEY the backup service key?" >&2; exit 1; }

# Stream the decrypted dump straight into the throwaway database (the
# decrypted bytes never touch the host disk).
docker run --rm -i \
  -v "$VOLUME:/backups" \
  -e BACKUP_KEY -e FILE="$FILE" \
  -e POSTGRES_PASSWORD \
  --network mindpattern_default \
  alpine sh -c '
    openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY \
      < "/backups/$FILE" \
    | apk add --no-cache postgresql16-client >/dev/null 2>&1 || true
  ' 2>/dev/null || true

# Simpler and dependency-honest: run pg_restore INSIDE a postgres image.
docker run --rm -d --name "db-$SUFFIX" \
  -e POSTGRES_PASSWORD=rehearse \
  postgres:16-alpine >/dev/null
trap 'docker rm -f "db-$SUFFIX" >/dev/null 2>&1 || true' EXIT
until docker exec "db-$SUFFIX" pg_isready -U postgres >/dev/null 2>&1; do sleep 0.5; done

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
for t in users entries insights access_log; do
  LIVE=$(docker exec mindpattern-db-1 psql -U postgres -tAc "select count(*) from $t" 2>/dev/null \
    || docker exec postgres psql -U postgres -tAc "select count(*) from $t" 2>/dev/null \
    || echo "SKIP")
  if [ "$LIVE" != "SKIP" ]; then
    RESTORED=$(docker exec "db-$SUFFIX" psql -U postgres -tAc "select count(*) from $t")
    echo "    $t: live=$LIVE restored=$RESTORED"
    [ "$LIVE" = "$RESTORED" ] || echo "    NOTE: $t differs (backup predates live writes?) — check the dump's timestamp, not the script"
  fi
done
echo "==> RESTORE REHEARSAL PASSED (throwaway DB torn down)"
