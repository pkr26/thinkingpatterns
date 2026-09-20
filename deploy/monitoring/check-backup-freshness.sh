#!/bin/sh
# Backup freshness check — cron-friendly, no Prometheus required.
#
# The compose backup service exports NO metrics and deliberately so (the
# production contract is untouched); the honest staleness mechanism is the
# filesystem itself: this script checks the mtime of the newest encrypted
# dump in the pgbackups volume and exits nonzero once it is older than
# BACKUP_MAX_AGE_HOURS. Wire it into any cron-alerting wrapper:
#
#   17 * * * * root BACKUP_MAX_AGE_HOURS=26 \
#     /srv/mindpattern/deploy/monitoring/check-backup-freshness.sh \
#     || /usr/local/bin/alert-operator "mindpattern backups stale"
#
# Usage: check-backup-freshness.sh [backups-dir]
#   backups-dir  defaults to $BACKUP_DIR, else auto-detected from the
#                compose volume `${MINDPATTERN_COMPOSE_PROJECT:-mindpattern}_pgbackups`
#                via `docker volume inspect` (needs a readable docker socket;
#                on Linux the volume directory is root-only, so run as root).
#
# Env:
#   BACKUP_MAX_AGE_HOURS   freshness window, default 26 (one daily dump plus
#                          2h slack; keep equal to the heartbeat alert's 26h
#                          in alerts.yml if you use that variant)
#   BACKUP_TEXTFILE_DIR    if set (and the check passes), the newest dump's
#                          mtime is also written as the node_exporter
#                          textfile heartbeat via backup-heartbeat.sh
#
# Exit codes: 0 fresh, 1 stale/missing/unauthenticated, 2 misconfiguration.
# Full HMAC verification (not just sidecar presence) happens in the restore
# rehearsal: bash backend/scripts/rehearse_restore.sh.
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)

max_age_h=${BACKUP_MAX_AGE_HOURS:-26}
case "$max_age_h" in
  ''|*[!0-9]*)
    echo "check-backup-freshness: BACKUP_MAX_AGE_HOURS must be a positive whole number (got '$max_age_h')" >&2
    exit 2
    ;;
esac
[ "$max_age_h" -ge 1 ] || {
  echo "check-backup-freshness: BACKUP_MAX_AGE_HOURS must be at least 1" >&2
  exit 2
}
max_age_min=$((max_age_h * 60))

dir=${1:-${BACKUP_DIR:-}}
if [ -z "$dir" ]; then
  if command -v docker >/dev/null 2>&1; then
    project=${MINDPATTERN_COMPOSE_PROJECT:-mindpattern}
    dir=$(docker volume inspect --format '{{.Mountpoint}}' "${project}_pgbackups" 2>/dev/null) || dir=""
  fi
fi
if [ -z "$dir" ] || [ ! -d "$dir" ]; then
  echo "check-backup-freshness: backups directory not found (pass it as \$1, set BACKUP_DIR, or run where 'docker volume inspect ${MINDPATTERN_COMPOSE_PROJECT:-mindpattern}_pgbackups' works)" >&2
  exit 2
fi

# Newest encrypted dump by mtime (names are service-controlled, no spaces).
newest=$(ls -1t "$dir"/mindpattern-*.dump.enc 2>/dev/null | head -n 1 || true)
if [ -z "$newest" ]; then
  echo "check-backup-freshness: STALE — no mindpattern-*.dump.enc in $dir (has the backups profile ever run?)" >&2
  exit 1
fi

# A newest dump without its HMAC sidecar is not a restorable backup
# (backup/README.md: a missing or mismatched .hmac is a hard stop).
if [ ! -f "$newest.hmac" ]; then
  echo "check-backup-freshness: STALE — newest dump $(basename "$newest") has no .hmac integrity sidecar" >&2
  exit 1
fi

# -mmin -N = modified less than N minutes ago. Supported by GNU, BusyBox and
# BSD find; avoids the GNU/BSD `stat` format split for the decision itself.
if find "$newest" -mmin "-$max_age_min" 2>/dev/null | grep -q .; then
  echo "check-backup-freshness: OK — newest authenticated dump $(basename "$newest") is younger than ${max_age_h}h ($dir)"
  if [ -n "${BACKUP_TEXTFILE_DIR:-}" ]; then
    if ! "$SCRIPT_DIR/backup-heartbeat.sh" "$newest"; then
      # The freshness verdict stands; a failed textfile write must be loud
      # but not reported as data staleness (the absent-metric alert in
      # alerts.yml catches a persistently broken heartbeat instead).
      echo "check-backup-freshness: warning — backup-heartbeat.sh failed for BACKUP_TEXTFILE_DIR=$BACKUP_TEXTFILE_DIR" >&2
    fi
  fi
  exit 0
fi

echo "check-backup-freshness: STALE — newest authenticated dump $(basename "$newest") is older than ${max_age_h}h ($dir)" >&2
exit 1
