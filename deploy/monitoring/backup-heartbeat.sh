#!/bin/sh
# Backup heartbeat for node_exporter's textfile collector (push-style
# freshness: the backup service itself exports no metrics by design).
#
# Writes mindpattern_backup_last_success_timestamp_seconds with the mtime of
# the newest encrypted dump into BACKUP_TEXTFILE_DIR/mindpattern_backup.prom.
# The timestamp is the DUMP's mtime, not "now" — the metric can therefore
# never claim a backup that the filesystem does not actually hold.
#
# Who calls it: the existing compose backup service must not be modified
# (production contract), so the natural caller is the host cron that runs
# check-backup-freshness.sh (which invokes this on every passing check when
# BACKUP_TEXTFILE_DIR is set). A custom backup cron can also call it
# directly right after a successful dump.
#
# Requires node_exporter on the host configured with
#   --collector.textfile.directory=<BACKUP_TEXTFILE_DIR>
# and a scrape job for that node_exporter. The matching (comment-guarded)
# alerts live in alerts.yml, group mindpattern-backup-textfile.
#
# Usage: backup-heartbeat.sh [dump-file | backups-dir]
#   No argument: newest dump in $BACKUP_DIR (same auto-detection rules as
#   check-backup-freshness.sh).
#
# Env:
#   BACKUP_TEXTFILE_DIR  default /var/lib/node_exporter/textfile_collector
#
# Exit codes: 0 written, 1 no dump found / mtime unreadable.
set -eu

textfile_dir=${BACKUP_TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}
target=${1:-}

resolve_dump() {
  if [ -n "$target" ] && [ -f "$target" ]; then
    printf '%s\n' "$target"
    return 0
  fi
  dir=${target:-${BACKUP_DIR:-}}
  if [ -z "$dir" ] && command -v docker >/dev/null 2>&1; then
    project=${MINDPATTERN_COMPOSE_PROJECT:-mindpattern}
    dir=$(docker volume inspect --format '{{.Mountpoint}}' "${project}_pgbackups" 2>/dev/null) || dir=""
  fi
  [ -n "$dir" ] && [ -d "$dir" ] || return 1
  ls -1t "$dir"/mindpattern-*.dump.enc 2>/dev/null | head -n 1 || true
}

# mtime as epoch seconds; GNU (`-c %Y`) and BSD/macOS (`-f %m`) flavors.
dump_epoch() {
  f=$1
  e=$(stat -c %Y "$f" 2>/dev/null) || e=$(stat -f %m "$f" 2>/dev/null) || e=""
  [ -n "$e" ] || return 1
  printf '%s\n' "$e"
}

dump=$(resolve_dump)
if [ -z "${dump:-}" ]; then
  echo "backup-heartbeat: no mindpattern-*.dump.enc found to report" >&2
  exit 1
fi
epoch=$(dump_epoch "$dump") || {
  echo "backup-heartbeat: cannot read mtime of $dump (neither GNU nor BSD stat available)" >&2
  exit 1
}

mkdir -p "$textfile_dir"
# Atomic publish: node_exporter never reads a half-written .prom file.
tmp="$textfile_dir/.mindpattern_backup.prom.$$"
{
  echo '# HELP mindpattern_backup_last_success_timestamp_seconds Epoch mtime of the newest encrypted MindPattern dump observed on this host (deploy/monitoring/backup-heartbeat.sh).'
  echo '# TYPE mindpattern_backup_last_success_timestamp_seconds gauge'
  printf 'mindpattern_backup_last_success_timestamp_seconds %s\n' "$epoch"
} > "$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$textfile_dir/mindpattern_backup.prom"

echo "backup-heartbeat: published $textfile_dir/mindpattern_backup.prom (last success $(date -u -r "$dump" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "epoch $epoch"))"
