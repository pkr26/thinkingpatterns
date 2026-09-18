# Authenticated database backups

The optional `backup` Compose profile writes one `pg_dump -Fc` file per day.
Each `*.dump.enc` is encrypted with AES-256-CBC/PBKDF2 and has a sibling
`*.dump.enc.hmac`. The HMAC uses a domain-separated key derived from
`BACKUP_KEY`; do not decrypt or restore a dump until the tag verifies.

With the backup profile running, verify and inspect a dump in the worker:

```bash
docker compose --profile backups exec backup sh -ceu '
  set -- /backups/mindpattern-*.dump.enc
  mindpattern-backup-mac verify "$1"
  openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY -in "$1" | pg_restore --list
'
```

Use the same pipeline to restore only after verification. A missing or
mismatched `.hmac` is a hard stop. To exercise a full restore into a
throwaway same-major Postgres container and compare live row counts, run:

```bash
BACKUP_KEY='the same secret used by the backup service' \
  bash backend/scripts/rehearse_restore.sh
```

Older pre-authentication dumps have no sidecar and must be treated as legacy
material: keep them isolated, validate their provenance separately, and
expire them on the existing retention schedule rather than silently accepting
them as equivalent to new backups.
