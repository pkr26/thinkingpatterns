# Off-site backup replication (opt-in overlay)

The production `backup` service writes daily encrypted dumps into the
`pgbackups` named volume — **on the same host as the database**. A host
loss takes the database and its backups together. This overlay replicates
that volume to an S3-compatible remote (AWS S3, MinIO, Backblaze B2,
Cloudflare R2, …) hourly with `rclone`, so a host fire no longer ends the
recovery story.

It is a **separate overlay file, deliberately outside the digest-pinned
production contract**: the main `docker-compose.yml` must keep rendering
only `@sha256` release images, and a mutable `rclone` tag (or a digest
TODO placeholder) would weaken that. Layer this file onto the main one
explicitly.

## What ships, and what does not

- **Ciphertext only.** Every `mindpattern-*.dump.enc` is client-side
  encrypted by the backup service (AES-256-CBC/PBKDF2 under `BACKUP_KEY`)
  and travels with its `.dump.enc.hmac` sidecar, so a restore can verify
  integrity before decrypting. This service never sees `BACKUP_KEY`.
  Therefore: **the off-site copy makes `BACKUP_KEY` custody matter more** —
  losing the host and the key together loses the journal corpus. See
  `docs/INCIDENT_RUNBOOK.md`, "BACKUP_KEY second-location custody".
- **`rclone copy`, never `sync`.** Replication can never delete from the
  remote. Local retention pruning (35 days by default) does **not**
  propagate off-site; set the remote lifecycle/retention policy yourself
  and make it match the deletion promise you give users.
- The volume is mounted **read-only**: replication cannot alter local dumps.

## Enable

Add to the owner-only secrets file (`/etc/mindpattern/secrets.env`, mode
0600 — never the release env asset or the checkout):

```dotenv
# rclone destination spec; the remote must exist in the config below.
BACKUP_OFFSITE_REMOTE=s3-offsite:mindpattern/backups
# Full rclone config INI, double-quoted so the multi-line value parses
# (Compose v2 dotenv supports quoted multi-line values). Example:
BACKUP_OFFSITE_RCLONE_CONFIG="[s3-offsite]
type = s3
provider = AWS
access_key_id = ...
secret_access_key = ...
region = us-east-1"
# Optional: replication interval in seconds (default 3600, minimum 60).
# BACKUP_OFFSITE_INTERVAL_SECONDS=3600
```

Then layer the overlay onto the main file (the deploy/README.md `compose`
function with one extra `-f`; the offsite service has its own
`backups-offsite` profile so the existing `--profile backups` behavior is
unchanged):

```bash
docker compose \
  --env-file /etc/mindpattern/secrets.env \
  --env-file "$RELEASE_ENV" \
  -f "$APP_DIR/docker-compose.yml" \
  -f "$APP_DIR/deploy/backup-offsite/docker-compose.yml" \
  --profile backups --profile backups-offsite \
  up -d backup backup-offsite
```

A copy runs immediately (before the first sleep), so `up -d` proves the
remote path, credentials, and bucket reachability at once; the healthcheck
(`rclone lsf` against the remote) keeps reporting it. Always run this
overlay **layered with the main file** — alone it would create an empty
project volume and copy nothing.

## Digest pinning

The `rclone/rclone:v1.69.1` tag is mutable operator tooling. Before
production use, pin it exactly like the production contract pins its
images:

```bash
docker buildx imagetools inspect rclone/rclone:v1.69.1
# then edit this file:  image: rclone/rclone:v1.69.1@sha256:<64-hex>
```

## Recovery when the HOST is gone

Full procedure: `docs/INCIDENT_RUNBOOK.md`, "Off-site replication". Shape:
new host → deploy the tagged release but do not start traffic → recover
secrets (including `BACKUP_KEY` from its second location) → one-shot fetch
from object storage (`BACKUP_OFFSITE_MODE=fetch`) → HMAC-verify → decrypt
with `-iter 600000` → `pg_restore` → `up -d --wait` (the API's entrypoint
runs `alembic upgrade head`).

## Rehearse

An off-site copy that has never been restored from is a hypothesis, not a
backup. Quarterly, run the fetch → verify → decrypt → restore sequence from
the **remote** copy into a scratch Postgres (mirroring
`backend/scripts/rehearse_restore.sh`), and confirm during it that the
second `BACKUP_KEY` location can actually produce the key. Staleness of the
replication itself is covered by
`deploy/monitoring/check-backup-freshness.sh` (local dumps) — if local
dumps are fresh and replicating, the remote is fresh.
