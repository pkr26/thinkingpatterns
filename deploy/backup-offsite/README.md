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

**Restart policy (audit round 2 F-10).** The service defaults to
`restart: no` via `BACKUP_OFFSITE_RESTART` — the push loop keeps itself
alive in-process, so a restart policy adds nothing for it. If you do set
`BACKUP_OFFSITE_RESTART=unless-stopped` (or `always`) for the push loop,
**never combine it with `BACKUP_OFFSITE_MODE=fetch`**: fetch is a one-shot
container by design, and a restart policy would re-run it forever,
hammering the remote. The runbook's fetch path uses
`docker compose run --rm`, which carries no restart policy at all —
prefer that shape for recovery.

## Digest pinning

The image is pinned at `rclone/rclone:1.69.1@sha256:600f…6138` (2026-09-22,
audit G-7/NEW-4) — including a tag repair: the previously documented
`rclone/rclone:v1.69.1` DOES NOT EXIST on Docker Hub (rclone tags are
unprefixed; `1.69.1` and `v1.69-stable` exist, `v1.69.1` does not), a
latent pull-time failure that would have surfaced only the first time the
overlay was needed. Upgrades are deliberate re-pins of tag AND digest
together:

```bash
docker buildx imagetools inspect rclone/rclone:<new-tag>
# then edit this file:  image: rclone/rclone:<new-tag>@sha256:<64-hex>
bash ../monitoring/verify.sh --production
```

`deploy/monitoring/verify.sh --production` fails this file on any mutable
image reference, and CI's `monitoring-verify` job
(`.github/workflows/ci.yml`) runs that assertion on every push.

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
