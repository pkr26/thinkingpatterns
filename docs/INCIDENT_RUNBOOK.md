# MindPattern incident response runbook

**For a mental-health product, an outage or a safety defect is a safety
issue, not just an SLO miss.** This runbook is the operator's checklist.

## Severity levels

| Level | Meaning | Examples | Target first response |
|---|---|---|---|
| **S1** | User safety or data exposure | crisis screen defect; journal plaintext leak; key disclosure | 15 min, all hands |
| **S2** | Service unusable | API down; login broken; recomputes 500ing | 1 hour |
| **S3** | Degraded | elevated latency; one client version broken; rate-limit storms | next business day |

## The first five minutes (any severity)

1. **Look at the four signals that exist**: `/healthz` (liveness), `/readyz`
   (DB reachability), `/metrics` (status-code families, recompute
   histogram, LLM failures, keystore length), container logs.
2. **Do not restart the database on a hunch** — the evidence must support
   the specific action (restarts destroy the in-memory keystore and rate
   counters; sessions opened in the last TTL window die with them).
3. **Write down the time** — everything below wants timestamps.
4. **Backup freshness** — during any incident that risks the host or the
   database, run `bash deploy/monitoring/check-backup-freshness.sh`
   (nonzero exit = the newest encrypted dump is older than
   `BACKUP_MAX_AGE_HOURS`). A stale backup turns any data-loss incident
   into an S1-scale recovery problem — see Off-site replication below.

## S1: suspected plaintext exposure

The design exposes plaintext in exactly two places: the single-use
processing session (server memory, ≤5 min TTL) and the consent-gated LLM
egress. For anything else claiming "leak":

1. Capture evidence: which endpoint, which auth state, what was observed.
2. Check `/metrics` `mindpattern_keystore_sessions` — an unexpectedly
   LARGE value means processing sessions are not being consumed.
3. If a third-party LLM endpoint is implicated: disable
   `MINDPATTERN_LLM_URL` at the next deploy (consent per user remains,
   but the egress point dies with the unset URL), and note which accounts
   had `llm_consent_at` set (their data may be in the provider's hands —
   provider retention is disclosed in the consent copy).
4. Rotate `MINDPATTERN_TOKEN_SECRET` if tokens are implicated (invalidates
   every session; users re-login). `BACKUP_KEY` rotation requires the
   dual-key procedure (below).
5. Disclosure: journal content is special-category data. Prepare the
   notification per your jurisdiction (GDPR Art. 33: 72h to the SA;
   FTC Health Breach Notification Rule for US non-HIPAA deployments).

## S1: crisis-screen defect

The crisis screen is offline static content on the client — a server
outage cannot break it. A CLIENT defect (bad number, broken link) is an
app-release emergency: hotfix, expedite review, and pin a regression test
against `shared/crisis_phrases.json` + the screen copy (both suites gate
this).

## S2: API down

1. `/readyz` 503 → database: check the `db` container, then Postgres logs.
   The app is fail-closed by design; it will not serve on a dead DB.
2. `/healthz` failing → the process itself: container logs, OOM (the
   memory limits exist to make this visible), CPU saturation from
   recomputes (`mindpattern_recompute_seconds` histogram — p95 climbing
   past ~5s means the analyze slots are saturated).
3. **Do not scale to a second instance.** The deployment contract is one
   host per database (in-process keystore/locks/counters; the boot guard
   enforces it). Saturation means: shed load (tighten
   `MINDPATTERN_PROCESSING_RATE_LIMIT`), then plan the Redis migration.

## Backups

- The compose backup service writes encrypted daily dumps; retention is
  the deletion promise (default 35 days).
- **Rehearse restores** — `bash backend/scripts/rehearse_restore.sh` is
  the scripted rehearsal; an unrehearsed restore is not a backup.
- `BACKUP_KEY` loss = all backups unreadable. Store it in a second secret
  location. Rotation: decrypt-and-redump the corpus under the new key in a
  maintenance window (the dumps are the only ciphertext that does not
  re-encrypt on the live path).

### `BACKUP_KEY` second-location custody

With off-site replication the ciphertext survives the host, so `BACKUP_KEY`
is the **only** path back to plaintext. The requirement, stated plainly:
**the key must survive the host AND the operator** — losing both together
loses the journal corpus. Concrete options (combine at least two):

- **Sealed envelope in a safe** (or a bank safe-deposit box): print the
  `openssl rand -base64 32` value, seal it, and record custody transfers.
- **Password manager with break-glass access**: a shared vault — not just
  the operator's daily account — where a second trusted party can retrieve
  the key under a logged, alarmed procedure.
- **Split knowledge**: split the key across two custodians (two half-keys,
  or an `ssss`-style secret-sharing scheme) so no single person alone can
  decrypt the corpus.

Prove it during every off-site rehearsal: if the second location cannot
produce the key while the exercise pretends the host is gone, you do not
have off-site backups.

### Off-site replication

`deploy/backup-offsite/` is an opt-in overlay that replicates the
`pgbackups` volume to an S3-compatible remote hourly with `rclone copy`
(copy, never sync — replication can never delete from the remote; remote
retention is the operator's lifecycle policy). It ships ciphertext only and
never sees `BACKUP_KEY`. Enable it with the layered command in
`deploy/backup-offsite/README.md` (its `BACKUP_OFFSITE_*` values live in
the owner-only secrets file, never the release env asset).

**Recovery when the HOST is gone** (database, local backups, and the
compose stack are all lost):

1. New host: follow deploy/README.md "Deploy a tagged release" through
   `compose pull`, but do not serve user traffic yet. Recover
   `/etc/mindpattern/secrets.env` — including `BACKUP_KEY` from its second
   location (above).
2. Start only the database: `compose up -d db`.
3. Fetch the newest ciphertext from object storage with the overlay's
   one-shot mode (a host with only the secrets file and the release assets
   can run it):
   ```bash
   mkdir -p /srv/restore
   docker compose --env-file "$SECRETS_ENV" \
     -f "$APP_DIR/docker-compose.yml" \
     -f "$APP_DIR/deploy/backup-offsite/docker-compose.yml" \
     --profile backups-offsite run --rm -v /srv/restore:/restore \
     -e BACKUP_OFFSITE_MODE=fetch -e BACKUP_FETCH_DIR=/restore backup-offsite
   ```
4. Authenticate before decrypting (the fetch brings the `.hmac` sidecars;
   a missing or mismatching tag is a hard stop), then pipe the decrypt
   straight into the running database — plaintext never touches host disk:
   ```bash
   NEWEST=$(ls -1t /srv/restore/mindpattern-*.dump.enc | head -n 1)
   docker run --rm -v /srv/restore:/restore -e BACKUP_KEY \
     --entrypoint mindpattern-backup-mac "$BACKUP_IMAGE" verify "$NEWEST"
   docker run --rm -i -v /srv/restore:/restore -e BACKUP_KEY \
     --entrypoint openssl "$BACKUP_IMAGE" enc -d -aes-256-cbc -pbkdf2 \
     -iter 600000 -pass env:BACKUP_KEY -in "$NEWEST" \
     | docker compose --env-file "$SECRETS_ENV" \
     -f "$APP_DIR/docker-compose.yml" \
     exec -T db pg_restore -U "${POSTGRES_USER:-mindpattern}" -d "${POSTGRES_DB:-mindpattern}" --clean --if-exists
   ```
   (`-iter 600000` must match the encryptor exactly, or decryption fails
   closed; `BACKUP_IMAGE` is the validated `@sha256` reference from the
   release env asset.)
5. `compose up -d --wait` — the api entrypoint runs `alembic upgrade head`
   — then verify `curl http://127.0.0.1:8000/readyz` before serving
   traffic.

**Rehearse this quarterly**: run steps 3–4 from the REMOTE copy into a
scratch Postgres (mirroring `backend/scripts/rehearse_restore.sh`), not
from the local volume. An off-site copy that has never been restored from
is a hypothesis, not a backup.

## Post-incident

- Blameless postmortem within 5 business days: timeline, root cause,
  detection gap (what would have caught it sooner), and one concrete
  change wired into CI/monitoring so the class cannot recur silently.
- The repo's own history is the pattern: every audit wave ended with
  regression tests pinning the fix.
