# Production deployment

The checked-in `docker-compose.yml` is a **production deployment contract**:
it has no application `build:` stanza. It requires both
`MINDPATTERN_API_IMAGE` and `MINDPATTERN_BACKUP_IMAGE` as immutable `@sha256`
references. A tagged GitHub release publishes the exact
`mindpattern-release-vX.Y.Z.env` fragment containing those references, plus
the verified therapist-portal archive and a SHA-256 file for each asset.

`docker-compose.dev.yml` is the only source-build overlay. It is for local
development and CI integration testing; never add it to a production command.
Likewise, never use `--build` when deploying a tagged release: that would
replace a provenance/SBOM-attested image with an unreviewed local build.

The public release env asset contains image references only. It deliberately
does not contain `MINDPATTERN_TOKEN_SECRET`, database credentials, `BACKUP_KEY`,
or proxy settings. Keep those in an owner-only file outside the checkout.

## Operator tooling (opt-in, outside the release contract)

Two directories add opt-in operator capabilities without weakening the
digest-pinned contract above — both pin their overlay images to the same
`repo:tag@sha256:…` form as the release contract (2026-09-22, audit
G-7/NEW-4; the overlays' former mutable tags — one of which,
`rclone/rclone:v1.69.1`, did not exist on Docker Hub at all — are now
pinned), and upgrades are deliberate re-pins (`docker buildx imagetools
inspect` → replace tag and digest together). CI enforces this:
`deploy/monitoring/verify.sh --production`, run by the `monitoring-verify`
job in `.github/workflows/ci.yml`, fails any mutable image reference in
the production compose or either overlay:

- `deploy/monitoring/` — Prometheus + optional Grafana/blackbox stack
  (profile-gated compose file of its own), alert rules grounded in the
  API's `/metrics` exposition, and backup-freshness scripts. See
  `deploy/monitoring/README.md` for boot, token wiring, and severity
  mapping against `docs/INCIDENT_RUNBOOK.md`.
- `deploy/backup-offsite/` — hourly `rclone copy` replication of the
  `pgbackups` volume (ciphertext only) to an S3-compatible remote, as a
  compose overlay layered onto the main file. See
  `deploy/backup-offsite/README.md` for the layered enable command and the
  host-gone recovery path.

## Deploy a tagged release

The following initial-install sequence is for a Linux host with Docker Compose
v2, `docker buildx`, `sha256sum`, and the GitHub CLI (`gh`). For a private
repository or package, authenticate `gh` and Docker to the organization that
owns the release; this repository cannot safely invent those credentials.

```bash
REPOSITORY=pkr26/thinkingpatterns       # change for a fork
TAG=vX.Y.Z                              # exact published release tag
APP_DIR=/srv/mindpattern
ASSET_DIR="$APP_DIR/release-assets/$TAG"

git clone --branch "$TAG" --depth 1 "https://github.com/$REPOSITORY.git" "$APP_DIR"
mkdir -p "$ASSET_DIR"
gh release download "$TAG" --repo "$REPOSITORY" --dir "$ASSET_DIR" \
  --pattern "mindpattern-portal-${TAG}.tar.gz" \
  --pattern "mindpattern-portal-${TAG}.tar.gz.sha256" \
  --pattern "mindpattern-release-${TAG}.env" \
  --pattern "mindpattern-release-${TAG}.env.sha256"

(
  cd "$ASSET_DIR"
  sha256sum -c "mindpattern-portal-${TAG}.tar.gz.sha256"
  sha256sum -c "mindpattern-release-${TAG}.env.sha256"
)

RELEASE_ENV="$ASSET_DIR/mindpattern-release-${TAG}.env"
"$APP_DIR/deploy/verify-release-env.sh" "$RELEASE_ENV"
```

The verifier does not source the downloaded file. It accepts exactly the two
expected keys and rejects tags, blank values, duplicate keys, non-GHCR paths,
and anything other than a lowercase 64-hex SHA-256 manifest digest. Inspect
both remote manifest lists before the first pull. The output must name the
same `@sha256:…` reference from the release env file and list its platforms.

```bash
API_IMAGE=$(sed -n 's/^MINDPATTERN_API_IMAGE=//p' "$RELEASE_ENV")
BACKUP_IMAGE=$(sed -n 's/^MINDPATTERN_BACKUP_IMAGE=//p' "$RELEASE_ENV")
docker buildx imagetools inspect "$API_IMAGE"
docker buildx imagetools inspect "$BACKUP_IMAGE"
```

Create `/etc/mindpattern/secrets.env` with mode `0600` for a first deployment
(or retain the existing file on an upgrade). It must contain at least:

```dotenv
MINDPATTERN_TOKEN_SECRET=<a unique 32+-character secret>
POSTGRES_PASSWORD=<a unique database password>
BACKUP_KEY=<a unique base64 backup-encryption key>
MINDPATTERN_TRUST_PROXY_HEADERS=0
```

Generate values once with `openssl rand -hex 32`, `openssl rand -hex 16`, and
`openssl rand -base64 32`; store them in the approved secret manager and that
owner-only file. Do not place secrets in the release env asset or checkout.

Use a shell function so an exported host variable cannot override the release
image references. The release env file is passed *after* the secrets file, so
it wins even if the secrets file accidentally contains an old image key.

```bash
SECRETS_ENV=/etc/mindpattern/secrets.env
compose() {
  (
    unset MINDPATTERN_API_IMAGE MINDPATTERN_BACKUP_IMAGE
    docker compose \
      --env-file "$SECRETS_ENV" \
      --env-file "$RELEASE_ENV" \
      -f "$APP_DIR/docker-compose.yml" "$@"
  )
}

# Prove the rendered deployment consumes both release digests before startup.
rendered_images=$(compose config --images)
printf '%s\n' "$rendered_images" | grep -Fx "$API_IMAGE"
printf '%s\n' "$rendered_images" | grep -Fx "$BACKUP_IMAGE"

compose pull
compose up -d --wait
curl --fail --silent --show-error http://127.0.0.1:8000/readyz

# Optional, profile-gated encrypted backups; this uses the independently
# attested backup-worker digest from the same release env fragment.
compose --profile backups up -d backup

# The rehearsal forwards these files to Compose without sourcing either one.
# It reads the live db service's role/database rather than assuming defaults.
bash "$APP_DIR/backend/scripts/rehearse_restore.sh" \
  --env-file "$SECRETS_ENV" --env-file "$RELEASE_ENV"
```

Do not replace `compose pull`/`compose up` with `--build`. A successful pull
of a digest reference and the two `grep -Fx` checks prove that Compose consumes
the release artifacts rather than a mutable tag or local Dockerfile. The
workflow publishes provenance and an SBOM for each image; retain the GitHub
release URL, digest fragment, and deployment record together for audit.

The portal archive contains the verified `dist/` tree. Extract it to the path
served by the nginx template; extraction invokes no Node build tool:

```bash
install -d -m 0755 "$APP_DIR/portal"
tar -C "$APP_DIR/portal" -xzf "$ASSET_DIR/mindpattern-portal-${TAG}.tar.gz"
test -f "$APP_DIR/portal/dist/index.html"
nginx -t && systemctl reload nginx
```

For later releases, use a clean checkout of that exact tag, download and
verify that tag's four release assets again, and repeat the same digest checks.
Use an atomic static-content promotion procedure if the site cannot tolerate
replacing `portal/dist` in place; do not rebuild the portal on production.

## Local source-build stack

Local development intentionally uses different image names and an explicit
overlay. These names are not deployable release references.

```bash
cd /path/to/thinkingpatterns
cat > .env <<EOF
MINDPATTERN_TOKEN_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
BACKUP_KEY=$(openssl rand -base64 32)
MINDPATTERN_API_IMAGE=mindpattern-api:local
MINDPATTERN_BACKUP_IMAGE=mindpattern-backup:local
EOF

docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.dev.yml config --quiet
docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.dev.yml up --build

# Optional local backup worker:
docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.dev.yml \
  --profile backups up -d backup

bash backend/scripts/rehearse_restore.sh --env-file .env --dev
```

## Production edge configuration

`nginx/mindpattern.conf.example` is the checked-in edge configuration for a
single HTTPS origin: the static therapist portal and `/api/` are served from
the same hostname. It enforces a restrictive CSP, disables request-inventory
access logs, and keeps the API on the host's loopback interface.

Before enabling it, replace `portal.example.com`, install a valid TLS
certificate, set a real `MINDPATTERN_TOKEN_SECRET`, and keep
`MINDPATTERN_TRUST_PROXY_HEADERS=0` unless nginx is the only path to the API.
If enabling proxy headers, set `MINDPATTERN_TRUSTED_PROXY_IPS` to the nginx
source address/CIDR as observed **inside the API container**. This is not
automatically `127.0.0.1` when host nginx enters through a Docker published
port; it is often a controlled Docker bridge gateway. Verify the direct peer
in your topology and allowlist only that address/CIDR. The API refuses a
proxy-header deployment without this allowlist.

The template cannot provision a DNS record, certificate, clinician identity
provider, MFA service, mobile signing keys, or app-store accounts. Those are
release prerequisites owned by the deploying organization, not values that
can safely be invented in source control.

The API's Uvicorn entrypoint intentionally uses `--no-proxy-headers`; its
own middleware must inspect the raw socket peer before it can trust a
forwarded address. The template also sets a 30-second `client_body_timeout`
to match the API's complete-body deadline. Keep both controls in place when
adapting this configuration.

## Rollback (2026-09-21 audit G-3)

The entrypoint auto-upgrades on every boot (`alembic upgrade head`), so a
rollback is NOT "redeploy the old image and boot it": the NEW image has
already auto-upgraded the schema before any rollback decision is made, and
an old image — lacking the new migration files — can neither apply nor
undo them; booting it against the upgraded schema is not a rollback. The
safe procedure:

1. **Restore the database from a pre-migration dump** (the one thing that
   actually reverses a migration). Take a manual dump BEFORE any deploy
   that includes new migrations — the backup image has no one-shot dump
   script (its dump loop IS the compose entrypoint), so exec the same
   pipeline the service itself runs, then verify the artifact before you
   rely on it (final verification 2026-09-22: the previous text named a
   nonexistent `backup.sh` and pointed at the monitoring `verify.sh`):
   ```bash
   docker compose --profile backups exec backup sh -ceu '
     umask 077
     stamp=$(date -u +%Y%m%dT%H%M%SZ)
     out="/backups/mindpattern-$stamp.dump.enc"; tmp="$out.tmp"
     PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h db -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
       | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 -pass env:BACKUP_KEY -out "$tmp"
     mindpattern-backup-mac write "$tmp" "$out.hmac.tmp"
     mv "$out.hmac.tmp" "$out.hmac"; mv "$tmp" "$out"   # sidecar first, ciphertext last
     mindpattern-backup-mac verify "$out"
   '
   ```
   This is your restore point. For a dump that lives off-site, fetch it
   with the authenticated path in `docs/INCIDENT_RUNBOOK.md` (machine-
   tested by `backend/scripts/rehearse_restore.sh --remote`), and exercise
   a full throwaway restore any time with
   `BACKUP_KEY=… bash backend/scripts/rehearse_restore.sh`.
2. **Pin the previous release images** in `.env`
   (`MINDPATTERN_API_IMAGE` / `MINDPATTERN_BACKUP_IMAGE` back to the
   prior @sha256 references from the release env asset) and
   `docker compose up -d`. The entrypoint's `alembic upgrade head` is a
   no-op against the restored (older) schema.
3. **Never `alembic downgrade`** against live data — the migrations are
   expand-only where possible, but a downgrade path is NOT tested for
   data preservation. Database restore is the rollback story.

Long-term policy: prefer expand/contract migrations (add column, dual-
write, drop later) so a rollback only needs step 2 — tracked as
follow-up work.
