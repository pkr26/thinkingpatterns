# Production deployment

The checked-in `docker-compose.yml` is a **production deployment contract**:
it has no application `build:` stanza. It requires both
`MINDPATTERN_API_IMAGE` and `MINDPATTERN_BACKUP_IMAGE` as immutable `@sha256`
references. A tagged GitHub release publishes the exact
`mindpattern-release-vX.Y.Z.env` fragment containing those references, plus
the verified therapist-portal archive and a SHA-256 file for each asset.

> **Compliance documents**: before first public service, complete the
> operator/compliance pack — `docs/OPERATOR_PACK.md` indexes the privacy
> policy template, data-retention schedule, subprocessor/BAA register,
> security policy, `security.txt` example, the signable DPIA template, and
> the incident runbook. deploy/README.md covers the mechanics; the pack
> covers the obligations.

## Digest-pin inventory & re-pin dates

Every image in the production contract is digest-pinned; each pin has a
deliberate re-pin discipline (Dependabot has no compose-ecosystem digest
updates for service images):

| Image | Pinned where | Pinned on | Re-pin procedure |
|---|---|---|---|
| API + backup worker | release env asset (`mindpattern-release-vX.Y.Z.env`), consumed as `@sha256` by `docker-compose.yml` | each release (workflow publishes provenance + SBOM, and since 2026-09-26 cosign-signs both digests keyless — verify with `cosign verify <ref>` against the repo's OIDC identity) | deploy the next tagged release; never rebuild on the host |
| `postgres:16-alpine@sha256:721873c34ceb…` | `docker-compose.yml` (db service) + `backup/Dockerfile` | 2026-09-26 (re-resolved via the Docker Hub registry API; previous pin 2026-09-07 had fallen ~6 weeks behind the moving tag) | `docker buildx imagetools inspect postgres:16-alpine` → replace tag AND digest together, deliberately — in BOTH files |
| `postgres:16-alpine@sha256:721873c34ceb…` (workflow-side) | `.github/workflows/ci.yml` (restore container) + `.github/workflows/release.yml` (postgres service container, production-integration restore container) | 2026-09-26 (moved off the superseded 2026-09-07 `cf78e766…` pin when the drift gate learned to scan workflows) | same inspect-and-replace discipline |
| `python:3.14-slim@sha256:51dafde81dbdb…` | `backend/Dockerfile` (both stages) | 2026-09-26 (re-resolved via the registry API; previous pin 2026-09-07) | same inspect-and-replace discipline |
| `prom/prometheus:v3.4.1@sha256:9abc6cf6aea7…` | `deploy/monitoring/docker-compose.yml` + `.github/workflows/ci.yml` (promtool copy step) | 2026-09-22 audit G-7/NEW-4 | same inspect-and-replace discipline; `deploy/monitoring/verify.sh --production` (CI's monitoring-verify job) fails any mutable reference |
| `grafana/grafana:12.0.0@sha256:263cbefd5d9b…` | `deploy/monitoring/docker-compose.yml` | 2026-09-22 audit G-7/NEW-4 | same inspect-and-replace discipline |
| `prom/blackbox-exporter:v0.25.0@sha256:b04a9fef4fa0…` | `deploy/monitoring/docker-compose.yml` | 2026-09-22 audit G-7/NEW-4 | same inspect-and-replace discipline |
| `prom/node-exporter:v1.9.1@sha256:d00a542e409e…` | `deploy/monitoring/docker-compose.yml` | 2026-09-26 (resolved from the Docker Hub registry API) | same inspect-and-replace discipline |
| `prom/alertmanager:v0.28.0@sha256:d5155cfac40a…` | `deploy/monitoring/docker-compose.yml` | 2026-09-26 | same inspect-and-replace discipline |
| `rclone/rclone:1.69.1@sha256:600f51856285…` | `deploy/backup-offsite/docker-compose.yml` | 2026-09-22 audit G-7/NEW-4 (including the tag repair: `v1.69.1` does not exist on Docker Hub — rclone tags are unprefixed) | same inspect-and-replace discipline |
| `aquasec/trivy:0.61.0@sha256:6967db29ce52…` | `.github/workflows/ci.yml` + `.github/workflows/release.yml` (image scanner) | 2026-09-22 (final verification) | version- and sha256-pinned scanner; re-pin deliberately |
| gitleaks 8.30.1, cosign-installer (`@c56c2d3e…` v3.8.0) | CI workflows | 2026-09-22/26 | version- and sha256-pinned external tools; bump on review |

**Drift gate (2026-09-26; workflows added 2026-09-27):**
`deploy/monitoring/check-image-drift.sh` (a CI step in the
monitoring-verify job, and runnable standalone) resolves every
`repo:tag@sha256` pin above — in the production compose, both operator
overlays, AND every `.github/workflows/*.yml` image reference — against the
live registry and FAILS when a tag has moved and the pin is older than 90
days per this table — a re-pin is now a scheduled obligation, not an
accident discovered by a failing Trivy scan. Update the "Pinned on" column
whenever you re-pin (the gate reads it, matching on the first 12 digest hex
characters, so each row above must keep its `@sha256:<12hex>…` form).

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

**Purpose-split secrets (2026-09-26) — recommended for every new
deployment.** The backend accepts dedicated secrets per purpose; each
falls back to `MINDPATTERN_TOKEN_SECRET` (identity derivation) when
unset, so existing deployments keep working, but a fresh deployment
should set all four from day one (rotation of one purpose then never
disturbs the others):

```dotenv
MINDPATTERN_AUTH_TOKEN_SECRET=<openssl rand -hex 32>   # bearer signing
MINDPATTERN_TOTP_WRAP_SECRET=<openssl rand -hex 32>    # therapist TOTP at rest
MINDPATTERN_PAIRING_SECRET=<openssl rand -hex 32>      # pairing-code HMAC digests
MINDPATTERN_DECOY_SECRET=<openssl rand -hex 32>        # unknown-user decoy salts
```

Caveats before ever CHANGING these on a live deployment: setting
`MINDPATTERN_AUTH_TOKEN_SECRET` (even to the same bytes as the legacy
secret) bumps the token key-scheme version and invalidates every
outstanding bearer; `MINDPATTERN_TOTP_WRAP_SECRET` rotation is one-way
(wrapped therapist secrets must be re-armed); `MINDPATTERN_PAIRING_SECRET`
rotation kills live pairing codes. The full rotation procedure is
`docs/INCIDENT_RUNBOOK.md` "Rotating `MINDPATTERN_TOKEN_SECRET`" —
read it before touching any of them.

Generate values once with `openssl rand -hex 32`, `openssl rand -hex 16`, and
`openssl rand -base64 32`; store them in the approved secret manager and that
owner-only file. Do not place secrets in the release env asset or checkout.

**File-mounted secrets (2026-09-26 infra audit) — compose reads these
INSTEAD of env where the consumer supports it.** Container environment
variables are visible to `docker inspect` on the host, so the signing and
backup secrets additionally mount as compose `secrets:` files under
`deploy/secrets/` (examples committed; real files gitignored; the app
resolves `<VAR>_FILE`, the db reads `POSTGRES_PASSWORD_FILE` natively, the
backup worker builds its pgpass line and passes `-pass file:` to openssl):

```bash
mkdir -p "$APP_DIR/deploy/secrets" && cd "$APP_DIR/deploy/secrets"
openssl rand -hex 32  > token_secret        # = MINDPATTERN_TOKEN_SECRET
: > auth_token_secret                       # optional; empty = derive
openssl rand -hex 16  > postgres_password   # same value as .env's POSTGRES_PASSWORD
openssl rand -base64 32 > backup_key        # = BACKUP_KEY
chmod 600 token_secret auth_token_secret postgres_password backup_key
# Only if you use the off-site replication overlay:
cp rclone_config.example rclone_config && $EDITOR rclone_config  # fill the S3 remote
chmod 600 rclone_config
```

`POSTGRES_PASSWORD` stays in the secrets.env as well — the api service
interpolates it raw into `MINDPATTERN_DB_URL` (compose cannot read secret
files for interpolation), so that one value remains env-based by design;
everything else above moves out of the environment.

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

## Branch protection (operator step — the repo cannot enable it for you)

Every guarantee above (digest pinning, CI gates, secret scanning, the
contract tests that pin the README's claims) is enforced by CI — and CI
only protects `main` if branch protection requires it. A repository
admin (not this checkout) must run, once per repository:

```bash
REPO=pkr26/thinkingpatterns    # change for a fork

# 1. Discover the exact check names your commits report (the workflow
#    is "CI"; each job surfaces as its own check, e.g. "backend",
#    "contract-gates", "web-contract-vectors"):
SHA=$(gh api "repos/$REPO/commits/main" --jq '.sha')
gh api "repos/$REPO/commits/$SHA/check-runs" --jq '.check_runs[].name'

# 2. Require them on main, plus one approving review, no direct pushes
#    past the checks (repeat the checks[] line for EVERY name step 1
#    listed that you want required — requiring all of them is the
#    honest default; the names below are illustrative):
gh api --method PUT "repos/$REPO/branches/main/protection" \
  -H "Accept: application/vnd.github+json" \
  -f 'required_status_checks[strict]=false' \
  -f 'required_status_checks[checks][][context]=backend' \
  -f 'required_status_checks[checks][][context]=backend-postgres' \
  -f 'required_status_checks[checks][][context]=contract-gates' \
  -f 'required_pull_request_reviews[required_approving_review_count]=1' \
  -f 'required_pull_request_reviews[dismiss_stale_reviews]=true' \
  -f 'enforce_admins=false' \
  -F 'restrictions=null'

# 3. Verify:
gh api "repos/$REPO/branches/main/protection" \
  --jq '.required_status_checks, .required_pull_request_reviews'
```

Notes: `checks[][context]` is the current schema (the older plain
`contexts[]` string array also works); `strict=false` keeps the checks
required while allowing merges of up-to-date branches without
head-branch freshness enforcement — set it to `true` if you want
"branch is up to date" forced too. Until this is done, anyone with
push access can bypass every gate this document describes.

## The patient web client (2026-09-25, WEB_PLAN P10)

The web app ships exactly like the portal: a static bundle extracted onto
the host, served by the same nginx, each app on its own subdomain with its
own `/api` proxy (the `app.example.com` server block in
`nginx/mindpattern.conf.example`). Same-origin proxying means
`MINDPATTERN_CORS_ORIGINS` stays empty — do not add a web origin to it.

- Release artifact: `mindpattern-web-<tag>.tar.gz` (+ `.sha256`) attached
  to the GitHub release. Verify the digest, then extract `dist/` to
  `/srv/mindpattern/web/dist` — never build on the prod host.
- The header set must stay aligned with `web/public/_headers` and the
  `index.html` meta fallback (pinned by `web/tests/securityConfig.test.ts`).
- No backend, container, or environment changes: the web client needs
  nothing beyond the existing API service and this static hosting.

Two operator steps were added with the 2026-09-26 hardening pass:

- **HSTS preload (optional, deliberate):** the patient app's HSTS header
  now carries `preload`. Submitting the domain at
  <https://hstspreload.org> is an operator decision — it is effectively
  irreversible at scale (removal takes months to propagate) and commits
  every subdomain of the registered domain to HTTPS. The header ships
  ready; submit only when that commitment is intended.
- **security.txt contact:** `web/public/.well-known/security.txt` (RFC
  9116) ships with an example contact. Replace the `Contact:` and
  `Canonical:` lines with the real ones before serving publicly — a
  placeholder disclosure channel is worse than none because it looks
  monitored. Keep `Expires:` within a year and refresh it with releases.
- The built shell carries Subresource Integrity hashes on every local
  subresource (stamped by `web/tools/add-sri.mjs` during
  `npm run build`). If you serve an `index.html` you did not build from
  this repo's pipeline, re-stamp or drop the attributes deliberately —
  a stale hash blocks the bundle.

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

### Which header config actually serves (2026-09-25 audit note)

Under the nginx deployment in this repository, **nginx is the enforcer**:
its `add_header ... always` lines at server level reach every response.
`web/public/_headers` ships inside the tarball but nginx never reads it —
it is the contract for a NON-nginx static host (e.g. a CDN object store)
and exists so the three configs (nginx, `_headers`, index.html meta
fallback) are pinned identical by `web/tests/securityConfig.test.ts`.
Do not "clean up" any one of the three: the test fails if they drift.

