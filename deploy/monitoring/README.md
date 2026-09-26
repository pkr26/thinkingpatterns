# Monitoring stack (operator tooling)

This directory is **operator tooling, deliberately outside the release-env
image contract**. The production `docker-compose.yml` consumes only the
immutable `@sha256` release references verified by `deploy/README.md`; this
stack holds its images in the same `repo:tag@sha256:…` pinned form (since
2026-09-22, audit G-7/NEW-4) but in this directory, not a release asset —
operator tooling must not weaken that contract, and it is not covered by
the release verification flow. `verify.sh --production` machine-checks the
pins (see "Verify" below), and CI (`ci.yml`, `monitoring-verify` job) runs
that assertion on every push; re-pin only deliberately ("Digest pinning"
below).

## What it is

- `prometheus.yml` — scrape config for the API's `/metrics` (30s interval,
  bearer token), plus optional commented jobs: the blackbox `/readyz`
  probe, the blackbox `tls` cert-expiry probe, and the host-metrics
  node_exporter scrape (see "Host-level failure modes").
- `alerts.yml` — alert rules, each with a `runbook` annotation pointing at
  `docs/INCIDENT_RUNBOOK.md`.
- `blackbox-modules.yml` — the blackbox exporter's module set as code:
  `http_2xx` (equivalent to the stock module incl. its 5s timeout and ip4 preference, used by the `/readyz`
  probe) and `tls` (the cert-expiry probe; see the file's header for why
  it deliberately skips chain verification). Mounted read-only over the
  path the image's own `--config.file` already points at, and
  shape-checked by `verify.sh`.
- `docker-compose.yml` — profile-gated services (a plain `up` starts
  nothing): `prometheus` + `grafana` behind the `monitoring` profile,
  `blackbox` behind the `blackbox` profile, `node-exporter` behind the
  `node` profile.
- `check-backup-freshness.sh` / `backup-heartbeat.sh` — backup-staleness
  detection (the backup service exports no metrics by design; see below).
- `verify.sh` — no-docker validation: promtool when installed, plus a
  YAML/structure/metric-grounding pass that proves every alert expression
  references only metric names `backend/app/metrics.py` actually exports
  (plus the exporter-provided names the optional host jobs use).

## Boot

```bash
# Find the production compose network name first (project defaults to the
# checkout directory name; the deploy/README.md flow uses /srv/mindpattern):
docker network ls | grep default    # e.g. mindpattern_default

export MINDPATTERN_COMPOSE_NETWORK=mindpattern_default
export MINDPATTERN_METRICS_TOKEN=<the token the api service uses>
export GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 24)

# The scrape credential travels by FILE (Prometheus does not env-expand
# config contents). Create the token file — owner-only, never committed
# (gitignored); `docker compose up` refuses to start without it:
umask 077
printf '%s' "$MINDPATTERN_METRICS_TOKEN" > deploy/monitoring/token

docker compose -f deploy/monitoring/docker-compose.yml \
  --profile monitoring up -d

# Optional /readyz probe (also uncomment its scrape job in prometheus.yml
# and its alert group in alerts.yml):
docker compose -f deploy/monitoring/docker-compose.yml \
  --profile monitoring --profile blackbox up -d

# Optional host metrics: disk alerts (also uncomment the mindpattern-node
# scrape job and the mindpattern-host alert group):
docker compose -f deploy/monitoring/docker-compose.yml \
  --profile monitoring --profile node up -d

# Optional TLS cert-expiry probe (same blackbox service; uncomment the
# mindpattern-blackbox-tls scrape job — replace its example.com target
# literals with your real origins — and the mindpattern-blackbox-tls
# alert group):
docker compose -f deploy/monitoring/docker-compose.yml \
  --profile monitoring --profile blackbox up -d
```

The monitoring containers join the production compose network as `external`
so Prometheus reaches the API at `api:8000` by service DNS — the same
network path the existing backup service uses for `pg_dump -h db`. Do not
switch to `host.docker.internal`: the API publishes port 8000 on
`127.0.0.1` only, so the host's bridge address refuses the connection.

Grafana listens on `127.0.0.1:3000` (loopback only, like the API): reach it
through an SSH tunnel. Prometheus publishes nothing; use a temporary
loopback port or `docker compose exec prometheus promtool ...` if you need
its UI.

## Token wiring

`/metrics` requires `Authorization: Bearer <MINDPATTERN_METRICS_TOKEN>`
(`backend/app/config.py`). Two consequences:

1. **The API side.** Production `/metrics` **404s** until the `api` service
   itself receives `MINDPATTERN_METRICS_TOKEN` — the production compose
   file does not (and must not, here) be edited for that. Add it with an
   operator-owned overlay that never enters the checkout:

   ```yaml
   # /etc/mindpattern/api-metrics.env-overlay.yml  (owner-only, 0600, never committed)
   services:
     api:
       environment:
         MINDPATTERN_METRICS_TOKEN: ${MINDPATTERN_METRICS_TOKEN:?}
   ```

   ```bash
   # extend the deploy/README.md compose() function with one more -f:
   docker compose --env-file "$SECRETS_ENV" --env-file "$RELEASE_ENV" \
     -f "$APP_DIR/docker-compose.yml" \
     -f /etc/mindpattern/api-metrics.env-overlay.yml up -d api
   ```

   The token grants aggregate operational counters only (no usernames, no
   paths, no per-user data — by design in `backend/app/metrics.py`), but
   treat it as a secret anyway.

2. **The Prometheus side.** `prometheus.yml` reads the credential with
   `bearer_token_file: /etc/prometheus/metrics-token`, mounted from
   `deploy/monitoring/token` by the compose `configs:` entry in this
   directory. Prometheus does **not** expand environment variables inside
   its config files — a `bearer_token: ${VAR}` line would send the literal
   string and 401 on every scrape, which is why the token travels by file.
   Fail closed, twice: `docker compose up` refuses to start when the token
   file is missing (compose resolves `configs: file:` eagerly), and
   Prometheus fails to load the config when the file exists but cannot be
   read. Keep the host file `0600`/owner-only and never commit it (it is
   gitignored).

## Alert philosophy and severity mapping

Alerts are grounded ONLY in what `backend/app/metrics.py` renders —
`mindpattern_requests_total{status}`, `mindpattern_recompute_seconds_*`,
`mindpattern_llm_calls_total{outcome}`, `mindpattern_keystore_sessions` —
plus Prometheus' own `up` (`probe_success` for the optional blackbox job).
`verify.sh` machine-checks this, so an alert cannot silently reference a
metric the API does not export. Thresholds follow the runbook's own
guidance where it states one (recompute p95 ~5s; the keystore gauge is the
S1 exposure indicator).

| Alert | Expression core | Runbook severity |
|---|---|---|
| `MindPatternAPIDown` | `up{job="mindpattern-api"} == 0` for 2m | **S2** — the matrix's literal "API down" example. (Not S1: the crisis screen is client-static; a dead API is service loss, not exposure. Escalate per the S1 checklist if exposure is suspected.) |
| `MindPatternHigh5xxRatio` | 5m `rate` of `mindpattern_requests_total{status="5xx"}` vs total > 5%, traffic floor > 4 req/5m, for 10m | **S2** — "recomputes 500ing" |
| `MindPatternRecomputeP95Slow` | `histogram_quantile(0.95, ... mindpattern_recompute_seconds_bucket[10m]) > 5` for 10m | **S3** — elevated latency; runbook's saturation guidance (shed load, do not scale out) |
| `MindPatternKeystoreSessionsStuck` | `mindpattern_keystore_sessions > 16` for 15m | **S2, escalate to S1** — the runbook's plaintext-exposure checklist names this gauge; >16 is 4x the analyze slots (4) held for three TTL windows (<=5 min each) |
| `MindPatternLLMFailureRatioHigh` | `mindpattern_llm_calls_total{outcome="failure"}` ratio > 25%, floor > 2 calls/15m, for 15m | **S3** — consent-gated enrichment degraded; core journaling unaffected |
| `MindPatternReadyzProbeFailing` *(commented; blackbox)* | `probe_success == 0` for 5m | **S2** — DB path broken while the process lives |
| `MindPatternBackupHeartbeatStale` / `...Absent` *(commented; textfile)* | `time() - mindpattern_backup_last_success_timestamp_seconds > 26h` / `absent(...)` | **S2** — recovery capability degraded; an amplifier for any live incident |
| `MindPatternHostDiskSpaceLow` *(commented; node)* | `node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.20` (real filesystems) for 30m | **S3** — time-bounded decay; Postgres degrades long before ENOSPC |
| `MindPatternHostDiskSpaceCritical` *(commented; node)* | same ratio `< 0.05` for 10m | **S2** — ENOSPC imminent; db writes and bounded log rotation fail |
| `MindPatternTlsCertExpiringSoon` *(commented; blackbox tls)* | `probe_ssl_earliest_cert_expiry - time() < 14d` for 30m | **S3** — inside the renewal window (warning) |
| `MindPatternTlsCertExpiryImminent` *(commented; blackbox tls)* | `probe_ssl_earliest_cert_expiry - time() < 3d` for 30m | **S2** — expiry is a scheduled total-origin outage (critical) |

Delivery is honest about its limits: **no Alertmanager runs by default**,
so alerts evaluate inside Prometheus (visible in its UI and API at
`/api/v1/alerts`) but nothing pages anyone until you wire delivery —
where S1/S2 pages land is an operator decision. `alertmanager/
alertmanager.example.yml` is the minimal starting config (severity routing
that mirrors the runbook, an inhibit rule, and the exact compose +
prometheus.yml snippets to enable it in its header comment): copy it to
`alertmanager.yml`, fill in the receiver URLs, and add the service.

## Host-level failure modes (opt-in)

The API's own exposition cannot see the two failure classes that take the
whole origin down from outside the container. Both ship as commented
opt-ins, exactly like the `/readyz` probe: service behind a compose
profile, scrape job + alert group commented until you enable them.

1. **Host disk filling up** (`node` profile). The `node-exporter` service
   mounts the HOST root filesystem read-only at `/host` (with `rslave`
   propagation so container-runtime volumes are visible) and points every
   collector at it — so `node_filesystem_avail_bytes` /
   `node_filesystem_size_bytes` describe the real disks holding pgdata,
   the pgbackups volume, and the bounded json-file logs. Two commented
   rules in `alerts.yml` (`mindpattern-host` group): under 20% free on
   any real filesystem for 30m is **S3** (Postgres and dumps degrade
   long before ENOSPC); under 5% for 10m is **S2** (db writes fail
   closed and the max-size-bounded log volumes can hit ENOSPC inside
   the window). The fstype filter excludes tmpfs/overlay so the
   container runtime's virtual mounts cannot fake or mask a real disk.
   The exporter publishes nothing and sits on the internal network only.

2. **TLS certificate expiry** (`blackbox` profile, `tls` module). The
   same blackbox-exporter container also runs a TLS-connect probe
   against your PUBLIC origins (replace the `portal.example.com:443` /
   `app.example.com:443` literals in the commented
   `mindpattern-blackbox-tls` scrape job) — the cert that can expire is
   the one nginx serves, and the exporter performs a real handshake to
   read `probe_ssl_earliest_cert_expiry`. Two commented rules: under
   14 days is **S3** (the warning: a 90-day cert this close to expiry
   has already missed several renewals); under 3 days is **S2** (the
   critical: expiry is a scheduled total-origin outage — every client
   fails TLS and the API reads as down). The `tls` module deliberately
   skips chain verification (see `blackbox-modules.yml`): a probe that
   fails verification yields no expiry series at all, which would
   silence exactly the alert watching the broken cert; with the skip,
   the gauge keeps reporting the real expiry (in the past after
   expiry, tripping both rules) while chain VALIDITY stays the
   clients' fail-closed job.

`verify.sh` grounds the `node_*` and `probe_ssl_earliest_cert_expiry`
names against their exporters (not `metrics.py`) and shape-checks
`blackbox-modules.yml`, so a typo'd module name fails the gate rather
than the probe.

## Backup freshness (the honest mechanism)

The compose backup service exports no Prometheus metrics, and it must not
be modified. Two supported paths:

1. **Cron + exit code (always works, no Prometheus).**
   `check-backup-freshness.sh` checks the newest `mindpattern-*.dump.enc`
   (+ its `.hmac` sidecar) in the `pgbackups` volume and exits nonzero past
   `BACKUP_MAX_AGE_HOURS` (default 26 = one daily dump + 2h slack). Any
   cron-alerting wrapper can consume the exit code:

   ```bash
   # /etc/cron.d/mindpattern-backup-freshness  (root: the volume dir is root-only)
   17 * * * * root /srv/mindpattern/deploy/monitoring/check-backup-freshness.sh \
     || /usr/local/bin/alert-operator "mindpattern backups stale"
   ```

   The script auto-detects the volume path via
   `docker volume inspect ${MINDPATTERN_COMPOSE_PROJECT:-mindpattern}_pgbackups`
   (or pass the directory as `$1` / `BACKUP_DIR`).

2. **Textfile heartbeat (only if node_exporter is deployed).** Set
   `BACKUP_TEXTFILE_DIR` in the cron above: on every passing check the
   newest dump's mtime is published as
   `mindpattern_backup_last_success_timestamp_seconds` to that directory
   (atomically, by `backup-heartbeat.sh`), and node_exporter's textfile
   collector exposes it to Prometheus. The matching `MindPatternBackup-
   HeartbeatStale` / `Absent` rules sit **comment-guarded** in
   `alerts.yml`; uncomment them once the heartbeat cron and the
   node_exporter scrape are wired. The timestamp is the dump's mtime, never
   "now", so the metric cannot claim a backup the filesystem does not hold.

Keep `BACKUP_MAX_AGE_HOURS` and the alert's 26h threshold equal when both
paths are active.

## Grafana

The datasource (Prometheus at `http://prometheus:9090`, stable uid
`mindpattern-prometheus`) is provisioned from
`grafana/provisioning/datasources/`, and a dashboard ships as code since
the 2026-09-21 follow-up: the provider at
`grafana/provisioning/dashboards/dashboards.yml` loads
`grafana/dashboards/mindpattern-overview.json` read-only (deletion and UI
edits disabled — change the JSON and let the 60s reload pick it up). The
overview carries the alert-backed panels: up/keystore/backup-age/5xx
stats, request rate by status family, recompute p50/p95 via
`histogram_quantile`, recompute rate, and the LLM outcome counters.
`verify.sh` grounds every panel expression against
`backend/app/metrics.py` the same way it grounds alerts.yml, so a panel
referencing a metric the API stopped exporting fails the drift gate.

## Digest pinning (deliberate re-pins only)

Every image in this directory's `docker-compose.yml` — and
`deploy/backup-offsite/`'s `rclone/rclone` — is pinned at
`repo:tag@sha256:…` (resolved 2026-09-22, audit G-7/NEW-4: the former
"pin before production" TODO was unenforced, and one referenced tag,
`rclone/rclone:v1.69.1`, did not even exist on Docker Hub — a latent
pull-time failure). An upgrade is a deliberate edit that replaces the tag
AND the digest together:

```bash
docker buildx imagetools inspect prom/prometheus:<new-tag>   # or: docker manifest inspect
# copy the manifest-list sha256 digest, then edit the file:
#   image: prom/prometheus:<new-tag>@sha256:<64-hex>
bash deploy/monitoring/verify.sh --production   # must still pass
```

`verify.sh --production` fails any image line that is not
`repo:tag@sha256:<64-hex>` (or a required-env `${VAR:?}` form with no
mutable default) across the production compose and both overlays, and the
`monitoring-verify` job in `.github/workflows/ci.yml` runs the same
assertion on every push — a dropped or stale digest fails the build, not
the deploy. Re-resolve on every deliberate upgrade — exactly the
discipline the `db` service's comment in the production compose file
describes.

## Verify

```bash
bash deploy/monitoring/verify.sh                # YAML + structure + grounding
bash deploy/monitoring/verify.sh --production    # …and the digest-pin contract
```

Runs promtool when installed and always the YAML/structure/metric-grounding
pass via the repo virtualenv (`../../.venv/bin/python`, needs PyYAML;
falls back to any `python3` with PyYAML). Exit 0/1 honestly; prints exactly
what was checked and which metrics each alert uses.

`--production` (audit G-7/NEW-4) additionally asserts the digest-pinning
contract: every `image:` line in the production `docker-compose.yml`, this
directory's overlay, and `deploy/backup-offsite/`'s overlay must be either
`repo:tag@sha256:<64-hex>` or a required-env `${VAR:?…}` reference with no
mutable default — any floating tag fails. Run it before any production use
of these overlays and after every re-pin; CI's `monitoring-verify` job
(`.github/workflows/ci.yml`) runs both modes on every push, so a dropped
digest fails the build rather than a later `compose pull`.
