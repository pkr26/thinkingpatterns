# Monitoring stack (operator tooling)

This directory is **operator tooling, deliberately outside the digest-pinned
production contract**. The production `docker-compose.yml` runs only
immutable `@sha256` release images verified by `deploy/README.md`; this
stack ships mutable version tags instead, because operator tooling must not
weaken that contract. Resolve and pin digests before production use —
nothing here is covered by the release verification flow.

## What it is

- `prometheus.yml` — scrape config for the API's `/metrics` (30s interval,
  bearer token), plus an optional commented blackbox job for `/readyz`.
- `alerts.yml` — alert rules, each with a `runbook` annotation pointing at
  `docs/INCIDENT_RUNBOOK.md`.
- `docker-compose.yml` — profile-gated services (a plain `up` starts
  nothing): `prometheus` + `grafana` behind the `monitoring` profile,
  `blackbox` behind the `blackbox` profile.
- `check-backup-freshness.sh` / `backup-heartbeat.sh` — backup-staleness
  detection (the backup service exports no metrics by design; see below).
- `verify.sh` — no-docker validation: promtool when installed, plus a
  YAML/structure/metric-grounding pass that proves every alert expression
  references only metric names `backend/app/metrics.py` actually exports.

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

Delivery is honest about its limits: **no Alertmanager is shipped**, so
alerts evaluate inside Prometheus (visible in its UI and API at
`/api/v1/alerts`) but nothing pages anyone by itself. Point an Alertmanager
or your existing pager at Prometheus when you need delivery.

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

The datasource (Prometheus at `http://prometheus:9090`) is provisioned from
`grafana/provisioning/datasources/`. **No dashboards are shipped.** Add
them in the UI, or provide a dashboards provider under
`grafana/provisioning/dashboards/` (provider yml + json) and mount it in
`docker-compose.yml` next to the datasources mount. Sensible first panels:
the request-family counters as `rate()`, the recompute histogram via
`histogram_quantile`, the keystore gauge, and the LLM outcome counters.

## Digest pinning (before production use)

The production contract pins image digests; this stack must reach the same
bar before it runs in production. For each image in
`docker-compose.yml` here:

```bash
docker buildx imagetools inspect prom/prometheus:v3.4.1   # or: docker manifest inspect
# copy the manifest-list sha256 digest, then pin it in this file:
#   image: prom/prometheus:v3.4.1@sha256:<64-hex>
```

Pin `grafana/grafana`, `prom/blackbox-exporter`, and (in
`deploy/backup-offsite/`) `rclone/rclone` the same way, and re-resolve on
every deliberate upgrade — exactly the discipline the `db` service's
comment in the production compose file describes. Until then, treat this
stack as dev/staging tooling.

## Verify

```bash
bash deploy/monitoring/verify.sh
```

Runs promtool when installed and always the YAML/structure/metric-grounding
pass via the repo virtualenv (`../../.venv/bin/python`, needs PyYAML;
falls back to any `python3` with PyYAML). Exit 0/1 honestly; prints exactly
what was checked and which metrics each alert uses.
