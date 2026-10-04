# Configuration and retention

Source paths and shell commands in this guide are relative to the repository root.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `MINDPATTERN_ENV` | `production` | Fails closed: only the literal `development` may use the dev secret, SQLite, or /docs; every other value (including unset) takes the production gates |
| `MINDPATTERN_DB_URL` | local SQLite | SQLAlchemy async URL (use `postgresql+asyncpg://…` in prod) |
| `MINDPATTERN_TOKEN_SECRET` | dev default | Legacy/root compatibility HMAC secret — required outside development (≥ 32 chars). Production also requires every purpose-split key below; the root value is no longer an allowed fallback there. Development retains the legacy fallback for local compatibility. |
| `MINDPATTERN_AUTH_TOKEN_SECRET` | *(development: token fallback; production: required)* | Dedicated bearer-token signing secret. Moving to or rotating it changes the token key-scheme version (`ksv`) and invalidates outstanding bearer tokens. ≥ 32 chars. |
| `MINDPATTERN_TOTP_WRAP_SECRET` | *(development: token fallback; production: required)* | Dedicated secret for TOTP-at-rest wrapping and recovery-code digests (internally HKDF-domain-separated). Rotation requires credential migration/reset; ≥ 32 chars. |
| `MINDPATTERN_PAIRING_SECRET` | *(development: token fallback; production: required)* | Dedicated secret for pairing-code HMAC digests. Rotation invalidates live pairing codes; ≥ 32 chars. |
| `MINDPATTERN_SCRYPT_N` | `131072` (2¹⁷) | Server-side scrypt work factor for login verifiers (power of two, 2¹⁵–2²⁰). Raised from 2¹⁶ on 2026-09-26 (login stays well inside the auth latency budget; offline guesses pay 2× the RAM on top of the client-side PBKDF2-600k stretch). Accounts hashed under an older factor fail login after an upgrade until re-registered, or pin this to `65536` for existing fleets |
| `MINDPATTERN_DECOY_SECRET` | *(development: token fallback; production: required)* | Dedicated secret for unknown-username decoy salts. It decouples decoy-salt stability from token-secret rotation; ≥ 32 chars. |
| `MINDPATTERN_METRICS_TOKEN` | *(empty)* | Bearer token for `GET /metrics` (aggregate counters only). Without it the endpoint 404s in every non-development environment — privacy fail-closed (see [operational endpoints](development.md#docker-and-operations)); ≥ 32 chars when set |
| `MINDPATTERN_AUDIT_MAC_SECRET` | *(development: HKDF token fallback; production: required)* | Current HMAC key sealing the versioned access-log chain. It must be exactly 32 bytes of hex (64 chars). Production refuses the derived fallback. |
| `MINDPATTERN_AUDIT_MAC_KEY_VERSION` | `1` | Positive integer written on new audit rows/state. Increment whenever the current audit key changes; never reuse a version. |
| `MINDPATTERN_AUDIT_MAC_PREVIOUS_SECRETS` | *(empty)* | Historical verification ring as comma/newline/space-separated `version:64hex` entries. Keep old keys until all rows/state under them expire. Duplicate versions, duplicate keys, malformed entries, and a collision with the current version fail boot. Use its `_FILE` form in production. |
| `MINDPATTERN_AUDIT_JOURNAL` | *(development: empty; production: required)* | Append-only tail anchor. Production validates and fsyncs the target before serving; append/compaction failures increment `mindpattern_audit_journal_failures_total` and make `/readyz` return 503 until a later durable operation succeeds. Compose wires `/var/lib/mindpattern/audit/journal.log` on `auditjournal`. |
| `<NAME>_FILE` (any secret) | — | File-mounted-secret convention: every credential-bearing variable the app reads (including token/auth/TOTP/pairing/decoy/metrics/audit current+historical keys, `MINDPATTERN_LLM_API_KEY`, and `MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN`) resolves `<NAME>_FILE` when the env value is empty. Unreadable files fail boot. Production Compose exposes only these file paths, never secret values, through container configuration. |
| `MINDPATTERN_TOKEN_TTL` | `86400` | Session-token lifetime in seconds (≤ 30 days; logout revokes the presented token immediately via its `jti`, and credential rotation/password change revoke every token via the epoch bump, so this is only the idle-expiry ceiling) |
| `MINDPATTERN_UNLOCK_DAYS` | `30` | Pattern-revelation threshold |
| `MINDPATTERN_PROCESSING_TTL` | `300` | Processing-session key lifetime (seconds); sessions are single-use |
| `MINDPATTERN_ANALYSIS_BLOB_BUDGET` | `8388608` | Cumulative ciphertext-byte budget bounding which entries one analysis may LOAD — the newest rows are kept whole and older rows are dropped past it, so peak recompute memory follows the analysis budget, never the account's storage quota. It never raises 413 (storage quotas are the `MINDPATTERN_MAX_*` settings) |
| `MINDPATTERN_LLM_URL` | unset | Dormant compatibility configuration for the retained provider/sanitizer helper. Production journal recompute does not call it. Keep unset; reactivation is a product/privacy change requiring code review, current consent/disclosure, vendor approval, and tests. When configured outside development, boot still validates the legacy provider/retention/policy companion fields. |
| `MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN` | *(empty)* | Therapist sharing is **fail-closed OFF in production**: `therapist_sharing_enabled` defaults to true only in development, and enabling it in production requires this controlled enrollment token (≥ 32 chars) with which therapists register. Journal recompute remains deterministic regardless of legacy LLM configuration. |
| `MINDPATTERN_THERAPIST_SHARING_ENABLED` | *(unset → development-only default)* | Explicit boolean override of the sharing default (`1`/`true`/`yes`/`on`, `0`/`false`/`no`/`off` — anything else refuses to boot). Enabling it in production still requires the enrollment token above |
| `MINDPATTERN_AUTH_RATE_LIMIT` / `_WINDOW` | `10` / `60` | Exact sliding-window rate limits for auth and salt lookups (2026-09-26: every limiter is an exact sliding window keyed on the monotonic clock, with sharded overflow locks bounding the key-set's memory — no fixed-window burst-of-2 edge at the boundary); registration conflicts also use a per-username bucket (login intentionally does not, so an attacker cannot spend a victim's lockout budget) |
| `MINDPATTERN_TOTP_FAILURE_LIMIT` | `10` | Per-username second-factor failure budget (distinct from the per-IP auth bucket on purpose: this keyed bucket is reachable only with a valid verifier, so there is no lockout oracle for unauthenticated spray) |
| `MINDPATTERN_ENTRIES_RATE_LIMIT` / `_WINDOW` | `120` / `60` | Entry creation rate limit |
| `MINDPATTERN_PROCESSING_RATE_LIMIT` / `_WINDOW` | `10` / `60` | Processing sessions + recompute rate limit |
| `MINDPATTERN_READ_RATE_LIMIT` / `_WINDOW` | `300` / `60` | Authenticated read/delete endpoints |
| `MINDPATTERN_EXPORT_RATE_LIMIT` / `_WINDOW` | `5` / `60` | Export endpoint rate limit |
| `MINDPATTERN_OPS_RATE_LIMIT` / `_WINDOW` | `240` / `60` | One shared, generous bucket for `/healthz` + `/readyz` — keeps load-balancer probes comfortable while bounding an unauthenticated flood that would otherwise bypass every API bucket and compete for the same pool |
| `MINDPATTERN_MAX_BODY_BYTES` | `2097152` | Whole-request body cap (413 before parsing) |
| `MINDPATTERN_BODY_READ_TIMEOUT` | `30` | Total seconds allowed to receive one request body (408 on timeout; 120-second maximum) |
| `MINDPATTERN_BODY_BUFFER_CONCURRENCY` | `100` | Concurrent-request count the edge body buffer is budgeted against (default matches the Docker entrypoint's `--limit-concurrency 100`; raise it only together with the server's own cap — `MINDPATTERN_MAX_BODY_BYTES` × this must stay within the 512 MiB edge body-buffer memory budget, validated at boot) |
| `MINDPATTERN_MAX_ENTRIES_PER_USER` | `10000` | Per-account entry quota (413 when exceeded) |
| `MINDPATTERN_MAX_USER_BLOB_BYTES` | `268435456` | Per-account total ciphertext quota |
| `MINDPATTERN_RECOMPUTE_ENTRY_LIMIT` | `2000` | Most-recent entries analyzed per recompute (threshold still counts all days) |
| `MINDPATTERN_DB_POOL_SIZE` / `_MAX_OVERFLOW` / `_POOL_TIMEOUT` | `5` / `10` / `30` | Connection pool sizing (`_MAX_OVERFLOW=0` is a legitimate hard cap) |
| `MINDPATTERN_DB_STATEMENT_TIMEOUT_MS` / `MINDPATTERN_DB_IDLE_IN_TX_TIMEOUT_MS` | `30000` / `300000` | Server-side timeouts on every pooled Postgres connection: the first bounds any single query, the second a transaction leaked open (which would pin xmin and block vacuum until noticed). Bounds: 1000–600000 / 1000–3600000 ms |
| `MINDPATTERN_CORS_ORIGINS` | *(empty)* | Comma-separated exact HTTPS origins for browser clients (exact loopback HTTP only in development); empty = no CORS headers (fail-closed) |
| `MINDPATTERN_TRUST_PROXY_HEADERS` | `0` | `1` enables sanitized `X-Forwarded-For` client identity only after the direct peer matches `MINDPATTERN_TRUSTED_PROXY_IPS`; do **not** use Uvicorn `--proxy-headers` |
| `MINDPATTERN_TRUSTED_PROXY_IPS` | *(empty)* | Required comma-separated direct proxy IP/CIDR allowlist when trusting forwarding headers |
| `MINDPATTERN_ACCESS_LOG_RETENTION_DAYS` | `730` | Therapist/patient access-audit metadata retention (1–3650 days) |
| `MINDPATTERN_TEST_DB_URL` | unset | Test-only: runs the pytest suite against an external DB (CI's Postgres job uses it); non-SQLite URLs must contain `test` in the database name |

Invalid numeric values abort startup instead of silently falling back, and
numeric settings carry upper bounds (token TTL ≤ 30 days,
processing-session TTL ≤ 300 s, request-body deadline ≤ 120 s, rate windows ≤ 3600 s, rate limits ≤
100 000/window).

## Deletion & retention scope (read this before operating)

> **Operator/legal pack**: `docs/OPERATOR_PACK.md` indexes the
> signable compliance documents built on the retention facts below — a
> privacy-policy template, the data-retention schedule (every number in
> one table), a subprocessor/BAA register, a security policy + fail-closed
> `security.txt` release generator, plus the DPIA template and incident runbook.
> Read that first when preparing a deployment.

`DELETE /api/account` (password proof required) removes the user and the
**full cascade** from the live database: entries, insights and questions,
PHQ-9/GAD-7/PHQ-2 measures, kept-audio attachment rows, therapist notes about
this patient, consent rows **in both
directions** (shares this patient granted and shares granted TO this
account as a therapist), pairing codes, and any in-memory processing keys
(the keystore is purged for the owner at delete time). Audio object deletion
is queued transactionally before those attachment rows disappear; a durable
object-deletion tombstone remains until the store confirms deletion and is
covered by backlog/age alerts. What deliberately survives on the live
database: **the access audit log** — every
therapist/patient read/write record outlives the deletion for
`MINDPATTERN_ACCESS_LOG_RETENTION_DAYS` (default **730 days**, 1–3650
selectable) as plain metadata (actor, action, target id, timestamp — no
journal content). It does **not** reach: database backups/WAL (retain per
your own policy and expire
them), any reverse-proxy logs in front of the API (this image disables
uvicorn access logs; configure your proxy likewise), or copies previously sent to a provider. Narration-only dispatch is now
disabled; separately opted-in STT/translation and historic provider retention
need the actual provider's deletion policy and consent disclosure. The optional compose
backup service makes retention concrete: every dump taken before a deletion
still holds that user's rows until it ages out, so `BACKUP_RETENTION_DAYS`
(default 35) is the expiry you are promising users — keep it short, encrypt
the dumps (they carry the full metadata set the live DB holds), and
rehearse `pg_restore` before you need it. The versioned export bundle includes
the encrypted entries, insights, all supported wellbeing measures and kept
audio ciphertext; sharing records, consent events and access-log rows; age,
recovery and processing-consent metadata; and canonical `username`, `user_id`,
`salt`, KDF parameters and the v2 key envelope when applicable. Those key
materials let the reviewed desktop/web decryptor recover the encrypted
content after account deletion. Native export remains disabled until a
reviewed streaming-to-file implementation exists.
