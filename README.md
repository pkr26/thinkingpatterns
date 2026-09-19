# MindPattern

A personal pattern-recognition engine for your mental state. Journal daily
(text, on-device encrypted), and after 30 active days the app surfaces the
patterns too large or too slow for a human brain to notice — *"you mention
'work' almost every Sunday, and those days read lower"*, *"the day after
family visits, your entries dip"*, *"the worry 'I can't sleep, my mind
won't stop' has returned nine times across eight weeks"* — plus one
reflective question a day.

**No advice. No diagnosis. No therapy. Pattern observations only — and every
observation shows you its evidence.**

## What's in this repo

| Path | What |
|---|---|
| `RESEARCH.md` | The industry/clinical-research audit behind the engine: every detector mapped to its citation |
| `CHANGELOG.md` | Release notes, plus the running log of the audit/remediation waves |
| `backend/` | FastAPI service (Python 3.12+): entry sync, secure processing session, stateful deterministic "mini-brain" v3 (see below), 30-day threshold, daily questions |
| `backend/tests/` | Unit + API integration + crypto vectors + production-hardening, adversarial red-team, and remediation-regression suites |
| `backend/scripts/seed_demo.py` | Seed a demo account with 84 days of realistic journal + real computed insights (see "Demo") |
| `backend/probe_brain.py` | Ground-truth probe: a planted-pattern corpus the brain must get right (9/9) with zero false associations |
| `mobile/` | React Native (iOS/Android) client: encrypted journal with atomic entry edits, history search + mood calendar, one-tap mood check-in, reflective questions, evidence-view pattern cards, crisis resources, therapist sharing, and scoped offline sync. Export is deliberately disabled pending a reviewed native streaming-to-file implementation. |
| `portal/` | Therapist web portal (React + WebCrypto): patient list, pattern cards with "Why this?" evidence panels, per-pattern drill-down into the decrypted evidence entries, therapist-private encrypted notes (editable, searchable, templates), the "since your last review" delta anchored to an explicit Mark-reviewed action, printable session summaries, caseload triage scan, mood sparklines, 401-expiry + idle auto-lock — read-only by construction |
| `shared/vectors.json` | Cross-platform crypto vectors (backend ⇄ mobile ⇄ portal), including non-ASCII AAD cases and the therapist wrap (ECDH→HKDF→AES-GCM) constructions |
| `shared/crisis_phrases.json` | Cross-platform crisis-language contract (client dialog tier + server suppression tier), consumed by both platforms |
| `shared/generic_questions.json` | Pre-threshold reflective question pool (embedded copies pinned to it by tests) |
| `docker-compose.yml` / `docker-compose.dev.yml` | digest-pinned production deployment contract / explicit local source-build overlay (+ optional profile-gated backup service) |
| `LICENSE` | MIT |

## The mini-brain v3 — pattern kinds and their evidence

The engine is **deterministic** (`update(state, entries, today)` is a pure
function — no clock, no RNG, no network) and **idiographic**: every claim is
computed within-person, against the user's own baseline, never against
population averages. Full citations in `RESEARCH.md`.

| Pattern kind | What it says | Method | Grounding |
|---|---|---|---|
| `temporal` | "'work' concentrates on Sundays" | weekday concentration vs your own writing schedule; exact binomial; **every** candidate weekday tested (not just the argmax), Benjamini–Hochberg FDR across all claims | day-of-week effects: Golder & Macy 2011 (*Science*); Mappiness |
| `mood_correlation` | "entries read lower on days 'work' appears" | **within-person residuals** (your mood minus your own rolling baseline — the intensive-longitudinal standard) + Welch's t on autocorrelation-deflated effective sample sizes + Cohen's d gate | Bolger & Laurenceau 2013; Fisher (idiographic models) |
| `link` | "the day after 'sleep' comes up, entries read lower" | lag-1 day-after association on residuals, same gates; the label reports the **modal exposed gap** (`lag_days` + gap1/gap2 counts) and says "the day after" only when gap 1 is the mode | sleep→next-day mood: Bourke et al. 2026 meta-analysis (118 studies); stress spillover: Bolger et al. 1989 |
| `inertia` | "mood carries over day to day more than usual" | lag-1 autocorrelation, recent vs your earlier norm (Fisher-z difference test) | Kuppens et al. 2010; Houben et al. 2015 meta-analysis |
| `instability` | "bigger daily swings than usual" | spread of within-person residuals, recent vs earlier | affective instability literature |
| `mood_shift` | "entries read lower than your baseline lately" | EWMA control chart (λ=0.18, ±2.7σ, personal baseline) | Snippe et al. 2023; Smit, Schat & Ceulemans 2023 (methods) |
| `rumination` | "the worry 'X' keeps returning" | near-duplicate **negative** phrase clusters + negation-heavy phrasing + absolutist-word density | Ehring & Watkins 2008 (RNT); Al-Mosaiwi & Johnstone 2018 (absolutist words) |
| `topic` | "'guitar' has been taking up more space in your writing" | emergent topic discovery: recurring content n-grams beyond the fixed lexicon (function/theme/sentiment words excluded); RISING topics tested against your own earlier entries (exact binomial, BH) or persistent presence (≥30% of entries — a direct measurement requiring ≥4 distinct following-token contexts, suppressed when ≥80% covered by the run's own recurring-phrase clusters; carries `detail.presence=true`) | bursty recurring topics are a standard diary-analysis signal |
| `recurring_phrase` | "the phrase 'X' keeps returning" | MinHash (64-perm) + LSH (16×4 bands) near-duplicate clustering | — |
| `avoidance` | "the day after 'X' comes up, you go quiet" | theme-days followed by journaling silence vs your own base skip rate (censoring-honest, exact binomial, BH) | avoidance/silence after stressors is a standard diary-analysis signal |
| `cadence` | "your writing rhythm has been less regular" | gap spread, recent vs your earlier norm (Brown-Forsythe) | engagement-rhythm change as a within-person signal |

Patterns carry a **lifecycle** (`candidate → emerging → confirmed → fading →
archived`, 45-day evidence half-life). Statistical kinds (`temporal`,
`mood_correlation`, `link`, `inertia`, `instability`, `mood_shift`) surface
only after qualifying on **≥2 distinct recompute days that constitute an
independent second observation** — evidence-date kinds need a qualification
day contributing NEW evidence; window-stat kinds (computed on a sliding
window — consecutive recomputes share ~179 of 180 days) need qualification
days ≥2 calendar days apart. Consequence: re-running an
unchanged corpus the next day surfaces nothing new. Direct-measurement
kinds (a literally repeated phrase, a persistent topic presence) report
what is in the text and keep immediate surfacing. A **semantic flip**
(dominant weekday, direction) retires the old pattern-id to fading and
forks a fresh `~2` id instead of silently relabeling under an intact
history. The app renders lifecycle states as evidence labels ("early
evidence" / "established" / "fading") with a **"Why am I seeing this?"
panel** per card — window, sample size, effect size, significance, and the
method in plain language.

Entries can carry **structured channels** (payload v2): a 1-5 sleep rating, an energy pick,
and activity tags. Poor-sleep nights (strictly below YOUR median rating) and recurring
proper names (person anchoring) ride the same theme machinery as every lexicon word —
same gating, same correction, rating-aware copy. Question feedback ("this resonated /
not me") is encrypted on-device, rides the next recompute as an opaque blob, and
reorders future questions.

Sentiment is a **graded lexicon engine** (curated-over-VADER: 7,200+ graded words +
emoji valence, the curation rules winning word-for-word: graded valences,
intensifiers, damped negation, "but" re-weighting — Hutto & Gilbert 2014),
deterministic and self-contained. The lexicon is curated: context-dependent
words ("kind", "fed", "present") were removed after measurement, and
"hardly"/"barely" are negation-only (VADER's treatment — never downtoners).

**Honesty guarantees, enforced by the backend regression suite:** base-rate correction
(a Sunday-heavy journaler gets no fake "everything happens on Sundays"),
one Benjamini–Hochberg FDR family per run spanning every statistical claim
— every testable candidate's p-value is computed **pre-gate** and the
effect-size gates filter only the corrected survivors (selecting on
extremeness first is selection-then-test and voids FDR control),
within-person detrending (a mood *trend* cannot manufacture
associations — the failure mode our probe demonstrated on v2 and now pins
as a regression test), corrupt-state → amnesia, determinism, and bounds on
everything.

**Deliberately absent** (see RESEARCH.md): relapse-*prediction* claims
(FDA wellness boundary), diagnosis language of any kind, bipolar flagging,
and critical-slowing-down signals (mixed replications).

## Demo

The 30-day threshold is honest design but makes the brain unjudgeable in a
five-minute demo — so seed an account whose history already exists:

```bash
cd backend
# terminal 1: the API (dev sqlite)
MINDPATTERN_ENV=development MINDPATTERN_DB_URL="sqlite+aiosqlite:///./demo.db" ../.venv/bin/uvicorn app.main:app --port 8000
# terminal 2: 84 days of realistic, structure-planted journal
../.venv/bin/python scripts/seed_demo.py \
  --db-url "sqlite+aiosqlite:///./demo.db" --username demo --password 'demo-patterns-2026'
```

The script uses the real client-side crypto (the app's own KDF + AES-GCM
path, pinned by `shared/vectors.json`) and the real API — the server only
ever sees opaque blobs and one single-use key. It prints the patterns the
brain surfaced; sign into the app as `demo` with the password you provided
to see the same cards. `probe_brain.py` runs the ground-truth check offline
(9/9).

## Sharing with a therapist (the zero-knowledge path)

A patient can let their therapist see every pattern and, one click deeper,
the entries behind it — without the server ever being able to read
anything:

1. **Therapist accounts** register through the portal with a P-256 wrap
   keypair; the server stores the public key and the PRIVATE key only as
   a blob encrypted under a password-derived HKDF subkey. One username
   namespace, two roles (`users.role`) — journal routes reject therapist
   tokens and therapist routes reject patient tokens (403 at the
   dependency layer). There is no therapist write path to patient data:
   read-only is the absence of endpoints, not a UI convention.
2. **Pairing**: the portal shows a short-lived (15 min), single-use code
   plus the therapist's **key fingerprint** (SHA-256 of their wrap key,
   first 8 bytes: `A1B2 C3D4 …`); the patient types the code, sees the
   therapist's NAME and public key — including the same fingerprint —
   confirms against an explicit disclosure, and re-authenticates with
   their password. Reading the two fingerprints back to each other is the
   out-of-band check: the server relays the wrap key during lookup, and a
   dishonest server could otherwise substitute its own key — a matching
   fingerprint read over the phone (or in the room) is the human proof
   the key belongs to the therapist. The app then wraps its data key to
   the therapist's public key (ECDH → HKDF, salt = both SPKI keys →
   AES-256-GCM, AAD bound to the patient/therapist pair) and uploads one
   small blob. The code burns in the same transaction (an atomic
   conditional UPDATE — concurrent redeems cannot both win). Codes are
   stored only as HMACs; unknown/expired/consumed all answer the same 404.
3. **Reads**: the portal unwraps the data key locally after login and
   decrypts the SAME blobs the patient's app decrypts — insights
   (byte-identical to `GET /insights`) and entries (paginated, date
   windows). Every surfaced pattern now carries `detail.evidence_dates`
   (the capped days whose entries fed it) and `detail.pattern_pid`, which
   power the drill-down: the portal fetches exactly those days, decrypts
   the entries, and highlights label occurrences with per-entry mood.
   Sensitive (crisis-adjacent) cards render non-quoting, as in the app.
4. **Notes** are the therapist's own record: encrypted under the
   therapist's password-derived key in the browser, attachable to a
   patient or a pattern, surviving a revoke and dying with either
   account. Patients cannot read them.
5. **Revoke** (password-gated) clears the wrapped key — future access
   ends immediately. What was already read cannot be unread; the grant
   disclosure says so plainly. Re-granting reactivates the same consent
   row (note continuity for the therapist). Every grant/revoke and every
   patient-data read/write is audit-logged; the access log outlives
   account deletion.
6. **Compliance flag**: sharing journal data with clinicians moves an
   operator into health-data territory (HIPAA BAA in the US or
   equivalent). The architecture (explicit consent records with
   disclosure versions, revocation, access audit) is built for it; the
   operator obligations are real.

## Safety

* **Crisis resources are built in and offline**: a "Get help" screen (988
  call/text, Crisis Text Line 741741, 911 guidance, findahelpline.com) is
  one tap from every screen, follows safe-messaging practice (#chatsafe),
  and never depends on the API being up.
* **Crisis-language handling is one cross-platform contract**
  (`shared/crisis_phrases.json`): a conservative `dialog` tier runs
  client-side, pre-encryption, over what the user just typed; the broader
  suppress tier (`dialog` + `suppress_extra`) keeps crisis-adjacent
  patterns out of question generation and card quotes. Crisis-adjacent
  patterns surface with `detail.sensitive=true`, and the app renders a
  non-quoting card ("A difficult thought has been returning…") with a
  support link instead of echoing the text back.
* **Observations, not verdicts**: no advice, diagnosis, or prediction
  anywhere — including the optional LLM path, whose output is sanitized,
  corpus-anchored, and restricted to the verifiable pattern kinds.
* The pre-threshold phase shows **device-local value only** (streak + mood
  trend computed on-device, never synced); the analysis threshold is
  enforced server-side.

## The security model (honest version)

1. **Keys are derived on your device.** `master = PBKDF2-HMAC-SHA256(password, salt, 600k)`; HKDF splits it into an `auth_key` (sent at login; the server stores `scrypt(auth_key)` with N=2¹⁶) and a `data_key` that encrypts everything.
2. **The server is blind to content — with one deliberate exception.** Entries/insights/questions are AES-256-GCM blobs (`nonce‖ct‖tag`), AAD-bound to `(user, entry, context)`, so blobs can't be relocated undetected and a DB leak yields no plaintext. The exception: to compute insights, the client sends the `data_key` in a **single-use** processing session (over TLS, memory-only, destroyed the moment the recompute consumes it, purged on account deletion). During that request the server can read your entries — that is the design trade-off of v1 (server-side analysis). On-device analysis is the path to removing it.
3. **Processing is bounded.** Nothing is decrypted before the 30-day threshold. After it: decrypt → analyze → re-encrypt, keys and plaintext buffers owned by the enclave are zeroized (`bytearray`-scrubbed). The enclave keeps **one** zeroized working copy of the data key per recompute run — minting a fresh immutable `bytes(key)` per item would leave N unzeroized copies for the GC. Honest scope: the analyzer itself creates Python/JS string copies of your text that only GC reclaims; a process memory image can still contain them. TEE-style guarantees are deployment work.
4. **Progressive revelation is enforced server-side.** Patterns are only computed, stored, and served after 30 distinct active days. Entry dates can't predate the account (backdating can't fast-forward the gate) and may be at most server-today + 1 day (device-local timezone grace). Before the threshold the client sees only its own device-local mood trend.
5. **Enumeration resistance — scoped truthfully.** Salt lookup (POST /api/auth/salt) never reveals account existence per request (deterministic decoys, identical for unknown and deactivated accounts). Registration must, like any name-based system, answer whether a name is taken; it is rate-limited per-IP **and** per-username to make mass probing impractical. The residual oracle is longitudinal: a name's salt changes decoy → real when it registers and real → decoy on deactivation, so a watcher who re-probes the same name over time learns the membership transition. That transition leak is inherent to name-based systems — the salt has to change hands at some point — and is stated, not claimed away.
6. **Destructive actions re-authenticate.** `DELETE /api/account` and enabling LLM analysis require the password-derived verifier — a stolen bearer token cannot erase a journal. `POST /api/auth/logout` bumps a token epoch that revokes every token for the account.
7. **Metadata the server does hold** (be aware of it): usernames, per-entry calendar dates and received timestamps, entry ciphertext sizes, insight dates. A DB leak reveals *when* and *how much* you wrote — never *what*.
8. **Optional LLM analysis is opt-in per user.** If the operator configures `MINDPATTERN_LLM_URL`, journal text is only sent to that third-party endpoint for accounts that explicitly consented (re-authenticated toggle in Settings, with the disclosure that named-provider retention applies), only post-threshold, with model output sanitized (labels length-capped, "recurring phrases" verified against your actual text, numerics clamped). Enabling records `llm_consent_at` + `llm_consent_disclosure` ("v1") on the account — cleared on disable, and included in the export bundle, so the GDPR record of what was consented to (and when) travels with the user's own data. Off by default for every account.
9. **Therapist sharing keeps the server blind.** The patient's client
   wraps the data key to the therapist's public P-256 key (the server
   stores the wrap, never a usable key); the portal unwraps it locally.
   Honest residual: the server *relays* the therapist's public key during
   pairing, so an actively dishonest server could substitute its own key
   and read the grant — the pairing fingerprint check (both humans read
   the same 8-byte SHA-256 of the key) is the out-of-band mitigation;
   without it, pairing trusts the server for identity discovery.
   See "Sharing with a therapist" above for the full lifecycle, including
   the honest revocation limit: revocation ends ACCESS, it cannot unread
   what a browser already decrypted.
10. **Transport & ops hardening.** Non-development boots with OpenAPI/docs disabled and refuses the dev token secret and SQLite in every non-development environment (fail-closed). Every response — including 500s, 413s, and slow-body timeouts — carries `nosniff`/`DENY`/`no-referrer`/`no-store` plus HSTS (`strict-transport-security: max-age=31536000; includeSubDomains`). Request bodies are capped at 2 MiB and have a bounded complete-read deadline before parsing; validation errors never echo input. Ciphertext-list pages are byte-bounded and use explicit continuation headers, so an oversized journal cannot turn one screen request into an unbounded response. Rate limiting covers auth, entries, processing, reads, and deletes. Forwarded client addresses are accepted only when the raw socket peer matches an explicit proxy allowlist; Uvicorn proxy-header rewriting remains disabled. Access logs are disabled in the image. Server export is streamed, while the mobile UI keeps export disabled until native streaming-to-file is reviewed. Per-account quotas bound storage and recompute cost.

The mobile client keeps derived keys memory-only: after an app restart the session token is still valid but the key vault is locked behind an unlock screen, and navigation is tri-state (no login-flash race). The session token itself is AES-256-GCM-encrypted under a random per-install device key held only by iOS Keychain/Android Keystore through `react-native-keychain`; there is no AsyncStorage key fallback. If that native secure-storage seam is unavailable, sign-in fails closed. The offline sync queue is scoped to both API origin and account; server error text is sanitized before reaching dialogs, and the app switcher sees only a blank shield. Sync is deliberately **push-only**: v1 is a single-device-writer design — entries push up, and the History screen pulls this account's entries back (same-device restore, new device). There is no multi-device conflict model.

## API surface & error contract

All routes mount under **`/api/v1`** (canonical); the same routers are also served under **`/api`** as a deprecated legacy alias for existing clients. `GET /api/v1/meta` returns `{unlock_days, llm_available, api_version, version}` — `api_version` is how a client discovers the canonical base. Alongside `GET /healthz` (liveness only, no DB touch), **`GET /readyz`** runs `SELECT 1` against the database and answers 503 when it fails — that is the probe to gate deploys on. `DELETE /api/v1/account` takes the verifier in the **`X-Account-Verifier`** header (a JSON body is still accepted as a deprecated fallback — DELETE bodies are unreliable across clients and proxies).

Every error response is one envelope: **`{"detail": <human string>, "code": <snake_case>}`**. The codes: `unauthorized`, `invalid_credentials`, `processing_session_required`, `processing_session_invalid`, `verification_failed` (403 — wrong verifier on a re-authenticated action), `not_found`, `request_timeout` (408), `conflict`, `account_deleted` (410 — the account was deleted mid-request), `payload_too_large`, `quota_exceeded`, `blob_quota_exceeded`, `validation_error` (never echoes input), `rate_limited` (+ `Retry-After`), `bad_request`, `entry_blob_invalid`, `entry_payload_malformed`, `internal_error`, `service_unavailable`.

## Running

```bash
# Backend (dev) — Python 3.12+
# NOTE: the app fails closed (MINDPATTERN_ENV defaults to production), so
# every local non-Docker command below opts into development explicitly.
cd backend
python3 -m venv .venv && source .venv/bin/activate   # or: uv venv
python -m pip install --require-hashes -r requirements.dev.lock.txt
MINDPATTERN_ENV=development uvicorn app.main:app --reload   # http://localhost:8000/docs

# Full stack from local source (postgres + API). The production compose file
# deliberately has no source builds; the explicit overlay below is required
# for local work only. See deploy/README.md for digest-pinned production.
cat > .env <<EOF
MINDPATTERN_TOKEN_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
BACKUP_KEY=$(openssl rand -base64 32)
MINDPATTERN_API_IMAGE=mindpattern-api:local
MINDPATTERN_BACKUP_IMAGE=mindpattern-backup:local
EOF
docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.dev.yml up --build

# Optional backups — profile-gated, never started by a plain `up`:
docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.dev.yml \
  --profile backups up -d backup
# Daily pg_dump -Fc into the pgbackups volume. BACKUP_RETENTION_DAYS
# (default 35) IS the deletion promise against backups — set it to the
# expiry you actually promise users, encrypt the dumps (they carry the
# full metadata set), and rehearse `pg_restore` before you need it.

# Mobile source (native projects are currently absent; see release preflight)
cd mobile && npm ci

# Mobile tests — real crypto modules against shared vectors + queue/client/screen regressions
cd mobile && npm test

# Cross-platform crypto check over the REAL compiled modules
node mobile/tools/verify_vectors.mjs

# Ground-truth probe: planted-pattern corpus, 9/9 must pass
cd backend && ../.venv/bin/python probe_brain.py

# Decrypt your ciphertext export locally (password never leaves the machine)
node mobile/tools/decrypt_export.mjs --bundle export.json
```

Crash reporting still ships absent (a deliberate privacy posture), but
production visibility grew a `/metrics` endpoint (2026-09-17): aggregate
counters only — status-code families, recompute-duration histogram, LLM
failure counts, keystore length — behind `MINDPATTERN_METRICS_TOKEN`
(fail-closed: without the token the endpoint 404s in production).

## Database & migrations

Schema changes ship as Alembic revisions (`backend/alembic/`) — the tree
now carries multiple revisions, so adoption below matters. The container
entrypoint runs `alembic upgrade head` against `MINDPATTERN_DB_URL` **before
starting uvicorn** (retrying 5× at 3s intervals, then failing closed — a
container must not serve against an unmigrated schema). Both the local
source-build command above and the production command in `deploy/README.md`
run this migration gate before serving. The app's startup
`create_all` runs only with `MINDPATTERN_ENV=development` (dev/test), never
in a deployed container. On Postgres, the migration session takes a
session-level advisory lock (`pg_advisory_lock(727272)`) with
`lock_timeout=15s` / `statement_timeout=300s`, so concurrent first-boots of
several replicas serialize instead of racing the same DDL. A database
created by a pre-migrations (create_all-era) deploy must be adopted once
with `alembic stamp head` so future revisions don't collide with existing
tables. Migration tooling reads `MINDPATTERN_DB_URL` directly — it does not
import the app config and needs no token secret. Operator workflow,
adoption, and autogenerate instructions: `backend/alembic/README.md`.

Runtime shape, briefly: `insights` carries
`UniqueConstraint(user_id, kind, for_date)` and writes are dialect upserts
(`on_conflict_do_update`), so concurrent workers can't duplicate a day's
row; question rows older than 90 days are purged during recompute;
recompute reads are SQL-bounded (`LIMIT recompute_entry_limit`) and never
hold a transaction across the analysis (the write phase is a second, short
transaction); and the connection pool is env-configurable
(`MINDPATTERN_DB_POOL_SIZE` / `_MAX_OVERFLOW` / `_POOL_TIMEOUT`, defaults
5/10/30).

## Testing

```bash
cd backend

.venv/bin/python -m pytest                     # full suite (includes 600k-iteration vectors)
.venv/bin/python -m pytest -m "not slow"      # fast path (what mutmut uses)

# The same suite against real Postgres (what CI's backend-postgres job does):
MINDPATTERN_TEST_DB_URL="postgresql+asyncpg://…/mindpattern_test" .venv/bin/python -m pytest

# Deep mutation testing over the security + services cores
# (see reports/mutation_report.md for scope and caveats)
PATH="$PWD/../.venv/bin:$PATH" ../.venv/bin/mutmut run
../.venv/bin/mutmut results                   # triage
../.venv/bin/mutmut show <id>                 # inspect a mutant
```

CI (`.github/workflows/ci.yml`) runs eight jobs: the backend suite on a
Python 3.12 + 3.14 matrix (97% coverage floor), the same suite against real
Postgres (`backend-postgres`, via `MINDPATTERN_TEST_DB_URL`), the mobile
and portal suites (typecheck, tests, production build, and hard dependency
audits), contract gates
(`probe_brain.py` must go 9/9; `verify_vectors.mjs` over the real compiled
modules), a Docker job (image build + compose boot asserting `/healthz`,
`/readyz`, `alembic current` at head, and a verified authenticated backup
restore), lint (ruff check + formatting + mypy), and supply-chain
(`pip-audit` on the pinned lock file). The release workflow repeats these
gates before publishing multi-architecture images; prerelease tags never
move the `latest` image tag.
Deep mutation testing runs weekly via `.github/workflows/mutation.yml`
(scheduled, resumable cache, results artifact — deliberately not a PR
gate), and Dependabot watches pip, npm, github-actions, and docker.
Between schedules, `.github/workflows/mutation-pr.yml` gates pull
requests incrementally: every hand-written behavioral mutant
(`redteam/mutation_campaign_*/`) whose target file is in the diff is
re-applied and must stay killed, plus a bounded diff-scoped `mutmut` run
where survivors fail the PR. Hand-written campaign history: round 1 —
36 mutants over the non-negotiables, 36/36 post-pins
(`reports/mutation_campaign_2026-09-18.md`); round 2 — 70 mutants over
brain round 2, the threshold, crypto contracts, crisis handling, ops,
idiographic isolation, the sync queue, and the red-team harnesses
themselves as oracles (`reports/mutation_campaign_2026-09-18_round2.md`,
which also records the first portal Stryker campaign — baseline 1.41% —
and the scoped mobile re-runs); round 3 — 62 mutants over backend
infrastructure: authorization & access control, database/ORM, boundaries,
error handling & transactions, cache/invalidation, and rate
limiting/concurrency (`reports/mutation_campaign_2026-09-19.md`, 46 killed
+ 14 new pins + 2 documented residuals).
`.pre-commit-config.yaml` mirrors the ruff gate locally.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `MINDPATTERN_ENV` | `production` | Fails closed: only the literal `development` may use the dev secret, SQLite, or /docs; every other value (including unset) takes the production gates |
| `MINDPATTERN_DB_URL` | local SQLite | SQLAlchemy async URL (use `postgresql+asyncpg://…` in prod) |
| `MINDPATTERN_TOKEN_SECRET` | dev default | HMAC secret for session tokens — must be set outside development (≥ 32 chars, or the app refuses to boot) |
| `MINDPATTERN_UNLOCK_DAYS` | `30` | Pattern-revelation threshold |
| `MINDPATTERN_PROCESSING_TTL` | `300` | Processing-session key lifetime (seconds); sessions are single-use |
| `MINDPATTERN_LLM_URL` | unset | HTTPS OpenAI-compatible endpoint for the optional LLM analyzer (exact loopback HTTP only in development); per-user consent still required; unset = deterministic mini-brain |
| `MINDPATTERN_AUTH_RATE_LIMIT` / `_WINDOW` | `10` / `60` | Fixed-window rate limits for auth and salt lookups; registration conflicts also use a per-username bucket (login intentionally does not, so an attacker cannot spend a victim's lockout budget) |
| `MINDPATTERN_ENTRIES_RATE_LIMIT` / `_WINDOW` | `120` / `60` | Entry creation rate limit |
| `MINDPATTERN_PROCESSING_RATE_LIMIT` / `_WINDOW` | `10` / `60` | Processing sessions + recompute rate limit |
| `MINDPATTERN_READ_RATE_LIMIT` / `_WINDOW` | `300` / `60` | Authenticated read/delete endpoints |
| `MINDPATTERN_EXPORT_RATE_LIMIT` / `_WINDOW` | `5` / `60` | Export endpoint rate limit |
| `MINDPATTERN_MAX_BODY_BYTES` | `2097152` | Whole-request body cap (413 before parsing) |
| `MINDPATTERN_BODY_READ_TIMEOUT` | `30` | Total seconds allowed to receive one request body (408 on timeout; 120-second maximum) |
| `MINDPATTERN_MAX_ENTRIES_PER_USER` | `10000` | Per-account entry quota (413 when exceeded) |
| `MINDPATTERN_MAX_USER_BLOB_BYTES` | `268435456` | Per-account total ciphertext quota |
| `MINDPATTERN_RECOMPUTE_ENTRY_LIMIT` | `2000` | Most-recent entries analyzed per recompute (threshold still counts all days) |
| `MINDPATTERN_DB_POOL_SIZE` / `_MAX_OVERFLOW` / `_POOL_TIMEOUT` | `5` / `10` / `30` | Connection pool sizing (`_MAX_OVERFLOW=0` is a legitimate hard cap) |
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

`DELETE /api/account` (password proof required) removes the user, entries,
insights, and in-memory processing keys from the live database. It does
**not** reach: database backups/WAL (retain per your own policy and expire
them), any reverse-proxy logs in front of the API (this image disables
uvicorn access logs; configure your proxy likewise), or a third-party LLM
provider's copies if a user consented to LLM analysis (provider retention
is out of our hands — surface that in consent copy). The optional compose
backup service makes retention concrete: every dump taken before a deletion
still holds that user's rows until it ages out, so `BACKUP_RETENTION_DAYS`
(default 35) is the expiry you are promising users — keep it short, encrypt
the dumps (they carry the full metadata set the live DB holds), and
rehearse `pg_restore` before you need it. The export bundle
includes `user_id` and `salt` so `mobile/tools/decrypt_export.mjs` can
turn it back into readable files offline.

## Scope decisions

- **The mini-brain v3** (`app/services/brain.py`) is described in the table
  above. The whole engine is deterministic; a corrupt or tampered brain
  state degrades to amnesia, never a bricked account. Recompute is only
  ever explicit: the Question screen's button opens the single-use
  processing session itself — no screen ships the data key automatically
  (the at-most-daily auto-refresh was removed after the red-team audit).
- The default analyzer is **deterministic**; the LLM path is INVERTED
  (2026-09-17): the model receives the brain's findings and may only
  attach one sanitized narrative to them — label-restricted by
  construction, it cannot mint claims that bypassed the statistics. It
  remains consent-gated, threshold-gated, and untested-by-unit-suite by
  design (its `_post` is monkeypatched in tests).
- The enclave is an in-process seam (`app/security/enclave.py`); SGX/TEE
  attestation is deployment work, not application logic.
- Single-process deployment: the rate counter, keystore, and token epochs
  assume one worker per instance (scale horizontally behind a shared
  counter when needed).
- Password change / key rotation remains out of scope (documented,
  deliberate). A leaked password requires account recreation; a leaked
  token dies at logout (epoch bump) or expiry.
- Mobile repo contains JS/TS source only; `ios/`/`android/` projects are
  generated with the React Native toolchain when building. TLS certificate
  pinning and native hardening (`FLAG_SECURE`, `allowBackup=false`) are
  native-project work items — the checklist lives in `mobile/README.md`.
- Time-of-day analysis (the "Sunday **evening**" refinement) requires a
  client payload extension — the entry contract (`v:1`, date-only) is
  versioned for exactly this.

## Red-team audit & remediation (2026-09-16)

A full adversarial audit ran as executable attack harnesses (`redteam/`,
report in `reports/redteam_audit_2026-09-16.md` — 96 verdicts). Every
fixable finding was remediated and pinned by regression tests; the
post-fix campaign re-run shows 63 attacks blocked with the remainder
documented as design residuals. Headlines: crisis-language normalization
on both engines (leetspeak/homoglyph/zero-width/non-English bypasses
closed, 30/35 -> 1/35), the phi=1.0 recompute crash fixed, the data key
now refuses plain HTTP, multi-worker boots are refused by a deployment
lock, KDF iteration floors and nonce-seam removal on both platforms, LLM
generation limits + spelled-contact rejection + 10s timeout, TTL ceiling
aligned with the consent copy, encrypted backups (required BACKUP_KEY),
and a username-free export bundle. See CHANGELOG "2026-09-16 red-team
remediation wave" for the full list.

## Post-audit changelog (security remediation)

This codebase underwent a multi-pass adversarial audit; all findings were
fixed or explicitly documented above. Highlights: scrypt moved off the
event loop (and N raised to 2¹⁶); register enumeration throttled
per-username with uniform work; salt lookup moved to POST with decoys;
tokens gained epoch revocation + logout; account deletion and LLM
enablement require re-authentication; baseline-phase recompute decrypts
nothing; processing sessions are single-use with key zeroization; LLM path
is consent-gated and output-sanitized; whole-body size cap + 422
input-echo removal + headers on 500s; multi-line XFF parsing + bounded
rate-counter memory + delete-endpoint rate limits; backdating blocked;
per-account quotas + streamed export; offline queue account-binding +
wipe races + loud capacity; login-flash tri-state; app-switcher privacy
shield; TS↔Python AAD canonicalization pinned with non-ASCII vectors.

## v3 changelog (analysis remediation)

The v2 engine was audited against a ground-truth corpus (`probe_brain.py`)
and clinical methodology (RESEARCH.md). Findings fixed: raw pooled mood
correlations manufactured false claims during any mood trend (now
within-person residuals — the intensive-longitudinal standard); the
weekday test selected the argmax day before testing (anti-conservative
~7×; now every candidate weekday enters the FDR family); binary sentiment
(now a graded VADER-style engine); no linking (now lag-1 day-after links);
no dynamics (now inertia + instability); recurring phrases were
sentiment-blind (negative clusters now surface as rumination with
absolutist density); EWMA λ moved into the validated 0.05–0.25 band; phrase
pattern-ids anchored on their earliest member (stable lifecycle). Added:
crisis resources screen (offline, safe-messaging), evidence panel per
pattern card, device-local baseline-phase mood trend, the demo seeder, and
emergent topic discovery (the audit's topic-blindness finding — the lexicon
no longer bounds what the brain can talk about).

A second independent audit of the v3 work was then applied: every weekday
candidate now enters the FDR family (not just the best); non-finite client
mood tags are rejected at the parse layer and clamped in the engine; the
device-local mood log is AES-256-GCM encrypted under the data key
(AAD-bound to the account, legacy plaintext migrates transparently);
high-frequency journal verbs can no longer surface as "topics".
**Migration note:** phrase/rumination pattern-ids changed format
(representative text → hash anchored on the cluster's earliest member), so
patterns stored by the pre-v3 brain orphan once and age out through the
fade → archive → drop lifecycle instead of being silently re-labeled.

## Post-audit remediation #2 (red-team round)

A second multi-pass adversarial audit found and this pass fixed:

* **Analysis runs on server-validated dates only.** The brain previously
  trusted the client-controlled `created_at` inside the encrypted blob —
  one entry dated year 3000 overflowed the decay math and 500-bricked
  every future recompute (reproduced end-to-end). The inner date is now
  sanity-checked against the stored `entry_date` (±1 day), decay weights
  are clamped, and `OverflowError` is handled.
* **Statistical honesty:** inertia/instability/mood-shift claims now carry
  real p-values inside the Benjamini–Hochberg family (they previously
  bypassed correction); the EWMA chart inflates its limits for
  autocorrelated mood (measured ~18% false alarms on stationary AR(1)
  series, now ≤2/12 in the regression sim); two *constant* mood groups can
  no longer fabricate p≈1e-22 from the variance floor alone; rising-topic
  claims are corrected for the full candidate family and require a
  substantial relative gain (false rising-topic windows on pure noise:
  66/100 → 19/100); corpus-boilerplate words ("unique day") can no longer
  surface as topics; pattern labels are capped at write time.
  *Honest residual, re-measured after the later full-family-BH and
  replication-gate fixes (which supersede the ~29% figure this pass
  reported):* single-shot pure-noise runs now surface **0** false
  statistical cards (0/60); daily-cadence pure noise (14 recomputes over a
  growing corpus) surfaces ≥1 false card in ≤1/24 runs (4.2%), and the one
  surviving card is a documented FDR-budget boundary case — a fluke weekday
  concentration at p ≈ 5e-4 that the q = 0.05 correction legitimately
  calls a discovery, corroborated the next day by a chance mention — not a
  gate leak. Regression-pinned by
  `test_daily_cadence_pure_noise_replication_bound` in `tests/test_brain.py`.
* **Crisis interlock:** rumination/recurring-phrase patterns whose label
  is crisis-adjacent (suicidal ideation, self-harm) are excluded from
  question generation — the app never asks the user to reflectively engage
  with such a thought; the offline crisis-resources screen is the path.
  The mobile app additionally exposes crisis resources from the login and
  locked screens, and can unlock the vault offline from a cached salt.
* **Ops fail-closed gaps:** `MINDPATTERN_ENV` is normalized (case/
  whitespace typos no longer disarm production gates); the ≥32-char token
  secret floor applies to every non-development environment; empty
  secrets are treated as unset; numeric settings are range-validated
  (0/negative abort startup); registration issues the token before the
  row commits.
* **Availability:** per-user locking makes the storage quota race-free
  (30 concurrent creates against a 5-entry quota now store exactly 5);
  baseline-phase recomputes load dates only (no ciphertext pull); analysis
  text is capped per entry and per recompute; overlong sentences are
  excluded from phrase clustering and LSH buckets are pair-capped (a
  crafted 400 KB corpus cost 127 s of pairwise comparison, now bounded);
  recomputes run on a dedicated capacity limiter so they cannot starve
  login scrypt on the shared thread pool.
* **Rate limiting:** registration's per-username bucket counts only real
  name conflicts (anonymous garbage probes cannot lock out a prospective
  user); login remains source-rate-limited rather than name-locked so a
  distributed attacker cannot spend a victim's lockout budget. IPv6 clients
  aggregate to /64; eviction prefers single-hit garbage over active
  multi-hit buckets.
* **Integrity:** SQLite enforces foreign keys (`PRAGMA foreign_keys=ON`),
  so `ondelete=CASCADE` is real and post-deletion stragglers become
  orphan-proof; only unique-constraint failures map to 409; processing
  sessions are single-use by atomic `pop()` (mechanism, not scheduling).
* **LLM sanitizer:** every label is corpus-grounded (prompt-injected
  "URGENT call 555-0134" labels are rejected) and URL/phone-free;
  non-finite numerics (NaN/Infinity) are dropped and all numerics are
  bounded, so a hostile model can no longer write invalid JSON into the
  insights blob.
* **Mobile:** changing the server URL clears the session (a live token +
  data key can no longer be silently repointed at an attacker's origin);
  sign-out preserves the offline queue (unsynced entries are no longer
  destroyed); a corrupt queue is quarantined, not deleted; enqueue is
  TOCTOU-safe; the legacy plaintext mood log migrates on first read; the
  vault auto-locks on background; the daily recompute stamp is per-account
  with an in-flight guard; entry/mood dates use device-local time; the
  account-deletion path clears mood log, stamps, cached salt and queue;
  server error text strips bidi/zero-width characters; off-origin
  redirects are refused.
* `probe_brain.py` now exits non-zero on any FAIL (it can gate CI).

The CI workflows are the current source of truth for test totals: they run
the backend matrix plus PostgreSQL, the 9/9 brain probe, mobile and portal
type/test/build/audit gates, and cross-platform crypto vectors from clean
dependency installs.

## License

MIT — see `LICENSE`.
