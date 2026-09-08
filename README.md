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
| `backend/` | FastAPI service (Python 3.12+): entry sync, secure processing session, stateful deterministic "mini-brain" v3 (see below), 30-day threshold, daily questions |
| `backend/tests/` | 560-test suite: unit + API integration + crypto vectors + production-hardening + adversarial red-team + remediation regressions |
| `backend/scripts/seed_demo.py` | Seed a demo account with 84 days of realistic journal + real computed insights (see "Demo") |
| `backend/probe_brain.py` | Ground-truth probe: a planted-pattern corpus the brain must get right (9/9) with zero false associations |
| `mobile/` | React Native (iOS/Android) client: encrypted journal, evidence-view pattern cards, crisis resources, baseline-phase mood trend |
| `shared/vectors.json` | Cross-platform crypto vectors (backend ⇄ mobile), including non-ASCII AAD cases |
| `docker-compose.yml` | postgres + api for local dev |

## The mini-brain v3 — pattern kinds and their evidence

The engine is **deterministic** (`update(state, entries, today)` is a pure
function — no clock, no RNG, no network) and **idiographic**: every claim is
computed within-person, against the user's own baseline, never against
population averages. Full citations in `RESEARCH.md`.

| Pattern kind | What it says | Method | Grounding |
|---|---|---|---|
| `temporal` | "'work' concentrates on Sundays" | weekday concentration vs your own writing schedule; exact binomial; **every** candidate weekday tested (not just the argmax), Benjamini–Hochberg FDR across all claims | day-of-week effects: Golder & Macy 2011 (*Science*); Mappiness |
| `mood_correlation` | "entries read lower on days 'work' appears" | **within-person residuals** (your mood minus your own rolling baseline — the intensive-longitudinal standard) + Welch's t + Cohen's d gate | Bolger & Laurenceau 2013; Fisher (idiographic models) |
| `link` | "the day after 'sleep' comes up, entries read lower" | lag-1 day-after association on residuals, same gates | sleep→next-day mood: Bourke et al. 2026 meta-analysis (118 studies); stress spillover: Bolger et al. 1989 |
| `inertia` | "mood carries over day to day more than usual" | lag-1 autocorrelation, recent vs your earlier norm | Kuppens et al. 2010; Houben et al. 2015 meta-analysis |
| `instability` | "bigger daily swings than usual" | spread of within-person residuals, recent vs earlier | affective instability literature |
| `mood_shift` | "entries read lower than your baseline lately" | EWMA control chart (λ=0.18, ±2.7σ, personal baseline) | Snippe et al. 2023; Smit, Schat & Ceulemans 2023 (methods) |
| `rumination` | "the worry 'X' keeps returning" | near-duplicate **negative** phrase clusters + negation-heavy phrasing + absolutist-word density | Ehring & Watkins 2008 (RNT); Al-Mosaiwi & Johnstone 2018 (absolutist words) |
| `topic` | "'guitar' has been taking up more space in your writing" | emergent topic discovery: recurring content n-grams beyond the fixed lexicon (function/theme/sentiment words excluded); RISING topics tested against your own earlier entries (exact binomial, BH) or persistent presence (≥30% of entries, a direct measurement) | bursty recurring topics are a standard diary-analysis signal |
| `recurring_phrase` | "the phrase 'X' keeps returning" | MinHash (64-perm) + LSH (16×4 bands) near-duplicate clustering | — |

Patterns carry a **lifecycle** (`candidate → emerging → confirmed → fading →
archived`, 45-day evidence half-life): weak signals must re-qualify on a
second day before they surface, and the app renders lifecycle states as
evidence labels ("early evidence" / "established" / "fading") with a
**"Why am I seeing this?" panel** per card — window, sample size, effect
size, significance, and the method in plain language.

Sentiment is a **graded lexicon engine** (VADER-style: graded valences,
intensifiers, damped negation, "but" re-weighting — Hutto & Gilbert 2014),
deterministic and self-contained.

**Honesty guarantees, enforced by 560 backend tests:** base-rate correction
(a Sunday-heavy journaler gets no fake "everything happens on Sundays"),
FDR-corrected multiple testing across every statistical claim, effect-size
gates, within-person detrending (a mood *trend* cannot manufacture
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

## Safety

* **Crisis resources are built in and offline**: a "Get help" screen (988
  call/text, Crisis Text Line 741741, 911 guidance, findahelpline.com) is
  one tap from every screen, follows safe-messaging practice (#chatsafe),
  and never depends on the API being up.
* **Observations, not verdicts**: no advice, diagnosis, or prediction
  anywhere — including the optional LLM path, whose output is sanitized,
  corpus-anchored, and restricted to the verifiable pattern kinds.
* The pre-threshold phase shows **device-local value only** (streak + mood
  trend computed on-device, never synced); the analysis threshold is
  enforced server-side.

## The security model (honest version)

1. **Keys are derived on your device.** `master = PBKDF2-HMAC-SHA256(password, salt, 600k)`; HKDF splits it into an `auth_key` (sent at login; the server stores `scrypt(auth_key)` with N=2¹⁶) and a `data_key` that encrypts everything.
2. **The server is blind to content — with one deliberate exception.** Entries/insights/questions are AES-256-GCM blobs (`nonce‖ct‖tag`), AAD-bound to `(user, entry, context)`, so blobs can't be relocated undetected and a DB leak yields no plaintext. The exception: to compute insights, the client sends the `data_key` in a **single-use** processing session (over TLS, memory-only, destroyed the moment the recompute consumes it, purged on account deletion). During that request the server can read your entries — that is the design trade-off of v1 (server-side analysis). On-device analysis is the path to removing it.
3. **Processing is bounded.** Nothing is decrypted before the 30-day threshold. After it: decrypt → analyze → re-encrypt, keys and plaintext buffers owned by the enclave are zeroized (`bytearray`-scrubbed). Honest scope: the analyzer itself creates Python/JS string copies of your text that only GC reclaims; a process memory image can still contain them. TEE-style guarantees are deployment work.
4. **Progressive revelation is enforced server-side.** Patterns are only computed, stored, and served after 30 distinct active days. Entry dates can't predate the account (backdating can't fast-forward the gate). Before the threshold the client sees only its own device-local mood trend.
5. **Enumeration resistance — scoped truthfully.** Salt lookup (POST /api/auth/salt) never reveals account existence (deterministic decoys, identical for unknown and deactivated accounts). Registration must, like any name-based system, answer whether a name is taken; it is rate-limited per-IP **and** per-username to make mass probing impractical.
6. **Destructive actions re-authenticate.** `DELETE /api/account` and enabling LLM analysis require the password-derived verifier — a stolen bearer token cannot erase a journal. `POST /api/auth/logout` bumps a token epoch that revokes every token for the account.
7. **Metadata the server does hold** (be aware of it): usernames, per-entry calendar dates and received timestamps, entry ciphertext sizes, insight dates. A DB leak reveals *when* and *how much* you wrote — never *what*.
8. **Optional LLM analysis is opt-in per user.** If the operator configures `MINDPATTERN_LLM_URL`, journal text is only sent to that third-party endpoint for accounts that explicitly consented (re-authenticated toggle in Settings, with the disclosure that named-provider retention applies), only post-threshold, with model output sanitized (labels length-capped, "recurring phrases" verified against your actual text, numerics clamped). Off by default for every account.
9. **Transport & ops hardening.** Non-development boots with OpenAPI/docs disabled and refuses the dev token secret and SQLite in every non-development environment (fail-closed). Every response — including 500s and 413s — carries `nosniff`/`DENY`/`no-referrer`/`no-store` plus HSTS (`strict-transport-security: max-age=31536000; includeSubDomains`). Request bodies are capped at 2 MiB **before** parsing; validation errors never echo input. Rate limiting covers auth, entries, processing, reads, deletes; behind a proxy it uses the rightmost `X-Forwarded-For` across **all** header lines; the counter's memory is bounded. Access logs are disabled in the image. Export is streamed. Per-account quotas bound storage and recompute cost.

The mobile client keeps derived keys memory-only: after an app restart the session token is still valid but the key vault is locked behind an unlock screen, and navigation is tri-state (no login-flash race). The offline sync queue is account-bound by mechanism; server error text is sanitized before reaching dialogs, and the app switcher sees only a blank shield.

## Running

```bash
# Backend (dev) — Python 3.12+
# NOTE: the app fails closed (MINDPATTERN_ENV defaults to production), so
# every local non-Docker command below opts into development explicitly.
cd backend
python3 -m venv .venv && source .venv/bin/activate   # or: uv venv
pip install -r requirements.lock.txt                  # pinned set the suite ran against
MINDPATTERN_ENV=development uvicorn app.main:app --reload   # http://localhost:8000/docs

# Full stack (postgres + api)
cat > .env <<EOF
MINDPATTERN_TOKEN_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
EOF
docker compose up --build

# Mobile (source; native projects are generated with the RN toolchain)
cd mobile && npm install && npm run ios   # or android; point Settings at your API

# Mobile tests: 425 tests — real crypto modules against shared vectors + queue/client/log regressions
cd mobile && npm test

# Cross-platform crypto check over the REAL compiled modules
node mobile/tools/verify_vectors.mjs

# Ground-truth probe: planted-pattern corpus, 9/9 must pass
cd backend && ../.venv/bin/python probe_brain.py

# Decrypt your ciphertext export locally (password never leaves the machine)
node mobile/tools/decrypt_export.mjs --bundle export.json
```

## Database migrations

Schema changes ship as Alembic revisions (`backend/alembic/`). The container
entrypoint runs `alembic upgrade head` against `MINDPATTERN_DB_URL` **before
starting uvicorn**, so `docker compose up --build` is always migrated; the
app's startup `create_all` runs only with `MINDPATTERN_ENV=development`
(dev/test), never in a deployed container. A database created by a
pre-migrations (create_all-era) deploy must be adopted once with
`alembic stamp head` so future revisions don't collide with existing tables.
Migration tooling reads `MINDPATTERN_DB_URL` directly — it does not import
the app config and needs no token secret. Operator workflow, adoption, and
autogenerate instructions: `backend/alembic/README.md`.

## Testing

```bash
cd backend

.venv/bin/python -m pytest                     # full suite (~10s, includes 600k-iter vectors)
.venv/bin/python -m pytest -m "not slow"      # fast path (what mutmut uses)

# Deep mutation testing over the security + services cores
# (see reports/mutation_report.md for scope and caveats)
PATH="$PWD/../.venv/bin:$PATH" ../.venv/bin/mutmut run
../.venv/bin/mutmut results                   # triage
../.venv/bin/mutmut show <id>                 # inspect a mutant
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `MINDPATTERN_ENV` | `production` | Fails closed: only the literal `development` may use the dev secret, SQLite, or /docs; every other value (including unset) takes the production gates |
| `MINDPATTERN_DB_URL` | local SQLite | SQLAlchemy async URL (use `postgresql+asyncpg://…` in prod) |
| `MINDPATTERN_TOKEN_SECRET` | dev default | HMAC secret for session tokens — must be set outside development (≥ 32 chars, or the app refuses to boot) |
| `MINDPATTERN_UNLOCK_DAYS` | `30` | Pattern-revelation threshold |
| `MINDPATTERN_PROCESSING_TTL` | `300` | Processing-session key lifetime (seconds); sessions are single-use |
| `MINDPATTERN_LLM_URL` | unset | OpenAI-compatible endpoint for the optional LLM analyzer; per-user consent still required; unset = deterministic mini-brain |
| `MINDPATTERN_AUTH_RATE_LIMIT` / `_WINDOW` | `10` / `60` | Fixed-window rate limits (auth, salt lookups; also per-username buckets on register/login) |
| `MINDPATTERN_ENTRIES_RATE_LIMIT` / `_WINDOW` | `120` / `60` | Entry creation rate limit |
| `MINDPATTERN_PROCESSING_RATE_LIMIT` / `_WINDOW` | `10` / `60` | Processing sessions + recompute rate limit |
| `MINDPATTERN_READ_RATE_LIMIT` / `_WINDOW` | `300` / `60` | Authenticated read/delete endpoints |
| `MINDPATTERN_MAX_BODY_BYTES` | `2097152` | Whole-request body cap (413 before parsing) |
| `MINDPATTERN_MAX_ENTRIES_PER_USER` | `10000` | Per-account entry quota (413 when exceeded) |
| `MINDPATTERN_MAX_USER_BLOB_BYTES` | `268435456` | Per-account total ciphertext quota |
| `MINDPATTERN_RECOMPUTE_ENTRY_LIMIT` | `2000` | Most-recent entries analyzed per recompute (threshold still counts all days) |
| `MINDPATTERN_CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins for browser clients; empty = no CORS headers (fail-closed) |
| `MINDPATTERN_TRUST_PROXY_HEADERS` | `0` | `1` = rate-limit by rightmost `X-Forwarded-For` across all header lines (only behind a trusted reverse proxy; run uvicorn with `--proxy-headers`) |

Invalid numeric values abort startup instead of silently falling back.

## Deletion & retention scope (read this before operating)

`DELETE /api/account` (password proof required) removes the user, entries,
insights, and in-memory processing keys from the live database. It does
**not** reach: database backups/WAL (retain per your own policy and expire
them), any reverse-proxy logs in front of the API (this image disables
uvicorn access logs; configure your proxy likewise), or a third-party LLM
provider's copies if a user consented to LLM analysis (provider retention
is out of our hands — surface that in consent copy). The export bundle
includes `user_id` and `salt` so `mobile/tools/decrypt_export.mjs` can
turn it back into readable files offline.

## Scope decisions

- **The mini-brain v3** (`app/services/brain.py`) is described in the table
  above. The whole engine is deterministic; a corrupt or tampered brain
  state degrades to amnesia, never a bricked account. The mobile app
  refreshes the brain after entry sync, at most once per day, only for
  accounts that have explicitly used insights once.
- The default analyzer is **deterministic**; the LLM path is consent-gated,
  threshold-gated, output-sanitized, and untested-by-unit-suite by design
  (its `_post` is monkeypatched in tests).
- The enclave is an in-process seam (`app/security/enclave.py`); SGX/TEE
  attestation is deployment work, not application logic.
- Single-process deployment: the rate counter, keystore, and token epochs
  assume one worker per instance (scale horizontally behind a shared
  counter when needed).
- Password change / key rotation remains out of scope (documented,
  deliberate). A leaked password requires account recreation; a leaked
  token dies at logout (epoch bump) or expiry.
- Mobile repo contains JS/TS source only; `ios/`/`android/` projects are
  generated with the React Native toolchain when building.
- Time-of-day analysis (the "Sunday **evening**" refinement) requires a
  client payload extension — the entry contract (`v:1`, date-only) is
  versioned for exactly this.

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
  *Honest residual:* mood/link/temporal claims still show a ~29%
  false-card rate on adversarial pure-noise journals — the effect gates
  pre-select significance at this corpus size, and no threshold separates
  those false positives from the probe's own true patterns without
  abandoning sensitivity. More data per claim is the real fix.
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
* **Rate limiting:** login per-username buckets count only failed
  verifications (anonymous garbage floods can no longer lock a victim
  out; unknown names never consume buckets); IPv6 clients aggregate to
  /64; eviction prefers single-hit garbage over active multi-hit buckets.
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

Test status at HEAD: backend **560 passed**, probe 9/9, mobile **425
passed**, cross-platform crypto vectors green.
