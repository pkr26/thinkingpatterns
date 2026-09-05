# MindPattern — v1 Build Plan

Personal pattern-recognition engine for mental state. Journal → encrypted sync →
"mini-brain" analysis → pattern surfacing after a 30-day threshold → one
reflective question per day. No advice, no diagnosis.

---

## 1. Architecture

```
┌───────────────────────────────┐         ┌──────────────────────────────────────┐
│  React Native app (iOS/Andr.) │  TLS    │  FastAPI backend                     │
│                               │ ──────► │                                      │
│  Entry screen (text|voice→stt)│         │  /api/auth      register, login,     │
│  crypto service (PBKDF2+      │         │                 salt lookup          │
│    HKDF + AES-256-GCM)        │         │  /api/entries   blob CRUD (opaque)   │
│  local cache (offline-first)  │         │  /api/processing/sessions            │
│  insights / question views    │         │  /api/insights  recompute + fetch    │
│  export / delete              │         │  /api/questions/today                │
│                               │         │  /api/account   export, hard delete  │
│  MASTER KEY NEVER LEAVES      │         │                                      │
│  DEVICE (except wrapped,      │         │  PostgreSQL (SQLAlchemy async)       │
│  per-session, for processing) │         │  (rate limit + keystore in-process) │
└───────────────────────────────┘         │                                      │
                                          │  Secure processing enclave:          │
                                          │  decrypt → analyze → re-encrypt →    │
                                          │  zeroize (plaintext is ephemeral)    │
                                          └──────────────────────────────────────┘
```

## 2. Security model (what v1 actually implements — post-remediation)

| Property | v1 implementation |
|---|---|
| Client-side encryption | AES-256-GCM envelope `nonce(12) ‖ ct‖tag`, AAD binds `(user_id, entry_id, context)` so blobs cannot be swapped between entries/users undetected. Key derived on device. |
| Credentials | `master_key = PBKDF2-HMAC-SHA256(password, salt, 600k)`. `auth_key = HKDF(master, "auth")`, `data_key = HKDF(master, "data")`. Only `auth_key` is sent at login (server stores `scrypt(auth_key)` at N=2¹⁶, hashed off the event loop). Tokens carry a revocation epoch; logout retires every token for the account. |
| Server blind to content | Server stores opaque blobs; no plaintext columns; tests assert plaintext bytes never land in the DB. Exception by design: the single-use processing session (below). |
| Secure processing | `POST /api/processing/sessions` delivers `data_key` over TLS into an **in-memory TTL keystore** (never persisted, single-use, destroyed on consumption and on account deletion, stored bytes zeroized). `SecureProcessingContext` decrypts, analyzes, re-encrypts, and scrubs the key + plaintext bytearrays it owns. Known limit: analyzer string copies are GC-reclaimed only — documented, not a TEE claim. |
| Threshold honesty | NOTHING is decrypted before 30 distinct active days (recompute short-circuits from DB metadata). Entry dates cannot predate the account. |
| Anti-enumeration | Salt lookup (POST /auth/salt) returns deterministic decoys for unknown AND deactivated accounts. Registration discloses name availability (inherent to name-based systems) but burns uniform CPU on both outcomes and is rate-limited per-IP and per-username. |
| Destructive actions | Account deletion and LLM-consent require the password-derived verifier; bearer tokens alone are insufficient. |
| LLM path | Per-user, re-authenticated opt-in; post-threshold only; model output sanitized (label caps, corpus-anchored recurring phrases, clamped numerics); silent rule-based fallback. |
| Metadata (known, documented) | Usernames, per-entry dates/timestamps, ciphertext sizes, insight dates are stored in the clear — never content. Access logs disabled in the image. |

## 3. The mini-brain (v2: stateful + incremental; LLM opt-in enrichment)

- Entry payload contract (encrypted by client): `{"v":1,"text":…,"sentiment":…,"created_at":…}`.
- **The engine** (`app/services/brain.py`): `update(state, entries, today)` is a pure
  function that folds the analysis window (last 180 days) into a persistent,
  encrypted pattern store. Window statistics are recomputed each run (pure
  function of the entry set — idempotent, immune to backdated entries);
  pattern *memory* persists in the store and evolves monotonically:
  - **Lifecycle**: `candidate → emerging → confirmed → fading → archived`,
    with drop-after-90-days. Weak signals stay hidden candidates until they
    re-qualify on another day; ≥10 occurrences surface immediately; fading
    patterns are shown fading, then archived, then forgotten.
  - **Decay**: evidence strength is an exponential half-life (45 days);
    recent mentions outweigh old ones.
  - **Statistics** (`app/services/statsig.py`): base-rate-corrected weekday
    concentration (exact binomial vs the user's own writing schedule),
    Benjamini–Hochberg FDR across all simultaneous tests, Welch's t +
    Cohen's d (with a measurement-noise floor for constant moods) for
    mood correlations.
  - **Mood trajectory**: EWMA control chart over daily mood (λ=0.3, ±2.7σ
    limits, run-of-3 in the last 5 points) → `mood_shift` patterns.
  - **Phrases** (`app/services/phrases.py`): MinHash (64 perm) + LSH
    (16×4 bands) near-duplicate clustering over unigram+bigram shingles.
- Analyzers: **brain** (default, above; `analyzer="brain"`), plus optional
  **LLM enrichment** — only when `MINDPATTERN_LLM_URL` is set AND the
  account consented; adds sanitized, corpus-anchored patterns on top of
  the deterministic core (`analyzer="llm"`).
- Pattern kinds: `temporal`, `mood_correlation` (both directions:
  lower/higher), `recurring_phrase`, `mood_shift`.
- Storage: two encrypted insight rows per recompute — kind `brain` (the
  carried-forward state) and kind `patterns` (the surfaced payload,
  `{"v":2,…}` with per-pattern `pattern_state`/`strength`/`is_new`).
  Corrupt state = amnesia + rebuild; GCM-tampered state = one retry
  without it (entries still authenticate or the recompute fails).
- Gate: patterns are only computed/stored/returned after **30 distinct
  active days**; before that the app shows only client-side sentiment.
- Client cadence: after entry sync the mobile app refreshes the brain at
  most once per calendar day, only when a patterns blob already exists
  (the first analysis remains an explicit user action on the Question
  screen); the processing session is single-use as always.

## 4. Daily questions

Deterministic rotation (seeded by date + user) over ranked patterns + a generic
reflective pool. Every template is a question (tests enforce this — the
"no advice" philosophy is a test invariant). One per day, stable within the day.

## 5. API surface

```
GET  /healthz
GET  /api/meta                                                        → {unlock_days, llm_available}
POST /api/auth/register        {username, salt, verifier}            → {token}   (+ per-username rate bucket)
POST /api/auth/salt            {username}                            → {salt}    (decoy if unknown/deactivated)
POST /api/auth/login           {username, verifier}                  → {token}
POST /api/auth/logout          (bearer)                              → 204, revokes ALL tokens (epoch bump)
POST /api/entries              {client_entry_id, blob, entry_date}   → {id}      (no pre-account dates; quotas)
GET  /api/entries?since=&offset=&limit=                               → [blobs]
DEL  /api/entries/{client_entry_id}                                   → 204 (rate-limited)
POST /api/processing/sessions  {data_key}                             → {session_token}  (single-use)
POST /api/insights/recompute   (X-Processing-Token)                   → {phase, patterns_stored, analyzer}
GET  /api/insights                                                    → {phase, active_days, blob}
GET  /api/questions/today                                              → {blob} | 404
GET  /api/account/export                                               → streamed ciphertext bundle
PUT  /api/account/llm-consent   {enabled, verifier}                    → {enabled}
DEL  /api/account               {verifier}                             → hard cascade delete
```

Rate limiting (fixed window, in-memory, bounded key count) on auth, salt,
register (per-IP + per-username), entries (create/delete), processing,
reads, export, consent, and delete. Whole-body cap (2 MiB) before parsing;
422s never echo input; security headers on every response including 500s.

## 6. Repository layout

```
backend/   FastAPI app (app/…), pinned requirements.lock.txt, tests (tests/…)
mobile/    React Native + TypeScript source, crypto service, vitest suite, tools/
shared/    crypto test vectors (incl. non-ASCII AAD) consumed by backend + mobile tests
reports/   mutation-testing report (historical)
docker-compose.yml  postgres + api for local dev (no redis: the counter is in-process)
```

## 7. Testing strategy

1. **Unit**: crypto (roundtrip, tamper, AAD binding, zeroization), KDF (determinism, separation, pinned vectors at real 600k iterations), tokens, threshold boundaries, pattern engine (corpus fixtures, determinism, no-false-positive), question engine.
2. **Integration/API**: full client-emulated flows over httpx ASGI transport with in-memory SQLite — auth, entry isolation between users, ciphertext-only storage assertions, 30-day gate (locked at 29, unlocked at 30), export/delete cascade, rate limiting.
3. **Mutation testing (deep)**: `mutmut` over `app/security/` and `app/services/` — every surviving mutant is triaged; security-module survivors are killed with additional tests; second run to confirm the improved kill rate. Report in `reports/mutation_report.md`.

## 8. v1 trade-offs (explicit)

- Attestation stubbed (enclave seam exists); true TEE is deploy-time work.
- Insights are computed server-side: the data key travels per single-use
  session. On-device analysis is the future path to a server that is blind
  during analysis too.
- In-memory rate counter + keystore: single-process deployments only.
- LLM path optional, per-user consent, deterministic default analyzer.
- Password change / key rotation is client-driven re-wrap (documented, out of v1 critical path).
- Environment: Python >= 3.12 (requires-python; dev venv is 3.14), PostgreSQL in docker-compose for dev/prod, in-memory SQLite for tests. Runtime dependencies pinned in backend/requirements.lock.txt.

## 9. Build order

1. Backend core: config, crypto, KDF, tokens, enclave, threshold → unit tests green.
2. Pattern + question engines → unit tests green.
3. DB, models, API routes, rate limiting → integration tests green.
4. Mobile app source + shared vectors + node verifier script.
5. Full pytest run → mutation run → triage → harden → re-run → report.
6. README, docker-compose, final verification.
