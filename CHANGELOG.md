# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added — Therapist sharing (zero-knowledge patient→clinician sharing)

The feature this app was building toward: a patient can let their therapist
see every surfaced pattern and, on click, the journal entries behind it —
read-only, with the therapist's own encrypted notes. The server stays blind
to content throughout.

- **Zero-knowledge grant (E2E preserved).** The therapist portal (new
  `portal/`, React + WebCrypto) registers with a P-256 wrap keypair; the
  private key is stored only as a password-encrypted blob. A patient types
  a short-lived single-use pairing code in the app ("Share with my
  therapist" in Settings), sees the therapist's name, re-authenticates with
  their password, and their client wraps the data key to the therapist's
  public key (ECDH → HKDF salted with both SPKI keys → AES-256-GCM, AAD
  `("consent-wrap", user, therapist)` — see
  `backend/app/security/sharing.py`, the reference implementation). The
  portal unwraps locally after login; the server never holds anything that
  decrypts patient content.
- **Pairing codes.** 8 chars, 15-minute TTL, single-use, stored only as an
  HMAC; unknown/expired/consumed answer the same 404. Codes replace
  username search so no therapist-enumeration oracle exists.
- **Role separation.** `users.role` gates every route: therapist tokens
  cannot reach journal endpoints (403 by dependency, not UI convention);
  patient tokens cannot reach therapist routes. There is NO therapist
  write path to patient data — read-only by construction.
- **Therapist reads + audit.** `GET /therapist/patients`, per-patient
  insights (byte-identical blob to the patient's own view) and entries
  (paginated, `since`/`until`). Every grant/revoke and patient-data
  read/write appends an `access_log` row; the log outlives account
  deletion (plain-string ids, no FK).
- **Evidence drill-down.** Surfaced patterns now carry
  `detail.evidence_dates` (the capped list of days whose entries fed the
  pattern) and `detail.pattern_pid` (stable id for note attachment). The
  portal fetches exactly those days' entries, decrypts them, and
  highlights label occurrences with per-entry mood — the "see all the data
  under this pattern" view. Sensitive (crisis-adjacent) cards stay
  non-quoting; the drill-down shows the patient's own words.
- **Notes.** Therapist-private (encrypted under the therapist's
  password-derived `portal-notes` key before leaving the browser),
  attachable to a patient or a pattern id, surviving revoke, cascading
  with account deletion on either side.
- **Revoke semantics, honestly stated.** Revoke (password-gated) clears
  the wrapped key — future access dies immediately; already-read data
  cannot be unread (the grant disclosure says so). Re-granting reactivates
  the same consent row, keeping the therapist's note continuity.
- **Cross-platform pins.** `shared/vectors.json` gains `wrap_vectors`
  (fixed test keypairs); backend, mobile (real quick-crypto seam code
  under node) and portal (real WebCrypto) all verify against them.
  Export bundles now carry share records (metadata only). GDPR posture:
  grant records the disclosure version, mirroring the LLM-consent record.
- **Tests.** Backend +64 API/crypto tests (role separation, pairing
  lifecycle, consent boundaries, cross-therapist isolation, E2E decrypt
  round-trips, audit, cascades, evidence dates) — suite 814. Mobile +26
  (wrap vectors, client wire shapes, full share-screen flows incl. wrong
  password/verifier/session-death branches) — suite 1103 at the same 98%
  per-file coverage floor. Portal: 62 (crypto vectors incl. the unwrap
  path, api client, app state machine, all views) with per-file coverage
  thresholds and a CI job.

### Security — 2026-09-16 red-team remediation wave

Full audit: `reports/redteam_audit_2026-09-16.md` (96 executable verdicts);
reproducible harness in `redteam/`. Post-fix re-run: 63 attacks blocked,
every remaining finding is a documented design residual. Highlights:

- **Crisis-language normalization (P0).** Both engines now normalize before
  matching (NFKC, invisible-character stripping, Cyrillic/Greek homograph
  folding — sigma family mapped by codepoint BEFORE NFKC, leet folding
  between letters, punctuation-to-space, >=4 single-letter token joining).
  The red-team bypass corpus went from 30/35 evasions to 1/35 (the partial
  split "k ill myself" is the designed residual — joining single letters
  into intact words would eat ordinary prose). New phrases cover unlisted
  English ("off myself", "out of my misery") and first-person ideation in
  es/fr/de/it/pt/zh/ja/ar/hi; suppress tier gains hopelessness phrasing.
  Pinned cross-engine by the shared JSON fixtures.
- **Recompute availability crash (P0).** `brain.py` mood-shift inflation
  divided by `(1 - phi)` with phi exactly 1.0 on a
  constant-within-float-noise baseline — every future recompute for such
  accounts 500'd. phi is clamped to 0.99 (saturates the existing
  inflation cap; no honest statistic changes).
- **The data key never rides plain HTTP (P0).** `openProcessingSession`
  refuses a consented insecure URL before any fetch — https or loopback
  only. Ordinary requests keep the BYO-server plain-HTTP consent.
- **Single-process deployment is enforced, not just documented (P1).** A
  file-lock keyed by deployment identity makes the second worker of a
  `uvicorn --workers 2` boot refuse to start (live audit previously showed
  one "single-use" token answering 6 recomputes and per-worker rate
  buckets). Same-process re-entrancy preserved for the test suite.
- **KDF iteration floor (both platforms).** `derive_master_key` /
  `deriveMasterKey(Async)` refuse iterations < 100,000 — no honest code
  path can silently downgrade the 600k contract (the server remains
  structurally unable to verify client work factors).
- **Nonce test seam removed from production encrypt (both platforms).**
  Fixed-nonce output moved to unmistakably named `encrypt_with_nonce` /
  `encryptWithFixedNonce`; `encrypt()` has no nonce parameter at all.
- **LLM hardening.** Timeout 30s->10s (the call runs inside the secure
  processing context, so its latency IS the key/plaintext exposure
  window); `max_tokens=512`, `temperature=0`; labels carrying spelled
  contact channels ("evil dot com", "call five five five ...") or >=3
  consecutive number-words are rejected regardless of corpus grounding.
- **Processing-session TTL ceiling 3600s->300s**, matching the mobile
  consent copy's "held in memory for up to 5 minutes".
- **Export bundle no longer carries the cleartext username** (user_id +
  salt remain — required by the AAD binding / future re-import).
- **Backups are encrypted at rest.** The compose backup profile pipes
  pg_dump through `openssl enc -aes-256-cbc -pbkdf2` with a REQUIRED
  `BACKUP_KEY` (the service refuses to start without one). Retention
  remains part of the deletion promise.
- **Mobile error-dialog sanitizer** now strips scheme-less domains
  ("evil.com/x") and phone-like digit runs; character-level bidi/zero-width
  tricks were already neutralized.
- **Startup warning when `TRUST_PROXY_HEADERS=1`** (direct-origin spoofing
  defeats per-IP limits; the compose default keeps loopback-only binding).
- Regression pins: `backend/tests/test_redteam_fixes_2026_09_16.py` +
  `mobile/tests/redteamFixes2026.test.ts`; the obfuscation corpus lives in
  the shared JSON fixtures and `redteam/crisis_corpus.json`.

Known residuals (documented, not fixable in this wave): SecureStore device
key needs Keychain/Keystore native custody; the offline unlock proof is an
offline password oracle (quantified at ~75 ms/guess/core); the auth_key is
a password-equivalent credential with no rotation path (needs a re-key
feature); consented LLM egress discloses plaintext by design; server-side
metadata (journaling dates/sizes) is visible to the operator; lockfile
hash pins need a networked `pip-compile --generate-hashes` run.

Post-release remediation wave across the whole tree, grouped. (Backend now
658 tests + 1 Postgres-gated skip; mobile 759 tests across 33 files; probe
9/9.)

### Security

- Enclave keeps ONE zeroized working copy of the data key per recompute
  run — per-item immutable `bytes(key)` copies would have lingered
  unzeroized until GC.
- Entry dates may be at most server-today + 1 day (device-local timezone
  grace); backdating rules (no pre-account dates) unchanged.
- Unified cross-platform crisis-language contract at
  `shared/crisis_phrases.json`: a conservative client-side `dialog` tier,
  and a suppress tier (`dialog` + `suppress_extra`) for server-side
  question/card suppression. Crisis-adjacent patterns carry
  `detail.sensitive=true`; the app renders a non-quoting card ("A difficult
  thought has been returning…") with a support link instead of quoting the
  text.
- LLM consent is recorded (`llm_consent_at` + `llm_consent_disclosure`
  "v1"), cleared on disable, and included in the export bundle.
- Salt-lookup enumeration posture documented honestly: per-request
  enumeration is closed (identical decoys for unknown AND deactivated
  accounts); the longitudinal membership-transition oracle (decoy→real on
  register, real→decoy on deactivation) is inherent to name-based systems
  and is stated, not claimed away.
- Mobile session token is stored AES-256-GCM-encrypted under a per-install
  device key (`mobile/src/secureStore.ts`) — with the plain limitation that
  the device key currently lives in AsyncStorage too (documented fallback
  pending react-native-keychain), so backups include both key and
  ciphertext.

### Analysis engine

- Full-family Benjamini–Hochberg: every testable candidate's p-value is
  computed pre-gate and the effect gates filter only corrected survivors
  (selecting on extremeness first voided FDR control — measured: ~half of
  pure-noise corpora surfaced a false statistical card).
- Replication gate: statistical kinds (temporal, mood_correlation, link,
  inertia, instability, mood_shift) surface only after qualifying on ≥2
  distinct recompute days that constitute an independent second observation
  — evidence-date kinds need a qualification day contributing NEW evidence;
  window-stat kinds need qualification days ≥2 calendar days apart.
  Consequence: re-running an unchanged corpus the next day no longer
  surfaces anything. Direct-measurement kinds keep immediate surfacing.
- Measured false-card rates on pure noise: 0/60 single-shot; ≤1/24 runs
  (4.2%) at daily cadence (14 recomputes), the survivor a documented
  FDR-budget boundary case, not a gate leak (regression:
  `test_daily_cadence_pure_noise_replication_bound`).
- Sentiment lexicon curated: context-dependent words removed ("kind",
  "fed", "present"); "hardly"/"barely" are negation-only per VADER.
- Link cards report the modal exposed gap (`lag_days` + gap1/gap2 counts)
  and say "the day after" only when gap 1 is the mode.
- Inertia's comparative claim uses a Fisher-z difference test; link/mood
  tests use autocorrelation-deflated effective sample sizes.
- Presence topics require ≥4 distinct following-token contexts and are
  suppressed when ≥80% covered by the run's recurring-phrase clusters
  (anti-boilerplate); they carry `detail.presence=true`.
- `update()` is copy-on-entry pure (input state never mutated); semantic
  flips (dominant weekday / direction) retire the old pid to fading and
  fork `pid~2` instead of silently relabeling under an intact history.
- LLM grounding is word-token based (no substring grounding).

### API

- Canonical mount `/api/v1`; `/api` kept as a deprecated legacy alias.
  `GET /api/v1/meta` returns `{unlock_days, llm_available, api_version,
  version}` so clients can discover the canonical base.
- `GET /readyz` (DB `SELECT 1`; 503 on failure) alongside `/healthz`.
- `DELETE /account` prefers the `X-Account-Verifier` header (JSON body is a
  deprecated fallback — DELETE bodies are unreliable across clients and
  proxies).
- Uniform error envelope `{"detail", "code"}` with snake_case codes:
  unauthorized, invalid_credentials, processing_session_required,
  verification_failed (403, wrong verifier), processing_session_invalid,
  not_found, conflict, account_deleted (410), payload_too_large,
  quota_exceeded, blob_quota_exceeded, validation_error, rate_limited
  (+Retry-After), bad_request, entry_blob_invalid, entry_payload_malformed,
  internal_error, service_unavailable. 422s still never echo input.
- Export endpoint rate-limited (`MINDPATTERN_EXPORT_RATE_LIMIT`/`_WINDOW`,
  defaults 5/60); numeric settings gained upper bounds (token TTL ≤ 30d,
  processing TTL ≤ 3600s, rate windows ≤ 3600s).

### Database

- `insights` carries `UniqueConstraint(user_id, kind, for_date)` with
  dialect upsert writes (`on_conflict_do_update`) — multi-worker-safe.
- Question rows older than 90 days are purged during recompute.
- Recompute reads are SQL-bounded (`LIMIT recompute_entry_limit`) and never
  hold a transaction across analysis (the write phase is a second, short
  transaction).
- Connection pool env-configurable (`MINDPATTERN_DB_POOL_SIZE` /
  `_MAX_OVERFLOW` / `_POOL_TIMEOUT`, defaults 5/10/30).
- Alembic: pg advisory lock (727272) + `lock_timeout` 15s +
  `statement_timeout` 300s on Postgres; the entrypoint retries migration
  5× at 3s intervals before failing closed. New revisions e930dbc4f001
  (insights unique) and a7c91e4b2d03 (consent record).
- `MINDPATTERN_TEST_DB_URL` runs the pytest suite against an external DB
  (CI's Postgres job; non-sqlite URLs must contain "test" in the DB name).

### Mobile

- Entry history screen (read/edit/delete; edit = delete + re-upload under a
  fresh id, delete first so a failed replacement never duplicates).
- Explicit one-tap mood check-in (a deliberate tap always wins over
  inferred sentiment); day-1 generic reflective questions pre-threshold,
  answered fully on-device (pool pinned to `shared/generic_questions.json`);
  "Write about this" question→journal bridge.
- 3-panel first-run onboarding (daily habit + 30-day threshold, encryption
  with the one honest exception, no-recovery warning + 13+ line) and an
  in-app offline privacy policy screen.
- Dark + light theme with a full accessibility pass (labels/roles, ≥ 4.5:1
  contrast pinned by tests, 44pt targets); honest inline save/sync feedback
  ("Saved ✓" / "Saved — will sync when online" / a loud "Not saved").
- Daily auto-recompute removed after the red-team audit: shipping the data
  key is only ever an explicit user act from the Question screen.
- Client targets `/api/v1` and sends the account verifier by header.
- Push-only sync documented as deliberate v1 scope (single-device writer;
  History pulls this account's entries; no multi-device conflict model).
- Recovered-entries surface in Settings: rejected/quarantined uploads are
  preserved, never destroyed.

### CI/DevOps

- CI overhaul: Postgres service job running the full backend suite against
  real Postgres, matrix Python 3.12/3.14, Docker build + compose boot gate
  (healthz/readyz assertions, migration-at-head check), contract gates for
  `probe_brain.py` and `verify_vectors.mjs`, and a supply-chain job
  (pip-audit; npm audit advisory until the Metro chain is fixed).
- Lint/type tooling: ruff gate (green rule set), advisory mypy step,
  pre-commit config, Dependabot for pip/npm/github-actions/docker.
- Scheduled weekly mutation testing (mutmut, resumable cache, results
  artifact); still not a PR gate.
- Packaging/hygiene: Dockerfile base image pinned by digest, compose
  postgres pinned by digest, entrypoint migration retry loop, optional
  profile-gated backup service with documented retention/encryption duties,
  MIT LICENSE, this changelog.
- Deliberate observability trade-off, stated plainly: no metrics or crash
  reporting ship in v1 (privacy posture) — production visibility is
  healthz/readyz + container logs. Documented gap, not an oversight.

## 1.0.0 - 2026-09-07

First release-quality tree after three audit/remediation rounds (security
adversarial audit, analysis-methodology audit, red-team round).

### Engine

- Deterministic, idiographic "mini-brain" v3: temporal (every weekday
  tested, Benjamini–Hochberg FDR), within-person mood correlations on
  residuals, lag-1 day-after links, inertia, instability, EWMA mood shift,
  rumination clustering, emergent topics, MinHash/LSH recurring phrases.
- Pattern lifecycle (`candidate → emerging → confirmed → fading →
  archived`, 45-day evidence half-life) with per-card evidence panels.
- Graded VADER-style sentiment engine; corrupt state degrades to amnesia.
- Ground-truth probe (`probe_brain.py`, 9/9 required, zero false
  associations) that exits non-zero on failure.

### Security model

- Client-side key derivation (PBKDF2-HMAC-SHA256, 600k) with HKDF split
  into auth key (server stores `scrypt(auth_key)`) and data key.
- AES-256-GCM blobs AAD-bound to (user, entry, context); cross-platform
  TS⇄Python crypto pinned by `shared/vectors.json` (incl. non-ASCII AAD).
- Single-use, memory-only processing sessions with key zeroization;
  30-active-day revelation threshold enforced server-side.
- Enumeration-resistant salt lookup with decoys; epoch token revocation;
  re-authentication for account deletion and LLM enablement.
- Fail-closed ops gates (production default env, ≥32-char token secret, no
  SQLite outside development), security headers on every response, 2 MiB
  body cap, bounded rate limiting, no access logs in the image.

### Platform

- FastAPI backend (Python 3.12+), Alembic migrations run by the container
  entrypoint, docker-compose stack (postgres + api).
- React Native mobile client (iOS/Android) with offline sync queue,
  device-local baseline mood trend, offline crisis resources screen.
- Optional consent-gated, output-sanitized LLM analysis path (off by
  default).

### Verification

- 573 backend tests (unit + API integration + crypto vectors +
  production-hardening + adversarial regressions), 97% coverage floor.
- 425 mobile tests with 98% per-file coverage thresholds.
- Mutation-tested security + services cores (mutmut; Stryker on mobile).
