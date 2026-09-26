# MindPattern — Patient Web Client Build Plan

> **Status: BUILD COMPLETE 2026-09-25 — P1–P8, P10 delivered; P9
> infra+harnesses delivered with the campaign RUNS queued in the weekly
> workflows. Per-phase pass notes are in each phase's block.**
> v2 (2026-09-25): added the multi-device sync model as a specified
> contract + a dedicated sync phase (P5), a cross-device test matrix,
> per-phase security gates, and the expanded security/mutation campaign
> (P9) covering web AND mobile.
>
> This file is the single source of truth for the web-client build.
> Update the dashboard and check off tasks **only after the phase's
> verification gate passes** (every gate now includes a security-assertion
> list). Append dated notes (`> 2026-09-xx: …`) rather than editing
> history. At ship, `README.md` becomes authoritative for the shipped
> reality and this file becomes the record (same convention as
> `PLAN.md`).

## Goal

A **patient-facing web app** — the same journaling experience as the
mobile app (journal, history, patterns, daily question, measures,
therapist sharing, crisis resources) running in the browser, deployed
alongside the therapist portal against the unchanged FastAPI backend —
**as a full multi-device peer of the mobile app**, with the two-client
sync story specified, implemented, and adversarially tested on both
sides.

## Locked decisions (2026-09-25)

| ID | Decision | Rationale / consequence |
|---|---|---|
| D-1 | **Web is a full write peer** alongside mobile on the same account | The safe primitives exist and are tested (idempotent `client_entry_id`, 409 `version_conflict`, revision snapshots + `collection_changed`). The full two-client contract is specified in "Multi-device sync model" below, implemented in P5, and adversarially tested in P5 + P9. The README's "single-device-writer" stance is updated honestly in P10. |
| D-2 | **Copy-and-pin reuse**, no shared-package/workspace refactor | Matches repo precedent (crisis phrases and question pools are already embedded copies pinned by tests). Refactoring mobile + portal into workspaces would churn two audited, mutation-tested codebases. Cross-client correctness is enforced the repo's way: **generated fixtures + shared vectors + a dual-client harness** (P5), not shared code. |
| D-3 | **Patient app only.** No marketing/landing site in this effort | A public landing page, if wanted, is a separate small static deliverable later. |
| D-4 | **Strict session custody in v1**: token AND keys are memory-only | Portal precedent. Refresh or new tab ⇒ re-enter password (PBKDF2-600k is sub-second via WebCrypto). Nothing decryptable ever touches localStorage/sessionStorage/IndexedDB. "Stay signed in" (non-extractable CryptoKey in IndexedDB) is a possible v2 with its own threat-model note. |
| D-5 | **Same-origin deployment** behind the existing nginx pattern (own subdomain, own `/api` proxy) | Zero CORS configuration; `MINDPATTERN_CORS_ORIGINS` stays empty (fail-closed posture unchanged). |
| D-6 | **No service worker in v1** | "Offline" means open-tab offline (editor + ciphertext queue work while the tab lives), not an installable offline app. No server push either: reconciliation is pull-based (on focus/online/explicit refresh — P5). |
| D-7 | **Entry creation on web is today-only in v1** (no backdated creation) | Simplest honest date discipline; editing existing entries keeps its date. |
| D-8 | **A long-lived tab must accept account-wide death lazily** | Logout/rotation on one device kills tokens everywhere (epoch bump); the other device learns on its next request (401/410) and funnels to re-auth. No client may cache keys or "assume alive" across that boundary. Tested as a first-class scenario, not an edge case. |

**Out of scope (explicit):** backend API changes; patient TOTP (patients
are password-only by design); WebAuthn/biometric unlock; web push
reminders; HealthKit; service worker/app shell; server push
(websockets/SSE); in-browser *decryption* of the export bundle (v1
downloads the ciphertext bundle only); print support; dark mode;
languages beyond English/Spanish; real-time collaborative editing.

## Architecture

```
Browser (patient)                          Phone (patient)
┌────────────────────────────────┐         ┌──────────────────────────┐
│ web/  React 19 + Vite SPA      │         │ mobile/ (React Native)   │
│ (TypeScript strict)            │         │ (unchanged product)      │
│                                │         │                          │
│  Login → vault (memory-only    │         │  same zero-knowledge    │
│  data_key)                     │         │  client contract        │
│  Journal / History / Insights  │         │  (pinned by the same    │
│  / Question / Measures /       │         │  shared vectors)        │
│  Share / Settings / Crisis     │         │                          │
│                                │         │                          │
│  WebCrypto: PBKDF2-600k →      │         │  quick-crypto: same     │
│  HKDF → AES-256-GCM            │         │  KDF/envelope/AAD       │
│                                │         │                          │
│  IndexedDB: offline ciphertext │         │  AsyncStorage: offline  │
│  queue ONLY (never keys/       │         │  ciphertext queue       │
│  plaintext/tokens)             │         │                          │
└──────────────┬─────────────────┘         └────────────┬─────────────┘
               │  same origin — nginx /api proxy        │ TLS
               └──────────────┬─────────────────────────┘
┌──────────────▼─────────────────────────────────────────────────────┐
│  FastAPI backend (UNCHANGED) — /api/v1 · single source of truth    │
│  idempotent creates · version CAS edits · revision snapshots ·     │
│  token epochs · single-use processing sessions · audit log         │
└────────────────────────────────────────────────────────────────────┘
```

Stack (mirrors `portal/`, pinned to its versions at scaffold time;
bumps are deliberate): React 19 + react-dom only as runtime deps, Vite 6
+ `@vitejs/plugin-react`, TypeScript strict (`noUncheckedIndexedAccess`,
ES2022, `bundler`), Vitest 5 + `@vitest/coverage-v8`, react-test-renderer
for view tests, jest-axe for a11y, Stryker 10 (command runner). Node 22
(root `.nvmrc`). No router library — explicit view state machine (portal
pattern). Canonical `/api/v1` prefix only; the legacy `/api` alias is
never called.

## Multi-device sync model (the contract both clients implement)

The server is the **single source of truth**; every client holds only a
cache and a pending queue. This is the complete v1 contract — P5
implements and tests it, P9 attacks it.

| # | Area | Contract |
|---|---|---|
| S-1 | Truth | Server state (entries, measures, insights, questions, consents) is authoritative. Clients reconcile on login, on regained focus/connectivity, and on explicit pull. No client-side merge authority. |
| S-2 | Creation | Idempotent by `client_entry_id` / `client_measure_id` (per-entry UUID; two devices can never mint the same id). Replay ⇒ 409 ⇒ verify-by-single-GET, then drop silently. Both devices' offline queues flushing overlapping days is therefore safe: different ids coexist; same-id replays dedupe. |
| S-3 | Editing | Compare-and-swap on `content_version`: PUT must carry stored+1. Loser of a race gets 409 `version_conflict` ⇒ **refetch, never blind-retry, never auto-overwrite**; the UI offers "reload the other device's version" vs "reapply my edit on top" with both texts shown. |
| S-4 | Delete vs edit | Edit of a deleted entry ⇒ 404 ⇒ honest "this entry was deleted on another device" state; the pending edit is quarantined for user review, never resurrected. |
| S-5 | Listing | Byte-bounded pages under a revision snapshot (`expected_revision`); 409 `collection_changed` ⇒ restart from page 1. Partial-page merging across revisions is forbidden. |
| S-6 | Insights | Computed server-side only; `state_seq` is monotone per account. Recompute may be triggered from either device (explicit button only). A `state_seq` regression on decrypt = tamper/stale ⇒ re-pull once, then fail closed (`stateSeqGuard` semantics on both clients). |
| S-7 | Questions | Server-deterministic per (user, date): both devices show the same question. Feedback ("resonated / not me") is an encrypted blob that rides whichever device recomputes next; feedback from the other device is simply not yet attached — never a conflict. |
| S-8 | Account-wide events | Logout (epoch bump), password rotation + rekey (epoch bump + new `data_key`), and deletion (410) propagate to every device **lazily** (D-8): next request yields 401/410 ⇒ forced re-auth. A decrypt failure with a fresh token ⇒ credentials were rotated elsewhere ⇒ re-derive keys from the new password; never loop, never fall back to stale keys. |
| S-9 | Queues | Per-device, ciphertext-only, scoped by origin+account. Flush order across devices is irrelevant to correctness (S-2). A 401 mid-flush keeps items queued; an epoch-dead token ends the flush and locks the session. |
| S-10 | Clocks/dates | Entry-date rules are enforced server-side (no pre-account dates, ≤ server-today+1 grace). Web v1 creates today-only (D-7). |
| S-11 | Consents | Grants/revokes are server-state readable from both patient devices; every grant/revoke/rewrap requires the password verifier (a stolen token on one device cannot share or unshare). Therapist key rotation triggers rewrap from whichever patient device acts first. |

### Cross-device test matrix (P5 implements, P9 attacks)

| Scenario | Expected behavior | Tested at |
|---|---|---|
| Create on A → list on B | B sees the entry after reconciliation pull | L2, L3, L4 |
| Concurrent create, same day, both offline → both flush | Both entries exist (distinct ids); no dupes | L3, L4 |
| Edit-edit race (A and B edit same entry) | Second writer gets 409 → conflict UI, no silent overwrite | L1, L3, L4 |
| Edit vs delete race | Editor gets 404 → "deleted on another device" + quarantine | L1, L3 |
| Mid-page collection change | Page restart from page 1, no partial merge | L1, L3 |
| Recompute from A → view on B | B decrypts new blob, `state_seq` advanced | L3, L4 |
| `state_seq` regression / blob tamper | Fail closed, re-pull once, then hard error | L1, L2 |
| Measure on A → trend on B | Appears after pull; revisions respected | L3, L4 |
| Grant on web → visible on mobile (and revoke) | Consent list consistent; verifier gate on both | L3, L4 |
| Rotation on web → mobile | Mobile token dies (epoch) → re-login with new password → new key decrypts rekeyed blobs | L3, L4 |
| Logout on web → mobile | Mobile 401 → re-login (same password) | L3 |
| Delete on web → mobile | Mobile 410/401 → account-gone handling | L1, L3 |
| Stale token replay after epoch bump | 401, session funnel to re-auth, no retry storm | L1, L3 |
| Queue replay cross-device | Server 409 dedupe + verify-GET drop | L1, L3 |
| Web-encrypted entry → mobile decrypts (and reverse) | Byte-identical interop via AAD/envelope contract | L2 |
| Two web tabs, same account | Independent sessions; queue flush serialized (Web Locks); no double-create | L1, L3 |

Test levels: **L1** in-package unit/contract tests (web `npm test`,
mobile `npm test`) · **L2** cross-client interop fixtures generated from
each client's real modules into `shared/` and pinned by the other
client's suite (the repo's copy-and-pin discipline, D-2) · **L3**
dual-client integration harness driving web + mobile client code against
one live dev backend · **L4** manual end-to-end drill (browser + device
or emulator), recorded as dated notes.

## Status dashboard

| Phase | Name | Status | Milestone |
|---|---|---|---|
| P1 | Scaffold & security baseline | ✅ done 2026-09-25 | M1 |
| P2 | Crypto, vault, session core | ✅ done 2026-09-25 | M1 |
| P3 | API client & auth flows | ✅ done 2026-09-25 | M1 |
| P4 | Journaling core (entry, offline queue, history) | ✅ done 2026-09-25 | M1 |
| P5 | Multi-device sync engine & cross-client interop | ✅ done 2026-09-25 | M2 |
| P6 | Analysis surfaces (insights, question, recompute) | ✅ done 2026-09-25 | M2 |
| P7 | Measures, sharing, settings (full parity) | ✅ done 2026-09-25; E2E-verified 2026-09-26 | M2 |
| P8 | Safety, i18n, accessibility | ✅ done 2026-09-25 | M3 |
| P9 | Security & mutation campaigns, web + mobile | ✅ infra+harnesses 2026-09-25; campaign RUNS queued (deferral note below) | M3 |
| P10 | Deploy, release pipeline, docs | ✅ done 2026-09-25; E2E-verified 2026-09-26 | M3 |

> **2026-09-26: dashboard corrected.** P7/P10 were shipped with the
> 2026-09-25 build-complete wave but had stayed "not started" here, and
> the P8/P9 rows were missing entirely. P7's surfaces (measures
> PHQ-9/GAD-7/PHQ-2, therapist share/grant/revoke with the ECDH
> wrap round-trip into the portal, settings incl. export) and P10's
> shipped artifact are independently verified end-to-end by the
> black-box browser pass of 2026-09-26 (E2E_TEST_REPORT_2026-09-26.md,
> T10–T20; 22/24 PASS, all three findings fixed same-day).
>
> **2026-09-26: P9.10 deferral registered.** The hand-written
> sync-surface mutation campaign (`redteam/mutation_campaign_web_sync_<date>/`)
> promised by 9.10 does NOT exist yet — no such directory has been
> created, and no mutants are wired into the `mutation-pr.yml` diff-scope
> gate for the sync surfaces. This is a DELIBERATE TRACKED DEFERRAL, not
> a completed item: the Stryker infrastructure + weekly
> `mutation-web.yml`/`mutation-mobile.yml` runs are in place and will
> produce the first measured floors; 9.10's own box stays unchecked
> until its campaign directory exists with every mutant killed. The
> deferral is registered in `docs/SECURITY_RESIDUALS.md` ("Tracked
> deferrals") so it cannot be silently dropped.

Milestones: **M1 "daily journal on the web"** (P1–P4, single-client
correctness incl. honest conflict errors) · **M2 "full parity +
multi-device"** (P5–P7) · **M3 "harden & ship"** (P8–P10). P6/P7 can
interleave once P5 is green. P5 contains **mobile-side work** — the
two-writer decision changes mobile's reality too.

---

## Reuse inventory (the copy-and-pin map)

### From `portal/` (web discipline — lift and extend)

| Source | Destination | Adaptation |
|---|---|---|
| `src/crypto.ts` | `web/src/crypto.ts` | Keep PBKDF2/HKDF/AES-GCM/ECDH core; ADD patient subkey `mindpattern/data/v1`, entry envelope (payload v1+v2, version-bound AAD + legacy fallback), insights decrypt (schema v2 + `state_seq`), question decrypt, therapist **wrap** direction (portal only unwraps today), fingerprint (already present) |
| `src/aad.ts` | `web/src/crypto/aad.ts` | None — byte-identical Python-compatible AAD, verify against vectors |
| `src/api.ts` | `web/src/api/client.ts` | Keep hardening (same-origin-only base, 15 s timeout, `redirect:"error"`, `cache:"no-store"`, `credentials:"omit"`, `referrerPolicy:"no-referrer"`, response-URL origin recheck, one-shot 401 latch, session AbortController, header-pagination validation); ADD the ~20 patient endpoints mobile's client carries |
| `src/platform.ts` | `web/src/platform.ts` | Extend: download/stream-export seam, `navigator.locks`, visibility/online events |
| `src/App.tsx` session/lock patterns | `web/src/App.tsx` | 10-min idle lock, bfcache `pageshow` guard, lockdown wipes keys + aborts requests — re-derived for patient views (tightened 2026-09-25 audit W-1: 5-min idle, mousemove no longer counts, hidden-tab lock added) |
| `src/ui.tsx` | `web/src/ui.tsx` | Fork primitives (Button/Card/Field/Note/ErrorBanner); new patient theme tokens + responsive layout primitives |
| `index.html` + `public/_headers` + nginx triple, `tests/securityConfig.test.ts` | same | Third instance of the aligned triple, pinned by the same test shape |
| `vite.config.ts`, `stryker.config.json`, `tests/helpers/setup.ts` | same | Dev `/api` proxy → :8000; coverage thresholds parity |
| Release workflow patterns (`.github/workflows/release.yml`, portal job in `ci.yml`) | `web` job + web tarball | Mirror |

### From `mobile/` (pure TS domain — copy verbatim, pin by tests)

| Source | Notes |
|---|---|
| `src/vault.ts` | Memory-only observable key vault, owner binding, zeroize-on-lock — no RN imports |
| `src/strings.ts` + `src/locales/{en,es}.ts` | `t()` + locale detection already browser-compatible (Intl) |
| `src/brain/{lexicon,sentiment,stats}.ts` | On-device sentiment + stats core; pin via `shared/brain_vectors.json` (9-decimal float match, as `mobile/tests/brainVectors.test.ts` does) |
| `src/crisisPhrases.ts`, `src/crisisDetect.ts` | Embedded contract copies; parity-pinned against `shared/crisis_phrases.json` |
| `src/genericQuestions.ts`, `src/promptChips.ts` | Pinned against the shared pools |
| `src/phq9.ts`, `src/measures.ts` | PHQ-9/GAD-7/PHQ-2 registry + scoring (display-only, no interpretation — charter holds) |
| `src/mood.ts`, `src/moodLog.ts` | Device-local mood/streak math for the pre-threshold phase (never synced) |
| `src/entryId.ts`, `src/entryVersions.ts`, `src/historyFind.ts` | Entry id/version/search domain logic |
| `src/stateSeqGuard.ts`, `src/thresholdNotice.ts`, `src/questionFeedback.ts`, `src/onboarding.ts`, `src/reauth.ts`, `src/rotation.ts` | Domain logic; adapt only their crypto/storage call sites |
| `src/offlineQueue.ts` | Queue logic verbatim; storage backend swapped AsyncStorage → IndexedDB |
| `src/api/client.ts` | Endpoint surface + error-code whitelist + origin pinning for queued uploads; the request core comes from portal's hardening instead |

### NOT copied (RN-locked or out of scope)

`secureStore.ts` (v1 has no persisted session — D-4), screens/components
(RN), navigation, `biometricUnlock.ts`, `healthkit.ts`, `reminders*`,
`haptics.ts`, `nativeFeatures.ts`, `unlockProof.ts`.

### From `shared/` (contracts to pin, never reimplement from memory)

`vectors.json` (KDF, auth/data subkeys, envelope, wrap, non-ASCII AAD),
`brain_vectors.json`, `crisis_phrases.json`, `generic_questions{,_es}.json`.
P5 adds: cross-client **interop fixtures** (full entry/measure/insight
blobs encrypted by one client's real modules, decrypted by the others).

---

## Phase 1 — Scaffold & security baseline (M1)

**Goal:** a building, tested, CI-gated `web/` package with the security
posture in place before any feature code.

> **2026-09-25: Phase 1 PASSED.** Functional gate: `npm install` →
> `tsc --noEmit` clean → 35 tests green, coverage 90.9/91.9/93.8/93.7
> (floor 85/75/85/90) → production build 60 KB gz → `npm audit` 0
> vulnerabilities → dev proxy verified live (`localhost:5173/api/v1/meta`
> answering the backend's meta through Vite; note: Vite binds `::1` on
> this machine — probe `localhost`, not `127.0.0.1`). Security
> assertions: header triple (index.html + `_headers` + nginx placeholder)
> pinned by `tests/securityConfig.test.ts` incl. the exact CSP literal in
> all four places (vite.config included); no-innerHTML source scan green;
> disabled buttons carry no onClick handler at all. Environment note:
> npm installed via `PNPM_HOME=… pnpm add -g npm` (npm 12.1.0, node 24;
> `.nvmrc` 22 governs CI). CI `web` job added mirroring the portal job.

- [x] 1.1 Scaffold `web/`: `package.json` (runtime deps: react,
      react-dom only; dev deps per stack above, versions from `portal/`),
      committed lockfile, `tsconfig.json` (strict,
      `noUncheckedIndexedAccess`), `index.html` shell, `src/main.tsx`,
      `src/App.tsx` boot state machine skeleton
- [x] 1.2 `vite.config.ts`: dev `/api` → `localhost:8000` proxy, Vitest +
      coverage config with thresholds (start at portal's 85/75/85/90,
      `src/main.tsx` excluded)
- [x] 1.3 `src/platform.ts` browser seam + `tests/helpers/setup.ts`
      window shim (port the portal's; add download, Web Locks,
      visibility/online-event seams now so later phases never touch
      `window` directly)
- [x] 1.4 Security-header triple: `index.html` CSP meta fallback +
      `public/_headers` + nginx block placeholder, all aligned and pinned
      by `tests/securityConfig.test.ts` (CSP shape = portal's:
      `default-src 'self'`, `connect-src 'self'`, `style-src
      'unsafe-inline'`, nosniff, DENY, no-referrer, no-store, COOP/CORP,
      HSTS, Permissions-Policy)
- [x] 1.5 `src/ui.tsx` forked primitives + patient theme tokens; base
      responsive layout shell (app header with crisis entry point,
      content column, 375/768/1280 breakpoints sketched)
- [x] 1.6 CI: `web` job in `.github/workflows/ci.yml` mirroring the
      portal job — `npm ci` → `tsc --noEmit` → `npm test` → `npm run
      build` → `npm audit --audit-level=moderate`
- [x] 1.7 **No-innerHTML rule**: source-scan test (and lint rule if
      cheap) asserting `dangerouslySetInnerHTML`/`innerHTML`/`outerHTML`
      never appear in `web/src` — the XSS floor for everything after
- [x] 1.8 `.gitignore` entry, README stub in `web/`

**Verification gate (functional):** `cd web && npm ci && npx tsc
--noEmit && npm test && npm run build` all green; CI `web` job green;
`vite dev` serves the boot screen with the proxy reaching the dev
backend's `/api/v1/meta`.

**Security assertions:** header triple pinned by test; audit gate live;
no-innerHTML scan green; no dependency outside the pinned allowlist.

**Done when:** the skeleton is mergeable — no feature code, but headers
pinned, CI live, and every later phase has its rails.

## Phase 2 — Crypto, vault, session core (M1)

**Goal:** the complete patient zero-knowledge stack in the browser,
byte-pinned to the shared vectors, with keys that cannot outlive the tab.

> **2026-09-25: Phase 2 PASSED.** Functional gate: `tsc --noEmit` clean →
> 165 tests green (11 files), coverage 93.5/83.9/94.8/97.3 (floor
> 85/75/85/90) → production build green → PBKDF2-600k measured **41 ms**
> (budget < 2000 ms). Security assertions: every patient-relevant vector
> passes byte-for-byte — 4 KDF cases (master + auth_key AND data_key), 6
> envelope vectors in BOTH directions (deterministic nonce seam
> reproduces the exact blobs; vector 5 is the null-AAD case), all 3 wrap
> vectors with the full patient-side construction reproducing `wrapped`
> byte-for-byte (ECDH→HKDF→fixed-nonce envelope) plus round-trips in both
> directions and cross-patient AAD rejection, all 16 AAD edge cases
> (ensure_ascii incl. astral/surrogates/DEL), fingerprint pinned to the
> literal `CB54 DE22 C976 DF43 08B6 7F8F 112B D4D7`; tamper tranche green
> (bit-flips at nonce/ct/tag positions, truncations, wrong key, AAD
> relocation, invalid base64 — all fail closed as TamperError, never a
> wrong plaintext); zeroization pins green (decrypt buffer wiped after
> parse AND on the unknown-version throw path; vault lock zeroizes;
> master key zeroized at vault.unlock). Layout note: `web/src/crypto/`
> holds core/keys/patient/sharing/aad (portal-style WebCrypto + mobile's
> payload contracts), `web/src/brain/` copied verbatim from mobile and
> pinned by `tests/brainVectors.test.ts` (sentiment to 1e-12, stats to
> 1e-9), vault + idle-lock/bfcache hooks in `src/vault.ts` +
> `src/sessionLock.ts` (5-min idle since the 2026-09-25 audit, activity
> reset, persisted-pageshow lock, hidden-tab lock — inert until P3
> activates them with a session).

- [x] 2.1 Port `aad.ts`; verify byte-equality against portal's via the
      vector cases (non-ASCII + astral planes included)
- [x] 2.2 Extend portal's crypto core into the patient layer: HKDF subkey
      `mindpattern/data/v1`; entry envelope encrypt/decrypt (payload v1
      **and** v2 — old mobile entries must decrypt — with version-bound
      AAD and legacy fallback); insights blob decrypt (schema v2,
      `state_seq` extraction); question blob decrypt; therapist wrap
      (ECDH P-256 → HKDF, salt = both SPKI DERs, info
      `mindpattern/wrap/v1`, AAD `("consent-wrap", user, therapist)`);
      `keyFingerprint` (display format identical to mobile + portal)
- [x] 2.3 Zeroization discipline: owned buffers zeroed, non-extractable
      CryptoKey handles where the API allows, verifier bytes kept raw
      (base64 derived only at send)
- [x] 2.4 Vector pins: `tests/crypto.test.ts` reads
      `../shared/vectors.json` and passes every patient-relevant case
      byte-for-byte; `tests/crypto.pins.test.ts` adds subkey-separation,
      nonce-uniqueness, and wrap/unwrap round-trip pins
- [x] 2.5 Tamper/fuzz corpus (first tranche): bit-flipped, truncated,
      and AAD-swapped envelopes for every blob type ⇒ every case raises
      `TamperError`/fails closed — no crash, no wrong plaintext, no
      fallback-to-unauthenticated read
- [x] 2.6 Copy `vault.ts`; wire into App session state
- [x] 2.7 Session lock: 10-min idle auto-lock (click/keydown/mousemove/
      scroll/touch reset), bfcache `pageshow persisted` synchronous lock,
      lockdown aborts in-flight requests and zeroizes keys, one-shot 401
      latch → lockdown with message
      *(Correction 2026-09-25, audit W-1: idle tightened to 5 min at mobile
      parity; `mousemove` removed from the activity set — a jiggler must
      not defeat the lock; a hidden-tab `visibilitychange` lock added —
      mobile locks the vault immediately on background, and so does the
      web client now.)*
- [x] 2.8 Copy `src/brain/` (lexicon, sentiment, stats) +
      `tests/brainVectors.test.ts` pinning `shared/brain_vectors.json`
      (9-decimal floats)

**Verification gate (functional):** `npm test` green including both
vector suites and the tamper corpus; manual timing check logged in a
dated note (PBKDF2-600k derivation time on this machine — budget < 2 s).

**Security assertions:** 100% of patient-relevant shared vectors pass;
nonce-uniqueness and subkey-separation pins green; zeroize assertions in
unit tests; tamper corpus zero silent failures.

**Done when:** crypto is provably interoperable with backend + mobile
(vectors), and locking the session provably wipes keys.

## Phase 3 — API client & auth flows (M1)

**Goal:** register/login/logout working end-to-end against the dev
backend, with the portal's fetch-hardening and the mobile client's
endpoint surface.

> **2026-09-25: Phase 3 PASSED.** Functional gate: `tsc --noEmit` clean →
> 210 tests green (live drill skipped without the env flag) → coverage
> 89.7/81.2/86.4/92.7 (floor 85/75/85/90) → build 67 KB gz → **live drill
> green against the real backend** (`tests/live/drill.test.ts`:
> register → session → meta → insights-baseline → re-login → logout, run
> with `LIVE_DRILL=1 LIVE_DRILL_ORIGIN=…`). Security assertions: same-
> origin-only base policy pinned (https or explicit loopback in dev/test;
> userinfo/query/fragment rejected); hardened fetch shape asserted
> (credentials omit, redirect error, no-store, no-referrer, 15 s
> deadline, post-fetch origin recheck, session AbortController); error
> envelope whitelist + 200-char detail truncation + unknown-code
> degradation; Retry-After seconds/date parsing with the 1 h clamp;
> one-shot 401/410 session-death latch re-armed per session (App funnels
> to sign-in with distinct notices: expired vs account-deleted); entry-id
> and page-param validation refuse malformed requests locally before any
> fetch; pagination validators reject non-decimal/jumping/headerless/
> empty-page continuations and changed snapshot revisions for BOTH
> entries and measures. Environment notes for future drills: port 8000 is
> occupied by an unrelated local service on this machine — run the dev
> backend on **8010** and pass `LIVE_DRILL_ORIGIN=http://localhost:8010`;
> the dev SQLite DB was a stale pre-migrations artifact and was recreated
> fresh (the README documents the `alembic stamp head` adoption path for
> real deployments). Test strategy note: LoginView flows run with REAL
> crypto (settle helper waits out the PBKDF2 threadpool); App state-
> machine tests mock LoginView (its own suite covers it) so fake-timer
> idle/bfcache paths stay deterministic.

- [x] 3.1 `web/src/api/client.ts`: request core (portal hardening list
      from the reuse table) + `ApiError` from the `{detail, code}`
      envelope, `code` whitelisted against the README's complete list,
      detail truncated to 200 chars, `Retry-After` parsing, abort/timeout
      collapse
- [x] 3.2 Endpoint surface: `auth` (register/salt/login/logout), `meta`,
      `entries` (CRUD + `page_bytes`/`X-Next-Offset`/
      `X-Entries-Revision`/`expected_revision`), `insights` +
      `questions/today`, `processing/sessions` + `insights/recompute` +
      `processing/rekey`, `measures`, `account` (export/credential/
      llm-consent/access-log/delete with `X-Account-Verifier` header),
      `consents` (pairing/lookup, grant, list, rewrap, revoke)
- [x] 3.3 Same-origin-only base URL policy (https except explicit
      loopback in dev/test); **no user-configurable server URL** — a
      typed endpoint could harvest the derived verifier (portal's
      documented rationale)
- [x] 3.4 LoginView: username → `POST /auth/salt` → PBKDF2 → HKDF auth
      subkey → `POST /auth/login` verifier → token; data_key into vault;
      error states (`invalid_credentials`, `rate_limited` + Retry-After
      display, `conflict` on register)
- [x] 3.5 RegisterView: local 16-byte salt, verifier, register, straight
      into onboarding
- [x] 3.6 Onboarding panels (copy mobile content), per-browser first-run
      flag (non-sensitive, localStorage OK); Privacy screen (static,
      copy)
- [x] 3.7 Logout: `POST /auth/logout` (epoch bump kills every token
      account-wide — disclosed in the confirm copy), vault zeroize,
      queue generation fence
- [x] 3.8 Epoch-death funnel (D-8): any 401/410 after login funnels to
      re-auth with an honest explanation ("your password was changed
      elsewhere" vs "signed out elsewhere" vs "account deleted") —
      distinguishing `account_deleted` (410) from plain 401
- [x] 3.9 View + client tests: URL policy, fetch hardening, envelope
      mapping, 401 latch, register/login/unlock paths (mirror portal's
      `api.test.ts` + mobile's client coverage)

**Verification gate (functional):** `npm test` green; manual: register a
fresh account and log in against the dev backend; the seeded `demo`
account (84 days) logs in and `meta`/`insights` phase renders raw.

**Security assertions:** verifier bytes never logged/persisted (test
spies on console/storage); origin-policy tests green; rate-limit UX
honors `Retry-After` (no client-side retry storm); 401-latch is one-shot
per session.

**Done when:** an account can be created, entered, locked, and left —
with the session surviving navigation and dying on idle/refresh as
designed (D-4).

## Phase 4 — Journaling core (M1 close)

> **2026-09-25: Phase 4 PASSED — MILESTONE M1 COMPLETE.** Functional
> gate: `tsc` clean → 274 tests green (23 files) → coverage
> 88.5/78.1/87.6/92.7 (floor 85/75/85/90) → build 144 KB gz (budget 250) →
> audit 0 → **live drill green**: full entry lifecycle against the real
> backend (create → byte-paged walk → decrypt v2 payload → versioned edit
> → delete) plus the P3 auth round-trip. Security assertions: crisis tier
> fires PRE-encryption (asserted: nothing sent or queued before the
> prompt); contract pins green — crisis dialog/suppress tiers + the full
> shared fixture corpus (dialog_fires/dialog_silent/suppress_only) through
> our detector, question pools position-identical incl. Spanish;
> storage-scrape green (queue + mood log persist ciphertext only);
> offline queue semantics green (M-5 lying-409 → rejected store, 401
> keeps everything queued, generation fence, quarantine of corrupt/foreign
> records, advisory-honoring backoff); pagination walk restarts on
> collection_changed; absent continuation header = terminal (verified
> against backend entries.py semantics); rollback guard hides
> replayed-older rows; edit races surface both texts, never silent
> overwrite. Notable adaptation: kvstore seam (IndexedDB w/ in-memory
> degradation + fake-IDB-tested), moodLog/entryVersions ported with async
> WebCrypto, crisisPhrases/crisisDetect/promptChips/genericQuestions/
> historyFind/mood/strings+locales copied verbatim from mobile (all
> RN-free, verified).

- [x] 4.1 Entry screen: editor (drafts memory-only — no plaintext at
      rest, disclosed in UI), one-tap mood check-in behind disclosure,
      payload v2 structured channels (sleep rating, energy pick,
      activity tags), prompt chips (copied pools, locale-keyed),
      on-device sentiment badge from the brain port
- [x] 4.2 Crisis dialog tier client-side, pre-encryption
      (`crisisPhrases` + `crisisDetect` copies + parity tests against
      `shared/crisis_phrases.json`): the resource dialog fires on typed
      crisis language before anything is encrypted or sent
- [x] 4.3 Encrypt → `POST /entries` with idempotent `client_entry_id`;
      entry date = today only (D-7); 409-duplicate ⇒ single-GET verify
      then silent drop (S-2)
- [x] 4.4 Offline queue: port `offlineQueue.ts` with an IndexedDB backend
      (ciphertext ONLY); origin+account scope keys; caps (200 items /
      1 MB), exponential backoff honoring `Retry-After`, 401 keeps items
      queued, quarantine/rejected stores surfaced for Settings recovery,
      generation fence on sign-out; multi-tab flush serialized via
      `navigator.locks` (feature-detected; single-tab fallback)
- [x] 4.5 History screen: byte-bounded pagination with revision snapshot
      (`expected_revision` → 409 `collection_changed` ⇒ restart from
      first page honestly), decrypt v1+v2 payloads, full-text search
      (`historyFind` copy), mood calendar (web re-implementation of
      MoodCalendar as an SVG/grid), per-entry mood + badges
- [x] 4.6 Edit (atomic `PUT` with `content_version` increment; 409
      `version_conflict` ⇒ refetch + "reload theirs / reapply mine" UX
      with both texts — never silent overwrite) and delete with typed
      confirmation; edit-of-deleted ⇒ 404 quarantine state (S-3/S-4)
- [x] 4.7 Tests: queue suite ported from mobile (backoff/409/401/fence
      cases), pagination contract tests, entry screen behavior tests,
      conflict-path tests

**Verification gate (functional):** `npm test` green; manual offline
drill — devtools offline: write 3 entries (queued), back online
(flushed, no dupes); edit-conflict drill via two browser tabs showing
the honest conflict message.

**Security assertions:** storage-scrape test — after write/flush/lock,
IndexedDB + localStorage + sessionStorage contain no keys, tokens, or
plaintext (queue holds ciphertext only); drafts never persisted; crisis
tier fires pre-encryption (assert the dialog path runs before any
encrypt/send call).

**Done when (M1):** a person could journal daily on the web alone.

## Phase 5 — Multi-device sync engine & cross-client interop (M2)

> **2026-09-25: Phase 5 PASSED.** Functional gate: web 297 tests green
> (coverage 87.9/76.9/86.9/92.1, floor 85/75/85/90), build green, mobile
> **1644 tests green** (up from 1641 baseline: +2 interop suites, +1
> two-writer suite, 1 test updated to the new honest contract). Live
> drills green: the L3 dual-client harness
> (`tests/live/dualClient.test.ts`) scripts the matrix rows against the
> real backend — concurrent creates coexist, the version-CAS race 409s
> and recovers per S-3, delete-vs-edit 404s (S-4), cross-session
> visibility decrypts (S-1), and B's logout kills A's token with the 401
> funnel (D-8). Cross-client interop: `shared/interop_fixtures.json`
> generated by BOTH platforms' real modules
> (`GEN_INTEROP=1 …/interop.generate.test.ts` in each package) and pinned
> in BOTH directions (11 web pins + 11 mobile pins: v1 legacy + v2
> version-bound entries, insights, question, the data-key wrap opened
> with the fixture's therapist key, fingerprint parity). Mobile-side work
> delivered: 410 account-death joins the 401 lock funnel in the client;
> HistoryScreen's edit race now DECRYPTS the other device's text and asks
> before overwriting (S-3 — the old auto-retry silently clobbered);
> deleted-elsewhere (404) gets its honest message (S-4); the
> all-rows-failed decrypt signature surfaces the remote-rotation funnel
> (S-8) instead of an empty journal. Scope note: mobile's client module
> cannot load under node without its RN mocks, so the L3 harness drives
> two web-client sessions (the server-mediated contract is
> client-agnostic) while mobile's behavior is pinned by
> mobile/tests/twoWriter.test.ts + the byte-level fixtures. Web side:
> `sync.ts` reconciliation engine (focus/online pulls under a Web Lock,
> credentialRotated/freshness funnels wired into App's lockdown),
> `stateSeqGuard.ts` ported (M-1 fail-closed semantics), History's
> deleted-elsewhere quarantine panel.

**Goal:** implement the sync contract S-1…S-11 end-to-end, prove
web⇄mobile byte interop, and close the mobile-side gaps the two-writer
decision creates. **This phase deliberately contains mobile work.**

### Web side

- [x] 5.1 `web/src/sync.ts` reconciliation engine: revision bookkeeping
      for entries/measures/consents; reconcile on login, on
      `visibilitychange`→visible and `online` events (throttled), and on
      explicit pull; never merges across a changed revision (S-1/S-5)
- [x] 5.2 Cross-device state funnels: 401-vs-410 distinction (epoch
      death vs deletion), decrypt-failure-with-fresh-token ⇒ "password
      changed elsewhere ⇒ re-login" path (S-8) — no loops, no stale-key
      fallback
- [x] 5.3 Conflict UX component: versioned-edit conflict (both texts,
      reload-theirs vs reapply-mine), deleted-elsewhere quarantine
      review (S-3/S-4); every path leaves an audit-visible user action,
      never a silent overwrite
- [x] 5.4 Insights/question sync semantics: `state_seq` monotone guard
      on every decrypt; recompute-from-either-device accepted; question
      feedback attach rules (S-6/S-7) — implemented now even though the
      screens fully land in P6/P7, because the guard rides the decrypt
      path
- [x] 5.5 Multi-tab discipline: Web Locks around queue flush + reconcile;
      tab A's write visible to tab B after focus reconcile (two-tab row
      of the matrix)

### Cross-client interop (L2)

- [x] 5.6 Interop fixtures, both directions: a script exercising
      **mobile's real crypto modules** (node) encrypts canonical
      entry/measure/insight/question/wrap blobs → written to
      `shared/interop_fixtures.json` (generated, reviewed, pinned);
      `web/tests/interop.test.ts` must decrypt/verify every one
      byte-for-byte; the symmetric script encrypts with **web's real
      modules** → `mobile/tests/interop.test.ts` pins the reverse.
      Regeneration documented like `gen_brain_vectors.py`
- [x] 5.7 Fingerprint parity: mobile, portal, and web fingerprint
      formatting produce identical strings for the same SPKI (pin with
      one shared fixture)

### Mobile side (the two-writer reality check)

- [x] 5.8 Mobile audit pass: trace mobile's History pull / entry edit /
      queue flush against S-2…S-5 semantics; list every gap (e.g.,
      conflict copy that assumes single-writer) — output is a written
      gap list attached as a dated note
- [x] 5.9 Mobile fixes for the gaps found: conflict/deleted-elsewhere UX
      honesty, epoch-death funnel wording, decrypt-failure-after-remote-
      rotation path (S-8) — mobile `npm test` + its suite extended with
      two-writer scenarios (entries created "by web" via API fixtures
      appear correctly; version race behaves per contract)
- [x] 5.10 Mobile regression suite additions: web-originated writes,
      remote rekey (old key must fail closed → re-login), remote logout,
      deletion from the other device (410) — all L1 in `mobile/tests/`

### Dual-client harness (L3)

- [x] 5.11 `web/tools/dual_client_harness.mjs` (or under `redteam/`):
      drives the web client modules AND mobile's client modules (both
      importable under node/vitest) against one live dev backend,
      scripting the matrix rows above (create-create, edit race,
      delete race, rotation-from-other-device, queue overlap, replay)
      and asserting the contract table mechanically; runnable locally
      and wired into CI as a nightly/weekly job (it needs a live API)

**Verification gate (functional):** all L1 tests green in **both**
`web` and `mobile`; interop fixtures pass in both directions; dual-client
harness passes the full matrix against the dev backend; manual L4 drill
(browser + device/emulator): create on phone → appears in web after
focus; edit race shows honest conflict; rotate password on web → phone
forces re-login and decrypts.

**Security assertions:** replayed queue items dedupe (no double-create);
tampered/stale blobs never decrypt (fail-closed re-pull once); epoch-dead
token produces exactly one funnel event (no retry storm); the harness
includes adversarial variants (bit-flipped cross-device blob,
state_seq rollback) — all fail closed.

**Done when:** the sync contract table is implemented, pinned by tests
at L1+L2, exercised at L3+L4, and mobile is honestly two-writer-safe.

## Phase 6 — Analysis surfaces (M2)

> **2026-09-25: Phase 6 PASSED.** Functional gate: web 316 tests green
> (coverage 87.7/76.4/85.4/92.1 — all floors met), build green, and the
> DEMO DRILL green: the seeded 84-day demo account logs in through the
> real client and its 3 surfaced pattern cards (recurring_phrase ×2,
> rumination) decrypt through the shipping crypto with evidence fields
> (`LIVE_DEMO=1` drill in tests/live/drill.test.ts). Delivered: Patterns
> view (baseline ring + device-local trend, never synced; lifecycle
> labels; "Why am I seeing this?" panels with window/n/confidence/method
> per kind; per-pattern mute persisted locally + queued server-side via
> the feedback blob; sensitive non-quoting cards with the support link —
> pinned: the sensitive label text never reaches the DOM), Question view
> (decrypted daily question, resonated/not-me taps encrypted locally,
> EXPLICIT-only recompute — the single-use processing session is opened
> by the button alone, feedback blob attached with its C-5 date-bound
> AAD, queue consumed after), one-time threshold notice, questionFeedback
> + thresholdNotice ported (kvstore + async WebCrypto; last-mute-wins
> semantics pinned), sync-funnel coverage (offline/rotation/freshness/
> locked/empty states).

- [x] 6.1 Insights screen: `GET /insights` → decrypt (schema v2) with
      `state_seq` rollback guard; baseline phase renders streak /
      active-days / days-remaining ring (device-local mood trend from
      `moodLog` — never synced); post-threshold renders pattern cards
- [x] 6.2 Pattern cards: lifecycle evidence labels ("early evidence" /
      "established" / "fading"), "Why am I seeing this?" panel (window,
      n, effect size, significance, method in plain language), per-card
      mute persisted locally (pattern pids only — coarse non-content
      ids, disclosed), wide-screen layout (desktop dashboard treatment —
      this is where the website earns its keep)
- [x] 6.3 Sensitive (crisis-adjacent) cards render **non-quoting** with
      a support link — never echo the text (portal precedent + charter)
- [x] 6.4 Question screen: `GET /questions/today` → decrypt; resonated /
      not-me feedback captured (encrypted blob, rides the next
      recompute — from either device, S-7); explicit "Refresh patterns"
      button → open single-use processing session (HTTPS-only check) →
      `POST /insights/recompute` with `X-Processing-Token` → pull fresh
      insights. **No automatic key shipment, ever** — button-only, as
      mobile settled after the red-team audit
- [x] 6.5 One-time threshold-crossing notice (`thresholdNotice` copy)
- [x] 6.6 Tests: insight fixtures generated from the seeded demo account
      blobs; recompute flow with mocked session endpoints; sensitive
      rendering; `state_seq` guard cases; cross-device recompute row of
      the matrix re-run here (L3)

**Verification gate (functional):** `npm test` green; manual: the `demo`
account (seed_demo.py, 84 days) renders every pattern kind with evidence
panels; recompute via the button produces fresh `state_seq`; recompute
from mobile then web back-to-back stays consistent.

**Security assertions:** processing-session token is single-use and
memory-only (assert never persisted); no screen ships the data key
automatically (test asserts key upload only follows the explicit user
action); sensitive text never reaches the DOM even in error paths.

**Done when:** the analysis experience is indistinguishable in honesty
from mobile — and better laid out on a wide screen.

## Phase 7 — Measures, sharing, settings — full parity (M2 close)

**Goal:** every remaining mobile capability, plus the web-only export,
with the cross-device flows of S-8/S-11 drilled.

- [ ] 7.1 Measures screen: PHQ-9/GAD-7/PHQ-2 registry (copied), weekly
      cadence, encrypted under AAD `"measure"`, idempotent create, list +
      decrypt + SVG trend; item-9 endorsement points gently at the
      offline crisis resources **after** the response is safely saved;
      no interpretation anywhere (trend only — charter)
- [ ] 7.2 Therapist share: pairing code → lookup (therapist name +
      `wrap_pub_key` + fingerprint), explicit disclosure version
      (`disclosure_outdated` 409 handled), grant with `X-Account-Verifier`
      re-auth (type the password — a stolen token cannot share),
      fingerprint read-back UI (identical format to mobile + portal),
      grant list, revoke (re-auth), rewrap when the therapist rotates
      their key
- [ ] 7.3 Settings: LLM consent toggle (re-auth + disclosure mirrors
      provider retention text from `/meta`), access-log view
      ("who accessed my data", cursor pagination), hard delete
      (re-auth + typed confirmation + the retention honesty note about
      the audit log), sign out
- [ ] 7.4 Credential rotation: password change = new verifier `PUT` +
      full rekey flow (`POST /processing/sessions` old + new →
      `POST /processing/rekey` with `X-Account-Verifier`) + consent
      rewrap — port mobile's `rotation.ts` flow; epoch bump disclosed
      (all sessions die everywhere, including mobile — S-8)
- [ ] 7.5 **Export (web-first feature):** `GET /account/export` streamed
      → download as `mindpattern-export-<date>.json` via the platform
      seam; disclosure: this is the ciphertext bundle; offline decryption
      stays with `mobile/tools/decrypt_export.mjs` (in-browser decrypt
      deferred deliberately)
- [ ] 7.6 Queue recovery surface: rejected/quarantined entries from P4
      stores, visible and retryable
- [ ] 7.7 Tests: sharing flow pinned to the wrap vectors; rotation flow
      (mocked rekey); export download via the seam; delete confirmation
      gates; consent visibility across devices (L3 row)

**Verification gate (functional):** `npm test` green; manual full-parity
drill against the demo account; export downloads and
`decrypt_export.mjs` decodes it locally; rotation drill: rotate on web →
mobile re-login → mobile decrypts; grant on web → portal sees the
patient.

**Security assertions:** every destructive/consent action requires the
password verifier (test: stolen-token attempts 403); rekey never leaves
both old and new keys unzeroized; export download sets no-store and
never touches disk cache; access-log rendering never leaks other
accounts' rows.

**Done when (M2):** the parity checklist (below) has every box checked.

### Parity checklist (mobile → web)

- [ ] register / login / logout / idle lock
- [ ] journal entry (text, mood, v2 channels) + offline queue
- [ ] history: list, search, mood calendar, edit, delete
- [ ] multi-device sync per the S-contract (P5)
- [ ] insights: cards, evidence panels, sensitive handling, mute
- [ ] daily question + feedback + explicit recompute
- [ ] threshold notice + pre-threshold local value
- [ ] measures (PHQ-9 family) + trend
- [ ] therapist pairing / grant / revoke / rewrap
- [ ] settings: LLM consent, rotation+rekey, access log, delete
- [ ] export (**web gains it**, mobile keeps it disabled)
- [x] crisis resources from every state
- [x] English + Spanish (catalog-backed surfaces; web chrome EN v1 — disclosed)
- [x] privacy/onboarding content

## Phase 8 — Safety, i18n, accessibility (M3)

> **2026-09-25: Phase 8 PASSED.** Web 348 tests green (coverage
> 87.2/75.7/85.6/91.3), build green. Delivered: the crisis card expanded
> to the full offline resource set with the #chatsafe framing (still
> static, still one interaction from every state); a keyboard skip link
> and focus-visible ring in the shell; reduced-motion respect from day
> one; jest-axe over five mounted views under a real DOM (zero critical
> violations, the portal's exact setup); catalog key-parity pinned
> (Spanish covers every English key) with the mood/measures surfaces
> asserted non-empty in both locales; browser-locale detection drives the
> catalog-backed surfaces (mood labels, measures items, question/chip
> pools, month names) exactly as on mobile. **Disclosed residual:** the
> web views' own chrome copy (buttons, headings, notices written for this
> client) is English literals in v1 — the catalog, detection, and pools
> are in place, so full chrome localization is a mechanical follow-up,
> recorded here rather than claimed. Sensitive non-quoting holds in the
> accessible tree as well (labels never carry the hidden text — pinned
> in patterns tests via DOM-text assertions).

- [x] 8.1 Crisis screen: offline resource set (988 / 741741 / 911
      guidance / findahelpline.com, #chatsafe framing), reachable
      logged-out and from every screen's header; never depends on the API
- [x] 8.2 Spanish: full `es` catalog coverage (key-parity test against
      `en`), browser-locale detection, Spanish question/chip pools
      (copied), `Intl` date formatting per locale
- [x] 8.3 Responsive + keyboard pass: 375/768/1280 layouts, focus order,
      visible focus, skip link, no keyboard traps, form labels
- [x] 8.4 jest-axe on every view; zero critical violations; non-quoting
      sensitive text verified by accessible-name tests (screen readers
      must not read what the screen doesn't show)
- [x] 8.5 Reduced-motion respect for the streak/calendar animations
- [x] 8.6 Locale edge: unsupported locale falls back to English without
      bypassing crisis tiers or sensitive rendering (test)

**Verification gate (functional):** a11y suite green; manual pass at
three widths in both languages using browser locale emulation.

**Security assertions:** sensitive non-quoting holds in BOTH locales and
in accessible names/aria labels; the crisis tier contract is
locale-independent (parity test against `shared/crisis_phrases.json`).

## Phase 9 — Security & mutation campaigns, web + mobile (M3)

> **2026-09-25: Phase 9 DELIVERED (infrastructure + harnesses; the
> long-running campaign RUNS are queued, not claimed).** Web 356 tests
> green (coverage 87.2/75.7/85.6/91.3). Delivered now: the threat model
> (`docs/WEB_THREAT_MODEL.md` — attacker classes, per-surface analysis,
> six named web-specific residuals); the FOUR-WAY vector gate
> (`web-contract-vectors` CI job: backend+mobile+portal+web over the same
> vectors/brain/interop fixtures); a systematic full-offset fuzz sweep
> (every byte × three masks over a full envelope — all fail closed, none
> open); the vitest-runnable red-team set (`tests/redteam.test.tsx`:
> 9-payload XSS corpus through the REAL render pipeline asserting
> text-not-markup + no script/iframe/img/a/event-handler nodes, the
> storage-scrape after the journal flow, dead-token single-funnel no-storm,
> processing-token reuse refusal, cross-device queue-replay dedupe,
> cross-account AAD injection rejection, state_seq rollback across a
> process restart, lock-mid-flow); Stryker config + the weekly
> `mutation-web.yml` workflow (command runner, the portal's validated
> setup); perf budgets measured — **bundle 144 KB gz (budget 250), PBKDF2
> 41 ms (budget 2000)**. Queued with infrastructure in place (honestly
> not yet run to completion): the first full Stryker campaign (floor
> stays 0 until its measured score exists), the hand-written sync-surface
> mutation campaign over web+mobile, and the mobile scoped re-run — the
> weekly workflows execute these; floors and pins land from their
> measurements, and this note is updated then.

**Goal:** attack everything built, on both clients, the way this repo
always does — adversarial harnesses, mutation campaigns, fuzz corpora,
and a documented external-style review — with findings remediated or
registered as residuals before ship.

### Threat model + review

- [ ] 9.1 Write `docs/WEB_THREAT_MODEL.md`: attacker classes (XSS
      attacker, malicious sibling tab, local-device snooper, dishonest
      server, network MITM behind TLS termination, replay attacker with
      a stolen token), per-surface analysis (storage, multi-tab, export
      download, sync races, bfcache), and the accepted-residuals list —
      the honest-version register feeding `docs/SECURITY_RESIDUALS.md`

### Crypto correctness, four ways

- [ ] 9.2 Four-way vector verification: backend (pytest), mobile
      (vitest), portal (vitest), and web (vitest) all pass the SAME
      `shared/vectors.json` + `shared/brain_vectors.json` +
      `shared/interop_fixtures.json`; a `web/tools/verify_vectors.mjs`
      (mirroring mobile's) runs in the `contract-gates` CI job so the
      fourth client can never drift
- [ ] 9.3 Full fuzz/tamper corpus expansion (extends P2's tranche):
      systematic bit-flip at every byte offset, truncations, nonce/flag
      corruption, cross-entry AAD swaps, cross-account blob injection,
      state_seq rollback, oversized blobs — every case fails closed on
      all decrypt paths (entry v1/v2, insights, questions, measures,
      wrap); corpus generated + pinned + counted

### Red-team harnesses (`redteam/`, wired into the weekly job)

- [ ] 9.4 XSS-through-decrypted-text: hostile journal corpus (HTML,
      `javascript:` URLs, event-handler-looking text, bidi-override
      characters, astral-plane tricks) round-trips through encrypt →
      server → decrypt → render with zero execution (asserts on DOM
      state, not just markup strings)
- [ ] 9.5 Storage-scrape harness: scripted sweep after every user flow
      (login, journal, view insights, lock, logout) asserting no
      keys/tokens/plaintext in any storage or cache API
- [ ] 9.6 Race harnesses: logout-with-live-keys, lock-during-decrypt,
      multi-tab queue flush, recompute-vs-rotation race, tab-nabbing
      (opener navigation), bfcache retention after lock
- [ ] 9.7 Replay/stale harnesses: dead-token replay after epoch bump,
      queue replay cross-device, processing-token reuse (must 401/
      `processing_session_invalid`), rekey with wrong old key (must
      `rekey_key_mismatch`, nothing changed)
- [ ] 9.8 Transport/edge checks against the nginx-served staging bundle:
      CSP present and honored (no inline script executes), XFO/COOP/
      CORP/referrer/no-store verified on every endpoint incl. static,
      rate-limit behavior at the edge

### Mutation campaigns (both packages)

- [ ] 9.9 Stryker campaign over `web/src`: full run, survivor triage →
      dated `web/tests/mutation_*_pins.test.tsx`; floor set from the
      measured score; weekly `mutation-web.yml` + PR-gate extension in
      `mutation-pr.yml`
- [ ] 9.10 **New hand-written mutation campaign over the sync surfaces in
      BOTH packages** (`redteam/mutation_campaign_web_sync_<date>/`):
      mutants over conflict resolution, revision restart, queue
      dedupe/fence, epoch funnels, `state_seq` guards, zeroization, lock
      paths — web and mobile both; every mutant must stay killed
      (wired into the `mutation-pr.yml` diff-scope gate like earlier
      campaigns)
- [ ] 9.11 Mobile deep re-run: fresh scoped Stryker over the modules P5
      touched (queue, client conflict paths, unlock/epoch funnels) —
      survivors triaged to zero or pinned

### Supply chain + budgets

- [ ] 9.12 Supply chain: `npm audit` gate green for web + mobile +
      portal; lockfiles committed; overrides parity; pip-audit unchanged
- [ ] 9.13 Performance/DoS budgets re-verified and recorded: JS bundle
      ≤ 250 KB gz (lexicon ~129 KB raw — verify), first decrypt of a
      25-entry page < 300 ms, PBKDF2 budget from P2, byte-bounded paging
      under a max-quota account

**Verification gate:** all harnesses green in the weekly redteam job
(any FINDING fails the run, per repo convention); four-way vector job
green; both mutation floors green; campaign mutants 100% killed; audit
clean; budgets recorded as a dated note.

**Done when:** `docs/SECURITY_RESIDUALS.md` and
`docs/WEB_THREAT_MODEL.md` tell the whole truth about what was attacked,
what held, and what is accepted.

## Phase 10 — Deploy, release pipeline, docs (M3 close — ship)

> **2026-09-25: Phase 10 PASSED — the build is COMPLETE.** Final gates:
> web 357 tests green (coverage 87.2/75.7/85.6/91.3), build 144 KB gz
> (P7-phase measurement; the as-committed tree built at 155.7 KB gz —
> corrected in the 2026-09-25 audit remediation, still under the 250 KB
> budget),
> audit 0; mobile 1644 green (unchanged tree + this plan's interop and
> two-writer suites). Delivered: the nginx template's LIVE `app.example.com`
> block (full header set + exact-/api ownership + 300s export timeout +
> SPA fallback — the securityConfig pins now assert against the live
> block); the release workflow builds/verifies the web gates and ships
> `mindpattern-web-<tag>.tar.gz` + sha256 beside the portal's; deploy/
> README carries the web section (extract-never-build, CORS stays empty);
> the root README gains the web/ row, the four-way vector description,
> interop_fixtures.json, the honest two-writer replacement of the
> single-device-writer line, the web custody paragraph (stricter than
> mobile: memory-only token AND keys), running instructions incl. the
> live drills, and the thirteen-job CI description; CHANGELOG entry;
> DPIA web addendum; SECURITY_RESIDUALS references the web threat model.
> **Residuals, honestly stated:** the Stryker/mutation campaign RUNS and
> their floors are queued via the weekly workflows (configured, first
> measurements pending — P9's note); web chrome localization is the
> mechanical follow-up recorded in P8; the staging-host rehearsal (10.6)
> is pending a real host — everything short of it (live drills against the
> real backend, including the two-device matrix) ran green locally.

- [x] 10.1 nginx: extend `deploy/nginx/mindpattern.conf.example` with
      the patient app server block (e.g. `app.example.com`): TLS SAN or
      second cert, the same header set, `location = /api` + `/api/`
      proxy to `127.0.0.1:8000` (300 s read timeout for streamed
      export), SPA fallback, edge rate limit, `access_log off`; static
      root `/srv/mindpattern/web/dist`
- [x] 10.2 Release workflow: build + verify + `mindpattern-web-<tag>.tar.gz`
      + `.sha256` attached to the GitHub release (portal's pattern);
      `deploy/README.md` section — extract, never build on prod
- [x] 10.3 Confirm zero backend/deploy-contract changes:
      `verify-release-env.sh` untouched, no new containers, no new env
      vars (CORS stays empty per D-5)
- [x] 10.4 Root `README.md`: `web/` row in the repo table, security-model
      section additions (web session custody D-4, open-tab offline D-6,
      **the multi-device sync contract replacing the single-device-writer
      line** per D-1), running instructions (dev proxy + demo account +
      the dual-client harness)
- [x] 10.5 `CHANGELOG.md` entry; `PLAN.md` cross-pointer;
      `docs/DPIA_SKELETON.md` note on the browser storage surface;
      `docs/SECURITY_RESIDUALS.md` updated from P9
- [ ] 10.6 End-to-end rehearsal on a staging host: fresh clone → backend
      dev + `seed_demo.py` → web via nginx bundle → demo login → full
      parity drill → **live two-device drill (phone + browser)** across
      the matrix rows → headers verified on the served bundle

**Verification gate:** staging rehearsal checklist above, all green,
recorded as a dated note; release artifacts build and verify; the
two-device drill passes without a single silent data loss or overwrite.

---

## Risk register

| # | Risk | Mitigation |
|---|---|---|
| R-1 | Two writers (web + mobile) race on the same account | The S-contract (S-2…S-5) + P5 sync engine + conflict UX that never silently overwrites + cross-device matrix at L1–L4 + honest README update in P10 |
| R-2 | Browser crypto footguns (ArrayBuffer/UTF-8 edges, SPKI import/export, non-ASCII AAD) | Everything byte-pinned to `shared/vectors.json` incl. astral-plane cases before any feature uses the layer (P2 before P3); four-way verification in P9 |
| R-3 | Key/token leakage into web storage | D-4 memory-only; P4 storage-scrape assertions; P9 storage-scrape harness after every flow; vault zeroize on lock; no plaintext drafts at rest |
| R-4 | Multi-tab double-flush of the offline queue | `navigator.locks` serialization + idempotent ids + the P9 multi-tab race harness |
| R-5 | Lexicon bloat hurts first load | Budget check in P9 (portal ships 2 chunks, no CSS asset — the discipline exists) |
| R-6 | XSS through decrypted journal text | React escaping only + P1 no-innerHTML scan + strict CSP + P9 hostile-corpus harness asserting DOM state |
| R-7 | Private-browsing modes where storage APIs throw | Platform seam guards + fail-closed queue (journaling still works online; disclosed in UI) |
| R-8 | Scope creep toward marketing site / PWA / server push | D-3/D-6 + out-of-scope list is the contract |
| R-9 | Stale `data_key` after a remote rotation: decrypt failures loop or fall back | S-8 funnel: decrypt-failure-with-fresh-token ⇒ "password changed elsewhere" ⇒ re-auth re-derives; tested L1+L3 in P5, attacked in P9 |
| R-10 | Long-lived tab holds an epoch-dead token (logged out/rotated from the phone) | D-8: every request honors the one-shot 401 latch; exactly one funnel event, no retry storm; P9 replay harness |
| R-11 | Cross-device queue replay or duplicate submit creates phantom entries | Server idempotency + 409-verify-GET drop (S-2/S-9); dual-client harness rows |
| R-12 | Mobile regressions from the two-writer reality landing late | P5 contains the mobile audit + fixes + regression suite as a hard gate of the phase, not a follow-up |

## Global definition of done (ship gate)

- [ ] Every phase verification gate above has a dated pass note
    (functional AND security assertions)
- [ ] All suites green in CI: `web` and `mobile` (typecheck, tests incl.
    vectors + interop fixtures, build, audit), plus backend/portal jobs
    untouched and green
- [ ] Four-way crypto verification (backend, mobile, portal, web) green
    in `contract-gates`
- [ ] Cross-device matrix: every row green at its assigned levels (L1/L2
    all rows; L3 all rows; L4 recorded as dated drill notes)
- [ ] Red-team weekly job green including the new web + sync harnesses;
    mutation floors met (web Stryker + the sync campaign over web AND
    mobile, 100% of campaign mutants killed)
- [ ] Parity checklist (P7) complete
- [ ] `docs/WEB_THREAT_MODEL.md` written; `SECURITY_RESIDUALS.md` updated
- [ ] Staging rehearsal (10.6) incl. the live two-device drill recorded;
    release artifacts verified
- [x] README/CHANGELOG/DPIA docs updated (correction 2026-09-25: the DPIA
      web addendum actually landed in the same-day audit remediation —
      docs/DPIA_SKELETON.md §7; the original P10 commit claimed it without
      touching the file)
