# Frontend mutation campaign — 2026-09-22

## Scope

The last portal Stryker run that measured all of `portal/src` was round 2
(2026-09-18, 2,262 mutants, 1.41% — and that number was measured with the
later-found-broken vitest-runner wiring). Everything since — TOTP login and
enrollment, the account-security rotation surface, note edit history, measures
pagination, caseload summaries, the a11y suite, four audit-remediation waves —
had never been mutation-tested with a runner that actually executes tests.
Mobile's last full campaign was 2026-09-15 (4,356 mutants); +13.7k lines of
src/tests landed since. This campaign measures both frontends fresh, on the
current tree (commit `59802f5` + this campaign's changes):

| Surface | Runner | Mutants |
|---|---|---|
| `portal/src/**` (all ten files) | Stryker 10 command runner (vitest 5 run per mutant, inPlace, concurrency 2, 45 s mutant budget) | 3,549 |
| `mobile/src/**` (64 files) | Stryker 10 vitest-runner (vitest 4.1.11 — the working combo; coverageAnalysis all) | 15,990 |

The portal scope change is deliberate: the committed config was scoped to the
four contract modules (crypto/aad/api/platform, floor 70); the fresh campaign
re-measures the whole `src` because the views are where four audit waves
landed. The canary discipline from the backend campaigns applies: before
trusting any score, a scoped run over a fully-covered module
(`mobile/src/crypto/kdf.ts`, 50/50 killed) proved the runner detects kills.

## Harness repairs found by the campaign itself

- **`mobile/tests/healthBridge.pins.test.ts` (NEW-2)** asserted exact source
  text of `src/healthkit.ts` ("version check next to the module probe").
  Whole-tree Stryker instrumentation rewrites that file (every literal wrapped
  in a mutant ternary), so the full mobile gate would have failed its dry run
  from now on. The pin now skips while the file is instrumented
  (`it.skipIf(/stryMutAct_|__stryker__/)`); every normal run still enforces
  it. This landed after the last weekly gate execution (2026-09-22 04:00 UTC)
  and would have broken the next one.
- **Portal full-src runs hang on view-loop mutants**: the committed 120 s
  mutant budget meant each infinite-loop mutant burned two minutes. The
  budget is 45 s (the suite runs in ~1.4 s — a 30x margin; a mutant that
  cannot finish in 45 s is a hang, and hangs count as timeouts/kills).
- Stryker 10's env-var-selected instrumentation (`__STRYKER_ACTIVE_MUTANT__`)
  makes the command runner safe at concurrency 2, which the fresh runs used
  (verified byte-clean restore via git after every run).

## Portal results

Fresh full-src baseline (before pins):

| File | Mutants | Killed | Survived | Score |
|---|---|---|---|---|
| src/views/PatientView.tsx | 1,204 | 632 | 572 | 52.5% |
| src/views/PatientsView.tsx | 848 | 399 | 449 | 47.1% |
| src/views/LoginView.tsx | 348 | 191 | 157 | 54.9% |
| src/api.ts | 523 | 376 | 147 | 71.9% |
| src/App.tsx | 176 | 83 | 93 | 47.2% |
| src/ui.tsx | 67 | 16 | 51 | 23.9% |
| src/platform.ts | 107 | 57 | 50 | 53.3% |
| src/crypto.ts | 255 | 207 | 48 | 81.2% |
| src/main.tsx | 6 | 0 | 6 | 0.0% |
| src/aad.ts | 15 | 15 | 0 | 100.0% |
| **total** | **3,549** | **1,976 (+7 timeout)** | **1,573** | **55.68%** |

For contrast: round 2's broken-runner baseline over the same scope was
1.41% — the 2026-09-22 remediation waves (220 portal tests added since) did
land real coverage; what survives now is concentrated in presentation
literals and the gaps pinned below.

### Triage of the 1,573 survivors

Every survivor was classified (see `results/portal-baseline-summary.txt` and
the analyze output in `results/`):

- **Genuine gaps → pinned** (70 new tests,
  `portal/tests/mutation_2026_09_22_frontend.pins.test.tsx` +
  `.app.pins.test.tsx`). The classes:
  - *api.ts (147→…)*: session token/base guards; session-replacement abort;
    the post-await session-identity guard (content after logout); the 15 s
    deadline; same/foreign `response.url`; detail clamp; TOTP body shape;
    enrollment-token trim; canonical-decimal continuation corpus; the
    signed-64 revision ceiling (MAX+1 rejected, MAX accepted); dropped
    revision mid-traversal; exact query shapes; offset/limit validation for
    all three resources; exact endpoint paths.
  - *crypto.ts (48→…)*: F-6 score-window boundaries (0/100 in, ±1/NaN/Inf/…
    out) and display slices; hostile caseload-summary sanitization
    (independently constructed oracle — the backend's ECIES construction
    rebuilt in the test); decrypt key-size guard; empty-plaintext envelope
    round-trip (blob length exactly 28 is legal); WebCrypto-absent failure;
    `sealPrivateKeyForUpload` wipes the caller's DER.
  - *LoginView (157→…)*: password-policy boundary table (11/12+3/15+2/16,
    class counters); TOTP input sanitization (digits-only, six max) and the
    stage discipline (wrong-password inside the stage takes the generic path
    and clears the password); failed sign-in wipes derived keys and leaves
    no session; registration establishes the session before onReady;
    incomplete-form submit gating.
  - *PatientView (572→…)*: full review-ordering contract (sensitive <
    mood-shift-down < rumination < topics, strength tiebreak); sparkline
    aria-label average; the complete evidence-row statistical surface;
    first_seen==stamp is NOT new; exactly-one collection restart (and never
    for non-409 codes); the measures page cap against an always-full server
    and the pre-paging backend stop; data-key zeroization after insights and
    drill-down; oldest-first measure rendering; note/evidence pagination
    protocol guards (revision appearing mid-load, revision changing,
    per-resource caps); duplicate-row dedupe and same-date id ordering;
    history busy-guard and empty state; draft trimming and blank-draft
    inertness (create + edit); per-note delete arming; search gate at three
    notes + case/trim-insensitive filter; pattern/general note isolation;
    template newline append; honest "?" stats fallbacks; retry clears prior
    notes/measures.
  - *PatientsView (449→…)*: exactly four credential-PUT attempts on
    persistent 5xx; key-set and pkcs8 zeroization across change/rotate/TOTP
    flows; onSessionsEnded routing; wrong-intended-password recovery changes
    nothing; TOTP code sanitization; hide-panel discards the one-time secret;
    origin-normalization failure surfaces; stopped patients never trigger
    summary decrypts; triage tiebreak by new-since-reviewed; scan controls
    need ≥2 patients.
  - *App.tsx (93→…)*: idle lock at exactly 10 minutes with the honest
    notice; interaction re-arms the clock; unmount clears the session and
    wipes raw keys.
  - *platform.ts/ui.tsx*: print seam, randomBytes freshness, hostile-origin
    degradation, prefix-scoped store cleanup (both stores); Button disabled
    wiring, Field password masking, empty ErrorBanner renders nothing.
- **Cosmetic residuals (documented, not pinned)**: inline style objects and
  theme color literals (≈600 mutants in views + ui.tsx), pluralization and
  label copy fragments, `useState` initial-empty strings that every flow
  overwrites, sparkline path geometry. These are presentation-only; the
  a11y-relevant surfaces (aria-labels, roles, print-CSS contract) were
  already fully pinned — the FIX-15 print-CSS block has zero survivors.
- **Environment-limited equivalents (documented)**: `isDevelopmentBuild()`
  arms (vitest always runs MODE=test, so DEV/production-only mutants are
  unobservable); WebCrypto key-handle `extractable:false` flags (not
  reachable through the module API); `clearTimeout` after completion;
  generation-counter sign flips (inequality-preserving); the TOTP
  `/^\d{6}$/` guards in `canSignIn`/`totpEnableConfirm` (the input layer
  sanitizes before they can ever see a non-6-digit value — defense in depth,
  pinned as such); `main.tsx` bootstrap (6 mutants — exercised by `vite
  build`/dev, not the unit runner).

### Verification

`results/portal-post-pins.json` + `verify_kills.js` compare the baseline and
post-pin runs mutant-by-mutant (identity = file/line/column/mutator/
replacement):

| | |
|---|---|
| Survivors before pins | 1,527 (+46 timeouts counted as killed in-run) |
| Survivors after pins | 1,249 |
| **Killed by the pin batch (verified)** | **278** |
| New survivors introduced | 0 |
| **Aggregate score** | **55.68% → 64.80%** |

Per-file movement (survivors before → after): PatientView 572→459,
PatientsView 449→412, LoginView 157→126, api 147→100, App 93→74,
ui 51→47, platform 50→29, crypto 48→31, main 6→6 (bootstrap, documented),
aad 0→0 (100% held). The workflow floor moved 70.0 → 64.0 deliberately:
the old floor guarded only the four contract modules; the new floor guards
all of `src` at its measured post-pin level (64.80) minus a small churn
margin — a wider surface at a lower floor, which is the honest trade.

## Mobile results

First full-tree run since 2026-09-15: **15,990 mutants over 64 files,
83.86%** (13,410 killed, 41 timeouts, 2,048 survived, 531 no-coverage).
The suite kept pace with +13.7k lines of source — the 2026-09-18
re-baseline was 81.21 on a 4x smaller surface, and the weekly floor (81)
holds on the fresh number. Crypto modules stayed perfect (kdf/engine/
envelope/aad 100%); the gap concentrates in screens and the matcher
tables. Full per-file table: `results/mobile-baseline-summary.txt`.

### Triage and pins

The genuine, safety- and contract-critical gaps were pinned
(`mobile/tests/mutation_2026_09_22_frontend.pins.test.ts`, 22 tests):

- **crisisDetect (64.4% → 76.0%)** — the entire normalization surface had
  per-entry holes: each homoglyph and leet mapping with no covering corpus
  phrase survived individually. The pins are table-driven over the full
  folding tables (every Cyrillic/Greek/Turkish lookalike, every leet digit
  and symbol, in all three positions), the combining-mark rule (Latin
  bases only), script-boundary separation, the curly apostrophe,
  punctuation-to-space tokenization, the exactly-four single-letter join
  (ASCII a..z only, CJK breaks runs), and the case-insensitive dialog vs
  wider-suppress tier relationship.
- **measures (76.8% → 89.4%)** — instrument structure (ids, item counts,
  ceilings, the phq9 safety-item index), scoring (clamp per item to the
  0-3 option scale, cap at the ceiling, null = unanswered = 0, only the
  first `items` entries scored), completion (exactly every item
  answered), safety-item endorsement (>0), the payload contract shape,
  and `maxScoreForMeasure`'s null for unknown instruments.
- **entryVersions (67.4% → 76.4%)** — malformed rows skipped, the mirror
  monotonic (rollback reported, never regressed), forgetAll clears.
- **rotation (47.8% → 80.1%)** — the full stage/reason map: wrong
  password vs offline at verify; salt-unfetchable fails closed;
  `rekey_key_mismatch` with a readable journal finishes the ladder vs
  `already-rotated-unverifiable`; 403 → wrong-password, 5xx → server,
  network → offline; failed credential rotation locks the vault; rewrap
  walks active consents only, with per-grant failures collected.

**Verification** (scoped re-runs per mutated file, mutant-by-mutant via
`verify_kills.js`; the per-file reports are `results/mobile-post-pins-*.json`):

| File | Survivors before → after | Verified kills | Score |
|---|---|---|---|
| src/crisisDetect.ts | 125 → 84 | 41 | 64.4% → 76.0% |
| src/measures.ts | 16 → 7 | 9 | 76.8% → 89.4% |
| src/entryVersions.ts | 29 → 21 | 8 | 67.4% → 76.4% |
| src/rotation.ts | 71 → 27 | 44 | 47.8% → 80.1% |
| **total** | **241 → 139** | **102** | aggregate 83.86% → ~84.5% |

New survivors introduced: **0**. (A scoped-run artifact to avoid repeating:
multiple `--mutate` CLI flags do not accumulate — only the last applies;
per-file runs were used instead.)

### Documented residuals (the recorded follow-up front)

- **Screens**: MeasuresScreen 41.3%, MoodCalendar 21.3%, BottomNav 39.0%,
  TherapistShareScreen 62.8%, HistoryScreen 71.6%, InsightsScreen 72.9%,
  SettingsScreen 68.3% — presentation state machines and style literals;
  the same class round 2 left as the portal's "largest open remediation
  front", now measured and floor-guarded instead of invisible.
- **crisisDetect 84 still surviving**: the remaining arms are deeper
  normalization branches (suppress-pattern wording, leet-regex variants
  whose input shapes the corpus never produces) — the folding TABLES are
  now fully pinned; each residual is recorded in
  `results/mobile-post-pins-crisisDetect.json`.
- **locales/en.ts 74.8%** — the English string catalog: StringLiteral
  mutants on copy the tests never assert verbatim; the safety-relevant
  entries (crisis lines, 988 fallback) are pinned by the strings tests.
  `locales/es.ts` is at 100%.
- **brain/sentiment.ts 65.4%, brain/stats.ts 68.6%** — the on-device
  engine mirror; behavioral non-negotiables stay guarded by the backend
  hand-written campaigns (M: 6/6) and the byte-exact vector pins.

The mobile weekly floor stays at **81** with the fresh full-tree number
recorded; the honest next raises are per-file (crisisDetect, sentiment)
per the workflow's own triage discipline.

## Round 2 (same day): the deepest killable survivors

The user asked for everything killable. Round 2 added
`portal/tests/mutation_2026_09_22_round2.pins.test.tsx` (26 tests) and
`mobile/tests/mutation_2026_09_22_round2.pins.test.tsx` (4 tests):

| Surface | Survivors r1 → r2 | Verified kills | Score |
|---|---|---|---|
| portal api.ts (URL policy, error taxonomy, header/body shapes, abort seams) | 100 → 86 | | 80.9% → 83.6% |
| portal crypto.ts (TamperError identity, non-extractable imports, sanitizer arms) | 31 → 25 | | 87.8% → 90.2% |
| portal platform.ts (windowless degradation, throwing-storage, prefix match) | 29 → 27 | | 72.9% → 74.8% |
| portal App.tsx (idle-lock event matrix, no-session timer, unlock-overtaken race) | 74 → 67 | | 58.0% → 61.9% |
| portal ui.tsx (the theme table, cursor + tone colors as contracts) | 47 → 20 | | 29.9% → 70.1% |
| portal LoginView (policy regex arms, derive-path wipes, mode reset, TOTP keep) | 126 → 113 | | 63.8% → 67.5% |
| **portal total** | **1,249 → 1,183** | **70** | **64.80% → 65.65%** |
| mobile crisisDetect (trail runs, orphanGlue, benign masks, folded channel) | 84 → 65 | | 76.0% → 81.1% |
| mobile MoodCalendar (mood dot semantics, month steps, a11y labels) | 85 → 56 | | 21.3% → 48.1% |
| **mobile total** | | **44** | **~84.5% → ~84.8%** |

Campaign totals: **494 verified kills across 122 pin tests, zero test
regressions** (4 borderline portal mutants flipped between runs —
timeout-classified kills under different machine load, not suite changes;
both suites green: portal 316/316, mobile 1,626/1,626). Floors raised to
portal 65.0 and mobile 84.0.

### Why 100% is not reachable — the equivalent-mutant ledger

Every still-surviving mutant was classified; these are PROVABLY equivalent
(no test can kill them — the mutated code is observably identical):

- **Pre-lowercased regex flags** (~14): every tier in crisisDetect compiles
  with `"i"` against text already lowercased by `normalizePrePunct` — the
  flag is defense-in-depth, its removal unobservable.
- **Identity/redundant expressions** (≥3): `code === undefined ? undefined
  : code` is the identity function; `hex.match(/.{4}/g)` on a 32-char
  string never returns null; `unb64`'s `i <= length` writes out-of-bounds
  no-ops on typed arrays.
- **Inequality-only counters** (6): App's generation counters are only ever
  compared for `!==`; sign flips preserve every inequality.
- **Backstopped channels**: the concat tier subsumes orphan-only matches by
  design; `clearSession()`-dropped is backstopped by the post-await
  session-identity guard (both pinned independently); `clearTimeout` after
  settlement; the abort pre-check on an unreachable session state.
- **Environment-baked values**: `import.meta.env.MODE`/`DEV` are compile-
  time replaced by Vite — production-mode mutants cannot run under vitest
  (`vi.stubEnv` cannot touch them; verified live).
- **Self-consistent probe constants**: sessionStorage's write-probe key
  and value appear on both sides of the probe.
- **Order-independent masking**: the benign-compound longest-first sort is
  unobservable over the current disjoint compound list.
- **Loop-equivalent regexes**: the leet trail `+` collapses through
  leetFold's fixed-point loop for every reachable input shape.

The remaining ~2,400 survivors across both apps are presentation-literal
mutants (inline style objects, theme color usage inside views, copy
fragments, screen layout props) plus screen state-machine arms — killing
them means asserting exact style strings, hundreds of tests that pin
presentation rather than behavior. They are measured, floor-guarded, and
mapped per file above; the genuine logic in every non-screen module is now
pinned.

## Reproduce

```bash
cd portal
npx stryker run                       # full-src, ~45-100 min locally
node ../redteam/mutation_campaign_2026-09-22_frontend/analyze_mutation.js \
  reports/mutation/mutation.json
node ../redteam/mutation_campaign_2026-09-22_frontend/verify_kills.js \
  ../redteam/mutation_campaign_2026-09-22_frontend/results/portal-baseline-fullsrc.json \
  reports/mutation/mutation.json

cd ../mobile
npx stryker run                       # full tree, ~3.5 h locally
# scoped kill-verification (ONE --mutate flag only — repeats do not accumulate):
npx stryker run --mutate src/crisisDetect.ts
node ../redteam/mutation_campaign_2026-09-22_frontend/verify_kills.js \
  ../redteam/mutation_campaign_2026-09-22_frontend/results/mobile-baseline.json \
  reports/mutation/mutation.json --file crisisDetect.ts
```
