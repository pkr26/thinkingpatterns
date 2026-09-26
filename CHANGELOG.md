# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## 2026-09-26 — independent mobile+web security audit: all four findings fixed, web hardened to industrial header policy

A fresh audit of both patient clients (verification: source-level control
comparison, both test suites executed, `npm audit` clean, repo secret scan)
found no exploitable vulnerability and four hardening gaps — F-1 Medium
(Android release signing), F-2 Low (no mobile cert pinning posture), F-3
Low (iOS snapshot shield race), F-4 Low (no secret-scanning gate). All four
are fixed here, plus an industrial hardening pass on the web client's
policy files:

- **F-1 (Medium) — Android release artifacts are never debug-signed
  again**: the `release` buildType now signs from a private
  `android/keystore.properties` (gitignored; `keystore.properties.example`
  documents the shape), and a `gradle.taskGraph.whenReady` guard throws a
  clear `GradleException` when a release output is demanded without it —
  debug builds are untouched. R8 minification is enabled for release with
  obfuscation deliberately off (`-dontobfuscate` + conservative keeps:
  the Hermes bundle carries the app logic; un-renamed symbols keep
  reflective bridge lookups safe). Pinned by new preflight checks 9-10.
- **F-2 (Low) — mobile transport trust posture**: Android now ships
  `network_security_config.xml` — release trusts SYSTEM certificate
  authorities only (a user-installed CA can no longer MITM the bearer
  token or the one-time data-key shipment), cleartext is banned outside
  the explicit loopback hosts the JS client already permits, and debug
  builds keep user-CA debugging via `<debug-overrides>`. SPKI pinning is
  recorded as a written decision (not an oversight) in
  `docs/SECURITY_RESIDUALS.md`: no static pins can exist for user-hosted
  servers and RN's JS fetch never exposes the peer certificate, so TOFU
  needs a native module this repo's CI cannot land safely; the iOS
  user-installed-CA residual is documented. Pinned by preflight check 11.
- **F-3 (Low) — iOS app-switcher shield is now native**: a synchronous
  `willResignActiveNotification` observer in `AppDelegate.swift` drops an
  opaque cover over the window BEFORE iOS captures the transition
  snapshot — the JS overlay in `App.tsx` (kept as belt-and-braces, with
  the themed color) rendered asynchronously through the bridge and could
  lose the race. Pinned by preflight check 12.
- **F-4 (Low) — secret-scanning CI gate**: a new `secrets` job in
  `ci.yml` runs gitleaks 8.30.1 (version- AND sha256-pinned, like every
  external tool in the pipeline) over the full git history AND the
  working tree. `.gitleaks.toml` extends the default rules; every
  allowlist entry (published crypto vectors, test fixtures, generated
  trees) carries a written defense. Verified clean locally in both modes.
  Preflight check 13 additionally refuses any tracked release-keystore
  material.
- **Web industrial hardening — CSP with zero `'unsafe-inline'`**: the
  shell stylesheet moved from an inline `<style>` block to the
  same-origin `/app.css` (React's CSSOM inline styles are outside
  style-src, so nothing else needed it), letting `style-src` tighten to
  `'self'` across all four configs (meta, `_headers`, nginx, dev
  server).
- **Web industrial hardening — policy upgrades**: `form-action 'none'`
  (zero native form submissions exist), `frame-src 'none'`,
  `upgrade-insecure-requests`, `Cross-Origin-Embedder-Policy:
  require-corp`, an extended deny-list `Permissions-Policy`
  (accelerometer, gyroscope, magnetometer, display-capture,
  idle-detection, browsing-topics, serial, bluetooth), HSTS with
  `preload` (submission to hstspreload.org is the operator step,
  documented in deploy/README.md), and `X-Robots-Tag: noindex, nofollow`
  + a robots meta — a mental-health journal must stay out of search
  indexes and referrer graphs. All four configs carry the identical CSP
  literal, now with a comment-stripped no-`unsafe-inline` drift pin.
- **Web industrial hardening — integrity + disclosure**: `npm run build`
  now stamps sha384 Subresource Integrity on every local subresource of
  the built shell (`tools/add-sri.mjs`, fail-closed), and the static host
  ships an RFC 9116 `.well-known/security.txt` (operators replace the
  placeholder contact — called out in deploy/README.md).

Verification: web 407 green (coverage over the 85/75/85/90 floors),
`tsc` + production build clean with both SRI stamps, mobile 1648 green +
typecheck + native-release preflight all-green (13 checks), gitleaks
clean in git-history and working-tree modes.

## 2026-09-25 (c) — mobile-parity security audit of the web client: all six findings fixed

`AUDIT_WEB_PARITY_2026-09-25.md` compared the patient web client control-by-
control against the standard the mobile client was held to. Core architecture
(crypto stack, key custody, transport hardening, queue/integrity, sharing,
crisis safety) was already at parity; six deviations were found and are all
fixed and tested here (web 406 green, coverage 89.3/80.2/88.3/93.3 over the
85/75/85/90 floors; build clean, 156.65 kB gz):

- **W-1 (Medium) — hidden-tab lock (mobile background-lock parity)**: the
  web client now locks the session the moment the tab is hidden
  (`visibilitychange → hidden`), exactly like mobile locks on AppState
  background — decrypted text no longer stays rendered (and readable in
  tab-hover previews) while the user is elsewhere. The idle window
  tightened from 10 to 5 minutes at mobile parity, and `mousemove` no
  longer counts as activity (a mouse jiggler used to defeat the idle
  lock; only click/keydown/scroll/touchstart reset it now).
- **W-2 (Medium) — anti-phishing error sanitizer (mobile F2 parity)**:
  server-supplied `detail` is now run through the mobile client's
  sanitizer before any banner render — URLs of ANY scheme, scheme-less
  domains (any alpha TLD, no allowlist), phone-like digit runs, bidi
  overrides, and invisible/zero-width characters are stripped, then
  capped at 200 chars + ellipsis. The 2026-09-19 mobile corpus (bit.ly,
  mindpattern-support.de, discord.gg, word-joiner domain splits) now pins
  the web client too (`detailToMessage` in `api/client.ts`).
- **W-3 (Med-Low) — password shape rules (mobile L-6 parity)**: web
  registration now enforces the common-word blocklist ("password",
  "qwerty", "123456"…, "mindpattern", "journal"), whole-password
  single-character runs, and keyboard walks — the shape rules a
  zero-knowledge server can never enforce. The policy is now genuinely
  identical to mobile's.
- **W-4 (Med-Low) — fingerprint attestation gate (mobile C-7 parity)**:
  granting therapist access now requires BOTH attestations — an explicit
  "we read the fingerprint back and it matched" confirmation AND the
  disclosure terms. Passive display plus a warning no longer suffices.
- **W-5 (Low) — server `user_id` validation (mobile L-7 parity)**: a
  login/register response whose `user_id` falls outside the 32-hex
  contract is refused fail-closed (keys zeroized, vault locked, no
  session) — a hostile server can no longer feed malformed ids into the
  vault owner binding, AAD contexts, or storage keys.
- **W-6 (Low) — sign-out flag hygiene**: explicit sign-out and account
  deletion now wipe this browser's non-content `mindpattern.*`
  localStorage flags (onboarding/mute/threshold stamps), matching
  mobile's origin-bound state wipe — a shared computer keeps no trace an
  account used it. Idle/expiry locks deliberately keep the flags (they
  are not sign-outs), and onboarding therefore honestly repeats after an
  explicit sign-out.

Threat-model and plan docs updated (`WEB_THREAT_MODEL.md` key-custody
residual now names the 5-min idle + hidden-tab bounds; `WEB_PLAN.md` 2.7
carries the correction note).

## 2026-09-25 (b) — independent-audit remediation of the web client commit

Every finding from the independent audit of the patient web client commit
was fixed and re-tested (web 386 green, coverage 89.1/79.8/88.0/93.2 over
the 85/75/85/90 floors; mobile 1648 green; build clean, audit clean):

- **Session custody**: the idle lock, bfcache guard, reconnect flush, and
  reconciliation were disarmed on the Measures/Share/Settings views
  (`sessionActive` had drifted); every authenticated view now locks, with
  per-view regression tests.
- **Offline queue**: a `Retry-After: 0` (or past-date) advisory caused a
  zero-pause re-POST storm — advisories now carry a 1 s floor; entries
  parked while "online" could strand for the session — the queue now also
  flushes at sign-in, on a 30 s periodic retry, and after any successful
  direct save (and the flush throttle no longer wedges on a backwards
  clock step); the generation fence gained a write-after-wipe rollback;
  corrupt member records are quarantined instead of dropped; the
  quarantine store is capped at 50 records; `enqueue` dedupes by
  `client_entry_id`.
- **Honesty on 409**: a direct save that answers 409 no longer claims
  success and discards the plaintext — every online failure parks the
  entry in the queue where the M-5 GET-verification referees it.
- **Logout**: the epoch-bump request no longer aborts itself when
  `clearSession()` fires in the same tick.
- **Patterns**: the sensitive non-quoting contract no longer trusts the
  payload flag alone — the suppress-tier matcher runs on every label,
  belt-and-braces with mobile and the backend.
- **Reconcile**: focus-time reconciliation no longer re-downloads the
  entire journal ciphertext to discard it — it is one insights round-trip;
  the History view owns the revision-pinned walk (now unit-covered:
  snapshot pinning, restarts, mode switches, dedupe, page cap, terminal
  probe).
- **Mobile two-writer**: the conflict-overwrite path now runs the FULL
  post-save work (H-6 crisis detection included — it used to skip it);
  "Keep theirs" applies the server's text and version locally; the 410
  funnel is code-checked (`account_deleted`/`gone` added to the mobile
  error-code contract — the codes were being sanitized away) with
  conflict/funnel tests added.
- **Security tests made honest**: hostile decrypted text now renders
  through a real jsdom DOM (inert, asserted); the sensitive-pattern
  accessible-name contract is actually asserted; the interop fixtures'
  "both sections exist" guards fail instead of skip; `listEntriesWalk`
  and the future-date classifier gained direct coverage; dead code
  removed (`sessionStore`, `phq9.ts`, an unused import).
- **Release provenance**: `mindpattern-web-<tag>.tar.gz` + sha256 are now
  actually attached to the GitHub Release (they were built, verified, and
  silently dropped); `mutation-web.yml`'s 65.0 floor is labeled what it is
  — portal-inherited and provisional until web's first measured run.
- **Docs**: the promised DPIA web addendum exists
  (`docs/DPIA_SKELETON.md` §7 — browser storage surface); the bundle-size
  figure is corrected everywhere it was stated; deploy/README names nginx
  as the production header enforcer.

## Unreleased

### Patient web client (2026-09-25): the web app, built phase by phase per WEB_PLAN.md

`web/` — the mobile app's journaling experience in the browser, against the
unchanged backend, as a full multi-device peer of the mobile app. Ten
phases, each with its verification gate recorded in `WEB_PLAN.md`:

- **Zero-knowledge parity, four-way pinned**: the complete patient crypto
  (PBKDF2-600k → HKDF auth/data subkeys, AES-256-GCM envelopes, entry
  payloads v1+v2 with version-bound AAD, insights/question blobs, the
  therapist wrap both directions, fingerprints) byte-pinned to
  `shared/vectors.json`; `shared/interop_fixtures.json` (generated by BOTH
  platforms' real modules) cross-pins web⇄mobile in both directions; the
  new `web-contract-vectors` CI job makes backend+mobile+portal+web the
  four-way vector gate.
- **Strict session custody (D-4)**: token AND keys memory-only — refresh
  re-authenticates; 10-min idle lock, bfcache guard, lazy account-wide
  death funnels (401 expired/rotated vs 410 deleted, distinct honest copy).
- **Journaling**: entry editor with on-device sentiment (the real brain
  port), structured v2 channels, PRE-encryption crisis tier; byte-paged
  history with search + mood calendar; honest version-conflict editing
  ("reload theirs / reapply mine"); ciphertext-only offline queue
  (IndexedDB, origin+account scoped, lying-409 verification, quarantine).
- **Multi-device contract (S-1…S-11)** implemented + adversarially tested:
  the L3 dual-client live drill scripts concurrent creates, the CAS race,
  delete-vs-edit, cross-session visibility, and epoch death against the
  real backend. MOBILE changed too (honestly two-writer): the 410 funnel
  joins the client lock; HistoryScreen's edit race now decrypts and SHOWS
  the other device's text before overwriting; deleted-elsewhere gets its
  message; the all-rows-failed decrypt signature surfaces the
  remote-rotation funnel; +2 interop suites and a two-writer regression
  suite (mobile 1644 tests green).
- **Patterns + question**: lifecycle labels, "Why am I seeing this?"
  evidence panels, sensitive non-quoting cards (label never reaches the
  DOM — asserted), per-pattern mute (local + server-side via the encrypted
  feedback blob), the explicit-only recompute (the single-use processing
  session opens by the button alone).
- **Measures/share/settings**: PHQ-9/GAD-7/PHQ-2 with score-ceiling
  honesty and the post-save item-9 support pointer; verifier-gated
  therapist sharing with the fingerprint read-back; LLM consent, access
  log, encrypted-bundle export (the web-first gain), queue recovery, the
  full rekey→rewrap→credential rotation with epoch-death disclosure,
  typed-DELETE account deletion.
- **Security campaign (P9)**: threat model
  (`docs/WEB_THREAT_MODEL.md`), full-offset fuzz sweep (every byte × 3
  masks — all fail closed), red-team harnesses (XSS corpus through the
  real render pipeline, storage-scrape, replay/stale-token set), the
  four-way CI gate, Stryker + weekly `mutation-web.yml` (floor lands from
  the first measured run — configured, not claimed). 356 tests green,
  coverage 87.2/75.7/85.6/91.3 (floors 85/75/85/90), bundle 144 KB gz at
  the P7-phase measurement (the as-committed tree built at 155.7 KB gz —
  under the 250 KB budget; figure corrected 2026-09-25).
- **Deployment**: the nginx template carries the live `app.example.com`
  block (same-origin /api proxy — CORS stays empty); the release workflow
  builds, verifies, and ships `mindpattern-web-<tag>.tar.gz` + sha256
  beside the portal's.

### Frontend mutation campaign (2026-09-22): fresh full-scope Stryker over portal + mobile

Both frontends re-measured from scratch on the current tree
(`redteam/mutation_campaign_2026-09-22_frontend/`), covering everything the
four audit-remediation waves added since the last campaigns:

- **Round 2 (same day)**: 30 more pin tests closed the deepest killable
  survivors — URL-policy arms, error taxonomy, derive-path wipes, the
  windowless platform seams, the idle-lock event matrix, the ui theme/tone
  contracts, crisisDetect's trail/orphan/mask/folded arms, and the
  MoodCalendar mood-dot semantics — 114 further verified kills (campaign
  total **494 across 122 pin tests, zero regressions**), portal to 65.65%
  (floor 65) and mobile to ~84.8% (floor 84). The report carries a
  per-class equivalent-mutant ledger documenting why 100% is not reachable
  (pre-lowercased regex flags, identity expressions, inequality-only
  counters, environment-baked MODE/DEV, backstopped channels).
- **Portal: all of `src` measured with the working command runner for the
  first time** — 3,549 mutants, fresh baseline 55.68% (the round-2 1.41%
  number came from the broken vitest-runner wiring; the scoped 74.10% baseline
  covered only the four contract modules). 70 survivor pins added
  (`tests/mutation_2026_09_22_frontend.pins.test.tsx` + the App-shell
  companion): api transport/pagination contracts (timeout deadline, session
  replacement, signed-64 revision ceiling, canonical continuation corpus),
  crypto sanitization windows (F-6 score boundaries via an independently
  constructed caseload-summary oracle), TOTP stage discipline and input
  sanitization, review ordering, collection-restart bounds, key-zeroization
  across every flow, note/search/delete machinery, the 10-minute idle lock,
  and the platform/UI seams. **278 mutant-by-mutant verified kills, zero new
  survivors, aggregate 55.68% → 64.80%**; the weekly gate's scope widened to
  match with the floor honestly re-based at 64.0. Remaining survivors are
  triaged in the campaign REPORT (style/theme literals,
  environment-limited equivalents, view copy fragments).
- **Mobile: first full run since 2026-09-15** — 15,990 mutants over the
  current tree (was 4,356), fresh baseline **83.86%** with the crypto
  modules still at 100%. The campaign found and fixed a gate-breaking
  test first: `healthBridge.pins.test.ts`'s NEW-2 source-text pin dies under
  whole-tree Stryker instrumentation, which would have failed the weekly
  gate's dry run from its next execution; the pin now steps aside while the
  file is instrumented and still enforces the shipped source in every normal
  run. 22 survivor pins added (`tests/mutation_2026_09_22_frontend.pins.test.ts`)
  over the safety/contract modules — the crisis matcher's complete
  homoglyph/leet folding tables and normalization pipeline, the measure
  registry's scoring/validation contracts, the entry-version monotonicity
  mirror, and the password-rotation stage/reason map — with **102
  mutant-by-mutant verified kills, zero regressions** (crisisDetect
  64.4→76.0%, measures 76.8→89.4%, entryVersions 67.4→76.4%, rotation
  47.8→80.1%). The weekly floor moved 81 → 83 (fresh level minus margin);
  screen-level residuals are mapped per file in the campaign REPORT.

### Final-verification remediation (2026-09-22): all residual gaps closed

Follow-up to the final independent verification
(`INDEPENDENT_AUDIT_FINAL_VERIFICATION_2026-09-22.md`): the three new
defects found during verification, the D-7 residue, every documented
deferral (TOTP, jest-axe, real portal mutation floor), and the
doc-drift bundle. Each fix carries its regression test where testable:

- **Portal note-edit-history was unreachable** (verification defect 1):
  the only "view history" trigger lived inside the hidden print-only
  block — invisible on screen, unclickable on paper; its tests passed
  only because react-test-renderer ignores CSS. The affordance now
  renders in the INTERACTIVE notes card ("View history" → inline prior
  revisions, toggleable), and the printed summary carries only a
  non-interactive "edited" marker plus whatever history was loaded. The
  P3 tests drive the reachable button and pin that no `edited`-labeled
  button exists anywhere.
- **Rollback runbook step 1 was unexecutable** (verification defect 2):
  `deploy/README.md` pointed at a nonexistent `backup.sh` and the
  monitoring `verify.sh`. Replaced with the real one-shot pipeline the
  backup service itself runs (pg_dump | openssl enc |
  `mindpattern-backup-mac write`, sidecar-first publication, then
  `mindpattern-backup-mac verify`), plus the off-site fetch and
  rehearsal pointers.
- **Grafana mounted tmpfs AND a named volume at `/var/lib/grafana`**
  (verification defect 3): one mount shadows the other — the tmpfs
  winning would silently discard `grafana.db` on every recreate. The
  named volume owns the path; tmpfs covers `/tmp` only.
- **Optional therapist TOTP shipped** (audit C-2/F-4, was a documented
  deferral): RFC 6238 (SHA-1, 6 digits, 30 s ±1 step). Verifier-gated
  three-step enrollment (`POST /account/totp/setup` → `enable` →
  `disable`; therapist tokens only), the secret AES-256-GCM-wrapped at
  rest under an HKDF subkey of the server `token_secret`, login answers
  `401 totp_required`/`totp_code_invalid`, every accepted code is
  single-use (persisted consumed-timestep replay fence), and re-running
  setup while ENABLED is a 409 so a phished password cannot strip the
  factor. Portal: LoginView code step (the password survives only
  inside the TOTP stage) and a full enrollment/disable section in
  Account security. Migration `d4e5f6a7b8c9` (three nullable columns);
  `backend/tests/test_totp.py` (5 tests) +
  `portal/tests/totp_2026_09_22.test.tsx` (4 tests); README error-code
  list and SECURITY_RESIDUALS updated (deferral closed, accepted
  residuals documented).
- **Portal jest-axe a11y suite delivered** (audit H-9c/F-6j, was
  deferred): `jest-axe` + `jsdom` dev dependencies;
  `tests/a11y.test.tsx` mounts every view (LoginView both modes,
  PatientsView caseload + account-security panel, PatientView chart)
  into a real DOM and asserts zero axe violations. It immediately found
  real violations — every Card title rendered `h3` straight under the
  page `h1` (heading-order skips) — fixed by promoting Card titles to
  `h2` (visuals unchanged) and demoting the PatientsView group labels
  to `h3`. The node-window shim in the shared setup no longer clobbers
  a real DOM window.
- **Portal mutation gate is real now** (audit H-5, was near-vacuous):
  root cause found and reproduced — `@stryker-mutator/vitest-runner`
  10 + vitest 5 silently ran ZERO tests per mutant (a body-emptied
  `buildAad` "survived"; 0.00 tests/mutant, 1.26% baseline). Switched
  to Stryker's command runner (a fresh `vitest run` process per mutant
  — no shared module graph to go stale; validated scoped: aad.ts 0% →
  100%), scoped `mutate` to the security/contract modules
  (crypto/aad/api/platform, mirroring the mobile per-file-floor
  philosophy). Full re-measured baseline: **74.10%** (652 killed /
  3 timeout / 229 survived; aad 100.00, crypto 81.18, api 74.16,
  platform 53.27) — `thresholds.break` and the weekly workflow floor
  raised 1.0 → **70.0**. `tests/securityConfig.test.ts` skips its
  out-of-package nginx read inside a mutation sandbox.
- **D-7 residue:** the five duplicate literals in
  `LANGUAGE_FUNCTION_WORDS_ES` (`que`, `cuando`, `donde`, `quien`,
  `otros`) removed — 185 literals → 180, zero behavior change (the
  frozenset collapsed them anyway) — with a no-duplicates invariant
  test next to the whitespace one.
- **Rewrap post-commit refresh race** (the narrow 500 window
  verification flagged beyond A-5): `ObjectDeletedError` from the
  post-commit `session.refresh` now maps to the same flat 404 as the
  commit-stage race, with a mock-race regression test.
- **Contract cosmetic:** the patient measures read now uses the same
  `has_more and rows` continuation guard as the three therapist reads
  (an empty page must never advertise a non-advancing offset;
  unreachable today behind the revision fence, pinned for symmetry).
- **Doc drift:** stale "promote both" TODO in `redteam/README.md` (the
  promotion shipped), the release.yml comment describing nonexistent
  tag-push steps (deployment is digest-only),
  `deploy/monitoring/prometheus.yml`'s pre-pinning comment, and the
  Trivy scanner image is now digest-pinned in both workflows
  (`@sha256:6967db29…`, resolved from Docker Hub).

### Independent-audit round 3 remediation (2026-09-22): NEW-1..NEW-4 + low-bundle residuals closed

Follow-up to the third independent verification pass (re-audit of
AUDIT_2026-09-21.md remediation at `64a99e1`). Every open item fixed,
each with its regression test:

- **NEW-1, the weekly mutation ceiling could never trip.** The
  surviving-mutant counter in `mutation.yml` counted *lines* containing
  "survived", but mutmut 2.4.4 prints ONE grouped header —
  `Survived 🙁 (500)` — so 500 real survivors parsed as 1 and the
  ceiling of 25 was unreachable. The parser now sums the header's own
  `(N)` (per-line counting survives only as a fallback for formats
  without a header). New tests in
  `backend/tests/test_audit_round3_2026_09_22.py` execute the ACTUAL
  python block extracted from `mutation.yml` against byte-faithful
  grouped results: 500 survivors must fail, a healthy 3 passes, and the
  F-7 refuse-unparseable guard still fires. The workflow header's stale
  "survivors do not fail the run" sentence is corrected too.
- **NEW-2, the HealthKit mirror was permanently inert.**
  `react-native-health@1.19.0` (the newest published) links and
  autolinks but predates iOS 18 — its native module exposes no
  `requestAuthorization`/`saveStateOfMind`, so the
  `src/healthkit.ts` seam always read "too old". Shipped
  `ios/MindPattern/HealthBridge/RCTAppleHealthKit+MindPatternStateOfMind.m`:
  a category on the pod's module implementing exactly the seam's
  documented contract (three promise-based methods,
  `@available(iOS 18.0, *)`-gated, `HKStateOfMindKindDailyMood` writes
  with the discrete -2..2 valence, write-only — `readTypes:nil` — API
  spellings pinned against Apple's documentation JSON). The HealthKit
  entitlement (`MindPattern.entitlements`) is declared and signed by
  both target configurations; `verify:native-release` grew from 5 to 9
  checks (FLAG_SECURE, adjustResize, entitlement signing, bridge
  presence + contract surface); `tests/healthBridge.pins.test.ts` pins
  the same facts in the ordinary suite; `healthKitCapability()` now
  answers "requires iOS 18 or later" on older devices instead of
  blaming the module. Honest limit: no Xcode exists on the authoring
  machine, so the ObjC is CI-preflight- and source-pinned but not
  compile-verified here (same caveat class as the 2026-09-21 native
  projects).
- **NEW-3, therapist rotation was unreachable from the portal.** New
  "Account security" panel in PatientsView (the access-history idiom):
  **Change password** (fetch salt → derive current keys → fresh salt →
  derive new keys → open the wrap blob with the current KEK → re-seal
  under the new KEK → `PUT /therapist/wrap-key` → `PUT /account/credential`
  with up-to-3 retries on network/5xx only → sign out; every derived
  byte zeroized), **Recover sharing key** (repairs the
  interrupted-change window: the blob is under the intended-new KEK
  while the credential never moved — re-seals under the current one),
  and **Rotate sharing key (compromise)** (fresh keypair,
  confirm-gated, with the backend docstring's "intentionally lost"
  copy). `crypto.ts` gains `openSealedPrivateKey` (fail-closed decrypt
  counterpart of `sealPrivateKeyForUpload`, returning caller-owned
  PKCS#8). `TherapistMe.wrap_key_blob` was already exposed. The
  previously untested note-edit-history UI is now covered. Portal:
  191 → 211 tests, typecheck clean.
- **NEW-4, `verify.sh --production` existed but was enforced nowhere.**
  The four overlay images are pinned to digests (re-verified against
  the Docker Hub registry API): monitoring prometheus/grafana/blackbox
  + offsite rclone — the offsite compose's `rclone/rclone:v1.69.1` tag
  turned out not to exist on Docker Hub at all (a latent pull-time
  failure; tags are unprefixed — now `1.69.1@sha256:600f…`). The
  monitoring-verify CI job now runs `verify.sh --production` as its own
  step (a mutable ref fails the build), the promtool extraction uses
  the same digest-pinned image, and both READMEs document the
  deliberate-re-pin policy.
- **Consent-revival cap gap (B-5 residual).** Re-granting a REVOKED
  consent skipped the ACTIVE-only grant-cap checks entirely — a patient
  at the cap could exceed it by one via revival. Revivals now count;
  a wrap REFRESH of an already-active row (which adds no live grant)
  still passes. Two API-level tests.
- **Foreign-store cap direction (D-1 hardening).** `_stored_from_dict`
  truncated over-cap evidence/qualification lists to the OLDEST N days
  while every merge path keeps the NEWEST N — a hand-edited store with
  >60 dates would silently lose its high-water mark and reopen the
  replication-bypass shape D-1 fixed. Load now keeps the newest window.
- **A-8 wording.** Middleware-SYNTHESIZED envelopes (429/413/400/408/
  500) on the deprecated `/api` mount now carry the `Deprecation`
  header, so README's "every response it serves" is true without
  qualification. The README error-code list also documents the
  `error` unmapped-status fallback, and the CI completeness gate now
  matches dict-literal `"code": "..."` envelopes (middleware,
  exception handlers) in addition to `code="..."` kwargs.
- **H.9d convention documented + ratcheted.** The "no slow markers on
  security pins" rule is written down where markers are registered
  (backend/pyproject.toml) and enforced by a test that freezes the
  grandfathered slow set to the two crypto-pin files — a new slow
  marker anywhere else fails the suite instead of silently removing a
  pin from every mutation campaign.
- **Ops/doc residuals.** The incident runbook's `NEWEST` selection now
  mirrors `rehearse_restore.sh --remote` exactly (newest-first over
  `*.dump.enc`, `.hmac` sidecar required, fails loudly when nothing
  qualifies); the rollback paragraph's wrong justification is corrected
  (the hazard is the NEW image auto-upgrading before the rollback
  decision, and an old image lacks the new migration files outright);
  redteam.yml's "eight FINDING verdicts" comment is now count-agnostic;
  the e_crisis/a_crypto harnesses regenerate their corpora into
  gitignored `redteam/results/corpus/` instead of dirtying tracked
  files at runtime (committed fixtures stay read-only inputs for
  f_mobile); mobile README documents the Podfile.lock-not-committed
  first-build step and the HealthBridge.

### Independent-audit round 2 remediation (2026-09-21): F-1..F-12 closed

Follow-up to the second independent audit
(INDEPENDENT_AUDIT_ROUND_2_2026-09-21.md) — every finding fixed, each with
its regression test:

- **F-1, the full-engine golden vectors were unpinned.** No test covered
  `shared/brain_vectors.json`'s `updates` section (the three full-engine
  corpora that are the acceptance gate for the on-device port).
  `backend/scripts/gen_brain_vectors.py` is refactored into importable
  builders and `test_brain_vectors.py` now regenerates the `updates`
  payload in-process and asserts it equals the committed JSON
  float-for-float — a hand-edit or engine regression in the full-engine
  vectors now fails the suite.
- **F-2/F-3, the truncated-entry fabrication class survived two paths the
  D-3 fix missed.** `stats.avg_sentiment` (and the legacy analyzer's
  copy) averaged blanked entries as neutral 0.0 — rendered to therapists
  as "average reading"; mood-correlation theme residuals likewise scored
  tag-only blanked entries 0.0. Both now apply the D-3 predicate
  (blank text with no explicit mood tag contributes no mood value; tagged
  entries still count). While fixing the residual path, a latent crash
  was found and closed: a theme day conferred only by tags on blank
  entries raised `KeyError` in `_detect_links` (a 500 on recompute);
  outcome days without mood evidence are now skipped as unmeasured.
- **F-4, rotation failure paths left the vault on the old key.** If the
  credential rotation or the re-login fails after the server already
  rekeyed, `rotatePassword` now locks the vault and drops the biometric
  wrap before returning `{ok:false}` — the C-1 "self-completing rotation"
  guarantee now holds on failure paths too (an entry can no longer be
  sealed under the dead old key while the vault sits unlocked).
- **F-5, the dead multi-word Spanish lexicon class.** 28 keys containing
  spaces (e.g. "sin esperanza", "sin dormir", "me duele") could never
  match under per-token lookup; removed, with a new invariant test
  forbidding whitespace in every per-token-consumed lexicon map (this
  would have caught all 30 dead entries including the audit's original
  three). `shared/brain_lexicon.json` + the mobile lexicon regenerated;
  the golden vectors stayed byte-identical (dead keys never matched).
- **F-6, TOTP deferral registered.** Optional TOTP/MFA for therapist
  accounts (audit Phase 2 workstream 2) was silently dropped from the
  wave-1 deliverables; it is now recorded as a tracked deferral in
  docs/SECURITY_RESIDUALS.md (verifier-gated re-auth, rate limits and
  access logging remain the standing controls).
- **F-7, the mutation gate could pass vacuously.** If `mutmut results`
  produced empty or error-only output, the survivor ceiling counted zero
  survivors and passed. The gate now asserts the results file carries
  recognizable mutant-status lines and a minimum processed-mutants floor
  before judging the ceiling. (Fixing this surfaced that the ceiling step
  also lacked `working-directory: backend` — the old check could never
  have run; both fixed.)
- **F-8, the portal banner fold let a failed scan hide a sensitive
  summary.** A scan row with `patterns: -1` (revoked mid-scan, dead key)
  unconditionally overrode a server summary flagging sensitivity — an
  in-session undercount of the safety banner. A successful scan still
  wins; a failed scan now falls back to the summary, matching the per-row
  display; the fold has its first tests (plus caseload-ordering and
  per-context note-draft pins).
- **F-9, revoked history no longer trips the consent list cap.** The
  grant path counted active consents only (Phase 2 B-5), but
  `GET /consents` counted every historical row — 100 revoked former
  therapists made the share screen fail to load. The cap now counts
  ACTIVE consents; the retained history (unique per therapist) still
  lists for disclosure.
- **F-10, claim wording and operator docs squared with behavior.** The
  CHANGELOG's "cannot be replayed across recomputes" now states the
  bounded ~48h window it actually is; the feedback AAD comment states the
  client seals the UTC day; `BACKUP_OFFSITE_RESTART` (default `no`, and
  never combine it with `MODE=fetch`) is documented in the offsite
  overlay README; the README's Spanish section now states the per-corpus
  (not per-entry) language gating for mixed-language journals.
- **F-11, previously untested fixes pinned.** New regression tests for
  the rekey executemany batch form (130 entries → exactly 2 batched
  UPDATE executions per the 100-row batching), the rekey-preserves-
  `content_version` half of the A-1 pin, onboarding panel persistence,
  the foreground `activeDays` refresh wiring, portal note-draft context
  isolation, and the caseload ordering branches.

- **F-12 (found during remediation), the C3 date-backdating red-team
  verdict was timezone-flaky.** The full re-run surfaced a tenth FINDING:
  `C3.date-backdating` reported the ±1-day grace window shifted by one
  day. Not a product change — the harness anchored its date offsets to
  the machine's LOCAL `date.today()` while the entry-date contract
  (entries.py, audit fix L-5) is server-UTC ±1; on this UTC-7 machine
  after 17:00 local the two diverge and the verdict flips (UTC CI runners
  never see it). The harness now anchors to server-UTC; verified BLOCKED
  at the same local hour that produced the false FINDING.

Verified: backend pytest green (1,323 tests), mobile 1581/1581 and portal
191/191 suites green (mobile +10, portal +6 tests), probe_brain 9/9,
crypto vectors pass, brain vectors regenerate deterministically
(byte-identical), monitoring verify passes, red-team gate green with all
9 residuals registered.

### Independent-audit remediation (2026-09-21): V-1..V-4 closed

Follow-up to the independent verification audit
(INDEPENDENT_AUDIT_VERIFICATION_2026-09-21.md) — every fixable finding
fixed, each with its regression test:

- **V-1, the weekly red-team gate was red.** `mobile/ios/.xcode.env`
  (committed with the Phase 1 native projects) trips the
  `G3.tracked-secrets` hygiene rule (`*.env` suffix). It is the
  React Native Xcode template (NODE_BINARY export only, no credential,
  required to be versioned) — registered as the ninth residual with a
  written defense in docs/SECURITY_RESIDUALS.md and the workflow's
  DOCUMENTED_RESIDUALS, so the weekly gate passes again while staying
  strict for everything else.
- **V-2, the Spanish theme lexicon (audit Phase 2 workstream 1's
  deferred demand).** `THEME_LEXICON_ES` in brain.py: the same nine
  canonical themes with Spanish words, LANGUAGE-GATED per corpus (an
  English theme word never reads Spanish text and vice versa — "son las
  cinco" mints no family theme; Spanish words never fire on English
  corpora; "other" keeps the historical English-map behavior). Language
  detection moved ahead of theme extraction; topic eligibility excludes
  Spanish theme words under "es". Spanish journals now get
  temporal/mood_correlation/link cards from Spanish text; the golden
  vectors' spanish-mixed case was strengthened to a 70-day corpus and now
  pins ES-derived candidates for the on-device port. The mobile app
  renders theme/tag labels localized (`insights.theme.*`, usted-register
  Spanish) — topics and phrases stay raw user words, and unknown labels
  pass through untouched.
- **V-3, provisioned Grafana dashboard + Alertmanager example (audit
  workstream 6's deferred demand).** A dashboard ships as code
  (mindpattern-overview.json: up/keystore/backup-age/5xx stats, request
  rate, recompute p50/p95, LLM outcomes) via a read-only provisioning
  provider; `verify.sh` now grounds every panel expression against
  backend/app/metrics.py exactly like alerts.yml. The minimal
  Alertmanager example (severity routing per the runbook, inhibit rule,
  enable-in-comments) lives at alertmanager/alertmanager.example.yml —
  delivery stays an operator decision.
- **V-4, note edit history missed the POST retry path.** An idempotent
  note-create retry arriving with different content now preserves the
  superseded blob as an immutable revision, exactly like PATCH; a
  byte-identical replay still writes none.
- V-5 needed no code (behavior was correct; the claims' wording was
  imprecise). V-6's `verify:native-release` preflight passes 5/5; a full
  Xcode/Gradle build still requires the operator toolchain (CocoaPods,
  Android SDK), which is a machine-setup step, not a repo fix.

Verified: backend pytest green (+9 ES-theme tests, +1 note-history
test), mobile and portal suites green, probe_brain 9/9, crypto vectors,
brain vectors regenerate deterministically, deploy/monitoring/verify.sh
(dashboard grounding live), redteam run_all 9/9 FINDINGs registered —
the weekly CI gate simulates green.

### Deep-audit Phase 3 (2026-09-21): MBC depth, time-of-day, note history, the on-device protocol

- **Measurement-based care depth.** GAD-7 (anxiety) and PHQ-2 (brief
  depression core) join PHQ-9 through a multi-instrument registry
  (mobile/src/measures.ts): one screen, one selector, the same
  zero-knowledge measure path; per-instrument score ceilings, history
  clamping, and en/es item copy. The portal labels the trend lines per
  instrument. No interpretation, as ever.
- **Time-of-day analysis (v2 channel).** The entry payload gains an
  optional coarse writing-window bucket (morning/afternoon/evening/
  night — never a clock time); ≥70% one window on a weekday narrows the
  temporal card to "Sunday evening". Strict server validation, v1
  corpora unchanged.
- **Note edit history (clinic readiness).** Every changing note update
  preserves the superseded blob as an immutable revision (new table,
  migration b8f4e2a7c9d1); GET /therapist/notes/{id}/revisions serves
  them ownership-scoped and audit-logged; the portal shows "edited —
  view history" with decrypted prior texts.
- **The on-device brain protocol.** POST /api/v1/insights/
  local-recompute: client-encrypted state + patterns with state_seq
  discipline and server-grounded analysis dates — no processing
  session, no key shipment. The port plan and acceptance gate:
  mobile/src/brain/PORT.md + shared/brain_vectors.json v2 full-engine
  golden cases (calm/work-anxiety/Spanish corpora).
- **Research + TEE design docs.** docs/IRB_STUDY_PROTOCOL.md (single-arm
  usability study, zero-knowledge-consistent data handling,
  comprehension benchmark as the published-claims gate) and
  docs/TEE_ATTESTATION_DESIGN.md (client-verified attestation flow for
  the interim server path).
- Deferred (tracked): the TS port itself per PORT.md; multi-device sync;
  multi-therapist organizations and handoff; clinician-configured
  measure cadence.

### Deep-audit Phase 2, waves 6–8: mobile polish, Spanish parity, ops maturity (2026-09-21)

- **Spanish parity (E-3 High, E-8, D-7).** The pre-threshold baseline
  loop is localized: `shared/generic_questions_es.json` (60 questions,
  position-parity with the English pool, embedded in the app with
  sync/invariant/parity tests) and a parallel Spanish prompt-chip pool —
  both keyed off the device locale; usted register, and the six
  remaining tú-form strings in the es catalog normalized. The three dead
  multi-word ES sentiment-lexicon entries ("eterno es", "por eso",
  "darme cuenta" — unreachable under per-token lookup) removed, mobile
  lexicon regenerated.
- **Mobile polish (E-9, E-10).** History is a windowed FlatList (header/
  footer chrome preserved; far-offscreen rows unmount — up to 500
  decrypted rows used to stay mounted forever), with the rnMock gaining
  a FlatList stub. Calendar VoiceOver speaks human dates instead of raw
  ISO strings; foregrounding refreshes activeDays (no more stale count
  across midnight in an always-open app); onboarding resumes at the
  persisted panel position instead of restarting at panel 1 (completing
  the M-18 intent); the mobile README screens table lists
  Measures/TherapistShare.
- **Ops maturity (G-3..G-7, H-4, H-6).** Rollback procedure documented
  (restore-point + image re-pin; never `alembic downgrade` live data);
  the operator overlays (backup-offsite, monitoring) carry the
  production hardening quartet (cap_drop ALL, no-new-privileges,
  read_only + tmpfs); fetch mode defaults `restart: no` (the
  restart-forever re-fetch trap); rclone excludes in-flight `.tmp`
  dumps; json-file log rotation on every service; Trivy image scans in
  the CI docker job and the release pipeline (fixable HIGH/CRITICAL
  fail); `deploy/monitoring/verify.sh --production` enforces the
  digest-pinned image contract (overlays fail until pinned); the weekly
  backend mutation run enforces a surviving-mutant ceiling; mobile
  coverage gains per-file floors for the security-critical modules
  (crisisDetect 98, questionFeedback 90, strings 90, rotation 85,
  aad/envelope/kdf 95); the release coverage gate runs on Python 3.14,
  the production interpreter. Portal Stryker weekly gate follows.

### Deep-audit Phase 2, wave 5: portal polish (2026-09-21)

The F-6 low-bundle, per item: the sensitive-caseload banner folds in
fresher manual-scan rows (per patient, a scan row outranks the summary
it supersedes); the note composer keeps SEPARATE drafts for the general
and pattern-anchored contexts (a general draft no longer rides into a
pattern note); `window.print()` and randomness go through the platform
seam (`printPage`/`randomBytes`) instead of bare globals;
`decryptMeasure` REJECTS out-of-range scores instead of clamping them
into plausible-looking clinical values; the caseload list no longer
flashes "No patients" before the first fetch (loading state), and
gains username search plus ordering (newest share / username /
post-scan triage: sensitive first, then most-new). jest-axe a11y suite
deferred (new dev dependency).

### Deep-audit Phase 2, wave 4: audit-trail read path + DPIA (2026-09-21)

- **The access audit trail is readable (B-4).** `GET /api/v1/account/
  access-log` — the patient's who-accessed-my-data view (GDPR Art. 15
  parity; own lifecycle rows as "self", therapist reads with display
  names); `GET /api/v1/therapist/access-log` — the therapist's own
  action history. Both cursor-paginated (`X-Next-Cursor`), consent-
  scoped, no cross-subject leakage; the previously dead
  `ix_access_log_actor`/`ix_access_log_user` indexes now serve them.
  The portal gains an on-demand "My access history" panel (loads only
  when asked).
- **DPIA completed for H-7**: the erasure section now discloses the
  730-day access-log retention residual (rows deliberately outlive the
  account for the compliance window); a subprocessor + international-
  transfer table (LLM provider, off-site backup — both optional and
  off by default); and an Art. 30 RoPA section pointing at the DPIA
  and docs/SECURITY_RESIDUALS.md.

### Deep-audit Phase 2, waves 1–3 (2026-09-21)

- **Therapist lifecycle (C-2/F-4).** `PUT /api/v1/account/credential` now
  accepts therapist tokens (a forgotten/phished therapist verifier was
  fixable only by deleting the account), and a new verifier-gated
  `PUT /api/v1/therapist/wrap-key` replaces the sharing keypair — the
  same route serves password changes (re-wrap the blob under the new KEK
  first) and wrap-key compromise. Patients see the new public half in
  `ConsentOut` and re-wrap via the existing `PUT /consents/{id}/rewrap`
  without re-pairing; rotations are audit-logged (`wrap_key_rotate`).
  Five lifecycle tests including an end-to-end rotation + patient
  re-wrap + successor-key unwrap.
- **DB hardening (B-3/B-5/B-6/B-7).** asyncpg pool connections now carry
  `statement_timeout` (30s default) and `idle_in_transaction_session_timeout`
  (5min default) via `MINDPATTERN_DB_STATEMENT_TIMEOUT_MS` /
  `MINDPATTERN_DB_IDLE_IN_TX_TIMEOUT_MS` — a leaked transaction can no
  longer pin xmin indefinitely; the rekey's per-row UPDATE loops became
  one executemany round-trip per batch; consent caps count ACTIVE grants
  only (100 grant/revoke cycles no longer lock a patient out of sharing
  forever); the redundant `ix_notes_therapist_patient` prefix index is
  dropped (migration a3e7c9d5f1b2); dead pairing codes are pruned by the
  daily sweep, not only opportunistically inside code mint.
- **Crypto residuals (C-5/C-6/C-7).** The feedback-blob AAD now carries
  the seal date (client seals under its local UTC date; the server
  accepts today-or-yesterday), so a blob captured by a hostile server is
  dead from the second day after sealing — the acceptance is a bounded
  ~48-hour clock-skew window (unlimited replays inside it, question
  ranking only, recomputes client-initiated), not an absolute
  replay-proof seal. `MINDPATTERN_DECOY_SECRET`
  decouples unknown-username decoy salts from token-secret rotation.
  The therapist-pairing fingerprint check is now an action: the grant
  dialog proceeds only through an explicit "fingerprints match" tap;
  a mismatch opens do-not-continue guidance instead of the password
  step.

### Deep-audit gap closure (2026-09-21, follow-up to AUDIT_2026-09-21.md)

The seven findings the Phase 1 plan left unscheduled (verified open during
remediation review), each with a regression test where testable:

- **A-7:** corrected the three stale "empty pages are unaudited" comments
  in the therapist read endpoints — empty pages ARE audited (the trailing
  commit persists the unconditionally-written audit row); only refused
  413 pages are unaudited.
- **A-8:** config now enforces upper bounds on `unlock_threshold_days`,
  `max_entries_per_user`, `max_user_blob_bytes` and `db_pool_timeout`;
  `analysis_blob_budget` must be >= `max_body_bytes` (one max-size entry
  always fits); a recompute whose budget loads zero rows refuses with
  413 instead of overwriting stored patterns with an empty run; the
  deprecated unversioned `/api` mount serves every response with
  `Deprecation: true`.
- **B-8 (half):** `users.is_active` documented as a reserved operator
  lever (README "Scope decisions" + runbook "Manual operator levers") —
  checked on every auth path, set only by direct DB action in v1.
- **D-6:** phrase pattern ids re-link to their stored record across
  window/budget rotation (anchor + variants matched at the clusterer's
  own Jaccard bar), so a chronic rumination's lifecycle no longer
  restarts as a fresh candidate when its anchor sentence leaves the
  180-day window.
- **D-8:** the per-character fold cache is explicitly bounded (cap +
  clear; behavior unchanged).
- **F-4 (warning half):** therapist registration now warns, before the
  account exists, that a forgotten password is unrecoverable.
- **F-3 residual:** removed the stale "a second browser sees the same
  anchor" comment contradicting the per-tab visit-anchor contract.
- **H-8:** incident runbook gained a Detection & escalation section for
  S1 (alert-rule inventory incl. the keystore tripwire, escalation ladder
  with bracketed contacts, manual operator levers).
- **H-1 caveat:** the red-team CI gate's 8 allowlisted FINDING ids now
  live in an authoritative register, `docs/SECURITY_RESIDUALS.md` (one
  written defense per id); the workflow asserts the register names every
  allowlisted id.

### Deep-audit Phase 1 remediation (2026-09-21, AUDIT_2026-09-21.md)

All 33 Phase 1 items from the eight-area deep audit, each with a
regression test naming its finding:

- **Brain correctness (the two verified HIGH defects).** The replication
  gate no longer reads set membership in the EVIDENCE_DATES_CAP-truncated
  list — genuinely new evidence must postdate the newest stored day, so a
  same-corpus recompute can never satisfy "independent replication" for a
  >60-evidence-day pattern. Spanish topic mining unions the Spanish
  function-word set into eligibility (no more presence cards for "cuando"
  et al.); the README's Spanish claim now states what actually fires.
  Budget-truncated (textless, untagged) entries stay out of the mood and
  PA/NA series instead of injecting fabricated neutral days; person-name
  anchoring is English-only (German noun orthography minted person cards
  for common nouns); the confirmation clock restarts at the
  candidate→emerging transition (a late-replicating claim surfaces as
  "emerging", never straight to "confirmed").
- **Security lifecycle.** Password rotation self-completes: the vault
  locks and the biometric wrap is disabled inside `rotatePassword` before
  the success alert (an Android-dismissable alert can no longer leave the
  vault on the old key). The biometric unlock path verifies the unwrapped
  key against the unlock proof and auto-deletes a stale wrap. The session
  device key uses the `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY` Keychain class.
- **Backend correctness.** Rekey advances `entries_revision` AND
  `measures_revision` in its commit (mid-pagination clients get
  `collection_changed`, never mixed-key pages). The GDPR export keeps
  every insight id queued past the first metadata chunk (the pending-tail
  truncation) and snapshots consent-share ids in the head transaction (a
  re-grant mid-download can no longer drop a share). Consent
  revoke/rewrap map a concurrently cascade-deleted grant to 404, never a
  500. Measures reads (patient + therapist) carry the full entries
  pagination contract: `page_bytes` byte-bounded pages with
  `X-Next-Offset`, legacy 413 over the 2 MiB budget, and the
  `X-Measures-Revision` snapshot marker backed by a new
  `measures_revision` column + migration.
- **Portal.** Printing emits only the `.print-only` summary (the
  interactive cards — including the decrypted journal drill-down — no
  longer print light-on-dark or leak raw text onto paper); notes and
  entries render with `white-space: pre-wrap`; load failures offer a
  retry button; the login form submits on Enter with `role="status"`
  notices.
- **Mobile UX.** The haptics preference loads at session start (not
  first-visit-to-Settings); the phishing warning uses the theme error
  color (WCAG-passing, no hex literals); the check-in vocabulary
  (moods/energy/sleep/activity tags) renders localized labels keyed by
  value while wire values stay English; reminder notification copy
  routes through the catalog; chips/options/radios meet the 44pt touch
  contract; the mute note auto-dismisses.
- **Ship blockers.** `ios/` and `android/` native projects are committed
  (generated from the pinned RN 0.87.1 toolchain with the hardening
  checklist applied: Health usage strings, `allowBackup="false"`,
  `adjustResize`, FLAG_SECURE in `MainActivity`), `@notifee/react-native`
  and `react-native-health` are declared dependencies (reminders and the
  HealthKit mirror are no longer permanent "unavailable" seams; audit
  overrides neutralize their build-tooling transitive advisories), and
  `verify:native-release` runs in CI (`native-release-preflight`).
- **Ops, docs, gates.** The incident runbook's host-gone restore commands
  work as written (`basename` + container `/restore` paths) and
  `rehearse_restore.sh --remote` machine-tests the off-site fetch path.
  `deploy/monitoring/verify.sh` + shellcheck run in CI; the red-team
  harnesses run weekly in CI failing on any FINDING. Stale README claims
  corrected (rotation model, LLM testing, error-code list with a CI
  completeness grep, `ANALYSIS_BLOB_BUDGET` semantics, portal per-tab
  anchor). Alembic autogenerate now compares types and server defaults,
  and the schema-parity test asserts both flags.

### Security hardening close-out (2026-09-15 -> 2026-09-21)

Between first release and this point the codebase went through an
internal security program whose artifacts (per-finding audit reports,
campaign result dumps, dated wave changelog entries) were removed in the
production cleanup. This section is the durable summary; the full
per-finding history and remediation diffs live in git history (commits
2026-09-15 .. 2026-09-21).

- **Red-team campaign (2026-09-16).** 96 executable attack verdicts
  against the running stack; every code-fixable finding fixed. The
  lasting changes: crisis-language normalization on both engines (NFKC,
  invisible-character stripping, homograph and leet folding, SMS-digit
  and past-tense forms, Romance-language suicidio family) taking the
  bypass corpus from 30/35 evasions to effectively zero; scrypt N=2^16
  KDF floor with decoy-salt timing cover; rate-limit and enumeration
  hardening. The executable harnesses stay in `redteam/` and remain
  runnable via `bash redteam/run_all.sh`.
- **Mutation-testing program (2026-09-15 .. 2026-09-19).** Four campaign
  rounds (mutmut over the backend cores; three hand-written behavioral
  campaigns; Stryker over mobile and portal). Every surviving mutant was
  either pinned by a new regression test or documented as a residual
  with a written defense. Durable artifacts: the pin suites in
  `backend/tests/test_mutation_pins.py` / `test_deep_mutation_pins.py`,
  the weekly scheduled campaigns, and the per-PR behavioral mutation
  gate (`.github/workflows/mutation-pr.yml`) that re-runs every mutant
  targeting a changed file.
- **Pentest rounds (2026-09-19).** Two independent rounds, 11 verified
  findings + 2 informational, all fixed and pinned (algorithmic-DoS
  budgets, single-use-code defeat under StaticPool, trusted-proxy CIDR
  discipline, feedback-blob pre-flight).
- **Full-codebase audit + verification (2026-09-19/20).** 154 actionable
  findings across engine/NLP, API/security, mobile, portal and deploy;
  all fixed, then re-verified by an independent pass. Highlights:
  mid-save vault-lock key zeroization, Spanish sentiment/diacritics
  parity on both platforms, replication gates extended to every
  statistical pattern kind, streaming measure export, phase-gated
  therapist insights.
- **Rotation machinery (2026-09-20 fourth pass).** The zero-knowledge
  recovery path: `POST /api/v1/processing/rekey` re-encrypts every blob
  under a new data key in one transaction; `PUT /api/v1/account/credential`
  retires a phished login credential; consent grants re-wrap to the same
  therapist. Entries gained monotonic `content_version` AAD binding with
  rollback detection on-device. Mobile orchestrates rotation with
  interrupted-rotation resume ("Change password" in Settings).
- **365-day simulation remediation (2026-09-21).** Long-horizon
  simulation pass; mute-only feedback blobs and TZ-pinned tests.
- **Accepted, documented residuals.** Data-key escrow during consented
  recomputes (now recoverable via rotation), CSP `style-src
  'unsafe-inline'` (no injection path), plaintext draft surviving vault
  lock (pinned trade-off), operator tooling mutable tags (flagged to pin
  before production).

Every remediation above is pinned by a regression test that names the
finding it guards; treat any of those failing as a release blocker.

### 2026-09-19 — Final wave: Spanish analysis language, monitoring, off-site backups, HealthKit seam, native checklist

Spanish + language detection by the coordinating engineer; monitoring and
off-site backups; HealthKit State of Mind seam and the native-project
checklist by parallel work streams. All gates green at close.

- **Spanish is the second analysis language.** A curated graded Spanish
  lexicon (~480 valences, negators, intensifiers, "pero" contrast,
  absolutist and sense-making sets, and a 180-word function-word
  detection set) ships in `sentiment_lexicon_es.py`. The English-only
  language gate became language DETECTION with per-language detection
  sets built from language-specific sources (merged lookup words cannot
  inflate the wrong side); Spanish prose now receives the full analysis
  — mood series, PA/NA, rumination, sense-making, topics — in Spanish,
  while German/French/other keep the honest historical suppression and
  now carry `stats.language = "other"` so the app shows a calm
  "not yet supported" card instead of an unexplained quiet analysis.
  English wins every lexicon collision by merge order. The historical
  "negation-dense Spanish is gated" pin was deliberately INVERTED (the
  same corpus now legitimately surfaces Spanish rumination — the honest
  reading in the user's language), with the gate's original intent
  preserved via a German corpus. The on-device engine received the
  Spanish tables through the same generated-artifact pipeline, and 7 new
  Spanish vector cases pin both platforms' Spanish behavior (39 sentiment
  vectors total). Mobile UI language (en/es) and journal analysis
  language remain deliberately independent systems.
- **Monitoring stack** (`deploy/monitoring/`): Prometheus scrape +
  alert rules grounded in the exact metric names the API exports (API
  down, 5xx ratio, slow recomputes, stuck processing sessions, LLM
  failure ratio), a profile-gated compose file kept deliberately
  OUTSIDE the digest-pinned production contract (operator tooling with
  a documented pinning step), plus backup-freshness checking (a
  textfile-collector heartbeat and a standalone cron-friendly script).
- **Off-site backup replication** (`deploy/backup-offsite/`): an
  overlay service syncing the already-encrypted pg_dump volume to an
  S3-compatible remote (rclone copy, never deletes), with the host-loss
  recovery path, BACKUP_KEY second-location custody options, and the
  rehearsal step documented in the incident runbook.
- **HealthKit State of Mind seam (mobile)**: the capability-probe
  pattern gains `src/healthkit.ts` — WRITE-ONLY mood mirroring to the
  Health app (discrete -2..2 valence classification), opt-in per
  account with honest disclosure (MindPattern writes, never reads;
  Health-side data stays in Health), fire-and-forget after a mood
  check-in, real when the native module links.
- **Native-project checklist (mobile)**: `verify_native_release.mjs`
  gained fail-closed checks (Health usage strings when the seam is
  imported, allowBackup=false, keychain dependency assertion), and the
  README's native section is now an ordered setup guide: iOS keychain
  accessibility verification, backup-exclusion trade-offs, notification
  prompt timing, the App Store health declaration, Android FLAG_SECURE
  and allowBackup reasoning, and a DESIGNED TLS/SPKI pinning approach
  with the self-hoster bypass requirement spelled out.

### 2026-09-19 — Third product wave: on-device brain begins, sense-making/diversity kinds, MBC measures, full i18n

All gates green at close: backend 1133 tests + probe 9/9 + mypy/ruff;
mobile 1339 tests + tsc + crypto vectors; portal 145 tests + tsc.

- **The on-device brain port begins (closing the processing-session
  exception).** The graded sentiment engine — the full merged lexicon
  (7,267 words + emoji valences), negation/intensifier/"but" rules,
  morphological candidates — is ported to TypeScript
  (`mobile/src/brain/`), with the statistics core (erfc via a
  derivation-first-principles Maclaurin+continued-fraction
  implementation agreeing with math.erfc to 2e-16, Pearson, Fisher-z
  difference p). Cross-platform vectors
  (`shared/brain_vectors.json`, 32 sentiment cases + stats) pin the two
  engines together, with a REGRESSION-guard test on each side: the
  mobile suite runs the TS port against the vectors, and
  `backend/tests/test_brain_vectors.py` regenerates them from the live
  Python engine so a server-side change that would break on-device
  parity fails first on the server. The lexicon artifact is GENERATED
  (`scripts/dump_brain_lexicon.py` → shared JSON + TS module) and
  byte-pinned both ways. Consequences shipped today: the device-local
  mood estimate, History badges and fallback mood-log values now use
  the REAL engine (the 20-word ratio hack is retired; its test pins
  moved to the graded engine's exact verdicts — e.g. "nothing" now
  scores mildly negative, VADER lineage). Honest scope: this is the
  foundation (sentiment + stats), not the cutover — day series, the
  inertia family, themes, phrases and lifecycle port next; only when
  the whole `update()` runs client-side can the data-key shipment end.
- **Two new pattern kinds.** `sense_making` (causal+insight word
  density per day, recent vs the user's earlier norm, Welch's t with a
  measurement-noise floor; grounded in the Pennebaker-lineage finding
  that RISING causal/insight language tracks benefit — surfaced only as
  a within-person rise) and `activity_diversity` (weekly Shannon
  entropy over activity tags, recent vs earlier weeks; both directions
  surface — narrowing and widening are different, equally honest
  observations; Ong et al. 2023). Both ship with question templates,
  describe() copy and mobile card rendering, and enter the same BH
  family and replication gates as every statistical kind.
- **The MBC module (measurement-based care), full stack.** The patient
  can complete the PHQ-9 (public-domain instrument) in the app; the
  score is an opaque encrypted blob (AAD context `"measure"`) stored
  under the same date/quota/idempotency discipline as entries
  (Alembic `b1c7f2e9a4d6`, `SCHEMA_HEAD` bumped; migration parity
  re-pinned). The therapist portal reads it through the SAME active
  consent, decrypting with the per-consent unwrapped data key — the
  server never learns a score, and the read is audit-logged like every
  patient-data access. The charter holds everywhere: the app computes
  and displays no severity bands and gives no interpretation (the
  screen says interpretation belongs to the clinician); SAFETY: item 9
  (self-harm) endorsement gently points at the offline crisis
  resources only AFTER the response is safely saved, throttled through
  the same per-day stamp as the entry crisis dialog. Portal renders a
  "Recorded measures" trend card; cross-implementation pinned with a
  Python-generated fixture. KNOWN SCOPE NOTE: measures are readable by
  an active consent that predates them — the grant disclosure copy
  should move to "v2" naming measures for new grants (follow-up).
- **Full i18n (mobile).** A rebuilt `strings.ts` i18n module (en/es
  catalogs of 551 keys each — completeness enforced by test; `t()`
  with interpolation and an es→en→key fallback chain; device-locale
  detection with an en-pinned test seam). ~540 user-visible strings
  extracted across every screen and component, including all
  accessibility labels; dates and calendars are now Intl/locale-aware
  (the en-US pinning and English month tables are gone). The drifted
  legacy keys were reconciled to the shipped copy. Crisis numbers and
  URLs are never translated; Spanish copy keeps the calm, non-clinical,
  advice-free register (verified by es render tests). Residual: no
  manual language override UI yet; mood.ts data labels and the
  prompt/generic question pools remain English this wave.
- **Housekeeping:** mobile navigation enumerations gained the Measures
  screen; the apiMock helper gained the measures methods; the mobile
  import-style quirk that produced TS5097 during the wave was resolved
  (extensionless imports everywhere).

### 2026-09-19 — Product wave: PA/NA + energy detectors, caseload summaries, reminders/biometrics, check-in collapse

Four features from the independent product audit, all cross-stack, all
gates green (backend 1117 tests + probe 9/9 + mypy/ruff; mobile 1283
tests + tsc; portal 140 tests + tsc; cross-platform crypto vectors).

- **Four new pattern kinds (mini-brain).** The sentiment walk was
  extracted into `_valence_walk` (byte-identical compound, pinned by a
  regression test) with a new `sentiment_components` summing valences by
  SIGN — positive and negative affect are separable streams, not ends of
  one scale (Emmons & Diener 1985; Abitante et al. 2024). Three new
  inertia-family claims ride the same Fisher-z machinery, BH family and
  replication gates: `energy_inertia` (the payload-v2 energy pick,
  finally analyzed — collected since 2026-09-17, read by nothing until
  now), `pa_inertia` and `na_inertia` (text-scored entries only; an
  explicit mood check-in is one valence judgment and cannot be honestly
  split). The fourth, `energy_mood_coupling`, is the cross-channel
  concordance claim: Pearson correlation of energy and mood within-person
  residuals, recent vs the user's own earlier norm, surfaced only as a
  rise. Each kind ships with question templates (advice-free,
  question-only invariants enforced), `describe()` copy and mobile card
  rendering (channel-aware evidence rows).
- **Per-pattern mute** (from the week-1 wave, folded into this entry for
  release notes): "stop showing me this" rides the encrypted feedback
  channel (`{"feedback", "muted", "unmuted"}`), lands in a muted set
  inside the encrypted brain state that survives the dump/load
  roundtrip, and removes the pattern from question generation while its
  lifecycle keeps evolving underneath. Muted cards surface after all
  live cards (never displacing them), never marked "new", and the mobile
  app collapses them into a reversible "Muted (N)" section. Sensitive
  cards offer no mute and are never quoted in the muted section.
- **Encrypted caseload summaries (therapist portal).** At every patient
  recompute the server — inside the processing session, where the
  surfaced patterns already exist in memory — writes a small per-consent
  summary (pattern count, sensitive-card presence, newest first-seen)
  wrapped to the therapist's PUBLIC key with the same ECIES construction
  as the data-key wrap (new AAD context `"caseload-summary"`, bound to
  the patient/therapist pair; Alembic revision `f0b3d8e5a7c2` adds the
  three nullable consent columns; `app.db.SCHEMA_HEAD` bumped). The
  portal decrypts N small blobs instead of N full insight payloads when
  triaging, and — the safety point — a sensitive card's PRESENCE now
  surfaces as a calm non-quoting banner on the caseload screen without
  opening every chart. Summaries are null until the patient's first
  post-grant recompute, cleared on revoke, skipped (never failing the
  recompute) for a malformed therapist key. Cross-implementation pinned:
  the portal's WebCrypto opens a fixture produced by the Python
  reference; the backend test unwraps through the reference too.
- **Mobile: local journaling reminders.** Opt-in (onboarding panel 1 +
  Settings), local-only daily notification at a chosen time (default
  20:00), no streak-shaming copy, per-account prefs in AsyncStorage with
  hostile-input sanitization, and a pure `nextReminderFireTime` (tested
  across midnight/month/year boundaries). The last-mile notification
  uses the existing `nativeFeatures` seam: with `@notifee/react-native`
  linked it schedules a repeating daily trigger (permission asked
  honestly; provisional = denied); without the module the Settings row
  honestly reports "not linked in this build" and the pref still
  round-trips. Account deletion clears prefs and cancels schedules.
- **Mobile: biometric unlock.** The derived DATA key can optionally rest
  in the OS keystore wrapped under biometry-current-set
  (`react-native-keychain`, service `com.mindpattern.biometric-unlock.v1`,
  this-device-only). UnlockScreen offers "Unlock with biometrics" only
  when hardware + wrap exist; success restores local decryption only
  (documented dummy master/auth keys — server re-auth still needs the
  password), failure is a calm inline note and the password path is
  never demoted. Settings toggle states the trade plainly before
  enabling; disabling and account deletion remove the wrap.
- **Mobile: check-in collapse.** The four optional check-in rows (mood,
  energy, sleep, tags) now live behind an "Add details (optional)"
  disclosure directly under the editor — a daily writer no longer
  scrolls past ten rows of optional chips. Save sits under the
  disclosure; a collapsed summary line ("Details added: mood, sleep")
  names exactly what is set so nothing is silently attached to an entry.
- **Earlier this wave (already noted above in the week-1 entry):** the
  HistoryScreen edit data-loss fix (structured channels now survive
  edits), question auto-load with the key-shipment step still
  explicitly tap-gated, and the one-time threshold-crossing card.
- **Housekeeping:** the committed `redteam/results/f_mobile.json` was
  stale — a re-run at clean HEAD reproduces today's verdicts (2/35
  dialog-tier misses, a 2-sample TS/Python parity break that predates
  this wave; none of this session's code touched crisis detection). The
  refreshed artifact is committed as-is; the parity finding deserves its
  own triage.

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
