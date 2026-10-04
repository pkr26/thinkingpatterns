# Web client end-to-end test report — 2026-09-26

Independent black-box E2E pass over the patient web client (and its
therapist-portal counterpart where the patient flow requires one), driven
through a real browser against the real backend. No source code of the app
was modified during testing; all temp scaffolding was reverted after the
run (see "Environment" below).

**Verdict: 22 of 24 test points PASS. 1 blocker (dev tooling, not the
production artifact), 1 P3 polish item, 2 flows not executable in this
runtime (documented honestly). The shipped production bundle is
functionally sound end to end, including the zero-knowledge crypto
round-trips.**

## Remediation (same day, post-report)

All three findings were fixed and re-verified after testing was declared
complete:

- **F1 FIXED** — both `web/vite.config.ts` and `portal/vite.config.ts`
  gained a dev-only `devInlineScriptHashes()` plugin (`apply: "serve"`,
  `transformIndexHtml` order `post`): it hashes every inline module
  script the dev server actually serves (the react-refresh preamble,
  whatever its bytes are in the installed plugin version) and appends
  those `'sha256-…'` tokens to the meta CSP; the dev server drops its
  CSP header so the hashed meta policy governs. No `'unsafe-inline'`
  anywhere (the pinned test still forbids it); the production triple
  (index.html, `_headers`, nginx) is untouched. Verified live: both dev
  servers now render their sign-in screens in the browser
  (`gui-test-screenshots/f1_web_dev_fixed.png`,
  `f1_portal_dev_fixed.png`).
- **F2 FIXED** — the Privacy view's Back button is wrapped in the
  codebase's standard flex-row container, so it hugs its label (measured
  55px in the served production bundle, down from 1006px;
  `f2_privacy_back_fixed.png`).
- **F3 FIXED** — "Delete my account" is now `disabled` until the
  confirmation text is exactly DELETE (handler guard retained as defense
  in depth; `f3_delete_gate_fixed.png`). The parity test
  `deletion requires the typed confirmation` was updated to pin the
  stronger contract (disabled state instead of a forced click), and the
  `rtr.tsx` `press()` helper now fails loudly when asked to press a
  disabled button.

Post-fix gates: web suite 407 passed / 5 skipped (coverage thresholds
green, SRI test green against a freshly stamped `npm run build`);
portal suite 316 passed; both typechecks and production builds clean.


## Environment

| Piece | Detail |
|---|---|
| Backend | FastAPI from `backend/`, `MINDPATTERN_ENV=development`, fresh throwaway SQLite DB, port 8010 (8000 was occupied by an unrelated app) |
| Web client | True production bundle (`tsc --noEmit && vite build`) served by `vite preview` on 5198 with a temporary env-driven `/api` proxy |
| Portal | True production bundle served by `vite preview` on 5196 (same temp proxy trick) |
| Browser | ZCode in-app browser (Chromium 146), GUI-only interaction: clicks, typing, screenshots; read-only DOM reads for diagnosis |
| Accounts | `e2e.tester` (patient) and `e2e.therapist` (via the portal's own registration UI); both destroyed with the test DB at cleanup |

Why the production bundle rather than `npm run dev`: the dev server is
itself broken in a browser (Finding 1), and `api/client.ts` fails closed
on plain-HTTP origins outside dev/test builds. A `--mode test` build
exercises the app's own sanctioned loopback-HTTP carve-out
(`import.meta.env.MODE === "test"`, the only such usage in the bundle)
with byte-identical application code. An HTTPS attempt with a self-signed
localhost cert was rejected by the webview (`ERR_CERT_AUTHORITY_INVALID`),
hence the mode fallback.

## Findings

### F1 (Blocker — developer experience, not production): `npm run dev` renders a permanently blank page

`http://localhost:5199/` loads (title shows) but `#root` stays empty. All
modules return 200; the React-refresh globals (`$RefreshReg$`,
`$RefreshSig$`, `$RefreshRuntime$`) are `undefined`. Root cause: the app's
own CSP (`script-src 'self'`, no `'unsafe-inline'`, pinned in BOTH
`web/index.html` meta and the Vite `server.headers`) blocks Vite's inline
react-refresh preamble script, so every transformed module throws on
execution. The portal dev server (`portal/`) has the identical blank-page
behavior — the configs share lineage. Production builds are unaffected
(no inline scripts; SRI-stamped).

Evidence: `gui-test-screenshots/t01_login_initial.png` (blank dev page);
read-only DOM/network probes described above.

Fix directions (pick one): serve the preamble from a same-origin file in
dev (plugin-react supports an external preamble via
`transformIndexHtml`), or relax `script-src` for the dev server only
(e.g. a hash/nonce for the preamble), keeping the pinned triple
production-only.

### F2 (P3, polish): Settings "Back"-style full-width buttons

The Privacy view's Back button renders ~1006 px wide (full content
width) instead of hugging its label. Cosmetic; same flex-container
pattern may affect other buttons.

### F3 (P3, polish): delete-account confirm button not gated in the disabled state

"Delete my account" is enabled even when the confirmation textbox
doesn't read DELETE; the guard lives in the click handler (wrong text →
error banner, no request sent — verified safe). A disabled-until-DELETE
state would communicate the gate better.

### Not executable in this runtime (no result claimed)

- **Offline queue / reconnect flush**: this browser runtime exposes no
  network-emulation (offline) control, so "save while offline → queue →
  flush on reconnect" could not be driven. The queue's code paths were
  otherwise exercised indirectly (every save consults it).
- **Spanish locale**: the runtime's `navigator.language` is `en-US` and
  exposes no locale override, so `locales/es.ts` rendering was not
  verified visually.
- **5-minute idle lock**: not waitable in a reasonable run; the lock
  family (hidden-tab/expiry funnels) was verified through its other
  members below.

## Test results

All screenshots are in `gui-test-screenshots/`.

| # | Test point | Result | Evidence |
|---|---|---|---|
| T1 | Register account (client-side KDF, verifier-only upload) | PASS | t02 |
| T2 | Onboarding 3 steps → Today | PASS | t02, t03 |
| T3 | Journal entry: text, prompt chip insertion, live on-device sentiment ("leans lighter") | PASS | t03 |
| T4 | Details expander: mood/energy/sleep scales + activity tags; save → "Saved." | PASS | t03 |
| T5 | History: mood calendar; entry decrypts; search hit ("lake") and miss ("qqq…" → "No entries match that search.") | PASS | — |
| T6 | Edit entry → saved, marked "edited ×1", new text decrypts | PASS | — |
| T7 | Patterns: honest pre-threshold state ("1 active day, 29 to go") | PASS | t04 |
| T8 | Question view: gated behind 30-day threshold | PASS | — |
| T9 | "Refresh patterns" recompute: processing session ran, "Baseline updated — 29 active days to go." | PASS | — |
| T10 | Measures PHQ-9: 9 questions answered → score 9/27 (hand-verified sum) | PASS | t05 |
| T11 | Measures GAD-7 → 6/21; PHQ-2 → 1/6 | PASS | t05 |
| T12 | Measures validation: empty save blocked ("an honest incomplete beats a guessed whole") | PASS | — |
| T13 | Share: pairing code from real portal therapist registration | PASS | — |
| T14 | Share: lookup → therapist identity + fingerprint MATCHES portal's (F486 9C51 … CB3F) | PASS | — |
| T15 | Share: dual consent checkboxes gate "Confirm and share"; grant created | PASS | — |
| T16 | Portal decrypts patient measures (9/6/1) — ECDH wrap/unwrap round-trip across clients | PASS | t06 |
| T17 | Portal clinician note save (templates, edit/history/delete affordances) | PASS | — |
| T18 | Revoke: patient side ("Revoked or ended") and portal side ("STOPPED SHARING… no longer reachable", notes retained) | PASS | — |
| T19 | Audit log: portal "My access history" and patient "Who accessed your data" both list every read/write with timestamps | PASS | t06 |
| T20 | Settings export: encrypted download fires | PASS | — |
| T21 | Password change: full re-encrypt → global sign-out → re-login with new password → journal still decrypts (incl. edit marker) | PASS | — |
| T22 | Crisis: "Get help" card (911 / 988 / Crisis Text Line / international); crisis-language save blocked once by the pre-encryption interstitial, second save proceeds | PASS | t07 |
| T23 | Multi-device: second tab session; both entries decrypt; entry written on device 2 appears on device 1 after focus reconcile; "Sign out (all devices)" → device 1 funnels to login with the honest token-expiry notice; wrong password → "invalid credentials" | PASS | — |
| T24 | Account deletion: DELETE-typed confirmation → lockdown notice; login then rejected; DB cascade verified (users: therapist only, entries 0, measures 0, access_log 8 rows survive as promised) | PASS | — |

API-level smoke checks that preceded the GUI pass: `/api/v1/meta`
contract fields; `/auth/salt` decoy salt for unknown users
(anti-enumeration); hardened headers (`nosniff`, `DENY`, `no-referrer`,
`no-store`, HSTS) on every response.

## Notes on product behavior observed (not defects)

- Two entries on the same date are permitted (each gets a fresh
  client-side id) — visible in History as two `2026-09-26` rows.
- After a full sign-out, onboarding re-runs on next login (W-6: the
  `mindpattern.*` flags are wiped with the session; deliberate).
- The production bundle's fail-closed origin gate (HTTPS-only) is
  correct behavior and blocked the plain-HTTP preview as designed.
