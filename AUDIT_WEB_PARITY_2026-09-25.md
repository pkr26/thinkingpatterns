# Web Client Security Audit — Mobile-Parity Standard — 2026-09-25

**Scope:** patient web client (`web/`), audited against the security standard the
mobile client (`mobile/`) was held to (AUDIT_2026-09-21 waves C/E/L/H/F/M +
red-team corpus), plus web-specific checks (CSP/headers, XSS, storage). Method:
control-by-control comparison of the shipping source on both sides, with the
prior web-audit remediation (commit `7cc0aa9`) taken as fixed and
regression-pinned — none of those findings are re-reported.

**Verdict:** The web client is at genuine parity with mobile on the core
security architecture — identical crypto stack, memory-only key custody,
ciphertext-only persistence, hardened transport, replay/rollback integrity,
zero-knowledge sharing, and crisis safety. Six deviations from the mobile
standard were found: **2 Medium, 2 Medium-Low, 2 Low**. None breaks the
zero-knowledge model; the two Mediums are session-exposure and
phishing-injection surfaces where mobile holds a stricter line.

> **REMEDIATION 2026-09-25 (same day):** all six findings are FIXED and
> re-tested — web suite 406 green, coverage 89.3/80.2/88.3/93.3 over the
> 85/75/85/90 floors, `tsc` + production build clean (156.65 kB gz). Per
> finding: W-1 hidden-tab `visibilitychange` lock + 5-min idle + mousemove
> removed from the activity set (`src/sessionLock.ts`, `src/platform.ts`
> `pageHidden`, App wiring); W-2 mobile F2 `sanitizeDetail` ported into
> `detailToMessage` (`src/api/client.ts`) with the 2026-09-19 corpus
> pinned in `tests/api.test.ts`; W-3 L-6 shape rules in
> `passwordPolicyError` (`src/views/LoginView.tsx`); W-4 second
> fingerprint-match attestation checkbox gating the grant
> (`src/views/Share.tsx`); W-5 `USER_ID_PATTERN` fail-closed validation in
> `adoptSession`; W-6 `localStore.removePrefix("mindpattern.")` on
> explicit sign-out and account deletion (flags deliberately survive
> idle/expiry locks). Details in CHANGELOG 2026-09-25 (c).

---

## 1. Controls confirmed AT PARITY (spot-verified in source)

| Control | Mobile standard | Web status |
|---|---|---|
| KDF / key schedule | PBKDF2-HMAC-SHA256 600k (floor 100k), salt ≥8B, HKDF auth/data subkeys | Identical constants (`web/src/crypto/core.ts:21-26`, `keys.ts:16-20`); 100% shared vector pass |
| Envelope | AES-256-GCM, `nonce(12)‖ct‖tag`, fresh random nonce, TamperError fail-closed | Identical (`core.ts:81-142`); full-offset fuzz sweep pinned |
| AAD binding | ensure_ascii JSON array, contexts incl. v2 version-bound entry AAD | Identical context set + `moodlog` (`aad.ts`, `patient.ts:79-83`) |
| Key custody | Keys memory-only, zeroized on lock/unlock/failure paths | Identical (`vault.ts`, `LoginView.tsx` every failure path wipes all three keys) |
| Session token storage | Encrypted at rest (Keychain device key) | Better-or-equal: token memory-only, never persisted (`client.ts:145`); storage-scrape red-team pin |
| Transport | HTTPS-only + loopback, `redirect:"error"`, final-URL check, 15s timeout | Parity, and stricter: same-origin only, no user-configurable server URL at all (closes mobile's verifier-collection/origin-switch class) (`client.ts:31-60, 195-228`) |
| Error-code contract | Allowlist of known slugs only | Parity incl. the `account_deleted`/`gone` spillover (`client.ts:79-117`) |
| Pagination integrity | revision snapshots, page caps, hostile-server bounds | Parity (`client.ts:424-542`) |
| Offline queue | ciphertext-only, origin+user scoped, caps, quarantine, **verified-409**, backoff clamps | Parity (`offlineQueue.ts`, M-5 GET-verification) |
| Rollback guards | stateSeqGuard fail-closed + self-heal; encrypted entryVersions high-water marks | Parity (`stateSeqGuard.ts:66-105`, `entryVersions.ts:91-113`) |
| Rotation | fresh salt → server rekey → rewrap ACTIVE grants → credential epoch bump, zeroize in finally | Parity (`Settings.tsx:122-173`) |
| Sharing wrap | ECDH P-256 → HKDF("mindpattern/wrap/v1") → GCM, SPKI length pin, 128-bit fingerprint | Byte-compatible both directions (`sharing.ts`), interop fixtures pinned |
| Crisis safety | shared phrase contract, evasion-hardened detector, pre-encryption, nothing logged, non-quoting render | Parity (`crisisDetect.ts`, contract-pinned to `shared/crisis_phrases.json`) |
| Leakage | no console/analytics/telemetry; credentials never in URLs; coarse time-of-day buckets | Parity (grep-verified zero hits; verifier header-only) |
| XSS | n/a (RN) | No HTML sinks anywhere; red-team corpus through real jsdom DOM; no-inner-HTML source scan enforced in CI |
| Headers | n/a | CSP+HSTS+COOP/CORP+nosniff+DENY+no-store triple-pinned (meta + `_headers` + nginx + vite) with drift test |

Dependencies: `react` + `react-dom` only; no sourcemaps in `dist/`; dev server
not exposed. The first web Stryker run remains pending (floor provisional) —
already disclosed in WEB_PLAN P9; not re-reported.

---

## 2. Findings

### W-1 (MEDIUM) — No lock on tab-switch/minimize: mobile locks the vault immediately on background — **FIXED 2026-09-25**

Mobile standard: `mobile/src/store.tsx:192-196` locks the vault on
`AppState === "background" || "inactive"`, plus an opaque app-switcher shield
(`App.tsx:30-50`) and Android `FLAG_SECURE`.

Web reality: `web/src/sessionLock.ts:16-49` implements only a 10-minute idle
lock and a bfcache (`pageshow.persisted`) guard. The `visibilitychange` handler
at `App.tsx:146` drives sync reconciliation only — it never locks. Switching
tabs or minimizing leaves the decrypted journal rendered and the keys in memory
for as long as the tab lives; browser tab-hover previews show the rendered
decrypted content.

Threat model fairness: residual #3 in `docs/WEB_THREAT_MODEL.md` accepts the
in-memory plaintext window "between decrypt and lock," but its framing implies
a lock bounds the window — switching away triggers no lock at all, so this
exceeds what is disclosed.

Recommendation: lock on `visibilitychange → hidden` (optionally with a short
grace period and re-auth on return, mirroring mobile's immediate-lock
behavior), routed through the platform seam for testability. Secondary: idle
reset counts `mousemove` (`sessionLock.ts:18`), so a mouse jiggler defeats the
10-minute lock; consider interaction-only events. Note the idle window is also
10 min vs mobile's 5 (`mobile/src/store.tsx:70-75`) — worth aligning or
documenting.

### W-2 (MEDIUM) — Server-error text rendered without the anti-phishing sanitizer (mobile F2 parity) — **FIXED 2026-09-25**

Mobile standard: `mobile/src/api/client.ts:297-343` strips from server-supplied
`detail` all URLs/scheme-less domains (any alpha TLD), phone-like digit runs,
bidi overrides, zero-width/invisible characters, and control chars, then
truncates to 200 — pinned by a hostile corpus (`tests/securityFixes.test.ts:83-129`).
Rationale: `detail` is attacker-controllable text (malicious/compromised
server) rendered in dialogs.

Web reality: `web/src/api/client.ts:176-179` truncates to 200 characters and
nothing else; the string is rendered verbatim in `ErrorBanner`/
`describeError` (`LoginView.tsx:79`, `Share.tsx:40,68,92`). React escaping
prevents XSS (verified by the red-team DOM corpus), but a hostile server can
still inject *"your account is at risk — recover at mindpattern-support.example
or call 555-…"* into every error banner. The error-code allowlist is at parity;
the detail text is not.

Recommendation: port `sanitizeDetail` (character-class + URL/domain/phone
stripping) into the web client's `message()` and pin it with the same F2
corpus. Cheap, high-leverage, and restores parity.

### W-3 (MEDIUM-LOW) — Password policy lacks the L-6 shape rules, and the parity comment overstates — **FIXED 2026-09-25**

Mobile standard: `mobile/src/screens/LoginScreen.tsx:73-98` adds (L-6, because
the zero-knowledge server can only see the verifier): a common-word blocklist
("password", "qwerty", "123456"…, "mindpattern", "journal"), single-repeated-
character rejection, and keyboard-walk rejection.

Web reality: `web/src/views/LoginView.tsx:29-40` implements length + class
variety only, while its comment claims "identical to mobile" — it matches the
pre-L-6 mobile policy. A web registration accepts e.g. `passwordpassword1!`
(3 classes, 17 chars — passes web, rejected by mobile). The credential then
protects the same account everywhere, including mobile's on-device unlock
oracle after the account is later enrolled there.

Recommendation: port the three shape rules and the blocklist; fix the comment.

### W-4 (MEDIUM-LOW) — Consent grant attests the disclosure, not the fingerprint match (mobile C-7 parity) — **FIXED 2026-09-25**

Mobile standard: after audit C-7, an explicit **"Fingerprints match"**
attestation tap is the only path to `grantConsent`
(`mobile/src/screens/TherapistShareScreen.tsx`).

Web reality: `web/src/views/Share.tsx:123-134` displays the fingerprint and a
strong STOP-on-mismatch warning, but the gating checkbox attests only the
disclosure terms ("they can read my patterns… audit-logged…"). A user can
check the box and grant without ever attesting they performed the out-of-band
fingerprint read-back — the exact passive-display posture mobile was required
to move beyond.

Recommendation: extend the attestation to cover the fingerprint check (e.g. a
second checkbox or combined text: "We read the fingerprint back and it
matched"), keeping grant disabled until both are accepted.

### W-5 (LOW) — Server-returned `user_id` adopted without shape validation (mobile L-7 parity) — **FIXED 2026-09-25**

Mobile standard: login refuses account ids outside `^[0-9a-f]{32}$`
(`mobile/src/api/client.ts:63, 690-692`) — a hostile server cannot feed
malformed ids into the vault owner binding, storage keys, or AAD contexts.

Web reality: `adoptSession` (`LoginView.tsx:44-56`) passes `token.user_id`
unvalidated into `setSession`, `vault.unlock`, localStorage key suffixes
(`mindpattern.onboarding.v1.<id>`, `mutedPids`), kvstore/stateSeq keys.
JSON-stringified AAD blocks injection into bindings, so impact is limited to
odd-but-harmless key shapes — this is defense-in-depth parity, not an
exploitable hole.

Recommendation: validate `token.user_id` against the 32-hex pattern before
adopting the session; fail closed like the therapist-role check above it.

### W-6 (LOW) — Per-account UI flags survive sign-out on shared computers — **FIXED 2026-09-25**

Mobile standard: sign-out wipes origin-bound local state
(`mobile/src/api/client.ts:205-221, 262-269`).

Web reality: `lockDown` (`App.tsx:80-88`) clears session + vault but leaves
`mindpattern.onboarding.v1.<userId>`, `mindpattern.mutedPids.v1.<userId>`, and
the threshold-notice stamp in localStorage. Content-free, but they disclose
that a given account used this browser (a `removePrefix` helper already exists
at `platform.ts:41-54` — it is simply not wired into the lock path).

Recommendation: call `removePrefix` for the app namespaces in `lockDown` (or
per-userId on logout), keeping D-9 ciphertext caches intact.

---

## 3. Notes (no action required / already disclosed)

- **WebAuthn/biometric unlock** absent — explicitly out of scope v1 (WEB_PLAN).
- **CSP**: `style-src 'unsafe-inline'` (inline style objects app-wide), no
  nonce/`strict-dynamic`, no reporting endpoint, HSTS without `preload`, no
  COEP. Given zero HTML sinks, single same-origin bundle, and no external
  assets, these are hardening opportunities, not exposures.
- **No client-side login lockout/backoff** — compensated by server 429 +
  clamped `Retry-After` (tested); mobile also has no counter (only a 500 ms
  pad against its offline oracle, which the web login flow doesn't have).
- **`MAX_LIST_PAGES` 200 (web) vs 100 (mobile)** — both bounded; not a defect.
- **Entry-text length uncapped client-side** — bounded by server 413 and the
  1 MB queue serialization cap; acceptable.
- Accepted residuals in `docs/WEB_THREAT_MODEL.md` (open-tab offline, English
  chrome v1, GC memory limits, single-tab drafts, pending Stryker floor)
  remain accurately disclosed **except** where W-1 extends beyond residual #3's
  framing.

## 4. Verification method

Control-by-control source comparison (mobile baseline inventory vs web
inventory), with each candidate gap confirmed by direct read of the shipping
files cited above. Prior-audit findings fixed in `7cc0aa9` (session custody on
all views, Retry-After floor, queue stranding, quarantine caps, verified-409,
logout abort race, non-quoting belt-and-braces, reconciliation DoS, test
vacuity, release provenance) were treated as closed per their regression pins
and not re-litigated.
