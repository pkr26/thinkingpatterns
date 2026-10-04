# Fathom Therapist Portal

A browser app for clinicians: **read-only, zero-knowledge access to shared
patient patterns**, plus the therapist's own encrypted notes.

## What it does

- **Patients hold every key.** A patient wraps their data key to the
  therapist's P-256 public key inside their app (pairing code flow). The
  server stores the wrapped key; this portal unwraps it locally — the
  backend never sees plaintext and cannot decrypt any patient blob.
- **Patterns, with their evidence.** Every surfaced pattern card carries
  the "why" panel (state, significance, effect size, evidence window) and
  a drill-down into the journal entries behind the pattern
  (`detail.evidence_dates` → decrypted entries, mood per entry).
- **Read-only by construction.** The portal's API surface is GET-only for
  patient data; there is no endpoint a therapist could use to change a
  patient's journal. Every read is audit-logged server-side.
- **Notes are the therapist's own record.** Encrypted with a notes key
  before leaving the browser; the password seals the keyring. Historical
  keys preserve access across credential and sharing-identity changes.
  Patients never see notes, which attach to a patient or pattern id.
- **Crisis-adjacent patterns render non-quoting** (same contract as the
  patient app): the card never echoes the wording; the drill-down shows
  the entries in the patient's own words.
- **"Since your last visit"** — patterns whose `first_seen` is newer than
  the visit stamp are flagged: the pre-session delta. Anchors are
  per-patient DATE STAMPS in per-tab sessionStorage: they survive idle
  locks within the tab's browser session and disappear when the tab
  closes — so a second tab or browser starts from its own anchor and two
  open tabs can legitimately disagree. Where sessionStorage is
  unavailable (locked-down privacy modes), a localStorage fallback is
  scrubbed at every lock boundary instead. Visit anchors contain no
  content; encrypted clinician drafts persist separately in IndexedDB.

## Language scope (deliberate)

This portal is **intentionally English-only in this release**, while the
patient clients (web and mobile) are bilingual. The scope reflects the current deployment model:

- The portal's readers are clinicians charting in one clinic's working
  language; every deployment of this generation is single-language on the
  clinician side, so a second locale would double the review surface of
  clinical-safety copy (non-quoting crisis wording, consent-scope
  explanations, interpretation-belongs-to-you disclaimers) with no user
  served yet.
- The patient apps localize because patients are many and self-select
  their language; a clinician's chart vocabulary is set by their
  organization, not by a per-session preference.

If localization is ever required, the seam is already narrow: all
user-facing strings live inline in `src/views/*.tsx` and `src/ui.tsx` —
no string is composed server-side. Extraction would move those literals
into a single strings module (keyed per view) consumed by the same call
sites; the security-copy rules above (crisis wording never quotes the
patient, disclaimers never soften in translation) would need to be part
of that work's acceptance tests. No strings extraction is attempted in
this release.

## Running

```bash
cd portal
npm ci
npm run dev        # http://localhost:5173 — /api proxied to localhost:8000
```

Start the backend first (see ../backend). In production the portal is a
static bundle behind the same HTTPS origin as the API. `/api` is reverse
proxied on that origin; do not deploy the sign-in page against a separately
user-configurable API host.

## Production safety requirements

- Serve the portal and API over one HTTPS origin. The sign-in page has no
  user-editable server field: salts, derived verifiers, bearer tokens, and
  enrollment tokens are sent only to its own origin. Development uses the
  same-origin Vite `/api` proxy on an explicit loopback host. Fetches use
  `redirect: "error"`, omit ambient cookies, and reject a response that
  reports a different origin, so a 30x cannot forward a bearer token.
- Configure the static host to emit the headers in `public/_headers` for every
  route. Vite copies that file into `dist` for hosts that support the common
  `_headers` format; other CDNs must translate the same CSP, frame, referrer,
  MIME-sniffing, cache, permissions, opener, resource-isolation, and HSTS
  policies into their native config. This is an HTTPS-production contract:
  the HSTS policy includes subdomains, so use a hostname whose subdomains are
  also HTTPS-controlled before enabling it. Do not add HSTS to local HTTP
  development headers.
  The CSP in `index.html` is a fallback, not a replacement for response
  headers. Its `connect-src` is same-origin only; a broad HTTPS egress policy
  would undermine the immutable sign-in destination.
- Therapist registration requires a 12+ character password. A 16+ character
  passphrase is accepted as-is; 12–15 character passwords must use at least
  three character types. Existing therapist accounts may still sign in with
  their established credential so operators can migrate them deliberately.
- New clinician enrollment is policy-gated by the server's public `/meta`
  response. A disabled or unreachable policy disables the registration action
  with an administrative explanation instead of treating a blocked enrollment
  as bad credentials. Where an organization issues a controlled enrollment
  token, the form sends it only as `X-Therapist-Enrollment-Token` on the
  HTTPS registration request and drops it from memory immediately afterward.
- Signing out, session expiry, idle lock, and component teardown cancel
  in-flight authenticated requests, drop non-extractable browser key handles,
  overwrite raw wrap/note key bytes where JavaScript permits it, and remove
  locally stored visit-date metadata.

## Account security panel

The patients screen carries an on-demand "Account security" panel
(collapsed by default — nothing is derived, fetched, or sent until it is
opened) that surfaces the backend's verifier-gated rotation routes:

- **Change password** verifies historical notes custody, then atomically
  commits the new credential, wrapped identity key, and wrapped notes keyring
  through the therapist password route. Lost-response retries reuse the same
  operation id and payload. Success ends all sessions and clears local keys.
- **Recover sharing key** supports an interrupted legacy two-step change.
  The current and intended passwords plus the interrupted change's salt
  restore the existing identity. Notes custody is verified and confirmed
  before changing the identity's wrapping.
- **Rotate sharing key** first verifies and preserves notes custody, then
  publishes a fresh identity. Existing patient grants are revoked and the
  therapist must sign in again. Patients must verify the new fingerprint
  and share again; retained note keys preserve historical clinician notes.

All actions re-authenticate with the current password-derived verifier;
a bearer token alone is insufficient.

## Crypto contracts

All crypto is WebCrypto and pinned byte-for-byte against
`shared/vectors.json` by `tests/crypto.test.ts`:

| Purpose | Construction |
|---|---|
| Login | PBKDF2(600k) → HKDF `mindpattern/auth/v1` (same schedule as the patient apps) |
| Private-key custody | HKDF `mindpattern/portal-wrap/v1` → AES-256-GCM(PKCS8 P-256 key), AAD `("therapist-key", username)` |
| Patient data key | ECDH P-256 × consent's ephemeral key → HKDF (salt = both SPKI DERs, info `mindpattern/wrap/v1`) → AES-256-GCM unwrap, AAD `("consent-wrap", user, therapist)` |
| Envelopes | nonce‖ct‖tag AES-256-GCM, AAD-bound like every other platform (see ../backend/app/security/crypto.py) |
| Notes | Active key from the encrypted notes keyring; legacy password-derived and identity-derived keys remain available for decryption. AAD `("note", therapist, patient, clientNoteId)` |

Key material lives in memory only. Closing the tab forgets everything.

## Tests

```bash
npm test           # vitest + coverage (global quality thresholds)
npm run typecheck
npm run build      # typecheck + production bundle
```
