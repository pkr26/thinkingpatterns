# MindPattern Therapist Portal

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
- **Notes are the therapist's own record.** Encrypted under the
  therapist's password-derived key before leaving the browser; patients
  never see them. Notes attach to a patient or to a specific pattern id.
- **Crisis-adjacent patterns render non-quoting** (same contract as the
  patient app): the card never echoes the wording; the drill-down shows
  the entries in the patient's own words.
- **"Since your last visit"** — patterns whose `first_seen` is newer than
  the locally stored visit stamp are flagged: the pre-session delta. The
  stamp is a date in localStorage; no content is ever stored locally.

## Running

```bash
cd portal
npm install
npm run dev        # http://localhost:5173 — /api proxied to localhost:8000
```

Start the backend first (see ../backend). In production the portal is a
static bundle behind the same origin as the API, or the API's
`MINDPATTERN_CORS_ORIGINS` must allowlist the portal origin.

## Crypto contracts

All crypto is WebCrypto and pinned byte-for-byte against
`shared/vectors.json` by `tests/crypto.test.ts`:

| Purpose | Construction |
|---|---|
| Login | PBKDF2(600k) → HKDF `mindpattern/auth/v1` (same schedule as the patient apps) |
| Private-key custody | HKDF `mindpattern/portal-wrap/v1` → AES-256-GCM(PKCS8 P-256 key), AAD `("therapist-key", username)` |
| Patient data key | ECDH P-256 × consent's ephemeral key → HKDF (salt = both SPKI DERs, info `mindpattern/wrap/v1`) → AES-256-GCM unwrap, AAD `("consent-wrap", user, therapist)` |
| Envelopes | nonce‖ct‖tag AES-256-GCM, AAD-bound like every other platform (see ../backend/app/security/crypto.py) |
| Notes | HKDF `mindpattern/portal-notes/v1`, AAD `("note", therapist, patient, clientNoteId)` |

Key material lives in memory only. Closing the tab forgets everything.

## Tests

```bash
npm test           # vitest + coverage (per-file thresholds)
npm run typecheck
npm run build      # typecheck + production bundle
```
