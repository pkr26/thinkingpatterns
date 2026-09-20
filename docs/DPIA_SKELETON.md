# DPIA skeleton — MindPattern deployment

A Data Protection Impact Assessment is required before processing journal
content (GDPR Art. 35: special-category data at scale). This skeleton maps
the product's architecture onto the assessment sections an operator must
complete for THEIR deployment. The product cannot complete it for you —
the operator, processor roles, and hosting choices are yours.

## 1. System description

- **Data processed**: journal entries (encrypted client-side, AES-256-GCM),
  mood check-ins, derived pattern observations, therapist notes (ciphertext
  plus the note's analysis-derived `pattern_pid` when anchored to a pattern),
  account metadata (usernames, entry dates/timestamps, ciphertext sizes).
- **The e2e claim, honestly**: content is encrypted client-side; the
  server decrypts ONLY within the single-use processing session
  (≤5 min TTL, memory-only) that computes the pattern analysis. A DB leak
  yields no plaintext. A compromised SERVER can read content during
  processing windows. Therapist sharing re-encrypts under the therapist's
  key; the server never holds a usable share key.
- **Optional LLM path**: consent-gated, third-party endpoint, disclosed
  retention. Keeping this OFF avoids the transfer entirely.

## 2. Necessity & proportionality

- Purpose: idiographic pattern observation for the user's own reflection;
  no profiling beyond the user's own data; no automated decisions about
  people; no diagnosis/advice/prediction (product-level constraints).
- Minimisation already built in: no email/phone; no third-party SDKs; no
  analytics; metadata limited to dates/sizes (plus therapist-note pattern
  pids — coarse topic ids, no note content); export/deletion paths; the
  30-day threshold suppresses premature processing.
- Operator decisions to document: log retention at the reverse proxy,
  backup retention (`BACKUP_RETENTION_DAYS` = the deletion promise),
  LLM endpoint choice and its retention terms.

## 3. Risk assessment (fill with your mitigations)

| Risk | Built-in mitigation | Operator residual |
|---|---|---|
| DB backup leak | client-side encryption; encrypted dumps (BACKUP_KEY) | key custody; retention window |
| Server compromise during processing | single-use session, TTL, zeroization best-effort | patching; host hardening; TEE is future work |
| Username enumeration | salt decoys, rate limits | reverse-proxy rate limits; the longitudinal transition residual is documented |
| Therapist over-read | consent records, revoke, full access audit log | BAAs where the therapist is HIPAA-covered |
| LLM egress | per-user re-auth consent, off by default, output sanitization | provider DPA; consider keeping it off |
| Lawful access to metadata | dates/sizes only in cleartext (plus coarse therapist-note pattern pids) | jurisdiction analysis |

## 4. Data-subject rights mapping

- **Access/portability**: server-side streamed ciphertext export API
  (`GET /api/account/export` — the user's own blobs, still encrypted at
  rest in transit) decrypted OFF the server by an offline CLI tool
  (`mobile/tools/decrypt_export.mjs`, run against the downloaded bundle);
  a readable Markdown rendering is produced by that same CLI. There is no
  in-app export in this build: the in-app path fails closed pending a
  reviewed native streaming-to-file implementation.
- **Erasure**: `DELETE /api/account` (password proof) cascades live data;
  backups age out per `BACKUP_RETENTION_DAYS` — this delay must be
  disclosed to the user; LLM provider copies per provider terms.
- **Rectification**: entries are user-authored and editable; no inferred
  records exist server-side (patterns re-derive from entries).

## 5. EU AI Act note (2026)

The optional LLM analysis is a transparency obligation area (disclosed,
consented, non-medical purpose). The deterministic engine is statistical
software over the user's own data with no automated decision-making.
Document the non-medical-purpose position; keep App Store/marketing copy
inside the general-wellness lane to match.

## 6. Sign-off

Operator, date, roles (controller/processor), hosting locations, and the
review cadence (re-run on any architecture change — e.g. enabling the LLM
path or moving to Redis-backed multi-host).
