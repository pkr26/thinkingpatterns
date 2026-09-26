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
  **Access-log residual (2026-09-21 audit H-7): audit rows are retained
  for the full `MINDPATTERN_ACCESS_LOG_RETENTION_DAYS` window (default
  730 days) BEYOND erasure — deliberately, so the trail of who accessed
  a deleted subject's data outlives the account for its compliance
  window. Rows carry usernames-adjacent ids and action names only, never
  content. Disclose this retention in the erasure notice; a shorter
  window is an operator decision that trades accountability for
  minimisation.**
- **Access to the access trail itself (2026-09-21 audit B-4)**: the
  subject can read who accessed their data (`GET /api/v1/account/access-log`)
  — GDPR Art. 15 parity for the audit trail — and therapists can read
  their own action history (`GET /api/v1/therapist/access-log` + the
  portal's "My access history" panel). Deleted accounts' trails are
  operator-readable via direct database query (the rows outlive the
  account by design).
- **Rectification**: entries are user-authored and editable; no inferred
  records exist server-side (patterns re-derive from entries).

## 4a. Subprocessors & international transfers (2026-09-21 audit H-7)

Complete for YOUR deployment — the defaults avoid both categories
entirely:

| Subprocessor | When engaged | Data disclosed | Transfer mechanism |
|---|---|---|---|
| LLM provider (`MINDPATTERN_LLM_URL`) | only if an individual user re-authenticates consent (off by default) | verbatim recent journal text (bounded: the newest entries up to a fixed count/character budget) plus the deterministic brain's findings, during that analysis; the model's OUTPUT is what is sanitized (labels length-capped, "recurring phrases" verified against the user's actual text) — the INPUT text is plaintext at the provider by design (see SECURITY_RESIDUALS `D2.plaintext-egress`) | provider DPA + region disclosed at consent time; if outside the EEA, SCCs (or an adequacy decision) must be executed by the OPERATOR before enabling |
| Off-site object storage (S3-compatible, `deploy/backup-offsite/`) | only if the operator enables the offsite backup overlay | encrypted dump artifacts only (BACKUP_KEY-wrapped; the operator holds the key) | none if the bucket region is in-EEA; otherwise document the transfer basis with the storage provider's DPA |

No other subprocessors exist: no analytics, no crash reporting, no
third-party SDKs in the mobile app, no map/font/CDN fetches.

## 4b. Art. 30 RoPA

This DPIA is not the record of processing activities. Maintain the Art.
30 RoPA alongside it: controller identity and contact (and DPO, if
designated), purposes (journal-based pattern observation; consented
therapist sharing), categories of subjects and data (data subjects:
app users and their consenting therapists; special-category: journal
content — Art. 9(2)(a) explicit consent is the ONLY viable basis for
this processing), recipients (the subprocessor table above), the
retention figures set in `MINDPATTERN_*` configuration (backup, access
log), and the security measures documented in the README's security
notes. Point the RoPA at this file and at `docs/SECURITY_RESIDUALS.md`.

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

## 7. Web client addendum (2026-09-25 — added in the audit remediation)

The patient web client (`web/`, WEB_PLAN D-4) adds a browser storage
surface to this assessment. What the browser may persist, per category:

- **Session token and derived keys: never persisted.** Both live only in
  the tab's memory; refresh, a new tab, or a 5-minute idle lock drops
  them and re-authenticates. A storage-scrape red-team harness asserts
  after every flow that no storage carries token, verifier, or key
  material.
- **localStorage: non-content flags only.** An onboarding-seen marker, a
  per-day notice-dismissed date, and the muted-pattern id list. No
  journal content, no usernames.
- **IndexedDB: ciphertext and metadata only.** The offline sync queue
  (encrypted entry blobs, origin+account scoped), encrypted entry-version
  marks, the encrypted device-local mood log, and a numeric analysis
  high-water mark. All content is AES-256-GCM ciphertext under the
  password-derived data key.
- **Residual (accepted, named in `docs/WEB_THREAT_MODEL.md`):** a live
  tab holds decrypted plaintext in memory between unlock and lock; the
  OS/user owns that window, as with any webmail. Offline journaling works
  only while a tab lives (no service worker in v1).

Re-run this addendum's review if a service worker, push notification, or
any new persistence is added to the web client.
