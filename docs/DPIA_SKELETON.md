# DPIA template — MindPattern deployment

*(Renamed in content 2026-09-26: this file was "DPIA skeleton" — it is
now a fill-in-and-SIGN template. The filename stays
`DPIA_SKELETON.md` for link stability; renaming to
`DPIA_TEMPLATE.md` is a one-line follow-up once no external documents
reference the old name.)*

A Data Protection Impact Assessment is required before processing journal
content (GDPR Art. 35: special-category data at scale). This template maps
the product's architecture onto the assessment an operator must complete
and sign for THEIR deployment. The product cannot complete it for you —
the operator, processor roles, and hosting choices are yours — but every
product-side fact below is stated from the code as shipped (verified
2026-09-26), so the only blanks are operator decisions.

## 0. Controller & contact block (OPERATOR-FILL)

| Field | Value |
|---|---|
| Controller (legal entity) | `OPERATOR-FILL` |
| Controller registration no. / address | `OPERATOR-FILL` |
| DPO (or privacy contact) | `OPERATOR-FILL` — appointing a DPO is indicated where core activities are large-scale processing of special-category data (Art. 37(1)(c)); take advice |
| Security contact / disclosure channel | `OPERATOR-FILL` (mirror it in `docs/security.txt.example` and the published privacy policy) |
| Processor(s) (hosting, backup target) | `OPERATOR-FILL` — list from `docs/SUBPROCESSOR_BAA_REGISTER.md` |
| Processing locations (controller, hosts, backups) | `OPERATOR-FILL` |
| Assessment date / review cadence | `OPERATOR-FILL` — re-run on any architecture change (e.g. enabling the LLM path, moving to multi-host) and at least annually |
| Version of this template relied on | repo commit / release tag `OPERATOR-FILL` |

Art. 35(7) requires FOUR elements — systematic description, necessity/
proportionality assessment, risks to data subjects, and measures —
provided by §1, §2, §3 (with §4's rights machinery), and §§4a/5 plus
the measures column of §3, respectively.

## 1. System description (Art. 35(7)(a))

- **Data processed**: journal entries (encrypted client-side, AES-256-GCM),
  mood check-ins, wellbeing measures (PHQ-9/GAD-7/PHQ-2 — encrypted
  blobs, scores never interpreted by the product), derived pattern
  observations, therapist notes (ciphertext plus the note's
  analysis-derived `pattern_pid` when anchored to a pattern),
  account metadata (usernames, entry dates/timestamps, ciphertext
  sizes), and the access audit log (actor ids, actions, target ids,
  timestamps — no content).
- **The e2e claim, honestly**: content is encrypted client-side; the
  server decrypts ONLY within the single-use processing session
  (≤5 min TTL, memory-only, key zeroized after the recompute) that
  computes the pattern analysis. A DB leak yields no plaintext. A
  compromised SERVER can read content during processing windows.
  Therapist sharing re-encrypts under the therapist's key; the server
  never holds a usable share key. Since 2026-09-26 the data key is a
  RANDOM key held in a password-wrapped envelope (v2 accounts) — the
  server stores only the opaque 60-byte envelope.
- **Optional LLM path**: consent-gated, third-party endpoint, disclosed
  retention. Keeping this OFF avoids the transfer entirely.
- **Journal-content retention statement (explicit)**: the product
  imposes NO time limit on journal content. Entries live until the user
  edits or deletes them, or deletes the account (hard cascade, no soft
  delete, no tombstones of content). There is no automatic expiry of
  journal ciphertext — if the controller requires a maximum retention
  age for content, that is an operator policy to implement and disclose
  (the product provides account deletion and per-entry deletion as the
  mechanics). Backups hold deleted content for
  `BACKUP_RETENTION_DAYS` (default 35) after any deletion — see §4.

## 2. Necessity & proportionality (Art. 35(7)(b))

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

## 3. Risk assessment (Art. 35(7)(c)) — fill with your mitigations

| Risk | Built-in mitigation | Operator residual |
|---|---|---|
| DB backup leak | client-side encryption; encrypted dumps (BACKUP_KEY) | key custody; retention window |
| Server compromise during processing | single-use session, TTL, zeroization best-effort | patching; host hardening; TEE is future work |
| Username enumeration | salt decoys, rate limits | reverse-proxy rate limits; the longitudinal transition residual is documented |
| Therapist over-read | consent records, revoke, full access audit log (forward hash-chained per patient since 2026-09-26 — tamper-evident) | BAAs where the therapist is HIPAA-covered |
| LLM egress | per-user re-auth consent, off by default, output sanitization | provider DPA; consider keeping it off |
| Lawful access to metadata | dates/sizes only in cleartext (plus coarse therapist-note pattern pids) | jurisdiction analysis |
| Audit-trail tampering | per-patient forward hash chain (`prev_hash`→`entry_hash`) with an account-deletion terminal row; removals/edits break the chain detectably | protect DB write access; verify the chain after any incident |

## 4. Data-subject rights mapping (Art. 35(7)(d) measures)

- **Access/portability**: server-side streamed ciphertext export API
  (`GET /api/v1/account/export` — the user's own blobs, still encrypted
  in transit) decrypted OFF the server by an offline CLI tool
  (`mobile/tools/decrypt_export.mjs`, run against the downloaded bundle);
  a readable Markdown rendering is produced by that same CLI. The WEB
  client downloads the ciphertext bundle; the MOBILE app's in-app
  export stays disabled pending a reviewed native streaming-to-file
  implementation.
- **Erasure**: `DELETE /api/v1/account` (password proof) cascades live
  data; backups age out per `BACKUP_RETENTION_DAYS` — this delay must be
  disclosed to the user; LLM provider copies per provider terms.
  **Access-log residual (2026-09-21 audit H-7) and its explicit
  defense**: audit rows are retained for the full
  `MINDPATTERN_ACCESS_LOG_RETENTION_DAYS` window (default 730 days,
  operator-selectable 1–3650) BEYOND erasure. Defense: the trail is
  what makes the erasure itself auditable — who read the deleted
  subject's data, and when, is exactly the record a controller needs to
  demonstrate compliance and handle post-deletion access demands; the
  rows carry actor/target ids and action names only, never content;
  deletion is sealed with a terminal `account_deleted` chain row so the
  chain remains verifiable past erasure. Disclose this retention in the
  erasure notice; a shorter window is an operator decision that trades
  accountability for minimisation.
- **Access to the access trail itself (2026-09-21 audit B-4)**: the
  subject can read who accessed their data
  (`GET /api/v1/account/access-log`) — GDPR Art. 15 parity for the
  audit trail — and therapists can read their own action history
  (`GET /api/v1/therapist/access-log` + the portal's "My access
  history" panel). Deleted accounts' trails are operator-readable via
  direct database query (the rows outlive the account by design).
- **Rectification**: entries are user-authored and editable (optimistic
  concurrency, 409 on lost races); measures have a verifier-gated
  DELETE correction path; no inferred records exist server-side
  (patterns re-derive from entries).

## 4a. Subprocessors & international transfers (2026-09-21 audit H-7)

Complete for YOUR deployment — the defaults avoid both categories
entirely. The template register (with BAA-required flags) lives at
`docs/SUBPROCESSOR_BAA_REGISTER.md`:

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
log — collected in `docs/DATA_RETENTION_SCHEDULE.md`), and the
security measures documented in the README's security notes. Point the
RoPA at this file and at `docs/SECURITY_RESIDUALS.md`.

## 4c. Minors / age gate (CONTROL IMPLEMENTED 2026-09-27 — was the 2026-09-26 product gap)

**The age gate shipped on 2026-09-27 and is a condition of registration
in the patient clients.** Registration in web (`web/src/views/LoginView.tsx`,
required checkbox — the create-account button stays disabled and the
submit path re-checks it) and mobile (`mobile/src/screens/LoginScreen.tsx`,
explicit toggle, same double gate) requires an unambiguous "I am 18 or
older" self-declaration before an account can be created. The
declaration is an act of the moment, not account data: nothing is
stored — no date of birth, no attestation record, no timestamp — so the
gate cannot become a birthday-collection surface (data minimisation by
construction). Therapist portal registration remains out of scope:
clinicians are adults professionally onboarded by the operator.

Residual (honest, and it belongs in the §3 risk table):

1. **Self-declaration is not age verification.** A minor can check a
   box; the product performs no documentary or third-party check. This
   is the industry-standard floor for non-social apps, not proof.
2. **Per-jurisdiction guardian consent remains an operator obligation.**
   Where the operator offers the service below the local information-
   society age (13/14/16 in GDPR member states; COPPA's 13 in the US),
   the operator must either refuse under-18 users (the posture this
   gate implements) or build and disclose verifiable parental consent
   per Art. 8 / COPPA — the product provides NO parental-consent
   machinery.
3. **A hard age-verification vendor is a documented future option**, not
   a shipped control: if an operator's counsel requires stronger
   assurance, integrate an age-assurance provider and record it in the
   §4a subprocessor table (which today lists none beyond the optional
   LLM/backup rows) — that trade (new subprocessor + new data) is a
   deliberate operator decision, not a default.

Operator sign-off on this section is required: the undersigned confirms
either (a) the shipped 18+ self-declaration gate is present in the
deployed clients (it is in the 2026-09-27 clients; verify your build)
with the residual above accepted, or (b) a documented guardian-consent
flow exists and is disclosed here.

## 5. EU AI Act note (2026)

The optional LLM analysis is a transparency obligation area (disclosed,
consented, non-medical purpose). The deterministic engine is statistical
software over the user's own data with no automated decision-making.
Document the non-medical-purpose position; keep App Store/marketing copy
inside the general-wellness lane to match.

## 5a. Art. 36 prior consultation — trigger definition

Consult the supervisory authority BEFORE processing when this DPIA
concludes a HIGH residual risk that cannot be mitigated by measures
available to the operator. Concretely, for this product, prior
consultation is triggered if ANY of the following is true at signing
time (check and initial):

- [ ] The LLM path (`MINDPATTERN_LLM_URL`) is enabled AND the provider
      retention terms do not include deletion-on-request or an EEA/adequate
      region (unmitigated third-country special-category transfer).
- [ ] Therapist sharing is enabled in a jurisdiction where clinician
      record-retention duties conflict with the hard cascade delete
      (see `docs/SECURITY_RESIDUALS.md` "Patient deletion destroys
      therapist notes") and counsel has not resolved it.
- [ ] The age gate (§4c — shipped 2026-09-27) is absent from the DEPLOYED
      clients while the service is publicly reachable (minors'
      special-category data with no lawful-basis control).
- [ ] Any §3 residual is rated high after the operator's own mitigations.

If NO box is checked, document that consultation was considered and not
triggered (Art. 36(1) expects the controller to seek advice where
appropriate — the record of the decision is the compliance artifact).

## 6. Sign-off (sign and date; keep with the RoPA)

| Role | Name | Signature | Date |
|---|---|---|---|
| Controller (or authorised officer) | `OPERATOR-FILL` | ______________ | ______ |
| DPO / privacy advice taken (Art. 35(2)) | `OPERATOR-FILL` | ______________ | ______ |
| Security lead (risk table accepted) | `OPERATOR-FILL` | ______________ | ______ |
| §4c age-gate control confirmed | `OPERATOR-FILL` | ______________ | ______ |
| §5a Art. 36 trigger review completed | `OPERATOR-FILL` | ______________ | ______ |

Review cadence: re-run on any architecture change — e.g. enabling the
LLM path, moving to Redis-backed multi-host, adding any subprocessor —
and at least annually.

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
  marks, the encrypted device-local mood log, the encrypted pending-
  measure record, the encrypted lock-time draft slot, and a numeric
  analysis high-water mark. All content is AES-256-GCM ciphertext under
  the password-derived data key.
- **Residual (accepted, named in `docs/WEB_THREAT_MODEL.md`):** a live
  tab holds decrypted plaintext in memory between unlock and lock; the
  OS/user owns that window, as with any webmail. Offline journaling works
  only while a tab lives (no service worker in v1).

Re-run this addendum's review if a service worker, push notification, or
any new persistence is added to the web client.

## Addendum: voice journaling (added 2026-09-29 remediation)

- **New processing:** consent-gated speech-to-text of recorded journal
  entries by a third-party STT provider ({STT_PROVIDER_NAME}); optional
  English translation of the resulting transcript by the analysis (LLM)
  provider, itself gated on the user's current analysis consent (never
  voice consent alone).
- **Audio lifecycle:** transcription audio exists in API memory for one
  upstream call and is never persisted. Kept recordings are
  client-side AES-GCM ciphertext in object storage with a 30-day
  default expiry (swept + lazy-enforced), therapist playback gated by a
  separate per-therapist `share_voice` grant with an audit row per
  served fetch, and account erasure best-effort-deletes objects before
  the row cascade.
- **Consent artifacts:** per-user voice-consent record (timestamp,
  disclosure version, SHA-256 policy fingerprint over provider/endpoint/
  model/retention/policy) — stale on any operator policy change, judged
  per request. Re-assess this addendum whenever the STT provider,
  endpoint, or retention terms change (the fingerprint forces
  re-consent, but the DPIA must document the new arrangement).
- **Cross-references:** docs/PRIVACY_POLICY_TEMPLATE.md (voice section),
  docs/DATA_RETENTION_SCHEDULE.md (kept-recording row),
  docs/SUBPROCESSOR_BAA_REGISTER.md (STT row),
  redteam/g_voice.py (adversarial campaign).
