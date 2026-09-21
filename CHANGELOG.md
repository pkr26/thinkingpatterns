# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## Unreleased

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
  accepts today-or-yesterday), so a blob captured by a hostile server
  cannot be replayed across recomputes. `MINDPATTERN_DECOY_SECRET`
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
