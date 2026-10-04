# Fathom: implementation plan to exceed 90 in every area

Created: October 3, 2026. Baseline: `9c1ba47508f474afc5f70588dd2771d80c2eece7`.

**Objective: earn at least 92/100 in each of the ten audited areas.** The target is achievable enough to guide an improvement program; it is not a promised result. Fixing code alone cannot establish usability, native-device behavior, operational recovery or clinical benefit. Those need their own evidence.

**Status: engineering fixes and local verification completed; external release/evidence gates remain.** The audit scores remain the historical baseline until an independent reassessment. Current outcomes and remaining gates are in [REMEDIATION_STATUS.md](REMEDIATION_STATUS.md), with evidence in `reports/remediation-2026-10-03/`; the prospective acceptance protocol is [VALIDATION_TO_90.md](docs/VALIDATION_TO_90.md). Preserve the historical `PLAN.md`; this is the current remediation plan.

Source of work: [main audit](AUDIT_2026-10-03.md), [mobile findings](reports/audit-2026-10-03/mobile.md), [web/portal findings](reports/audit-2026-10-03/web-portal.md), [backend services](reports/audit-2026-10-03/services.md), [operations and evidence findings](reports/audit-2026-10-03/ancillary.md), and [validation baseline](reports/audit-2026-10-03/validation.md). The [file manifest](reports/audit-2026-10-03/file-coverage.json) records the original 781-file scope.

## Execution ledger — October3 remediation

Checked boxes below mean the described engineering work has supporting local
source/test evidence. Unchecked compound items may include implemented source
plus unrun hardware, human or deployment requirements; read this ledger and
the remediation status before treating them as wholly untouched or complete.

| Stage | Current disposition | Evidence still needed |
|---|---|---|
| P0 | Historical baseline retained; isolated API/PostgreSQL/Chrome/Android toolchains and regressions established | Full Xcode, representative hardware/performance baseline and actual release operator inputs |
| P1 | Functional/data-loss source fixes and correct-behavior tests implemented; real Android/browser core journeys pass | Full iOS build and hardware-specific APIs |
| P2 | Atomic patient/clinician custody, durable retry/checkpoint/erasure protocols, encrypted native typed-draft restart recovery and independently decryptable exports implemented | Independent protocol review and complete physical interruption matrix; retained competing branches must not be guessed |
| P3 | Draft/history/notes/labels/localization/navigation, verified resume progress and honest states improved | Human accessibility, native-language and representative user/clinician task outcomes |
| P4 | Lifecycle/admission/revocation/audit/object-deletion fixes,31-migration graph, real PG full suite and exact ciphertext upgrade pass | Production workloads, real object-provider outage/inventory and deployed-network fault exercises |
| P5 | Authenticated routes/catalogs/QR deferred; initial patient/portal gzip budgets pass; typed application bodies checked | Device/network/history-scale latency and memory distributions, continued domain simplification |
| P6 | CI evidence gates corrected; actual Android compilation added; authenticated Docker backup/PG restore and real promtool fault tests pass | Public configuration/signing, hard npm audit upstream resolution, hosted CI, delivered alerts and measured production RPO/RTO |
| P7 | Prospective full-pipeline/usefulness/safety protocol published; claims corrected and unnecessary narrative dispatch disabled | Independent held-out calibration, language/clinical review and appropriately reviewed participant studies |
| P8 | Not completed; scores remain historical | Independent ten-area reassessment against the unchanged rubric; every area92+ |

## 1. What we will do, in order

| Stage | Work package | Main responsibility | Depends on | Completion evidence |
|---|---|---|---|---|
| P0 | Reproduce failures and establish a runnable integration baseline | Engineering / QA | None | Fresh baseline, regression specifications, browser/native toolchains |
| P1 | Repair startup and immediate data-loss/function blockers | Mobile / web / API | P0 | Correct native boot, saves, questionnaire, recovery and recompute behavior |
| P2 | Make persistence, sync, key changes and restoration dependable | Clients / API / database | P0; P1 fixes integrated | Failure-injected, real-crypto round trips without lost acknowledged data |
| P3 | Complete patient/clinician journeys and accessible UI | Product / client engineering | P1; P2 for destructive/account flows | Durable drafts, conflict recovery, clear statuses, device and accessibility evidence |
| P4 | Strengthen backend, database, privacy and analysis contracts | API / database / security | P0; transaction design coordinated with P2 | Concurrent lifecycle tests, migration proof, bounded admission and deletion |
| P5 | Improve measured performance and maintainability | All engineering areas | Stable P2/P4 interfaces | Performance budgets met; coherent typed workflow boundaries |
| P6 | Make CI, backups, deployment and release checks trustworthy | Platform / QA | P0; P2/P4 for recovery drills | Clean release gates, isolated restore, operational fault drills |
| P7 | Validate usefulness, safety and language with people | Product / clinical / research | Research design can start at P0; study uses stable build | Usability, language, statistical and safety reports supporting actual claims |
| P8 | Independently re-audit and release only on demonstrated results | Reviewers / release owner | P1–P7 | Every area independently assessed at 92+; no unresolved release blockers |

Run independent client, API and infrastructure work in parallel. Complete transaction/protocol design before clients implement migrations. Begin usability recruitment and validation design early because they have different lead times from coding.

The first implementation batch is: fix native root registration and the iOS Health bridge; fix actual questionnaire/HealthKit/recovery contracts; handle empty analysis groups; propagate persistence failures; protect editor revisions; cancel late microphone acquisitions; render the exact validated insights response; then establish ordered, revision-aware audio synchronization. Fix the dev Compose parser and broken CI conditionals alongside this batch. Keep destructive key-change workflows gated until their preservation protocol passes P2.

Use small reviewable changes, each with a behavioral regression and relevant checks. Estimate individual packages after P0 establishes the actual toolchain and reproduction cost; no calendar release date is promised before that evidence.

## 2. What a score above 90 requires

Keep the audit's categories and weights. A high weighted average cannot hide an area at or below 90. Publish the scoring criteria before implementation, then record evidence, remaining limitations and deductions for each area during P8. Tests and coverage support the judgement; they do not mechanically generate an application score.

| Area | Current | Target | Evidence required for the target |
|---|---:|---:|---|
| Product UX and accessibility | 68 | 92+ | Core-task usability, understandable privacy/save/recovery controls, manual accessibility and language review |
| Patient web | 57 | 92+ | Reliable storage/recording/freshness, real-browser core journeys, clean production build and measured responsiveness |
| Native mobile | 50 | 92+ | Android/iOS cold boot and core journeys; real permissions, HealthKit, biometrics, notifications and privacy behavior |
| Clinician portal | 52 | 92+ | Notes and revisions survive all security changes; durable drafts, conflicts and useful accessible longitudinal review |
| Backend/API | 76 | 92+ | Valid inputs do not crash; typed contracts, concurrency/recovery correctness and measured resource bounds |
| Database and migrations | 80 | 92+ | Existing-install upgrades, transactional revisions, concurrent lifecycle safety and verified object deletion/restore |
| State, persistence and sync | 46 | 92+ | No loss of acknowledged data in the declared failure matrix; operation ownership, ordered retries and recoverable migrations |
| Security and privacy | 64 | 92+ | Downgrade/revocation weaknesses closed; custody protocol, consent and release independently reviewed |
| Scientific evidence and safety | 54 | 92+ | Calibrated end-to-end analysis, reviewed supported-language behavior, comprehension/usefulness evidence, claims limited to results |
| Delivery, operations and maintainability | 67 | 92+ | Accurate CI, reproducible artifacts, restore/alert/deploy drills, current documentation and maintainable domain boundaries |

Zero known critical/high defects in supported core journeys is a completion condition. Findings marked as source-level concurrency leads must be investigated, not silently counted as fixed or proven exploits. A justified non-applicable disposition needs evidence and reviewer agreement. Unrun checks remain unverified.

## 3. P0 — Establish evidence and execution discipline

- [x] Preserve the audit and its logs as the historical baseline. Inventory each finding with its reproduction, affected data, proposed fix, dependencies, regression and disposition.
- [x] Convert independent failure probes into tests asserting correct behavior. A passing test that demonstrates the old defect is not remediation evidence.
- [ ] Bring up isolated API, PostgreSQL and object storage with synthetic accounts; use real client crypto and persistent browser storage. Keep fake-provider, SQLite and mock-native results labelled by scope.
- [ ] Install/configure full Xcode and Android SDK, plus required monitoring/shell validation tools. Record supported OS/browser/device versions and build configuration. Add native build and launch checks that actually exercise the launchers.
- [ ] Record baseline latency, bundles, memory, task success and accessibility failures on named profiles. Freeze acceptance budgets before using results to declare success.
- [x] Keep production origin, security contact, signing material and provider/operator configuration as explicit release inputs. Use local development values for engineering; production validation rejects placeholders. Never invent contact details or commit signing secrets.

**Done when:** failures are reproducible, the integration environment is repeatable, and each critical finding has a correct-behavior regression or a documented hardware validation procedure.

## 4. P1 — Stop immediate failures and data loss

- [ ] Align the JS/native root component identifiers without changing established encryption/AAD domains. Import the full HealthKit class interface; compile and boot both targets.
- [x] Correct HealthKit metadata and valence conversion, and adapt questionnaire tap handlers so native events cannot become retry records. Pass the actual recovery token rather than the response object.
- [x] Make empty statistical groups an explicit insufficient-evidence case. Exercise short valid journals, all-filtered groups, duplicate dates and mixed mood/text inputs; no divide-by-zero and no invented observation.
- [x] Return typed storage failures. Clear an editor only after an acknowledged durable commit, and only if the submitted revision is still current. Keep newer writing and failed drafts recoverable.
- [x] Reserve microphone acquisition synchronously. Invalidate acquisition on unmount/reset/lock, stop late streams, and clean up recorder construction/start failures.
- [x] Validate and render one exact insights payload, including generation/schema checks; remove the second unchecked fetch.
- [x] Correct audio parent-entry ordering and acknowledgement ownership as an initial safe patch, followed by the durable outbox in P2. A missing parent must retain the recording for repair/retry.

**Done when:** the old reproductions fail on the baseline and pass with safe behavior on the fixed build; actual core actions complete. Static preflight and mock-only tests cannot close native launch or platform-API findings.

## 5. P2 — Make saved data and key custody dependable

### P2a. One operation-ownership and persistence contract

- [ ] Define ownership by account, session, API origin, resource, key generation and edit revision as relevant. Every delayed completion checks ownership before changing UI, queues, files or secure storage.
- [x] Separate pending user data from disposable cache. A committed write means durable storage; an in-memory fallback cannot claim that data is saved on the device.
- [x] Use stable operation IDs, dependency ordering, compare-and-swap acknowledgements and erase/session tombstones in the outbox. Upload the journal before its audio. A late acknowledgement cannot delete a replacement take or restore an erased queue.
- [ ] Store large encrypted audio in an appropriate file/blob store with a transactional index. Migrate existing rows with verified readback. Handle quota and device storage limits explicitly; offer retry/export rather than silently evicting accepted recordings.
- [x] Make lock timeouts fail safely. Use Web Locks/transactional storage where available; never enter a critical section merely because a waiting deadline expired.
- [ ] Create a registry of every encrypted local/server store and its key/version dependency: journal, safety plan, pending measures, audio, drafts, biometric vault and clinician notes/revisions. Reuse it for migration, deletion and export verification.

### P2b. Preserve patient data through security changes

- [ ] Design v1 rekey as an atomic or resumable operation covering every registered encrypted store, including server `AudioAttachment` records. Check counts, IDs and decryptability before retiring old keys.
- [ ] Persist safe migration checkpoints and resume after app/process death. Serialize concurrent edits or reject stale versions; do not overwrite content acknowledged under a later revision.
- [x] Specify auth-verifier KDF separately from envelope-wrapping KDF. Supported nondefault envelope parameters must survive password change and fresh login across clients.
- [x] Bind recovery to the locally verified enrolled scheme. Reject server-driven v2-to-v1 downgrade; never send a v2 raw recovery key as legacy proof.
- [x] Require fresh user presence/current proof for recovery-kit replacement/removal. Recheck enrollment epoch after expensive verification, so revoke/reset races cannot issue a new live token. Zero candidate keys in `finally` paths.
- [x] Define logout-current versus logout-all semantics explicitly and align UI, API and tests. Do not treat the stale live-drill expectation as proof the backend already implements account-wide logout.

### P2c. Give clinician notes independent key custody

- [x] Generate a random account notes data key independent of password-derived keys and the replaceable P-256 sharing identity. Encrypt a versioned keyring bound to immutable therapist UUID and purpose; keep keys out of server plaintext.
- [x] Preserve existing legacy/password and identity-derived v2 decrypt keys inside encrypted custody before switching credentials. Use the actual UUID-bound legacy AAD. An unreadable item is a surfaced failure, never a skipped migration input.
- [x] Commit credential material, private-key wrap, notes-keyring envelope, KDF/custody version and lifecycle epoch atomically under current proof and snapshot/CAS conditions. Make lost-response retries recoverable by operation ID/status or a reviewed staged protocol.
- [ ] Migrate current notes and every revision in bounded batches. Preserve text, identities and revision semantics; verify the complete collection before retiring old envelopes. Account reload must recover after every interruption boundary.
- [x] Rotate sharing identity separately from notes custody. Define the compromise path, retained-old-key exposure and grant re-verification; re-encryption cannot retract ciphertext copies already obtained.
- [x] Version protocol capability and prevent old clients from writing formats that invalidate migration guarantees. Retain byte-exact legacy crypto fixtures and existing `mindpattern` AAD domains during branding changes.

### P2d. Prove independent export and recovery

- [x] Emit strict streamed JSON with one `audio` key and the identity/KDF/version metadata needed for AAD and v1/v2 decryption, including required username binding.
- [x] Upgrade the export tool for legacy, v2 and mixed bundles, audio extraction and supported KDF bounds. Use a masked interactive password prompt; reject malicious work-factor/resource requests.
- [x] Validate restoration independently of the exporting implementation using known content, IDs, timestamps, metadata and audio bytes. A download success alone is not recovery evidence.

**Done when:** real-key, real-database failure injection proves readable/recoverable accounts after password change, recovery, identity rotation, export and fresh login. Include every note revision and registered store. No migration skips valid data; no acknowledged item disappears under the routine application, network and concurrency failures in the verification matrix; no plaintext key is found in DB, logs or captured requests. The changed custody protocol receives independent security review before release.

## 6. P3 — Complete excellent patient and clinician experiences

- [ ] Provide one clear daily entry path, optional check-in, readable history detail and durable drafts. Deliver useful private readback before enough data exists for patterns; do not populate empty screens with invented inferences or pressure users with streaks.
- [ ] Use explicit states: not saved, saved on this device, syncing, received by server, needs action. Show pending-recording retry/export and recovery actions. Explain actual offline capabilities; a loaded web shell is not a verified cold-start offline vault.
- [x] Preserve patient edit metadata. Keep both local and remote versions on conflicts; successful retry awaits the actual commit. Never automatically overwrite an undecryptable newer item.
- [x] Persist encrypted portal drafts scoped to account/patient/note/pattern and base revision. Recover across chart changes, lock, reload and crash. A 409 keeps the pending text and explains reconciliation.
- [x] Guard async safety-plan hydration/dirty state and enforce identical save/load limits. Do not silently discard an oversized existing plan; show a recoverable repair path.
- [ ] Use browser URLs/back/forward for chart/history navigation. Add TOTP QR plus manual enrollment, usable recovery-code capture and separately verified print/export views.
- [x] Bind share approval to immutable lookup code, clinician identity and key fingerprint. Editing the code invalidates prior lookup. Revocation/regrant requires fresh voice opt-in.
- [x] Repair body-lifetime cancellation, 401/410 session expiry, late playback/Blob URLs and scratch-file cleanup across patient, native and portal paths.
- [ ] Make locale updates reactive. Correct topic/sleep/tag/direction copy, evidence units, timezone labels and Unicode highlight offsets. Review English/Spanish phrasing with native speakers.
- [ ] Schedule future reminder cadence correctly; route foreground/cold-start taps immediately when ready and dispose listeners. Report preference-save failures truthfully. Keep reminders optional and easy to pause.
- [ ] Use actual safe-area insets and layouts that work at maximum text size with keyboard open. Correct Face ID purpose/API usage, initialize capture shielding from existing state, and bundle privacy manifests/resources correctly. Replace release origin/icon/identity placeholders without changing cryptographic identities.
- [x] Attempt every independent local account erasure even if one fails; persist a retry tombstone and report incomplete cleanup. Clear temporary plaintext/key buffers when ownership ends.
- [x] Review password-strength policy locally and consistently. Repeated/common strings cannot receive the strongest label; existing sign-in credentials must not be invalidated by a new enrollment policy.

**Accessibility gate:** audit web critical journeys against [WCAG 2.2 AA](https://www.w3.org/TR/WCAG22/), including keyboard, visible focus, labels/groups, accessible authentication, status/errors, reflow and chart table/text equivalents. Combine automated checks with actual VoiceOver, TalkBack and desktop screen-reader tasks; include 320px layouts, zoom, large fonts, reduced motion, dark/light and orientation changes. Record and resolve findings rather than calling an automated scan a certification.

**Usability gate:** run formative sessions with representative patients and clinicians, including assistive-technology users. Start with at least five participants in each audience, expand as needed, and preregister a target of at least 90% unassisted core-task success with no acknowledged-save loss. Report raw task outcomes and sample limitations; five participants are formative evidence, not population-level validation. Verify understanding of save location, recovery, sharing scope and observation uncertainty.

## 7. P4 — Harden backend, database and privacy contracts

- [x] Reject stripped MACs on records requiring authenticated audit integrity. Explicitly version legitimate legacy records; a removed MAC must not turn a new record into an accepted legacy record. Test the stated DB-writer threat model.
- [x] Verify durable revocation hydration before serving protected requests, or use a proven durable fallback/retry. Test startup DB failure and revoked-token access after restart.
- [x] Enforce configured body admission/concurrency and decoded byte bounds. Align API process admission with actual memory budgets; test slow clients, maximum bodies and simultaneous requests.
- [ ] Continuously verify advisory-lock ownership and fail readiness/admission when the guard connection is lost. Test connection termination, partition/reconnect and a competing process. Preserve the declared single-process deployment until distributed semantics are designed and proven.
- [x] Use fresh transaction state and common lifecycle/version checks for note edits/rekey, recovery, audio replacements/deletes, consent and account deletion. Investigate the stale ORM identity-map, divergent note lock keys, expired-audio quota subtraction and incomplete audio locking with concurrent PostgreSQL tests.
- [ ] Commit content and collection/revision changes together. Add justified database constraints only after checking existing data. Verify indexes/query plans with realistic history and clinician workloads.
- [x] Implement a durable object-deletion outbox/tombstone and retry. Local failure-injected tests prove bytes are deleted after row deletion and retry; lifecycle expiry is a backstop.
- [ ] Validate deletion, outage recovery and inventory reconciliation with the configured production object provider.
- [ ] Test all31 migration steps as a complete upgrade path on representative old-install snapshots, plus fresh bootstrap on PostgreSQL and supported SQLite. Verify preserved ciphertext and integrity; rehearse forward repair and restore when rollback is unsafe.
- [ ] Introduce versioned runtime parsers for API/decrypted data: finite numbers, dates, enums, decoded limits and cross-field relations. Clarify extra-field rejection versus strict type coercion. Preserve unaffected records and distinguish malformed data from empty data.
- [x] Review consent at dispatch and revoke/regrant boundaries. Disable unnecessary LLM narrative egress unless a reviewed, measurable client feature needs it; confirm mobile usage before claiming no consumer anywhere.
- [ ] Prefer bounded, human-reviewed deterministic narrative. Before exposing generated text, evaluate supported-language diagnosis/advice/manipulation failures; a larger English phrase blacklist is insufficient.
- [x] Select most-recent LLM input within byte/entry budgets before chronological presentation. Detect translation truncation, preserve the original and implement a completeness contract or verified chunking; partial text cannot masquerade as complete analysis input.
- [x] Filter muted/sensitive questions before the candidate cap.
- [ ] Expose phrase-budget clipping and evaluate cluster precision/recall independently of deterministic implementation consistency.

**Done when:** failure-mode and concurrent integration tests pass on the real database/object store; resource tests meet declared budgets; every source-level lead has an evidence-backed disposition; privacy and consent behavior agrees across clients and services.

## 8. P5 — Make performance and architecture measurable

- [ ] Lazy-load noninitial screens, locale catalogs and lexicons. Profile sentiment work, then debounce/move it off the main thread where necessary.
- [ ] Page/cancel history decryption and rendering; batch encrypted version-map operations rather than rewriting the entire map per item. Test 1,000- and 10,000-entry accounts and bounded memory.
- [ ] Extract coherent authentication/vault, writing/outbox, recording/playback, sharing, rotation and clinician-notes workflows from large screens/API modules. Keep platform adapters explicit; avoid arbitrary file splitting or a state-library rewrite as a substitute for correct transitions.
- [ ] Replace `any` at security/session boundaries with typed contracts and runtime validation. Tighten unchecked Python function bodies and preserve meaningful integration coverage during refactors.
- [ ] Measure cold boot, typing, warm save, sync, large-history navigation and API p95/p99 on named low-cost hardware/network profiles. Gather only consented aggregate timing/status information, never journal/clinical plaintext.

**Proposed engineering budgets, to freeze after P0:** patient initial JS ≤150 kB gzip (baseline 254.96); portal ≤100 kB gzip (baseline 86.22); warm native local save p95 ≤1 second; first useful check-in ≤60 seconds in task sessions. These are project goals, not published standards or current achievements.

For deployed web performance, target the published good thresholds at the 75th percentile: LCP ≤2.5 seconds, INP ≤200 ms and CLS ≤0.1, separately for mobile/desktop. Record field evidence when traffic permits; lab results alone cannot establish field INP. [Core Web Vitals guidance](https://web.dev/articles/vitals).

**Done when:** budgets are met without weakening encryption/durability, and workflow boundaries make ownership, retries and recovery easier to verify. Keep the existing bounded architecture unless measurements justify a change.

## 9. P6 — Make delivery and recovery trustworthy

- [ ] Correct Compose indentation and prove the documented development startup. Run format/type/build gates; fix stale password-policy assertions and build-artifact/SRI assumptions with current build outputs. Retain the fail-closed release-time `security.txt` configuration gate; generic builds must omit the file rather than shipping a placeholder.
- [ ] Correct mutation workflow exit logic at below/equal/above thresholds. Preserve documented floors and ratchet risk-focused coverage using meaningful surviving mutants; an app score above 90 is not a requirement that every mutation number equals 90.
- [ ] Make missing/failed red-team campaigns fail completeness checks, including `g_voice`. Require exact campaign/result inventory, terminal status and nonzero exit on infrastructure/process errors.
- [ ] Match mutation identity, source/scope and actual result before crediting a kill. RuntimeError, missing or changed-scope mutants cannot count as killed. Document any accepted timeout classifications.
- [ ] Preserve both NFD and NFC AAD vectors byte-for-byte. Enforce cross-client crypto interoperability and avoid collapsing intentionally distinct fixtures.
- [ ] Update endpoint inventory and simulations for recovery/rekey/delete routes. Make failed sync/determinism checks fail campaigns. Keep historical reports dated and distinguish sampled blobs, fake providers and final recompute from full current production lifecycle coverage.
- [ ] Unify backup encryption/MAC/decryption secret resolution; reject ambiguous file/env inputs or use one explicit resolver. Authenticate before decryption; test wrong secret, truncated/tampered artifacts and both documented secret paths.
- [ ] Restore backup into an isolated environment and compare account/data/metadata/object inventory. Include retained audio/object-store coverage or state explicit supported recovery limits. Test remote backup freshness and alert delivery.
- [ ] Rehearse deployment, schema upgrade, forward repair/restore, public TLS, disk pressure, readiness, provider failure and lost guard ownership. Run actual monitoring-rule and shell checks. Verify complete image digests and dependency updates with compatible native builds.
- [ ] Set release RPO/RTO, retention and key custody from measured drills. Initial proposals are ≤24-hour recovery point and ≤4-hour recovery time; prove or revise before promising them. Disaster restoration must preserve every item at the measured recovery checkpoint and explicitly report the possible newer-data loss window. Local-only entries require device storage or an independent export; they are not covered by a server backup. If zero disaster data loss is required, design and prove a stronger recovery architecture before making that promise.
- [ ] Use [OWASP ASVS](https://owasp.org/projects/asvs) and [MASVS](https://mas.owasp.org/MASVS/) to structure evidence and an independent release security review. Fill operator/legal templates with actual values and qualified review; do not claim certification from adopting a checklist.

**Done when:** an isolated restore succeeds using the exact documented commands, relevant alerts actually arrive, release artifacts reproduce, and CI fails incomplete/incorrect evidence rather than producing a reassuring but inaccurate summary.

## 10. P7 — Establish usefulness and safe scientific claims

- [ ] Separate daily value from statistical inference. Test whether people can record, recover, reflect and understand observations before optimizing engagement.
- [ ] Publish an evaluation protocol for the complete pipeline: user-level false discoveries, repeated overlapping windows, sparse/irregular logging, serial dependence, null/persona cases, effect thresholds, language and annotation disagreement. Add conservative sensitivity analyses and held-out datasets with independent labels.
- [x] Distinguish entries from distinct days in contracts/UI. Association, sentiment and questionnaire scores are not diagnoses or causal conclusions.
- [ ] Define an interpretable effective-observation contract and presentation; current effective sample-size calculations remain internal detector math.
- [ ] Evaluate phrase clustering, questions and crisis/resource presentation on annotated supported-language cases. Involve qualified clinical reviewers and native-language reviewers. Measure missed/incorrect resources and confusing/unsafe wording; do not claim real-time human monitoring that the product does not provide.
- [ ] Review actual STT/translation accuracy, completion, retention, deletion and consent with the configured providers. Fake responses prove protocol behavior only.
- [ ] Conduct an appropriately reviewed prospective feasibility/usefulness study if health-benefit claims are intended. Design stronger outcome studies for stronger claims; restrict launch copy to the evidence actually obtained.
- [ ] Define observation feedback such as useful/inaccurate/irrelevant, and evaluate whether it improves comprehension and presentation without biasing statistical claims.

Effectiveness, privacy and the intended audience are distinct evaluation questions; involve mental-health and engineering expertise rather than treating simulation success as health benefit. [NIMH guidance on mental-health technology](https://www.nimh.nih.gov/health/topics/technology-and-the-future-of-mental-health-treatment).

**Done when:** independent evaluation supports the stated observation/safety/usefulness claims for the supported population/languages. The current Monte Carlo, same-engine replay and synthetic provider reports remain useful diagnostics, not clinical efficacy evidence. External evaluation may change scope or delay a 92+ score; do not alter the rubric to hide that.

## 11. Complete finding-to-work mapping

The main audit uses numbered findings; `AUD-01`–`AUD-12` below are aliases for those numbers. `S-01`–`S-05` and `A-01`–`A-07` alias the numbered service and ancillary findings. Mapping is a work assignment, not a resolution.

| Main audit | Implementation |
|---|---|
| AUD-01 native boot / iOS category | P1, P3, P6 |
| AUD-02 clinician note loss | P2c |
| AUD-03 false saves / newer writing erased | P1, P2a, P3 |
| AUD-04 offline audio loss/races | P1, P2a |
| AUD-05 recovery protocol/revocation | P1, P2b, P4 |
| AUD-06 incomplete v1 rekey | P2b |
| AUD-07 late microphone | P1, P3 |
| AUD-08 unchecked rendered insights | P1, P4 |
| AUD-09 questionnaire / HealthKit | P1, P3 |
| AUD-10 brain empty-group crash | P1, P7 |
| AUD-11 audit-MAC downgrade | P4 |
| AUD-12 unusable v2 restoration tool | P2d |

| Mobile finding | Implementation |
|---|---|
| M01 root registration; M02 iOS category; M03 HealthKit contracts; M04 questionnaire tap; M05 recovery token | P1 |
| M06 audio parent ordering; M07 stale flush/erase; M08 oversized storage | P1, P2a |
| M09 recovery downgrade; M10 omitted rekey stores | P2b |
| M11 biometric API/Face ID; M12 safety-plan schema; M13 edit metadata; M14 late playback; M15 incomplete deletion | P2a, P3 |
| M16 recovery-kit presence/cleanup | P2b, P3 |
| M17 locale reactivity; M18 notification routing; M19 placeholders; M20 capture state | P3, P6 |
| M21 export decryption | P2d |
| M22 edit conflict completion | P2a, P3 |
| M23 reminder scheduling; M24 privacy/resource bundling; M25 insight meaning | P3, P6, P7 |

| Web/portal finding | Implementation |
|---|---|
| WP-01 legacy note UUID; WP-02 identity-derived note loss | P2c |
| WP-03 suppressed storage error | P1, P2a |
| WP-04 late microphone; WP-05 rendered replay; WP-06 newer writing cleared | P1, P2a |
| WP-07 body cancellation; WP-08 raw export 401 | P3 |
| WP-09 fallback mutual exclusion | P2a |
| WP-10 calendar timezone; WP-11 note conflict; WP-12 draft loss; WP-13 safety-plan races | P2a, P3 |
| WP-14 share identity binding; WP-15 UTF16 spans; WP-16 late voice URLs | P3 |
| WP-17 nondefault KDF incompatibility | P2b |
| WP-18 misleading password strength | P3 |
| WP-19 interrupted multi-request credential change | P2c |
| WP-20 unchecked decrypted shapes | P4 |

| Service / ancillary finding | Implementation |
|---|---|
| S-01 unused narrative egress; S-02 insufficient multilingual safety filter; S-03 newest payload omission; S-04 incomplete translation | P4, P7 |
| S-05 steady topic described as rising | P3, P7 |
| A-01 invalid dev YAML; A-02 mutation gate exit logic; A-03 missing voice campaign | P6; quick fixes alongside P1 |
| A-04 backup secret/decrypt documentation; A-05 false mutation-kill attribution; A-06 stale endpoint/coverage claims; A-07 lost NFD vector | P6 |

Additional main-audit risks are explicitly assigned: evidence-unit errors and pre-cap question filtering → P4/P7; voice regrant → P3/P4; body concurrency, guard ownership, revocation hydration, note/audio transaction leads → P4; object deletion/migrations/query plans → P4/P6; streamed duplicate export property → P2d; backup secret precedence → P6; payload casts/monoliths → P4/P5; safe areas/localization/privacy resources → P3; current mobile dependency advisories → P6; inaccessible charts, first-month value and unverified human/scientific outcomes → P3/P7.

## 12. Verification matrix and final release gate

| Journey / failure | Required evidence |
|---|---|
| Save during offline, quota, aborted transaction, reload, navigation or lock | Current text preserved; acknowledged data readable; accurate local/server status |
| Audio parent not yet synced, replacement during flush, queue erase, 401 | Ordered upload; no silent take loss/resurrection; tombstone and correct retry |
| Async response after logout, new account/origin, unmount or body timeout | Old operation cannot mutate new ownership; tracks, URLs and scratch files cleaned |
| Password/recovery/key changes with legacy/v2/mixed data | Every registered store and note revision readable after fresh login |
| Security change interrupted before/after each commit, lost response, concurrent edit | Idempotent/resumable recovery; no stale overwrite or stranded credential/wrap |
| Export with legacy/v2/mixed entries plus audio | Strict JSON; independently decryptable content/IDs/metadata/audio; wrong proof rejected |
| Revocation restart, stripped MAC, recovery revoke race, guard loss | Tested fail-closed behavior for the stated threat and deployment models |
| Upgrade old DB, object-store outage during deletion, backup restore | Preserved upgrade/checkpoint records; deletion reconciles; restore reports loss window and meets measured RPO/RTO |
| Device permissions, biometric cancellation, HealthKit denial, notification tap, capture | Actual Android/iOS behavior and privacy-resource evidence |
| Long histories, cheap devices, slow clients, simultaneous recompute/save/export | Recorded latency/memory/query plans meeting frozen budgets |
| Screen reader, keyboard, zoom/large fonts, Spanish, timezone/Unicode | Manual critical-task evidence plus automated regression coverage |
| Observations, uncertainty, crisis resources and translations | Independent supported-language/clinical review and correctly scoped evaluation |

Record each package's change, baseline reproduction, regression result, real integration/device evidence, limitations and reviewer decision in a new remediation evidence directory. Keep build SHA, environment and exact commands with results; never overwrite the original audit to imply it described fixed code.

### Final acceptance checklist

- [ ] Every finding has an evidence-backed resolution or justified disposition; all release blockers are closed.
- [ ] Required format, types, unit/integration, native build, browser, migration, crypto, red-team and release checks pass. Skips are explained; unavailable required checks are not counted as passes.
- [ ] Supported password/recovery/rotation/export flows preserve every acknowledged item and revision in the failure matrix.
- [ ] Manual usability, accessibility, supported-language, device and safety validation is complete for the intended release scope.
- [ ] Backups restore; monitoring alerts arrive; deployment/rollback or forward-repair procedures are rehearsed.
- [ ] An independent reassessment publishes evidence and deductions for all ten areas; **each earns at least 92/100**.
- [ ] Any area below 92 generates the next concrete remediation package and keeps this objective open.

This plan translates the ambition for an exceptional application into dependable data custody, effortless daily use, accessible care workflows, honest observations and demonstrated operations. Continue measuring those qualities after release and use the results to choose the next improvements.
