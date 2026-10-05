# Fathom — independent audit across 24 tracks

**Date:** October 4, 2026 (America/Phoenix). **Source:** `ad5c2d42f1ce11278302f5154be81237cc7003b8`.

The review covered all 24 requested tracks and identified **22 finding groups: 1 High, 15 Medium and 6 Low**. These include application defects, inaccurate documentation, defective verification gates and one study-design gap. OPS-03 groups four individually described test defects. Severity describes the consequence in the stated scenario, not an observed production incident: High denotes substantial account/data-boundary impact; Medium denotes bounded integrity, privacy, workflow or assurance failures; Low denotes narrower documentation or gate defects. No Critical issue was established.

**The highest-priority finding is CL-01:** patient-web work begun under account A can finish after switching to account B and use B's session. Controlled tests reproduced wrong-account dispatch of encrypted writing, raw voice audio and a processing key. The writing path also deletes A's recoverable draft. The test does not show B decrypting A's writing or an external provider accepting the request.

The project has substantial security and regression coverage, and the fresh database upgrade and authenticated backup/restore checks passed. However, passing aggregate tests missed the new defects. The audited revision also has independently reproduced failures in its regression, mutation applicability, secret-scan and red-team policy gates. This audit is **not an all-clear or release certification**.

All findings, reproductions, source locations, impact boundaries and remediation directions are included below in this single file. This publication copy preserves the original audit results; subsequent fixes and validation are recorded in [REMEDIATION.md](REMEDIATION.md). No application source or existing tests were changed during the audit phase to make checks pass.

The original report, component reports and raw logs remain local under the ignored `reports/independent-audit-2026-10-04/` directory; they are not included in this publication. Literal artifact paths below identify that retained local provenance, not downloadable repository files. Historical `evidence/` references and commands are relative to the original report directory. Source line references describe the audited commit and can move after remediation. No production deployment or real patient data was used.

## Scope and independence

The inventory contains **1,271 tracked files**: backend 219, web 151, portal 58, mobile 313, deployment 29, documentation 51, red-team tooling 33, shared fixtures 8, backup 3, general tools 6, GUI test infrastructure 5, GitHub workflows/configuration 9, root files 11 and historical reports 375. The source inventory (`reports/independent-audit-2026-10-04/evidence/source-inventory.json`) records paths and SHA-256 hashes.

Current implementation and configuration were examined by separate backend, client, mobile and analysis/operations review passes. Fresh tests and purpose-written probes were used to challenge their behavior. Historical audit claims and coverage percentages were not accepted as proof. This is an independent technical review within this workspace, not an external accredited security, accessibility, regulatory or clinical certification. File inventory is comprehensive; manual source review was risk-based and does not mean every historical report, dependency source or application line was examined equally.

Execution used synthetic accounts and content, disposable local SQLite/PostgreSQL databases and an Android emulator. The review did not access a production deployment, real patient records or third-party transcription accounts. Existing unit-test adapter boundaries, real cryptography/API paths and actual native execution are identified separately in each finding. A probe that passes by asserting a defect means **the defect was reproduced**, not that the control passed.

## Findings register

| ID | Severity | Issue | Evidence level |
|---|---|---|---|
| [CL-01](#cl-01) | High | Retired web operations dispatch under a replacement account and can remove the original draft | Controlled current modules, real cryptography/request construction |
| [CL-02](#cl-02) | Medium | A late voice transcript overwrites newer typed writing | Rendered current component, delayed response |
| [CL-03](#cl-03) | Medium | Stale policy consent passes microphone preflight | Current component; backend still rejects transcription |
| [CL-04](#cl-04) | Medium | Failed clinician revision lookup is presented/printed as no history | Real encrypted note and rendered output |
| [CL-05](#cl-05) | Medium | Web export's 100 MiB limit is below the permitted account size | Real bounded reader and configuration comparison |
| [BE-01](#be-01) | Medium | Recovered savepoint failure suppresses external audit-journal evidence after commit | Real SQLite and PostgreSQL fault injection, negative control |
| [BE-02](#be-02) | Medium | Backend recompute accepts a legacy ciphertext downgrade after a modern edit | Real API/crypto/engine on SQLite and PostgreSQL |
| [BE-03](#be-03) | Low | Stale metadata assertion keeps the backend test gate red | Full suite and isolated rerun |
| [MOB-01](#mob-01) | Medium | Active/finishing recordings survive screen cleanup as plaintext cache files | Real hook, controlled native adapters; SDK source inspected |
| [MOB-02](#mob-02) | Medium | Late native scheduling recreates a reminder after account retirement/cancellation | Real ownership primitives, controlled native scheduler |
| [MOB-03](#mob-03) | Low | Claimed full-engine mobile parity gate does not consume full-engine cases | Current test/fixture/plan comparison |
| [ANL-01](#anl-01) | Medium | Unsupported-language text enters clinician-facing average mood readings | Real engine; display path inspected |
| [ANL-02](#anl-02) | Medium | Non-Latin text is omitted from the language-classification denominator | Real engine, synthetic mixed-script corpus |
| [ANL-03](#anl-03) | Medium | Raw p-values are labeled as corrected values | Production selection path and cross-client labels |
| [OPS-01](#ops-01) | Medium | Release changelog gate accepts an unrelated version | Exact workflow AWK on macOS and Linux |
| [OPS-02](#ops-02) | Medium | 53 of 220 behavioral mutants cannot apply to current source | Actual harness pre-write failure paths |
| [OPS-03](#ops-03) | Medium | Four red-team checks use obsolete fixtures/oracles | Fresh complete campaign and source comparison |
| [OPS-04](#ops-04) | Low | History secret scan blocks on a public test digest | Pinned Gitleaks, 96-commit history |
| [DOC-01](#doc-01) | Low | Retention schedule omits durable encrypted mobile drafts | Storage implementation/document comparison |
| [DOC-02](#doc-02) | Medium | Four-week study cannot evaluate a new account's unlocked analysis | Study design versus 30-active-day threshold; validation-plan gap |
| [DOC-03](#doc-03) | Low | Study materials make an unqualified zero-knowledge claim | Processing implementation/document comparison |
| [DOC-04](#doc-04) | Low | Compose restoration example skips backup authentication | Documentation/helper comparison; actual correct restore passed |

## Coverage of all 24 tracks

“Reviewed” below means the stated work occurred; it is not a blanket pass. Open assurance work is recorded separately from confirmed defects.

| # | Track | Independent work and outcome | Remaining boundary |
|---|---|---|---|
| 1 | Architecture and threat model | Mapped client encryption, server processing keys, clinician custody, provider calls, deployment locks and durable state. BE-02, CL-01 and DOC-03 expose boundary/claim mismatches. | No hardware enclave; operator and recipient trust limits remain. |
| 2 | Code quality and maintainability | Backend lint/format/types and all client type/build checks; examined state ownership and large modules; inventoried mutation applicability. OPS-02. | Module size and test counts do not prove maintainability; fresh full mutation campaign pending. |
| 3 | Functional correctness and API contracts | Backend/client suites, live local API drills and independent race/export/revision/analysis probes. CL-01–05, BE-02, ANL-01. | Complete GUI and every device/network workflow not exercised. |
| 4 | Authentication and authorization | Token/role/MFA/step-up/recovery/revocation paths, existing adversarial cases and owner-switch probes. CL-01 is a client ownership failure. | No new backend login bypass established; timing observation is inconclusive. |
| 5 | Cryptography and key lifecycle | Shared vectors, AAD and envelope/recovery/rekey paths; real legacy-replay and modern-mismatch controls. BE-02. | No formal cryptographic proof, hardware custody certification or guaranteed string zeroization. |
| 6 | Sharing and consent | Grant/revoke/rewrap, MFA, scope and policy checks reviewed/tested. CL-03; OPS-03c reveals an unexercised voice-grant check. | Previously decrypted recipient data cannot be recalled; human identity comparison still matters. |
| 7 | Privacy and data lifecycle | Storage inventory, erasure/purge/outbox/retention/export review and interruption probes. CL-01, CL-05, MOB-01/02, DOC-01/03. | Provider-side deletion and full production retention evidence unverified. |
| 8 | Offline, concurrency and crash recovery | Queue/draft/revision/rotation logic and live two-web-client drills; delayed operations and recovered-savepoint probes. CL-01/02, BE-01, MOB-01/02. | Two-web-client drill is not actual web/mobile interoperability; OS eviction/storage-exhaustion matrix pending. |
| 9 | Database integrity and migrations | SQLite/PostgreSQL regression profiles; real prior-head PostgreSQL upgrade and exact ciphertext/schema restore comparison. BE-01/02. | Small synthetic same-major dataset; every historical migration and production-size lock behavior not established. |
| 10 | Browser security and compatibility | Web/portal session, crypto, rendering, origin and request code reviewed; fresh builds/tests plus independent rendered-component probes. CL-01. | No fresh Chromium/Firefox/Safari GUI matrix, live reverse-proxy headers or browser-extension threat assessment. |
| 11 | Native mobile | Full unit/vector/configuration/backport checks; real Android debug build and emulator smoke; native lifecycle probes. MOB-01–03. | No iOS compilation/signing or physical-device custody certification; detailed device limits below. |
| 12 | Usability | Traced error, draft, voice, export and clinician evidence flows; rendered adverse outcomes. CL-02–05, ANL-03, DOC-02. | No representative patient/clinician usability study or distressed-user evaluation. |
| 13 | Accessibility | Inspected shared controls, labels, crisis access and test coverage; native UI hierarchy observed. | Full keyboard, screen-reader, zoom, contrast, motion and device-size evaluation unperformed; no conformance claim. |
| 14 | Localization and fairness | Locale/vector review and new unsupported/mixed-script engine probes. ANL-01/02. | Native-language comprehension, transcription quality and representative subgroup fairness unverified. |
| 15 | Analysis and statistics | Traced eligibility, selection, p-values and summaries; production-path p-value proof; 4,000 synthetic longitudinal users and 30,423 recomputes. ANL-01–03. | Four declared null-generator cells do not establish universal calibration or clinical validity. |
| 16 | Mental-health safety and clinical evidence | Reviewed crisis/suppression/measures/claims and study protocol; existing safety regressions; offline crisis emulator check. ANL-01–03, DOC-02/03. | No clinical trial, validated sensitivity/specificity, jurisdictional resource certification or specialist sign-off. |
| 17 | Voice and external providers | Consent, recording, upload/translation/lifecycle paths and controlled races. CL-01–03, MOB-01, OPS-03c. | No real provider processing, retention audit or multilingual audio-quality study. |
| 18 | Performance and capacity | Inspected quotas/bounds, one-owner deployment and capacity tests; actual export-bound failure and synthetic engine run. CL-05. | No production load/soak, p95/p99 targets, low-end-device battery/memory profiling or capacity certification. |
| 19 | Dependencies and supply chain | Fresh pip/npm advisory checks, exact mobile patch gate, hash/action pin review, image drift and full-history secret scan. OPS-04. | Mobile registry still reports patched advisory graph; Chainguard check unavailable; full license/SBOM closure not independently completed. |
| 20 | Deployment and release | Compose/workflow/startup gates reviewed; exact release extractor reproduced; Android build, native preflight, monitoring, secret and mutation checks. OPS-01–04, BE-03. | No signed store release, production rollout/rollback or remote endpoint verification. |
| 21 | Backup and disaster recovery | Real current-helper encrypted pg_dump/authenticated restore into a separate database; all tables/digests/constraints/indexes matched. DOC-04 and OPS-03a. | Full-host/object-store/audit-volume/secrets/offsite recovery and RPO/RTO measurement pending. |
| 22 | Monitoring, incidents and audit logs | Commit/journal/chain inspection and real retry reproduction; monitoring structure, pinned promtool and shell checks. BE-01. | Real alert delivery, staffed response and incident rehearsal not demonstrated. |
| 23 | Test effectiveness | Fresh suites and independently written defect probes, stale-oracle/applicability audit and evidence triage. BE-03, MOB-03, OPS-02–04. | Coverage is not adequacy; fresh full mutation and complete native/browser end-to-end campaigns remain open. |
| 24 | Documentation, claims and evidence | Compared architecture, retention, study, backup, parity and evidence labels with current behavior; docs checker also passed. DOC-01–04, ANL-03, MOB-03, OPS-01. | Legal/regulatory/privacy representations require appropriate specialist and operator review. |

## Fresh execution summary

- **Backend:** lint, format and type checks passed; independent integrity probes reproduced BE-01/02 on both SQLite and PostgreSQL. After isolated reruns, unique SQLite outcomes are 2,098 passed / 6 skipped / 1 failed and PostgreSQL outcomes are 2,102 passed / 2 skipped / 1 failed. The remaining failure is BE-03. These are reconciled outcomes, not two single green runs; initial shared-lock interference and all original counts are preserved below.
- **Patient web:** 824 passed, 5 skipped; typecheck/build/advisory scan passed. **Portal:** 523 passed; typecheck/build/advisory scan passed.
- **Mobile:** 2,314 passed, 1 skipped; red-team configuration reran these plus 8 cases (2,322 passed), so these totals must not be added as unique tests. Typecheck, vectors, 25 native preflight checks and reviewed dependency backports passed. Android debug compilation, synthetic registration, online journal save, cold-start lock and password re-unlock succeeded. An unresolved debug-emulator navigation observation prevented verification of history/offline replay; it is described below without assigning a confirmed application-defect severity.
- **Independent client/mobile probes:** seven client probes and three mobile probes reproduced the reported defects. Backend, statistical and operational probe details are preserved below.
- **Database/backup:** prior-head migration and real authenticated restore passed, with all 21 tables, 41 constraints, 56 indexes and ciphertext digests matching.
- **General tooling:** 24 tooling tests, documentation check (46 docs/53 API error codes), pinned promtool rule scenarios and shellcheck on nine scripts passed.
- **Red-team campaign:** 108 complete verdicts, zero harness errors: 84 BLOCKED, 9 FINDING, 13 INFO, 2 PARTIAL. The runner's exit 0 means completeness. The separate CI policy would fail on six findings outside its three documented residuals; stale oracles, a mitigated dependency graph and inconclusive timing are distinguished in the report.
- **Release/mutation/secrets:** exact changelog extraction failed its version contract; 53 registered mutations cannot apply; pinned history secret scan exits 1 for a public digest. These are gate-quality findings, not proof of every vulnerability suggested by their tool labels.
- **Statistics:** the held-out synthetic run observed at least one statistical card in 9.1–11.8% of users across the four 90-day cells. This is a longitudinal synthetic event rate, not the single-recompute FDR, a clinical harm rate or a universal calibration result.

The evidence manifest (`reports/independent-audit-2026-10-04/evidence-manifest.json`) provides hashes for retained artifacts. Raw logs preserve setup errors and environment failures as well as successful reruns. Detailed reports explain their interpretation; no failed run was silently turned into a green result. The audit-owned API, synthetic runtime directory, PostgreSQL container, emulator and Metro processes were cleaned up; cleanup logs are retained. The audit phase left tracked application source unchanged.

## Work still needed for assurance

These are explicit audit limitations and follow-up scopes, **not additional confirmed vulnerabilities**:

| ID | Open validation | Evidence needed to close it |
|---|---|---|
| GAP-01 | iOS, signed release and physical-device behavior | iOS archive/install, production Android artifact, actual biometric/key invalidation, reinstallation, voice interruptions, notifications and data erasure on supported devices. |
| GAP-02 | Browser compatibility and accessibility | Real supported-browser journeys plus keyboard, screen-reader, zoom/large-text, contrast and motion assessment, including patient and clinician tasks. |
| GAP-03 | Clinical safety and usability | Qualified review and appropriately designed participant evaluation of crisis handling, non-diagnostic wording, evidence comprehension and post-threshold personal observations. |
| GAP-04 | Statistical and language calibration | Predeclared longitudinal endpoints, broader null/effect/missingness cells, mixed-language corpora and representative subgroup evaluation with uncertainty. |
| GAP-05 | External voice/translation providers | Real consent-to-processing/deletion journeys, provider configuration/retention evidence and representative language/audio-quality measurements. |
| GAP-06 | Capacity and resilience | Production-like load/soak, latency/resource objectives, large exports/histories, offline backlog, disk pressure, OS eviction and low-end hardware profiling. |
| GAP-07 | Production release and incident operation | Actual TLS/origin/header/config checks, a verified release/rollback exercise, routed alert delivery and a staffed incident rehearsal. |
| GAP-08 | Complete disaster recovery | Coordinated recovery of DB, object storage, external audit journal and required keys from offsite media, with measured RPO/RTO and deletion-retention consistency. |
| GAP-09 | Privacy, retention and participant representations | Reconciled inventories and reviewed participant/provider/operator documents; appropriate legal/privacy review where applicable. This report makes no legal compliance determination. |
| GAP-10 | Current behavioral test assurance | Repair stale tests/mutations, run fresh full campaigns in isolated checkouts, retain negative controls, and execute the currently bypassed voice-grant/export-recovery scenarios. |
| GAP-11 | Supply-chain completeness | Verify registry/image access, maintain reviewed source-backport evidence, and complete release artifact/SBOM/license provenance review. |

## Intentional residuals kept separate from new findings

The repository documents password-equivalent authentication verifier replay until credential rotation, offline password guessing against captured envelopes/ciphertext, and visible metadata such as dates/sizes. This audit's campaign reproduced those architectural residuals. A tool's metadata-inference narrative is illustrative; it does not prove an actual person's diagnosis, beliefs or behavior.

Requested server analysis receives a data key and plaintext in process; it is not a hardware enclave. Immutable runtime strings cannot be guaranteed erased. Sharing revocation cannot retract keys or content already retained by a recipient. One active serving process/host per database is the supported deployment boundary. Mobile has an intentional scoped RAM draft fallback; full native account export and the complete on-device analysis port are unfinished capabilities. These facts must stay explicit in product and study claims, but are not counted again as newly discovered defects.

## Recommended repair order

1. **Restore account ownership invariants:** CL-01 first, then late-write/cleanup races CL-02 and MOB-01/02. Keep original drafts recoverable when work retires.
2. **Restore evidence integrity:** BE-01/02, CL-04 and ANL-01–03. Correct the evidence labels and unsupported-language summaries alongside their regression probes.
3. **Repair user-facing contracts:** CL-03/05, then reconcile the study, retention, parity and restore documentation (DOC-01–04, MOB-03).
4. **Make verification trustworthy:** BE-03 and OPS-01–04. Repair intended behavioral oracles; do not obtain green checks by broad exemptions or counting setup errors as successes.
5. **Close the relevant release gates:** execute the device/browser, clinical, production and recovery validations above before making the corresponding assurance claims.

This audit records issues and directions; it does not implement or validate fixes. The following sections preserve the full component findings and execution evidence.


---

## Independent client audit — patient web and therapist portal

Date: 2026-10-04 (America/Phoenix). Audited source: `ad5c2d42f1ce11278302f5154be81237cc7003b8`.

This review independently examined current source and ran fresh checks. Earlier audit reports were not used as evidence of correctness. Application source, committed tests, and configuration were not changed. Independent probes and logs are retained locally in `reports/independent-audit-2026-10-04/evidence/`; ordinary test/build commands also regenerate their ignored output directories.

### Result

**Five confirmed client findings: one high and four medium.** Seven independent probes reproduce the defective behavior. These probes deliberately assert the observed defect, so their passing status means reproduction succeeded, not that the application is correct.

| ID | Severity | Confirmed finding |
| --- | --- | --- |
| CL-01 | High | Retired patient operations use a replacement account's bearer, including entry ciphertext, raw voice audio, and a processing data key; the entry path also clears the original account's recoverable draft. |
| CL-02 | Medium | A late transcription silently overwrites journal text typed while transcription is pending. |
| CL-03 | Medium | The microphone preflight accepts voice consent that the server explicitly reports as stale for the current policy. |
| CL-04 | Medium | A failed clinician-note history request is presented and printed as “no earlier text recorded.” |
| CL-05 | Medium | Web account export rejects responses over 100 MiB although the backend permits 256 MiB of account ciphertext by default. |

### Fresh validation

| Check | Result | Evidence |
| --- | --- | --- |
| Patient web, `npm test -- --maxWorkers=2` | Exit 0; 57 test files passed, 3 skipped; 824 tests passed, 5 skipped | `reports/independent-audit-2026-10-04/evidence/web-tests.log` |
| Portal, `npm test -- --maxWorkers=2` | Exit 0; 26 files, 523 tests passed | `reports/independent-audit-2026-10-04/evidence/portal-tests.log` |
| Web and portal `npm run typecheck` | Both exit 0 | `reports/independent-audit-2026-10-04/evidence/web-typecheck.log`, `reports/independent-audit-2026-10-04/evidence/portal-typecheck.log` |
| Web and portal `npm run build` | Both exit 0 | `reports/independent-audit-2026-10-04/evidence/web-build.log`, `reports/independent-audit-2026-10-04/evidence/portal-build.log` |
| Web and portal `npm audit --json` | Both exit 0; zero reported advisories | `reports/independent-audit-2026-10-04/evidence/web-npm-audit.log`, `reports/independent-audit-2026-10-04/evidence/portal-npm-audit.log` |
| Existing web live drill and two-client live drill against disposable local API | Exit 0; 3 tests passed, 1 separately gated seeded-demo test skipped | `reports/independent-audit-2026-10-04/evidence/web-live-drills.log`, `reports/independent-audit-2026-10-04/evidence/web-live-command.json` |
| Independent web probes | Exit 0; 6 defect reproductions passed | `reports/independent-audit-2026-10-04/evidence/web-independent-probes.log`, probe source (`reports/independent-audit-2026-10-04/evidence/web-independent.test.tsx`), voice probe source (`reports/independent-audit-2026-10-04/evidence/web-voice-independent.test.tsx`) |
| Independent portal probe | Exit 0; 1 defect reproduction passed | `reports/independent-audit-2026-10-04/evidence/portal-independent-probes.log`, probe source (`reports/independent-audit-2026-10-04/evidence/portal-independent.test.tsx`) |

Command arrays, working directories, UTC execution timestamps, and exit codes are recorded in `reports/independent-audit-2026-10-04/evidence/web-commands.json`, `reports/independent-audit-2026-10-04/evidence/portal-commands.json`, and the independent/live `*-command.json` files. The live API was a fresh local development database containing synthetic accounts, not a production system.

Coverage on this run: web 87.23% statements / 81.67% branches / 86.38% functions / 91.54% lines; portal 92.00% / 85.25% / 90.46% / 95.46%. Aggregate coverage passing did not detect the independent findings below. Dependency audit results are registry advisory results for the installed dependency trees, not a proof that dependencies contain no vulnerabilities.

<a id="cl-01"></a>

### CL-01 — Retired asynchronous operations dispatch through a replacement account

**Severity: High. Status: confirmed by controlled current-module execution with real cryptography and the real API request-building code.** The network boundary is stubbed in these defect probes; a naturally occurring browser race and production exploit were not claimed.

Source:

- `web/src/views/Entry.tsx:354` captures the original owner; `:400–403` copies its key and captures a write permit. After asynchronous encryption, `:447` checks only that some vault is unlocked. `:459` dispatches using the API's current session, and `:502–503` clears the original draft and reports success.
- `web/src/views/Entry.tsx:242–247` reads a recorded Blob asynchronously and then transcribes it without checking that the originating view/account/session still exists. `:233–281` has no effect cleanup invalidating this operation on unmount.
- `web/src/views/Question.tsx:98–106` copies the data key, awaits storage, then opens a processing session without validating the original account/session.
- `web/src/api/client.ts:525–549` correctly captures a session at request dispatch, but that is already too late when a caller started work under a previous session.
- `backend/app/api/entries.py:355–360` assigns incoming opaque entry ciphertext to the authenticated user; it cannot infer the client-side encryption owner from an opaque blob.

Reproduction A — journal save and loss of draft:

1. Unlock account A and enter a synthetic journal entry.
2. Start save and suspend completion of the real entry encryption at its asynchronous boundary.
3. Run the lock sequence: preserve A's encrypted draft, clear the session, lock the vault, unmount A's editor. Confirm the draft remains readable with A's key.
4. Sign in as account B, then release A's outstanding encryption.
5. Observe a `POST /entries` with B's bearer and ciphertext authenticated only for A/key A. The callback reports `sent`; A's encrypted draft is removed. Decrypting the posted blob for B/key B fails.

Reproduction B — raw voice audio: hold the recording Blob's `arrayBuffer()` promise, retire A's view/session, install B, then resolve the Blob. The request to `/audio/transcriptions` carries A's exact synthetic audio bytes under B's bearer.

Reproduction C — processing key: suspend `captureWritePermit()` during A's “Refresh patterns,” unmount/retire A, install B, then resume. The processing-session request carries A's actual data key under B's bearer.

Impact: account isolation is lost across these asynchronous boundaries. The entry path can make A's writing disappear from A's recoverable draft while creating ciphertext B cannot read; voice and processing operations can be attributed to the wrong account. The ciphertext test does **not** show B decrypting A's journal. The audio/key tests prove wrong-account dispatch, not that an external provider accepted the request or that B obtained A's key from the server.

Remediation: capture an immutable operation owner, key identity, and session cancellation/generation token at entry; reject the operation after every relevant await and immediately before network dispatch or durable cleanup if any changes. Add unmount cleanup for voice work. Prefer an API facility that accepts an expected session/owner so future callers cannot accidentally send old-account data through a new bearer. Preserve the original draft when a save retires before a valid owner-bound acknowledgement. Apply the same review to `History.tsx:414–431`, which statically has the analogous unfenced edit dispatch; that additional path was not independently reproduced here.

Evidence: the first two tests in `reports/independent-audit-2026-10-04/evidence/web-independent.test.tsx` and the first test in `reports/independent-audit-2026-10-04/evidence/web-voice-independent.test.tsx`; verbose results (`reports/independent-audit-2026-10-04/evidence/web-independent-probes.log`).

<a id="cl-02"></a>

### CL-02 — Late transcription replaces newer typed journal text

**Severity: Medium. Status: confirmed by current EntryView rendering with a delayed API response.**

Source: `web/src/views/Entry.tsx:263` unconditionally calls `setText(result.original_text)`. The text area at `:601–606` is disabled only while draft hydration is incomplete; it remains editable during transcription. The response token at `:237–248` distinguishes transcription operations but does not track the editor's revision.

Reproduction:

1. Open the journal with an existing typed draft and complete a recording.
2. Keep the transcription request pending.
3. Type a different, meaningful sentence into the still-enabled text field.
4. Return a successful transcription. The field now contains only the recorded words; the newer typed sentence disappears without confirmation or a merge option.

Impact: unsaved patient writing is silently lost during an ordinary supported interaction. The automatic encrypted-draft write can subsequently persist the overwritten value as well.

Remediation: capture the editor revision at transcription start, and only replace it if it is unchanged. Otherwise offer to insert/append or replace the transcript while preserving the user's current draft. Cover both pre-existing text and edits made after the request began.

Evidence: second test in `reports/independent-audit-2026-10-04/evidence/web-voice-independent.test.tsx`, verbose results (`reports/independent-audit-2026-10-04/evidence/web-independent-probes.log`).

<a id="cl-03"></a>

### CL-03 — Stale voice-policy consent passes microphone preflight

**Severity: Medium. Status: confirmed control-flow defect; backend enforcement remains present.**

Source:

- `web/src/views/Entry.tsx:128–137` checks only `consent.enabled` before starting the recorder.
- `backend/app/api/account.py:2282–2290` separately reports `enabled` and `active_for_current_policy`, explicitly permitting an old yes to be reported as not current.
- `backend/app/api/audio.py:79–84` rejects transcription when policy consent is not current.
- `web/src/views/Settings.tsx:201–202` already makes the correct distinction when displaying the setting.

Reproduction: supply a normal preflight response `{ enabled: true, active_for_current_policy: false }` with audio availability enabled; press “Record instead.” The recorder's `start()` is called.

Impact: a known-stale consent state lets the user record a take that the backend will refuse to transcribe. This can waste a sensitive recording and present a policy-consent error only after capture, although the server had already supplied enough information to prevent it. This probe does **not** establish transcription by an unauthorized external provider; server-side policy checks block that path.

Remediation: require `enabled === true && active_for_current_policy === true` before microphone acquisition, with a clear route to renewed consent. Update test fixtures to carry the complete current consent contract and test stale/unknown values.

Evidence: third test in `reports/independent-audit-2026-10-04/evidence/web-voice-independent.test.tsx`, verbose results (`reports/independent-audit-2026-10-04/evidence/web-independent-probes.log`).

<a id="cl-04"></a>

### CL-04 — Note-history transport failure becomes a false absence claim

**Severity: Medium. Status: confirmed with a real encrypted clinical note and rendered screen/print output.**

Source: `portal/src/views/PatientView.tsx:947–950` catches a failed revisions fetch and stores an empty history array without marking failure. `:1643–1646` renders an empty array as “no earlier text recorded”; `:1812–1816` prints the same claim. The separate decrypt-failure path at `:934–943` already handles its analogous error honestly.

Reproduction:

1. Load a valid note whose authoritative version is 2, so “View history” is available.
2. Make the revisions request fail with a network error.
3. Press “View history.” Both the interactive history and printable session summary say “no earlier text recorded.” Neither reports the request failure.

Impact: an unavailable clinical history is misrepresented as an absent history and can be copied into the printed clinical summary. The current note remains intact; this is a misleading-record defect, not deletion of server-side revisions.

Remediation: retain separate loading/loaded-empty/failed states, render “history could not be loaded” on transport failure, offer retry, and propagate that state to print. A successfully fetched empty collection is the only case eligible for an absence claim.

Evidence: `reports/independent-audit-2026-10-04/evidence/portal-independent.test.tsx`, verbose results (`reports/independent-audit-2026-10-04/evidence/portal-independent-probes.log`).

<a id="cl-05"></a>

### CL-05 — Supported account size exceeds the web export ceiling

**Severity: Medium. Status: confirmed byte-limit behavior plus source-confirmed contract mismatch.**

Source: `web/src/api/client.ts:419–421` sets the export reader ceiling to `100 * 1024 * 1024` bytes. `web/src/views/Settings.tsx:295–298` consumes the full response before offering the download. `backend/app/config.py:458` allows 256 MiB of account ciphertext by default; `backend/app/api/account.py:1187` streams the account bundle. The export also contains serialization and metadata overhead.

Reproduction: feed `api.exportAccountRaw()` a streamed 101 MiB response and consume its actual guarded reader. Exactly 100 MiB are delivered; the next chunk produces the client's safe-size-limit error. The probe reuses a 1 MiB chunk to avoid generating a large account or allocating a large response body. It establishes the enforced transport ceiling, not a full large-account database benchmark.

Impact: valid accounts can grow beyond the size the advertised web export can download. The backend accepts the data, but the web client cannot complete the full-account export. Mobile currently directs users to web for full-account export rather than offering another full export path.

Remediation: support a bounded streaming-to-file or resumable/paged export, or make the supported account/export contract consistent and visible before users reach the limit. Simply lifting a cap without controlling browser memory use is not a sufficient large-account solution.

Evidence: third test in `reports/independent-audit-2026-10-04/evidence/web-independent.test.tsx`, verbose results (`reports/independent-audit-2026-10-04/evidence/web-independent-probes.log`). Mobile behavior was cross-checked by the mobile audit owner at `mobile/src/screens/SettingsScreen.tsx:385`; no mobile body-cap defect is asserted.

### Reviewed controls and scope limits

The review covered route/component inventories and selected code paths for registration, session locking, same-origin transport, draft ownership, offline queues, account rotation/deletion, sharing and voice consent, crypto envelopes, journal/measure/clinician-note flows, localization, accessible UI primitives, production security headers, build integrity, and test architecture. Deep independent reproduction focused on owner lifecycle, voice, export, and clinical record presentation. This is not a line-by-line certification of every client source line.

Controls observed in current source include same-origin credential destinations and redirect refusal (`web/src/api/client.ts`, `portal/src/api.ts`), owner/generation-fenced durable storage (`web/src/kvstore.ts`), resumable local rotation/erasure, action-specific step-up and fingerprint checks (`web/src/views/Share.tsx:126–172`), real crypto-vector/interop tests, encrypted clinician drafts, and explicit keyboard focus handling in patient dialogs. Their presence and passing test coverage are useful evidence, but do not override the reproduced findings.

Additional static observations / coverage gaps, not counted as confirmed defects:

- **Fresh-browser legacy AAD boundary:** web stores encrypted v2-bound IDs separately from numeric version high-water marks (`web/src/entryVersions.ts:36–82`), and History uses that memory to disable legacy fallback. Portal keeps a session/module-memory v2-bound set (`portal/src/crypto.ts:510–512`, `:584–609`). A fresh observer that has never authenticated the v2 binding still permits legacy fallback; backend audit findings own any resulting end-to-end replay claim. This report does not duplicate it as an independently established client exploit.
- **Analysis display provenance:** the portal formats any numerical `stats.avg_sentiment` as “average reading” at `PatientView.tsx:1358–1364` and `:1734–1738`, without language-coverage metadata or a language disclaimer alongside it. The separate analysis audit owns the reproduced unsupported-language aggregation finding.
- **Browser/device accessibility:** existing jest-axe suites ran, but there was no fresh full Safari/Firefox/Chromium GUI walkthrough, keyboard/screen-reader session, zoom/contrast review, or real microphone hardware test in this client workstream. jsdom/renderer results do not establish those properties. Web's axe assertion filters only critical/serious violations (`web/tests/a11y.test.tsx:20–23`).
- **Actual client mix:** the passing live dual-client drill explicitly drives two web sessions; it does not drive a web browser and a native mobile client concurrently (`web/tests/live/dualClient.test.ts:13–18`). Mobile native/runtime testing is covered by its separate workstream.
- **Manual GUI tooling:** `e2e_gui/README.md:19–23` describes synthetic seed scripts and manual browser scenarios, not an automated browser regression suite.
- **Mutation/performance:** no full Stryker campaign, browser heap-retention experiment, large-caseload load benchmark, or large-account end-to-end export benchmark was executed here. Existing mutation configurations were inspected only.
- **Deployment/external dependencies:** production HTTP headers, actual provider retention policy, production origin behavior, and organizational clinical operating procedures cannot be certified from these local client tests. Deployment and provider configuration have separate audit owners.

Accepted/documented design boundaries, not newly reported defects: patient clients offer English/Spanish while this portal release is deliberately English-only; already disclosed/decrypted clinician data cannot be cryptographically recalled merely by revoking future access; browser byte-array zeroization is best effort; per-tab clinician visit anchors can differ between tabs. These should remain accurate in product disclosure and operator documentation.

### Re-run the independent probes

From the repository root, run each command from the indicated client directory:

```sh
## Working directory: web
node_modules/.bin/vitest run --config ../reports/independent-audit-2026-10-04/evidence/web-independent.config.mjs --reporter=verbose

## Working directory: portal
node_modules/.bin/vitest run --config ../reports/independent-audit-2026-10-04/evidence/portal-independent.config.mjs --reporter=verbose
```

The tests use synthetic owners, keys, mock bearer strings, and audio bytes. They do not require or record real credentials. Because they assert current defective behavior, a correct remediation should require changing these assertions into regression expectations for rejected stale dispatch, preserved text, current consent, honest history failure, and a consistent export contract.


---

## Independent backend audit — October 4, 2026

Audited commit: `ad5c2d42f1ce11278302f5154be81237cc7003b8`. Application code was not modified. This report records source inspection, fresh execution of existing checks, and newly written behavioral probes. Historical audit conclusions were not treated as proof.

### Confirmed findings

<a id="be-01"></a>

#### BE-01 — Medium: a recovered audit savepoint failure silently prevents committed journal evidence from being written

**Status: reproduced on fresh file-backed SQLite and disposable PostgreSQL 16.** This is a controlled fault-injection reproduction of the application's explicit retry path, not a claim that an unprivileged attacker can force the exact constraint race on demand.

**Locations:** `backend/app/deps.py:91–96`, `backend/app/deps.py:116–128`, `backend/app/api/_audit.py:1080–1134`.

`get_session` records every SQLAlchemy `after_rollback` event in a lifetime `rolled_back` boolean. The callback does not distinguish a nested savepoint rollback from rollback of the outer request transaction, and a later successful commit does not reset that flag. Meanwhile, `append_access_log` deliberately catches `IntegrityError` from its nested transaction and retries. Once that retry succeeds, the caller can commit the audited action and audit row normally, but dependency teardown skips `flush_audit_journal` because `rolled_back` remains true.

**Reproduction:** `reports/independent-audit-2026-10-04/evidence/backend-independent-probes.py`, test `test_audit_savepoint_retry_commits_but_omits_external_journal`. Register a synthetic account; perform a normal audited commit as a control; inject one `IntegrityError` into `session.flush` inside the audit append's savepoint; let its existing retry succeed and commit. The database contains sequence 3, while the journal still contains only sequences 1 and 2 and does not contain the committed row's hash. The no-fault control does append to the journal.

**Evidence:** SQLite reproduction (`reports/independent-audit-2026-10-04/evidence/backend-independent-probes.log`), PostgreSQL reproduction (`reports/independent-audit-2026-10-04/evidence/backend-independent-probes-postgres.log`). Both exit 0 because their assertions demonstrate the defective behavior. There were two flush attempts, with the second succeeding.

**Impact:** an ordinary recovered database failure can silently weaken the independent evidence used to detect database rollback/truncation. The database audit record still exists; this is not loss of the primary journal or evidence that account data is disclosed. The journal verifier explicitly treats a journal behind the database as benign (`backend/app/api/_audit.py:1255–1262`), so the omitted evidence does not automatically become a verification failure. The failed-flush observer is bypassed as well because no flush is attempted.

**Remediation:** track commit/rollback state and staged audit entries per outer transaction/savepoint. Preserve the committed prefix after a recovered nested rollback and exclude only entries belonging to an actually rolled-back transaction. Do not merely clear a single global flag without retaining the safeguards against uncommitted tail entries. Add a regression using the real `get_session` dependency and the recovered nested-savepoint path, with both persisted database and external journal assertions.

<a id="be-02"></a>

#### BE-02 — Medium: recompute accepts a legacy ciphertext downgrade after observing a modern entry

**Status: reproduced on fresh file-backed SQLite and disposable PostgreSQL 16.** Assumes an attacker or corruption/recovery event can replace stored ciphertext with an earlier valid blob for the same account and entry. It does not bypass an API ownership boundary and does not apply to arbitrary attacker-created ciphertext.

**Locations:** `backend/app/security/crypto.py:104–136`, `backend/app/api/insights.py:1931–1942`.

The server's recompute path always offers both the version-bound v2 AAD and the legacy version-free v1 AAD. It does not persist an authenticated per-entry record that this entry has already authenticated under v2. The client has a separate v2-bound guard; recompute does not consult that client guard. The comment at `crypto.py:111–112` claims the server's recompute keeps a per-ID high-water mark, which the inspected path does not implement.

**Reproduction:** `reports/independent-audit-2026-10-04/evidence/backend-independent-probes.py`, test `test_legacy_ciphertext_replay_is_accepted_by_recompute`. Create one legacy-bound entry; edit it through the normal API into a version-2-bound entry; perform a successful recompute of the new text. Replace only the database blob with the captured legacy blob, leaving `content_version=2`. Recompute returns successfully, its engine input is the old synthetic text, and its published `state_seq` advances from 1 to 2. This can make stale text look like a freshly computed result.

**Negative control:** a modern version-2-bound blob with a version-3 echo returns `400 entry_blob_invalid`. The reproduced bypass specifically uses the unconditional legacy fallback, not a general failure of AES-GCM verification.

**Evidence:** SQLite reproduction (`reports/independent-audit-2026-10-04/evidence/backend-independent-probes.log`), PostgreSQL reproduction (`reports/independent-audit-2026-10-04/evidence/backend-independent-probes-postgres.log`). Both run the real API, real ciphertext, real database, and real analysis engine. A spy records analysis inputs without replacing analysis logic.

**Impact:** integrity of fresh observations can be undermined for entries with a captured legacy version, even after the backend successfully analyzed a modern edit. No plaintext recovery or cryptographic forgery is demonstrated. Legacy compatibility by itself is intentional; accepting a downgrade after positive evidence of a modern binding is the missing boundary.

**Remediation:** preserve authenticated encryption-generation/version state for each analyzed entry and reject legacy fallback after v2 has been authenticated. Bind that state to a trusted client/server anti-rollback mechanism, or migrate legacy blobs before claiming complete rollback protection. Ensure a corrupted or removed state cannot silently reset the protection. Correct the server-high-water claim until the behavior exists. Include mixed-generation migration and legitimate legacy-edit controls.

<a id="be-03"></a>

#### BE-03 — Low: obsolete metadata expectation keeps the backend regression gate red

**Status: reproduced in the complete SQLite and PostgreSQL runs and both isolated focused reruns. Classification: test-oracle defect, not a product regression.**

**Locations:** `backend/tests/test_mutation_pins.py:698–705`, `backend/app/main.py:1024`.

`test_app_metadata_and_healthz` still requires the old description `Zero-knowledge personal pattern recognition for mental state.` The application now advertises `Encrypted journaling API and deterministic pattern analysis.` The latter is consistent with the code's in-process decryption boundary. This stale exact-string assertion fails before the remainder of that test's health-check assertions run.

**Reproduction:** from `backend/`, run `.venv/bin/python -m pytest tests/test_mutation_pins.py::test_app_metadata_and_healthz`. The isolated rerun log `reports/independent-audit-2026-10-04/evidence/backend-sqlite-focused-rerun.log` shows the actual and expected values; other setup errors from the initial concurrent run disappear when using an isolated lock directory.

**Impact:** the existing backend test gate remains red on this commit and can obscure newly introduced failures. This result does not justify reverting the corrected product description.

**Remediation:** update the test's expected description to the reviewed current claim, or test the intended metadata contract without pinning obsolete prose. Retain the separate health-response assertions.

### Verification completed

| Check | Result and evidence |
|---|---|
| Ruff lint | Pass; log (`reports/independent-audit-2026-10-04/evidence/backend-ruff.log`) |
| Ruff format check | Pass, 206 files already formatted; log (`reports/independent-audit-2026-10-04/evidence/backend-format.log`) |
| Mypy | Pass, 50 application source files; log (`reports/independent-audit-2026-10-04/evidence/backend-mypy.log`) |
| New independent integrity probes | Both defects reproduced on SQLite and PostgreSQL; negative control rejects v2 version mismatch; logs linked above |
| Previous-head PostgreSQL upgrade | Pass; migrated fresh database to `a3f7c1d9b5e2`, seeded synthetic legacy journal/current note/note revision/audio metadata, upgraded to `e1b7c9d3a5f2`; exact ciphertext preserved and authenticates; log (`reports/independent-audit-2026-10-04/evidence/backend-migration-backup.log`) |
| Authenticated backup/restore | Pass; current `backup/backup_mac.py` encrypted a real `pg_dump -Fc`, then verified/decrypted it into `pg_restore` in a separate database. All 21 tables' row counts and full-row/ciphertext SHA-256 digests, 41 constraints, 56 indexes and schema head matched; log (`reports/independent-audit-2026-10-04/evidence/backend-backup-roundtrip.log`), snapshot (`reports/independent-audit-2026-10-04/evidence/backend-backup-snapshot.json`), drill script (`reports/independent-audit-2026-10-04/evidence/backend-backup-roundtrip.py`) |
| Complete SQLite regression suite | 2,105 collected: initial run 2,085 passed, 5 skipped, 1 failed and 14 setup errors; raw log (`reports/independent-audit-2026-10-04/evidence/backend-pytest-sqlite.log`). The 14 errors were audit-harness cross-process lock interference, not application failures. Focused isolated rerun of all 15 non-passing nodes: 13 passed, 1 documented S3-arm skip, 1 persistent BE-03 failure in 15.85s; rerun (`reports/independent-audit-2026-10-04/evidence/backend-sqlite-focused-rerun.log`), nodes (`reports/independent-audit-2026-10-04/evidence/backend-sqlite-rerun-nodes.txt`). Combined unique outcomes: 2,098 passed, 6 skipped, 1 failed; this is not a single green full-suite run. |
| Complete PostgreSQL regression suite | 2,105 collected: initial run 2,090 passed, 2 skipped, 13 failed; raw log (`reports/independent-audit-2026-10-04/evidence/backend-pytest-postgres.log`). Twelve failures were `MultipleWorkersError` from the overlapping audit runs, confirmed in the tracebacks. Focused isolated rerun of all 13 failing nodes: 12 passed and only BE-03 failed in 4.80s; rerun (`reports/independent-audit-2026-10-04/evidence/backend-postgres-focused-rerun.log`), nodes (`reports/independent-audit-2026-10-04/evidence/backend-postgres-rerun-nodes.txt`). Combined unique outcomes: 2,102 passed, 2 skipped, 1 failed; this is not a single green full-suite run. |

Runtime: local backend environment is Python 3.14.7 / pytest 9.1.1. Tests explicitly unset `MINDPATTERN_TEST_DB_URL` for SQLite. PostgreSQL tests use a newly created, disposable PostgreSQL 16 Alpine container named `audit20261004-backend-pg`, bound only to `127.0.0.1:32784`. Full regression, independent probes, upgrade and restore each use separate synthetic databases. No existing database, account, ciphertext or credentials were used.

The backup worker image was reused only as a runtime containing Python/OpenSSL; the current checked-out helper was mounted read-only. Its SHA-256 and worker image digest are recorded in the log. This drill verifies a small synthetic same-major restore, not disaster-recovery timing, off-site access or provider availability.

The disposable `audit20261004-backend-pg` container was stopped successfully after all checks. Its `--rm` lifecycle removed the container; all databases existed only inside that container. The two audit-created private rerun lock directories were removed. Evidence, encrypted synthetic backup and its sidecar remain available. Cleanup log (`reports/independent-audit-2026-10-04/evidence/backend-cleanup.log`). No production application, database, deployment or user data was modified.

### Scope, controls and limits

Inspected implementation spans authentication, token parsing/revocation, MFA and step-up proofs; patient/therapist role dependencies; encryption/AAD, sharing and key-envelope primitives; recovery and resumable corpus rotation; consent/share mutation fences; entries and snapshot/revision contracts; measures/local-analysis APIs; logical deletion/physical purge; audio deletion outbox; access-log chaining/journaling/verification; SQLAlchemy models and Alembic migration structure. Existing baseline coverage includes API isolation, malformed input, crypto vectors, migration parity, rotation interruption, consent/revocation, audit-chain tampering, property tests and historical regressions. Source inspection and representative trace-through were risk-based, not a claim that every one of the roughly 42,611 application lines received equal manual attention.

| Project audit track | Backend work performed and interpretation |
|---|---|
| 1 Architecture/threat model | Traced server key/plaintext boundaries, durable/in-memory state, one-process/one-host guard, database/provider trust. Hardware-TEE and deployment evidence remain separate. |
| 3 Functional correctness/API contracts | Full regression and independent real-API probes; malformed input, owner-bound CRUD, revisions, export and recompute inspected. BE-02 is a demonstrated integrity defect. |
| 4 Authentication/authorization | Reviewed live token/role/MFA gates, recovery, step-up and revocation; relevant baseline tests executed. No new authentication bypass established. |
| 5 Crypto/key lifecycle | Reviewed AAD, envelope, sharing, recovery and resumable rotation; baseline/vector regressions and independent replay negative control. BE-02 identifies missing backend downgrade protection. |
| 6 Sharing/consent | Reviewed grant/revoke/rewrap fences, current disclosures, scope flags and clinician custody; baseline lifecycle/isolation tests. No new cross-patient disclosure established. |
| 7 Privacy/data lifecycle | Inspected bounded logical erasure/physical purge, tombstones, retained audit state, audio outbox/reconciliation and export. Baseline erasure/retention tests executed. Provider-native lifecycle compliance was not verified against a live customer provider. |
| 8 Offline/concurrency/crash recovery | Backend rotation journal, stale generation checks, snapshot revisions, locks and retry boundaries reviewed/tested. Client persistence/crash behavior is covered in the client report. BE-01 concerns savepoint recovery. |
| 9 DB integrity/migrations | Full SQLite/PostgreSQL profiles, actual prior-head upgrade, exact ciphertext and schema restore comparisons. |
| 21 Backup/DR | Fresh current-helper authenticated pg_dump/restore drill passed; off-site restore, recovery-time targets and real incident drill remain unproved. |
| 22 Monitoring/incidents/audit logs | Reviewed commit coupling, MAC/hash chain, independent journal and retention verification. BE-01 proves missing evidence after a recovered rollback. Alert routing/operations are covered in the operations report. |
| 23 Test effectiveness | Newly written independent probes expose behavior absent from current test assertions; BE-03 and full-suite failure triage documented separately from product defects. |

Important intentional boundaries are not counted as newly discovered vulnerabilities: processing is in-process rather than a hardware TEE; immutable Python plaintext cannot be deterministically erased; deployment is constrained to one serving host/process per database; revocation cannot remove a data key already unwrapped by an authorized clinician; cryptographically valid local-analysis uploads are patient-authored content, not a guarantee of independently computed clinical truth. External deployment verification, production secrets, qualified legal/clinical sign-off and real hardware remain outside this backend execution.

### Reproduce the independent checks

From `backend/`, for isolated SQLite:

```sh
env -u MINDPATTERN_TEST_DB_URL PYTHONPATH=. .venv/bin/python -m pytest -c pyproject.toml ../reports/independent-audit-2026-10-04/evidence/backend-independent-probes.py -q -s
```

For PostgreSQL, create an empty disposable database and additionally set `AUDIT_PROBE_DB_URL` to its SQLAlchemy `postgresql+asyncpg://` URL. The probes create synthetic rows and must never be pointed at an existing production database. The PostgreSQL container used by this audit is removed after verification.

Harness bookkeeping: an initial duplicate baseline command was interrupted before it was incorrectly labeled PostgreSQL; its partial SQLite output is retained as `backend-pytest-accidental-duplicate-interrupted.log`. An initial external-probe invocation omitted `-c pyproject.toml`, so async tests were not enabled; `backend-independent-probes-missing-config.log` records that harness mistake. The initial complete SQLite and PostgreSQL suites overlapped: although their principal databases differed, some existing test helpers hardcode the same app identity/in-memory database and therefore share the process-lock file. This produced `MultipleWorkersError` setup failures. The focused rerun uses a private `MINDPATTERN_LOCK_DIR` so those failures can be evaluated without that interference. These harness errors are retained and are not counted as product defects or successful validation.


---

## Independent native mobile audit — 2026-10-04

Audited commit: `ad5c2d42f1ce11278302f5154be81237cc7003b8`. Application code and existing tests were not modified. New probes and this report are confined to this audit's report directory. Results below are fresh executions and current-source review; earlier audit conclusions were not used as proof.

### Result

Two Medium defects were reproduced at the JavaScript/native boundary using the shipping implementation with controlled native adapters. One Low documentation/verification mismatch was established by source inspection. No Critical or High mobile defect was established by these checks. An Android emulator navigation observation remains unisolated and is reported separately. This is not a release certification: iOS compilation, signed releases, physical-device custody and most authenticated device journeys remain unverified.

| ID | Severity | Status | Finding |
|---|---|---|---|
| MOB-01 | Medium | Reproduced with native adapters; native cleanup implementation inspected | Active or finishing recordings can retain plaintext cache files after their screen unmounts. |
| MOB-02 | Medium | Reproduced with native adapter and real ownership primitives | A suspended reminder reconciliation can recreate a notification after account retirement and cancellation. |
| MOB-03 | Low | Static verification | Full-engine mobile parity acceptance is described as present, but its test does not consume full-engine cases. |

<a id="mob-01"></a>

### MOB-01 — Recording cleanup does not own active and finishing files

**Locations:** `mobile/src/audio/recorder.ts:113`, `:141`, `:145`, `:193`, `:203`; `mobile/src/screens/EntryScreen.tsx:106`; `mobile/src/store.tsx:268`.

The unmount cleanup only deletes `takeRef.current`. That reference is populated after stopping and completing the asynchronous base64 file read. During an active recording it is null. During a pending stop/read it is also null, and the continuation may publish the take after cleanup has already run. Neither path deletes the recording's known native URI at unmount. Backgrounding locks the vault and removes the authenticated screen tree, making this a normal interruption path rather than a process-kill-only case.

The pinned `expo-audio` 57.0.5 implementation supports the concern: iOS `AudioRecorder.swift:254` stops/releases the recorder without deleting its file; Android `AudioRecorder.kt:210`/`:292` releases/resets without deleting the output file. Its actual cache locations match this app's later cold-start scrub (`ExpoAudio/` and `Audio/`). These dependency source excerpts and hashes are captured in `reports/independent-audit-2026-10-04/evidence/mobile/source-observations.txt`.

**Impact:** sensitive voice remains as plaintext in the app-private native cache after the user's recording screen is gone/locked. The exposure is to access to that app-private storage, not an unauthenticated remote attacker. Cold-start, account-erasure and origin-retirement scrubs mitigate subsequent lifetime; ordinary background/foreground transitions do not constitute cold start. Do not interpret this finding as proof that recording continues after native disposal.

**Reproduction:** `reports/independent-audit-2026-10-04/evidence/mobile/independent-probes.test.tsx` has two probes. One starts recording, supplies a native cache URI/file, and unmounts while `take` is null. The other suspends `readAsStringAsync`, unmounts, and then resolves the read. In both cases the file remains and the app calls no deletion function. Independent probe log (`reports/independent-audit-2026-10-04/evidence/mobile/independent-probes.log`) records both results.

**Fix direction:** track ownership of the native recording URI independently of the finished take; invalidate late start/stop/read continuations on reset/unmount; stop and remove the owned active file and ensure late completions remove their own file instead of publishing state. Keep the existing cold-start recovery scrub. Add interruption cases around permission, prepare, native stop and file read, then confirm file-system behavior on real iOS and Android devices.

**Evidence limit:** controlled tests exercised the real hook with native adapters; physical-device forensic file inspection was not performed. The native dependency review establishes that its disposal callbacks do not supply the missing deletion.

<a id="mob-02"></a>

### MOB-02 — Late reminder scheduling outlives account retirement

**Locations:** `mobile/src/reminderSync.ts:37`, `:46`, `:50`, `:68`, `:80`; `mobile/src/nativeFeatures.ts:169`, `:174`, `:197`, `:215`, `:230`; `mobile/src/accountErasure.ts:58`, `:83`.

Reminder reconciliation checks `assertAccountActive` before entering the scheduler. The scheduler then awaits native permission/channel operations and eventually calls `createTriggerNotification` without another owner/generation check. These native mutations are not registered in `localWriteGuard`'s tracked commit set. Account retirement can therefore drain tracked writes and cancel the reminder while a previously admitted scheduler is suspended; that scheduler later recreates it. The measure scheduler has the same pattern. Account replacement can similarly let a stale reconciliation replace the device-global reminder ID with the earlier account's schedule.

**Impact:** notifications can reappear after account retirement/sign-out/cancellation or take another account's selected schedule. Their content is generic, which bounds disclosure, but a Fathom reminder can disclose app use and violate the user's removal/disable expectation. This is not a claim that journal text appears in notification content.

**Reproduction:** the third isolated probe enables a reminder, suspends the real scheduler's native permission call, marks the account deleted, retires the session owner, awaits `waitLocalWriteCommits`, and cancels the daily reminder. Releasing permission causes a new `createTriggerNotification` call and `syncReminderSchedule` returns `true`. Probe source (`reports/independent-audit-2026-10-04/evidence/mobile/independent-probes.test.tsx`); execution log (`reports/independent-audit-2026-10-04/evidence/mobile/independent-probes.log`).

**Fix direction:** make each reconciliation carry account/session/generation ownership through every native await; serialize/track physical scheduling commits so retirement waits and then cancels them. Preference revision changes must invalidate older operations too. Apply the same lifecycle discipline to migration and sibling-reschedule paths, not only the primary scheduler.

**Evidence limit:** the final proof intentionally exercises real retirement/drain/cancel primitives rather than claiming a full device deletion journey. An additional full-erasure harness experiment returned a separate `check-in notification` cleanup failure; its cause was not isolated and it is not counted as a second defect or as a successful end-to-end deletion. That experiment is retained in `reports/independent-audit-2026-10-04/evidence/mobile/erasure-integration-experiment.log`.

<a id="mob-03"></a>

### MOB-03 — Documented full-engine parity gate is not connected

**Locations:** `mobile/src/brain/PORT.md:10`; `mobile/tests/brainVectors.test.ts:20`; `shared/brain_vectors.json`.

The port plan labels its acceptance gate “already in place” and points at `brainVectors.test.ts` for complete surfaced cards/state. The JSON currently contains 62 sentiment cases and three full-engine `updates` cases. The mobile consumer's declared/used structure includes only `sentiment` and `stats`; it never iterates `updates`. Its passing result demonstrates the implemented cores, not complete-engine parity. The same paragraph still says 53 sentiment vectors.

**Impact:** a reviewer can overstate what a green mobile vector run proves. The full on-device engine is explicitly unfinished elsewhere in the plan, so the unfinished feature itself is not classified as a regression.

**Reproduction:** `reports/independent-audit-2026-10-04/evidence/mobile/brain-vector-inventory.json`, current test source, and the captured source excerpts. No full engine mutation was required to establish the missing consumer.

**Fix direction:** describe golden fixtures as available and the full-engine acceptance runner as pending, or add an explicit pending/failing acceptance target until the port exists. Update the current case count. Require all `updates` cases when claiming complete on-device parity.

### Fresh validation

Commands are captured in `reports/independent-audit-2026-10-04/evidence/mobile/run_checks.py`, summary JSON files and logs. Tests ran against installed dependencies; this audit did not claim a fresh `npm ci`/CocoaPods installation.

| Check | Fresh result | Evidence |
|---|---|---|
| `npm test` | 2,314 passed, one intentionally skipped interop fixture generator; 113 test files passed, one skipped | `reports/independent-audit-2026-10-04/evidence/mobile/unit-coverage.log` |
| Coverage | Statements 91.30%; branches 86.01%; functions 88.40%; lines 95.07%; configured thresholds passed | Same log |
| `npm run typecheck` | Passed | `reports/independent-audit-2026-10-04/evidence/mobile/typecheck.log` |
| `npm run verify:vectors` | Passed | `reports/independent-audit-2026-10-04/evidence/mobile/vectors.log` |
| Red-team configuration | 2,322 passed, one skipped; its merged include configuration reruns the ordinary suite plus eight adversarial cases | `reports/independent-audit-2026-10-04/evidence/mobile/redteam.log` |
| `npm run verify:native-release` | All 25 static/configuration checks passed | `reports/independent-audit-2026-10-04/evidence/mobile/native-preflight.log` |
| Dependency patch verification | Passed | `reports/independent-audit-2026-10-04/evidence/mobile/dependency-patches.log` |
| Custom dependency audit | Passed its exact-advisory/backport policy and seven validator tests | `reports/independent-audit-2026-10-04/evidence/mobile/dependency-audit.log` |
| Raw `npm audit --json` | Exit 1: 28 high affected dependency nodes, resolving to two reviewed/backported advisory roots (`braces`, `node-forge`) | `reports/independent-audit-2026-10-04/evidence/mobile/npm-audit-raw.log` |
| Android native debug build | `assembleDebug --no-daemon` succeeded; 470 actionable tasks, 442 executed; approximately 130 seconds | `reports/independent-audit-2026-10-04/evidence/mobile/android-assemble-debug.log` |
| Android runtime smoke | Installed debug APK on read-only Android 35 ARM64 AVD, loaded the real Metro/native bundle, reached login | `reports/independent-audit-2026-10-04/evidence/mobile/android-runtime-smoke.log`, login UI (`reports/independent-audit-2026-10-04/evidence/mobile/android-login-ui.xml`) |
| Native authentication/write | Registered a disposable synthetic account through the app against an isolated development API; completed all three onboarding panels; saved a synthetic journal entry and observed progress advance from 0/30 to 1/30 | runtime summary (`reports/independent-audit-2026-10-04/evidence/mobile/android-runtime-summary.json`), authenticated entry UI (`reports/independent-audit-2026-10-04/evidence/mobile/android-authenticated-entry.xml`) |
| Native process restart/unlock | Force-stopped/reopened app, observed the Locked gate, entered the synthetic password and returned to journal with 1/30 progress | cold-start gate (`reports/independent-audit-2026-10-04/evidence/mobile/android-coldstart-locked.xml`), after unlock (`reports/independent-audit-2026-10-04/evidence/mobile/android-after-native-unlock.xml`) |
| Offline crisis UI | Enabled airplane mode and reached the crisis page from logged-out login; resource copy remained available | offline crisis UI (`reports/independent-audit-2026-10-04/evidence/mobile/android-offline-crisis-ui.xml`) |
| Android secure screenshot | `screencap` captured black app content while the crisis screen's UI hierarchy was present | secure-screen image (`reports/independent-audit-2026-10-04/evidence/mobile/android-secure-screen.png`) |
| Independent regression probes | Three probes confirm the two defects above | `reports/independent-audit-2026-10-04/evidence/mobile/independent-probes.log` |

Raw registry findings and the successful reviewed-backport gate are both reported; the graph is not described as having zero vulnerabilities. Neither a debug build nor the source-oriented native preflight establishes signed release correctness. Gradle emitted deprecation warnings for future Gradle 10 compatibility; that did not fail the pinned build. Initial emulator loading attempted a not-yet-accessible Metro port; using the normal emulator-reachable 8081 server loaded the app. This setup failure is not classified as an application defect.

### Runtime observation requiring isolation — Android bottom navigation

On the Android 35 ARM64 debug emulator, repeated ADB taps at the accessibility-reported centers of History and Settings left the journal screen in place. The observation persisted after process restart and password unlock. Upper controls, including registration, journal editing/saving and the details expander, responded. The final History node reported `[196,2259][360,2375]`; the corresponding center tap did not change the screen. See runtime summary (`reports/independent-audit-2026-10-04/evidence/mobile/android-runtime-summary.json`), post-tap hierarchy (`reports/independent-audit-2026-10-04/evidence/mobile/android-history-tap-result.xml`), and window state (`reports/independent-audit-2026-10-04/evidence/mobile/android-window-state.txt`).

This bounds the native smoke coverage: history display and full cross-screen workflows were not verified. It is **not yet assigned a confirmed application-defect severity** because debug overlays, emulator automation and native hit-testing have not been separated from a shipping layout/control fault. `BottomNav.tsx:121` uses fixed bottom padding rather than safe-area insets; that is a relevant review target, not an established root cause. Recheck by manual touch/TalkBack on a release-configured device, then inspect the hit regions and safe-area treatment if reproduced. The debug runtime also warned that `process.env.EXPO_OS` was not inlined; no failed Expo operation was isolated from that warning.

### Inspected controls and accepted product limits

The source review covered account storage inventory/erasure, secure storage and biometric ownership, vault locking and key-copy lifetimes, rotation/local rekey, offline entry/audio queues, API origin/response handling, audio recording/playback/export, notifications, HealthKit, navigation, crisis/measures/locales, shared controls, native manifests/build scripts and dependency patch tooling. Existing ownership, encryption/vector, recovery, failure-path and screen suites were exercised by the full test run. This is not a claim of exhaustive proof for every branch.

- `store.tsx:26` intentionally retains an account-bound plaintext draft in RAM across vault lock. This is an explicit recovery/privacy tradeoff, separate from MOB-01's disk file lifetime. JavaScript strings and native transient copies are not proven to be zeroized.
- `secureStore.ts` uses a native Keychain/Keystore device key and fails closed rather than writing a new plaintext device key. `biometricUnlock.ts` requests current-biometric-set access and device-only/passcode-set accessibility. Their actual OS enforcement remains a device gate.
- Full-account mobile export is intentionally disabled in `SettingsScreen.tsx:385` pending native streaming-to-file; separate retained-audio export is implemented. This is a known capability limit, not a newly discovered broken export path.
- Personalized question processing can send a data key under explicit user action and consent (`QuestionScreen.tsx`); only parts of the local brain have been ported. The product must not be represented as wholly local analysis on the strength of mobile tests.
- HealthKit is intended as an opt-in write-only mirror. Its native bridge/permissions/entitlement were inspected, but no iOS Health record was actually written in this audit.
- TLS/SPKI pinning remains absent, as already documented. Whether it is required depends on the chosen device/network threat model; no pinning-bypass exploit is asserted here.

### Unverified release and assurance gates

1. **iOS build and distribution:** `xcodebuild -version` fails because the active directory contains only Command Line Tools; `mobile/ios/Pods` is absent. No iOS build, signed archive, install, TestFlight or App Store validation was performed. See `reports/independent-audit-2026-10-04/evidence/mobile/environment.json`.
2. **Physical devices:** no physical device was attached. The five-row [device checklist](../../../../mobile/tools/DEVICE_VERIFICATION_CHECKLIST.md) has blank result/signature fields. Current-biometric re-enrollment, actual Keychain/Keystore invalidation, passcode changes, uninstall/reinstall, real notification delivery and OS-specific recording/snapshot behavior remain open. The Android emulator screenshot result covers only that observed emulator configuration.
3. **iOS reinstall semantics:** device-only Keychain accessibility is not itself evidence that uninstall removes an item; this source has no demonstrated first-install Keychain reset contract. The checklist's fresh-install requirement needs direct verification rather than assuming its chosen accessibility class proves it.
4. **Authenticated native end-to-end flows:** emulator registration, online journal save, cold-start locking and password re-unlock succeeded against a disposable backend. Real-device recovery/biometrics, history navigation, offline upload/reconnect, conflict handling, key rotation, native voice upload/playback/export and account deletion remain unverified. Unit/integration adapters cover many of these logic paths. No actual microphone recording, crisis call/text or external sharing was triggered.
5. **Accessibility and localization:** source properties and regression suites were reviewed; no full TalkBack/VoiceOver user journey, large-text/device-size matrix, external-keyboard journey or native Spanish usability review was completed. Native iOS privacy-shield accessibility text is literal English; its user impact should be included in that device review.
6. **Performance:** the build and test times above are execution facts, not device latency/battery/memory measurements. Low-end hardware, large histories, storage exhaustion, OS process eviction, recording interruptions and sustained offline load require profiling/stress evidence.
7. **Test assurance:** Stryker exists with an in-place mutation configuration and an 84% break threshold. A full fresh mutation campaign was not run against the shared working tree. The Node suite aliases native modules and crypto; its coverage percentages do not measure native SDK behavior.
8. **Independent safety validation:** passing crisis phrase, scoring, translation and statistical vectors cannot establish clinical validity, sensitivity/specificity on representative populations, comprehensibility under distress or appropriateness of crisis resources across jurisdictions. Those are separate specialist validation scopes, not claims made by this mobile audit.

### Cleanup

The audit-owned Metro listeners on ports 8081/8082 and read-only emulator `emulator-5580` were stopped; the temporary synthetic password file was deleted. The parent-owned disposable API on port 18974 was left running for its owner's cleanup. See `reports/independent-audit-2026-10-04/evidence/mobile/cleanup.json`. Application source and existing test files remain unchanged.


---

## Independent analysis, operations, and evidence audit

Baseline: `ad5c2d42f1ce11278302f5154be81237cc7003b8`; audit date October 4, 2026 (America/Phoenix). These findings come from current source and new controlled execution. No application source was changed. Synthetic probes are under `evidence/`.

<a id="anl-01"></a>

### ANL-01 — Medium: unsupported-language text still becomes a clinician-facing mood average

**Tracks:** 3, 14, 15, 16. **Status:** reproduced with production engine; display path verified in source.

**Locations:** `backend/app/services/brain.py:4874–4913`, `:5352–5367`; `portal/src/views/PatientView.tsx:652`, `:1358–1364`, `:1734–1738`.

The engine excludes untagged unsupported-language entries from its mood-analysis series, but later constructs `stats.avg_sentiment` from `per_entry` instead of that filtered series. Unsupported text is therefore scored with the default lexicon and enters the account summary. The portal displays that value as “average reading” without its language/coverage qualification, including print output.

**Reproduction:** run `.venv/bin/python reports/independent-audit-2026-10-04/evidence/analysis-independent.py`. In `analysis-boundaries.json`, 35 predominantly German, untagged entries are correctly marked `language: other` but produce `avg_sentiment: -0.625`. A corpus with exactly one explicitly recorded mood of `+1.0` and 34 unsupported untagged entries produces `0.029`, rather than the average of the available valid mood evidence, `1.0`. A repeated phrase surfaces, so the portal's on-screen summary condition can be satisfied. No clinical interpretation of those numbers is assumed.

**Impact:** an unsupported-language corpus can present a misleading numeric mood summary to a clinician. This also undermines the language fallback promised by the analysis guide.

**Remediation:** derive summary values from the same eligible observations used by analysis; represent no evidence as unavailable, not neutral; include explicit source and coverage information in the payload/UI. Test unsupported, mixed tagged/untagged, empty, and budget-truncated entries.

<a id="anl-02"></a>

### ANL-02 — Medium: non-Latin text is absent from the language-detection denominator

**Tracks:** 14, 15, 16. **Status:** reproduced with production engine.

**Locations:** `backend/app/services/brain.py:4802–4869`, especially the Latin token extraction and `scored` list.

Language identification measures recognized English/Spanish tokens only against extracted Latin tokens. A large amount of Chinese or other non-Latin text does not contribute to the denominator. The all-non-Latin special case works only until a recognizable Latin word appears.

**Reproduction:** the `unsupported_cjk_with_one_english_word` case in `analysis-independent.py` supplies repeated Chinese prose plus one English word per entry. The result says `language: en` and emits `avg_sentiment: -0.625`. The dominant writing is unsupported; the recognized token can re-enable the English path.

**Impact:** code-switched or predominantly unsupported-script journals may miss the unsupported-language indication and enable text-derived analysis outside the stated English/Spanish scope. The probe demonstrates misclassification; it does not measure population prevalence or clinical harm.

**Remediation:** assess script/text coverage and per-entry language eligibility before scoring. Preserve explicit mood inputs independently; test supported-language quotations inside unsupported-language prose, and the inverse. Validate the resulting policy with native-language reviewers rather than treating a larger word list as proof.

<a id="anl-03"></a>

### ANL-03 — Medium: raw p-values are displayed as corrected p-values

**Tracks:** 12, 15, 16, 24. **Status:** production-path reproduction plus presentation-source verification.

**Locations:** `backend/app/services/brain.py:3067`, `:3228`, `:5170–5186`; `backend/app/services/statsig.py:101–122`; `portal/src/views/PatientView.tsx:378`; `mobile/src/screens/InsightsScreen.tsx:354–355`; `mobile/src/locales/en.ts:625` and the corresponding Spanish string. The same misleading wording exists in `web/src/locales/en.ts:492` and Spanish; this audit did not establish that the web currently renders that string.

The engine correctly uses a Benjamini–Hochberg selection gate, but it leaves each detector's **raw** rounded p-value in `detail.p_value`. The boolean-selection function does not return adjusted p-values. The portal labels this field “p (corrected)” and mobile labels it “corrected for running many tests.” Selection after correction and a numerically adjusted p-value are different facts.

**Reproduction:** `analysis-p-values.py` wraps the existing correction function only to record its inputs/outputs; it returns the original decisions unchanged. A real surfaced `link` card in a 45-test family has raw p `0.0005902790363899967`, serialized p `0.00059`, and independently calculated BH-adjusted p `0.02656255663754985`. See `analysis-p-value-proof.json`. Both values select the claim at 0.05 in this example; the demonstrated defect is the evidence label, not an omitted selection gate.

**Impact:** the displayed value is approximately 45 times smaller than the BH-adjusted p-value in this example, while labeled corrected. A p-value ratio is not an evidence-strength ratio. Readers cannot accurately interpret the technical evidence panel.

**Remediation:** either label the number “unadjusted p; passed the multiple-testing gate” or calculate, persist and display the actual adjusted value together with the family/method. Use distinct raw/adjusted fields and cross-client fixtures. The distinction and the BH dependence conditions are described in the [official SciPy documentation](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.false_discovery_control.html).

<a id="ops-01"></a>

### OPS-01 — Medium: the release changelog gate accepts an unrelated version

**Tracks:** 20, 24. **Status:** reproduced with the exact checked-in AWK program on macOS and Linux/BusyBox.

**Location:** `.github/workflows/release.yml:64–71`.

The dynamic AWK regular expression uses single-backslash bracket escapes inside a string and interpolates the version as a regex. The executed expression does not provide literal version matching. It can capture a section for an entirely unrelated version, and the nonempty-file check then accepts it.

**Reproduction:** `operations-independent.py` extracts and runs the actual workflow program. Requested `1.0.0` with a changelog containing only `[9.9.9]` outputs `UNRELATED VERSION NOTES`; `test -s` would pass. The normal exact-header control also includes the following release's notes. Both local AWK and AWK from the pinned Linux Postgres image reproduced the unrelated-version case. See `operations-independent.json`.

**Impact:** a tag can pass the “matching changelog” release contract without a matching entry, and release notes can contain unrelated content. This does not demonstrate bypass of the separate build/security gates.

**Remediation:** parse the heading's version as a literal token, compare exact strings, stop at the next heading, and reject duplicates/missing entries. Test exact matches, prefixes, prereleases, absent versions and regex characters on the CI interpreter.

<a id="ops-02"></a>

### OPS-02 — Medium: 53 behavioral mutation probes no longer apply to current source

**Tracks:** 2, 20, 23. **Status:** reproduced using the actual harness's pre-write failure path; no source mutations were applied.

**Locations:** `redteam/run_pr_mutation_gate.py:89–130`; `redteam/mutation_campaign_2026-09-18_round2/harness.py:801–810`; campaign definitions under `redteam/mutation_campaign_*/harness.py`.

Of 220 registered behavioral mutants, 53 have missing find-strings and return `SETUP-ERROR`. Of these, 46 target files changed by the current commit. Failures span backend auth/consent/audit/analysis, mobile queues/navigation/crisis handling and portal crypto. The full per-mutant list is in `mutation-stale-proof.json` and `operations-independent.json`.

**Impact:** these probes cannot exercise their intended control on the audited revision. A PR touching their targets can fail the mutation gate because the harness is stale, and historical kill counts do not measure the current code. No fresh mutation score is claimed.

**Remediation:** update each mutation and its behavioral oracle against the current implementation; retain explicit expected behavior and verify a genuine failing negative control. Add a cheap all-campaign applicability preflight to ordinary CI. Do not merely waive setup errors or count them as killed mutants.

<a id="ops-03"></a>

### OPS-03 — Medium: four red-team checks use stale fixtures or source-text assumptions

**Tracks:** 6, 17, 20, 21, 23. **Status:** all four failures observed in the fresh complete campaign; underlying mismatches inspected independently.

The campaign produced 108 complete verdicts: **84 BLOCKED, 9 FINDING, 13 INFO, 2 PARTIAL**, zero harness errors. The runner exits 0 for completeness; the separate workflow verdict policy would reject findings outside its three documented residuals. These four additional findings are test defects, not evidence of the vulnerabilities their labels imply:

| Sub-issue | Location | Observed mismatch | Required repair |
|---|---|---|---|
| OPS-03a: backup configuration oracle | `redteam/g_infra.py:35–56` | Requires an empty plaintext `BACKUP_KEY` env fallback that production intentionally removed; recognizes the KDF iteration pin only as one exact single-line source string, although formatting split those arguments. It reports a backup finding despite a passing real encrypted backup/restore. | Execute/inspect the actual helper contract and file-secret flow; stop making formatting and obsolete env fallback requirements. |
| OPS-03b: valid-staging positive control | `redteam/g_infra.py:269–274`, `:317–322` | Supplies only DB URL and the root token secret while current production-like startup requires independently configured auth/TOTP/pairing/decoy/audit inputs. Secure refusal is reported as a finding. | Build the positive fixture with all current required production inputs; retain negative controls for missing inputs. |
| OPS-03c: therapist voice authorization scenario | `redteam/g_voice.py:345–435` | Promotes/logs in a therapist without enrolling MFA. Both voice requests stop at `mfa_enrollment_required`, so neither voice-grant acceptance nor audio access logging is actually tested. | Enroll the synthetic therapist and authenticate the appropriate MFA session before testing the downstream grant and audit controls. |
| OPS-03d: export-recovery version | `redteam/h_privacy.py:161`, `:174–219` | Hardcodes export version 2; the current API emits version 3 (`backend/app/api/account.py:503`). The mismatch prevents the password-only decryption branch from running for either key scheme. | Validate current versioned shape and independently decrypt both v1/v2 account exports with current attachment/recovery metadata. |

**Impact:** false alarms coexist with unexercised downstream controls. Correcting a label to green without exercising the intended behavior would leave the actual assurance gap open.

**Additional timing alert:** `B3.login-timing` reported 169 ms versus 267 ms from only four samples per group while other validation was active. Its summary claims indistinguishability even when its verdict is FINDING. This is an inconclusive timing observation, not a confirmed enumeration exploit. Repeat randomized/interleaved samples on an otherwise idle target, with uncertainty estimates and the threat model recorded.

**Evidence:** `redteam-current.log`, individual campaign JSON files and `redteam-policy-evaluation.json`. The other reported FINDINGs are the three documented architectural residuals and the mobile registry advisory graph, discussed separately.

<a id="ops-04"></a>

### OPS-04 — Low: the full-history secret gate fails on a public test digest

**Tracks:** 19, 20, 23. **Status:** reproduced with pinned Gitleaks 8.30.1 over 96 commits.

**Locations:** `backend/tests/test_mutation_pins_2026_09_30.py:168`; `.gitleaks.toml`; `.github/workflows/ci.yml:758–761`.

The history scan reports one `generic-api-key` finding in commit `0e8757584dd40eee26a5fb558afe7eb2d7e5d1b8`. Current source identifies the value as the content digest for `app.cache` in `MODULE_CONSTANTS_DIGESTS`, not an authentication credential. Gitleaks exits 1, which blocks the configured secret-scan gate.

**Evidence:** redacted `gitleaks-history.json` and `gitleaks-history.log`. No actual credential disclosure was established by this finding.

**Remediation:** narrowly account for this exact public digest/match while preserving planted-secret tests in the same file/path and rechecking history/staged/no-git modes. Do not exempt the test tree or assume all digest-shaped strings are safe.

<a id="doc-01"></a>

### DOC-01 — Low: the retention schedule describes mobile drafts as memory-only

**Tracks:** 7, 24. **Status:** source/document mismatch.

**Locations:** `docs/DATA_RETENTION_SCHEDULE.md:32`; `docs/architecture.md:50–52`; `mobile/src/journalDraft.ts`; `mobile/src/store.tsx:26–32`.

The retention table says the mobile draft is a memory-only stash. Current implementation has encrypted durable structured drafts as well as a scoped RAM fallback. The architecture guide describes both. An operator using the retention table alone would omit a real persisted data category and its cleanup/recovery lifecycle.

**Remediation:** inventory both durable encrypted drafts and the RAM fallback, identify save/sign-out/deletion/retirement cleanup, and verify the table against actual storage behavior. MOB-01 separately shows that the same table's claim of immediate voice deletion on normal unmount is not always true.

<a id="doc-02"></a>

### DOC-02 — Medium validation-plan gap: the proposed four-week study cannot expose a new account's unlocked analysis

**Tracks:** 12, 15, 16, 24. **Status:** document/implementation constraint mismatch; no participant study was run.

**Locations:** `docs/IRB_STUDY_PROTOCOL.md:17–19`, `:34–35`, `:58–60`; `docs/architecture.md:33–35`.

The draft specifies four weeks of naturalistic app use, inclusion at three journaling occasions per week, and evaluation at week four. New accounts require 30 distinct active journaling days for analysis. Even daily use over a four-week period cannot meet that threshold; the minimum suggested cadence is substantially below it. The protocol explicitly uses three sample cards, which can support a sample-card comprehension task but does not resolve exposure to a participant's own generated observations.

**Impact:** this protocol cannot supply evidence of actual post-threshold pattern workflows or longitudinal usefulness for newly enrolled accounts. It can still evaluate onboarding, journaling and the explicitly described sample-card task.

**Remediation:** state that limited scope explicitly, or redesign the duration/cadence and endpoints to include adequate post-unlock experience under qualified study review. Do not weaken the production threshold to make a study endpoint convenient.

<a id="doc-03"></a>

### DOC-03 — Low: study privacy copy makes an unqualified zero-knowledge claim

**Tracks:** 1, 7, 16, 24. **Status:** source/document mismatch.

**Locations:** `docs/IRB_STUDY_PROTOCOL.md:26–30`, `:68–70`; `docs/architecture.md:26–31`; `backend/app/security/enclave.py:1–16`.

The study draft says the app “is zero-knowledge and STAYS that way.” The shipped processing path explicitly receives the data key and decrypts journals for requested server analysis; the architecture guide correctly discloses this exception. Investigators not receiving content and the server being unable to decrypt are different properties.

**Remediation:** describe the actual processing exception and distinguish investigator access, server processing, third-party voice/translation and data stored at rest. Obtain the intended reviewers' approval before using participant-facing materials. This finding concerns truthful system description, not a legal determination.

<a id="doc-04"></a>

### DOC-04 — Low: the production Compose comment demonstrates unauthenticated restoration

**Tracks:** 21, 24. **Status:** instruction mismatch; insecure example was not executed.

**Location:** `docker-compose.yml:269–272`; contrast `backup/README.md:3–6` and `backup/backup_mac.py:117–137`.

The backup-service comment shows piping bare `openssl enc -d` directly to `pg_restore`. That path skips the HMAC authentication required by the maintained backup helper and README. The actual backup and rehearsal implementation authenticates first and passed the new restore drill.

**Remediation:** replace the copied command with the authenticated helper invocation and check restoration examples together. Keep deliberate legacy migration procedures clearly separate from the ordinary restoration path.

### Statistical evaluation performed and its limits

The new `analysis-independent.py` runs the complete production `brain.update` lifecycle on synthetic stationary corpora with independently generated theme choices and mood, not only a detector function. Four declared cells combine mood AR(1) coefficients 0/0.5 and complete/irregular journaling. Each user has a 90-day horizon and weekly recomputes after at least 30 observations; no detector threshold or generator was tuned after inspecting results.

The 40-user-per-cell exploratory pilot observed ever-surfaced statistical claims in 4/40, 1/40, 3/40 and 2/40 users. The completed follow-up used a separate seed, 1,000 users per cell and 30,423 full-engine recomputes. It took 222 seconds in this environment. The generator, cells and production code were unchanged after the pilot. Evidence: follow-up results (`reports/independent-audit-2026-10-04/evidence/analysis-null-heldout.json`), probe (`reports/independent-audit-2026-10-04/evidence/analysis-independent.py`).

| Mood autocorrelation | Missing entries | Users ever shown a statistical claim | Wilson 95% interval |
|---|---|---|---|
| 0 | None | 118/1,000 (11.8%) | 9.95–13.95% |
| 0.5 | None | 104/1,000 (10.4%) | 8.66–12.45% |
| 0 | Independent 22% daily omission | 105/1,000 (10.5%) | 8.75–12.55% |
| 0.5 | Independent 22% daily omission | 91/1,000 (9.1%) | 7.47–11.04% |

Results count users who ever receive a statistical claim under this particular stationary generator; they do not equate a per-user 90-day event probability with per-recompute FDR. Direct phrase/presence measurements are excluded using the engine's statistical-kind distinction. Most observed claims were `topic` cards. The simulation establishes a measurable longitudinal false-signal burden for these synthetic cells, not a newly proven violation of the single-recompute BH gate or a clinical-risk rate. The product's repeated-use validation should specify and evaluate the user-facing longitudinal endpoint explicitly.

This covers only four generator cells and weekly recomputation. It does not cover every missingness process, seasonal schedule, code-switching distribution, tag cardinality, duplicate-day behavior, effect alternative, vulnerable population, or real provider transcription. It supplies no clinical-benefit estimate and no universal false-discovery guarantee. Existing source acknowledges an unproven dependence assumption (`statsig.py:15–30`); the [SciPy method notes](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.false_discovery_control.html) explain why dependence conditions matter. The study and calibration obligations in `docs/VALIDATION_TO_90.md` therefore remain open.

### Additional observations, not new vulnerabilities

- Core logic is concentrated in large modules: `brain.py` 5,377 lines, `account.py` 2,806, `insights.py` 2,599, clinician `PatientView.tsx` 1,830 and mobile `SettingsScreen.tsx` 1,461. Size is not a defect by itself; extracted protocol/state-machine boundaries would make ownership and recovery invariants easier to review. New race/integrity findings provide specific priorities for that work.
- Hash-pinning static language tables can protect a versioned data artifact, but `backend/tests/test_mutation_pins_2026_09_30.py` explicitly kills constant/table mutations by digest. Such kills establish a changed artifact, not that an independent behavioral test detects the resulting clinical or security harm. Report those separately from behavioral mutation effectiveness.
- This audit did not perform a fresh full Stryker/mutmut campaign; in-place campaign mutation would interfere with the shared source while other checks run. Applicability, existing policies and independent defect-detecting probes were assessed; no old mutation percentage is presented as current.
- The image-drift check's self-test passed. Its live registry scan exited 1 because the Chainguard registry check could not complete/authenticate after retry. This is an environmental validation limit, not proof of a vulnerable/missing image. Other responses and a moved Python tag still inside the configured age window are preserved in `image-drift-live.log`.
- Monitoring structure/digest checks and real pinned `promtool` rule scenarios passed. This does not demonstrate delivery to a real staffed receiver; the checked-in Alertmanager file is an operator template.
- The restored database drill does not prove recovery of every deployed object-store object, the external audit-journal volume, operator secrets or offsite credentials. Coordinated full-host recovery and measured recovery objectives remain separate operational evidence.
- Ordinary CI/build/test output, emulator behavior and source labels do not establish complete accessibility conformance. Manual evaluation remains necessary; see [W3C's evaluation-tool guidance](https://www.w3.org/WAI/test-evaluate/tools/selecting/).
