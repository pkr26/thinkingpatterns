# Independent verification of commit 9f22fb3

Date: October 4, 2026 (America/Phoenix). Audited commit: `9f22fb34977091297092680d0b4f24ad4b273162`, “fix: remediate all 22 independent audit findings.”

This review started from a clean working tree. It covered the commit's 132 changed files and all 22 remediation claims, using separate backend, web/portal, mobile and operations reviews. Historical reports were used to identify claims, not as proof that the implementation worked. Current behavior was checked with fresh suites, controlled failing-before reproductions, real browser downloads, native build checks and isolated mutation executions. The repairs described here are working-tree changes; this audit did not create a commit or publish/deploy anything.

## Findings and repairs

The commit fixed its original examples but left additional cases unprotected. Nine finding groups were identified and repaired. Severity describes the reproduced consequence, not an observed production incident.

| ID | Severity | Reproduced gap | Repair and maintained regression |
|---|---|---|---|
| R1 | Low | **CL-01: History pagination outlived its owner.** After account A's first page settled, retiring A and signing in as B allowed the old walker to dispatch its continuation with B's bearer. The outer view guard prevented rendering, but ran too late to prevent dispatch. This was a GET-only defect; no cross-account plaintext disclosure or write is alleged. | `web/src/api/client.ts` binds the complete walk, including snapshot retries, to the initiating session. `History.tsx` supplies its mounted-view/key guard. `remediationClientOwnership.test.tsx` covers account replacement, unmount and key replacement. |
| R2 | Medium | **CL-01/02: audio completion deleted newer writing.** Saving an entry cleared the submitted editor, then awaited a kept-recording upload. New text typed and durably autosaved during that upload was subsequently deleted using an earlier `unchanged` decision. The visible text survived, but a reload lost its recovery copy. A real-crypto/storage regression verified the new draft existed before upload completion and disappeared afterward. | `web/src/views/Entry.tsx` queues submitted-draft cleanup before further asynchronous work; newer autosaves follow it in the draft write queue. `remediationVoice.test.tsx` retains the controlled upload race. |
| R3 | Medium | **ANL-02: language exclusion did not reach every detector.** A supported English-majority window correctly excluded dominant-Chinese entries from its mood average but still produced a negative rumination card entirely from their short English quotations. Affect/sense-making inputs and person/topic interpretation also admitted excluded text. In another mixed corpus, Spanish “sin tension” was scored using the English lexicon and misclassified as rumination. | `backend/app/services/brain.py` applies entry eligibility to downstream inputs and retains the source language for phrase members. Explicit ratings and neutral repetition remain available. `test_audit_analysis_remediation_2026_10_04.py` verifies actual cards, detector inputs, Spanish negation, and reclassification of an already-stored worry without stale negativity. |
| R4 | Medium | **MOB-01: a second iOS recording skipped transcription.** The pinned Expo iOS implementation can reuse its recording URL when `prepareToRecordAsync()` receives no options. The screen deduplicates transcription by URI, so record → save → record could silently omit the second transcription. The screen regression failed with one call instead of two using an SDK-faithful test seam. | `mobile/src/audio/recorder.ts` passes the recording options on each preparation to create a fresh file identity and records the previous URI for cleanup. `tests/screens/entryVoice.test.tsx` verifies two separate takes. Physical-device validation remains separate. |
| R5 | Medium | **MOB-02: preference producers escaped ownership fences.** Daily and measure reminder setters read preferences before acquiring a permit. An older delayed enable could overwrite a later disable and recreate notifications. A read started before same-account session/key replacement could also write afterward. Six controlled storage cases failed on the audited implementation. Cross-review also reproduced an earlier UI boundary: after a Settings screen retired, its delayed account lookup could resolve the replacement account and enable that account's reminders; an old enable could enter after a newer disable. | `mobile/src/reminderPreferences.ts` captures custody before the read and serializes tracked preference/cadence writes; `reminders.ts` and `measureReminders.ts` use it. `notificationOwnership.test.ts` covers ordering and retirement; rendered Settings controls additionally bind intent before identity lookup and reject retired-screen/account/key work. Erasure tests also assert explicit rejection of retired writes while retaining cleanup guarantees. |
| R6 | Low | **DOC-01: sign-out retention was still described incorrectly.** Both clients deliberately preserve encrypted drafts through sign-out, while the new shared table claimed deletion. Mobile clears its RAM fallback; web has no separate API-origin retirement operation. Related documentary contradictions remained: the entrypoint recommended blindly stamping Alembic head, and the proposed study called self-report objective, all instruments standardized, its benchmark pre-registered and its risk classification already determined. | `docs/DATA_RETENTION_SCHEDULE.md` separates web/mobile durable drafts and RAM lifetime. Real client lifecycle regressions cover sign-out recovery and mobile origin retirement; existing account-erasure controls remain. The entrypoint comment now requires the verified matching historical revision. Study wording now matches its explicitly unapproved, unregistered draft status and its stated measures. |
| R7 | Medium | **OPS-02: shared test machinery could bypass behavioral reruns.** The actual inventory selected zero controls for mobile/portal shared helpers, Vitest/Vite configuration and dependency manifests. Backend dependency-lock changes also selected zero Python controls; relevant configuration/dependency paths were missing from workflow triggers. | `redteam/run_pr_mutation_gate.py` selects the supported controls for helper/configuration/dependency changes. `.github/workflows/mutation-pr.yml` triggers those changes and reads `.nvmrc`. Maintained tests verify selectors and workflow path coverage; actual inventory probes select all 17 mobile and 3 portal controls for their shared support changes. |
| R8 | Low | **OPS-02: empty or skipped-only successful runners were accepted as passing baselines.** Calling the classifier with exit 0 and empty output returned no setup error for pytest, Vitest and probe runners. Such a baseline provides no observed passing control. | `redteam/mutation_oracles.py` requires an executed passing verdict, including pytest's quiet progress format. It removes ANSI color sequences before classification. Tooling tests reject empty/skipped-only output and accept real quiet/colored successful formats. |
| R9 | Medium | **Android build evidence did not reproduce with strict dependency verification.** A fresh build stopped because the pinned Guava parent POM lacked a checksum entry. This was missing metadata, not an observed checksum mismatch. | The downloaded cached POM was byte-compared with the artifact fetched from Maven Central. `mobile/android/gradle/verification-metadata.xml` adds only that parent POM's SHA-256 entry; strict verification remains enabled. |

The entry-guard regressions were additionally strengthened: their module disables the global fixture that automatically signs legacy inserts. A deliberate removal of the production API sealing call now fails the API regression instead of being repaired by the fixture. This is an assurance improvement; no missing production seal was found in the audited API implementation.

## Disposition of the original 22 claims

| Original ID | Independent result |
|---|---|
| CL-01 | Original entry, voice, processing-key and edit dispatch probes pass; remaining pagination/draft cases fixed in R1/R2. |
| CL-02 | Transcript conflict/apply/discard behavior verified; additional successful-save draft race fixed in R2. |
| CL-03 | Recording preflight requires both enabled consent and current-policy activation. Ownership is rechecked after the consent request. |
| CL-04 | Failed note-history transport/decryption remains unavailable in screen and print; a successful empty result remains distinct. Portal suite passes. |
| CL-05 | Ticket ownership, expiry, replay, revocation, role and bounded body controls verified. Fresh Chromium download at the full default ciphertext quota recovered every entry. |
| BE-01 | Real transaction regressions exercise nested rollback, recovered conflict, outer rollback, committed prefixes, journal publication and audio cleanup. |
| BE-02 | Guard binding, ciphertext/metadata tamper, sticky modern-AAD observation and explicit bootstrap controls pass. API sealing is now verified without fixture repair. Coherent replay of an entire previously signed record remains an explicitly documented architectural limit. |
| BE-03 | The exact API-description contract matches the implementation and passes. |
| MOB-01 | Native adapter ownership regressions pass; repeated iOS take gap fixed in R4. |
| MOB-02 | Native scheduling/draining controls pass; upstream preference and cadence races fixed in R5. |
| MOB-03 | Port documentation accurately limits the parity claim to implemented components. No full-engine mobile parity is claimed. |
| ANL-01 | Unsupported/unrated text no longer fabricates neutral average evidence; explicit finite ratings, null unavailable averages and source/count validation pass. |
| ANL-02 | Unicode coverage gates pass; additional downstream and per-phrase language defects fixed in R3. |
| ANL-03 | EN/ES client and portal technical displays label raw p-values as unadjusted. This audit makes no new clinical or population-calibration claim. |
| OPS-01 | Both release paths use the same literal-version parser. Missing, duplicate, malformed/prefix and empty sections are rejected by executable tooling tests. |
| OPS-02 | Applicability and actual behavioral reruns checked; remaining selection/baseline gaps fixed in R7/R8. The J3 anchor was updated to preserve its disabled-rumination mutation after R3. |
| OPS-03 | Fresh auth/API/LLM/analysis/voice/privacy probes execute the intended controls. Backup/config probes pass; export recovery includes journal and recording ciphertext. Timing is reported as a bounded diagnostic. Existing verifier-replay and visible-metadata architectural findings remain explicit. |
| OPS-04 | Pinned Gitleaks 8.30.1 passed all nine positive/negative controls across history, no-git and staged fixture modes; a fresh 97-commit history scan found no leaks. |
| DOC-01 | Additional inaccurate draft lifetimes corrected in R6 and checked against actual client lifecycle behavior. |
| DOC-02 | Four weeks remains insufficient for 30 distinct active days; the draft protocol limits evaluation to attainable onboarding/journaling/sample-card endpoints. Residual self-report/standardization/pre-registration/risk-status contradictions were also corrected. This is a source/document consistency review, not institutional approval. |
| DOC-03 | Study copy distinguishes client encryption, optional server key/plaintext processing and provider consent/retention. It no longer promises unqualified zero knowledge. |
| DOC-04 | Restore guidance invokes the authenticated helper before plaintext reaches `pg_restore` and requires a pipefail shell. Backup helper tests exercise tampered/missing authentication and failed pipelines. |

## Fresh verification

Original aggregate counts were not used as substitutes for fresh results. The initial SQLite coverage run overlapped source editing and is not accepted as final coverage evidence; the separate final run used stable source and its own coverage database.

| Check | Fresh result |
|---|---|
| Full SQLite backend | **2,223 passed, 6 skipped; 95.37% application coverage**, unchanged 95% floor; 687.92 seconds. |
| Backend static checks | Ruff and mypy passed for all 52 application files. |
| PostgreSQL | **2,224 passed, 2 skipped** in the full run started before the last phrase-language extension; **67 final-source focused checks** then passed for transaction/guard/analysis/export contracts. These overlapping counts are separate, not a combined full-final-suite claim. |
| Web | **850 passed, 5 skipped**; configured coverage floors, typecheck and build passed on repository Node 22.14.0. |
| Portal | **538 passed**; configured coverage floors, typecheck and build passed on Node 22.14.0. |
| Mobile | **2,363 passed, 1 skipped**; red-team configuration **2,371 passed, 1 skipped** (overlapping suite). Configured coverage floors, typecheck, crypto vectors, 25 native configuration checks and dependency/backport policy passed on Node 22.14.0. |
| Android | Strict-verification debug build passed after the single checksum repair. Fresh invocation reused valid incremental outputs; 470 tasks, 43 executed. |
| Real browser export | Chromium 154.0.8037.93 downloaded **358,463,942 bytes**, containing **2,683 entries** at exactly 268,435,456 ciphertext bytes. Every entry decrypted and matched the synthetic input; page preserved and no query credentials. Incremental verifier peak text buffer: 1,181,908 bytes. |
| Packaged backend bootstrap | Fresh Docker build passed; actual packaged entrypoint migrated an isolated database and executed the explicit bootstrap successfully, without networking. Temporary image tag removed afterward. |
| PostgreSQL upgrade/restore | Prior head with legacy and modern encrypted entries → migration → explicit bootstrap → authenticated backup/restore. Both ciphertexts, guards and marker preserved; all 22 tables, 42 constraints and 57 indexes matched. Repeat bootstrap and tampered backup rejected; tampered decrypt emitted zero plaintext. |
| Frozen analysis diagnostic | Same generator, original held-out seed 731092001, 4,000 synthetic users: all four cell results exactly matched archived evidence; 230.443 seconds. Rates remained 11.8%, 10.4%, 10.5%, 9.1% for the specified repeated-user diagnostic, not a claimed universal 5% bound. |
| Red-team verification | Fresh auth/API/LLM/analysis/voice/privacy plus backup/config and multiworker probes ran. Expected architectural residuals remained labelled. The isolated checkout had no development DB for the optional dump-content inspection, which correctly reported NOT-RUN. |
| Tooling/docs | **51 tooling tests passed**; documentation check passed for 46 files and 53 API error codes. |
| Secrets | Real Gitleaks 8.30.1: nine scanner controls passed, 97-commit history clean, and final maintained-source snapshot clean. Ignored generated evidence is outside the maintained-source scan. |
| Behavioral mutations | **220/220 verified: 210 KILLED and 10 CAUGHT**, with passing unmodified baselines and no credited setup errors or exemptions. Four isolated execution shards were followed by a final 17-control mobile replay after the UI repairs. The final classifier rechecked every recorded command; source hashes and behavioral verdicts are recorded in [the control ledger](COMMIT_REAUDIT_MUTATIONS.json). Applicability preflight also passed 220/220. |

Suite counts overlap and must not be added as unique tests. Physical-device tests and production operations are separate scopes. The PostgreSQL full-run snapshot and later focused results are distinguished above rather than presented as one combined total.

Reproduce maintained checks using the existing lockfile dependencies, the repository Node version, and separate test databases/lock directories for concurrent backend runs:

```sh
(
  cd backend
  audit_lock_dir="$(mktemp -d)"
  trap 'rm -rf "$audit_lock_dir"' EXIT
  MINDPATTERN_LOCK_DIR="$audit_lock_dir" env -u MINDPATTERN_TEST_DB_URL \
    .venv/bin/python -m pytest tests/ -o addopts= -q \
    --cov=app --cov-report=term --cov-fail-under=95
)
(cd web && npm test -- --maxWorkers=2 && npm run typecheck && npm run build)
(cd portal && npm test -- --maxWorkers=2 && npm run typecheck && npm run build)
(cd mobile && npm test -- --maxWorkers=2 && npm run typecheck)
backend/.venv/bin/python -m unittest discover -s tools/tests -v
python3 tools/check-docs.py
python3 redteam/run_pr_mutation_gate.py --preflight
```

Use `python3 redteam/run_pr_mutation_gate.py --all` only in an isolated checkout with installed dependencies: it applies and restores actual source mutations. A passing preflight alone is not behavioral evidence. Real-browser export, migration/restore and the frozen simulation are separately recorded experiments, not effects of these standard suite commands.

## Boundaries

Tests and controlled races establish the scenarios they execute, not all possible interleavings or production certification. The browser experiment uses current Chromium and a directly seeded disposable database; it is not an API throughput benchmark or a Safari/Firefox result. A native build and SDK-faithful recording regression do not establish physical iOS microphone/notification behavior. Production provider processing, clinical/population validity, signed release installation, production deployment/monitoring and offsite disaster recovery were not certified. Existing skipped tests remain visible. No real accounts, production data, or existing unrelated containers were changed.

Local raw logs and probes are retained under the ignored `reports/independent-audit-2026-10-04/last-commit-9f22fb3/` directory, separately from this maintained report; generated logs/downloads are not intended for publication. Historical audit/remediation records retain their original dates and provenance.
