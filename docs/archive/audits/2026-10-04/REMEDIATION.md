# Remediation of all 22 independent-audit findings

Audited baseline: `ad5c2d42f1ce11278302f5154be81237cc7003b8`. The [original audit](AUDIT.md) preserves the historical findings; this report records their fixes and the completed local validation. No production deployment or real-account modification was performed.

This publication includes the complete finding register, outcomes, rerun commands and limits. Original reports, component reviews, raw logs, probe scripts and detailed manifests remain local under the ignored `reports/independent-audit-2026-10-04/` and `reports/remediation-2026-10-04/` directories. Literal references to those paths identify local provenance; they are not links to published files. The compact [mutation verification record](mutation-verification.json) preserves all 220 control outcomes.

**All 22 finding groups have implementation and passing local regression evidence. All 220 mutation controls have passing behavioral proofs. The closing maintained-source scan is recorded below.**

## Finding-by-finding register

| ID | Remediation | Maintained implementation / regression |
|---|---|---|
| CL-01 | Bind asynchronous journal, question, history and voice operations to their original mounted view, login/session, account and key identity. Retired work cannot dispatch under a replacement account or remove the original draft. | [Owner contract](../../../../web/src/patientOperation.ts), [async boundary regressions](../../../../web/tests/remediationClientOwnership.test.tsx) |
| CL-02 | Retain newer typing when transcription arrives; present the transcript for an explicit apply/discard choice and prevent an ambiguous save. | [Entry workflow](../../../../web/src/views/Entry.tsx), [deferred transcript regressions](../../../../web/tests/remediationVoice.test.tsx) |
| CL-03 | Recording preflight requires consent active for the current provider policy, beyond its stored enabled flag. | [Entry preflight](../../../../web/src/views/Entry.tsx), [current-policy consent tests](../../../../web/tests/remediationVoice.test.tsx) |
| CL-04 | Failed clinician revision lookup has explicit unavailable state in screen and print output. | [Clinician view](../../../../portal/src/views/PatientView.tsx), [encrypted history/rendering tests](../../../../portal/tests/views.test.tsx) |
| CL-05 | Native same-origin form download uses a bounded, expiring, single-use capability; removes the Settings browser-buffer ceiling. Server checks account, role, epoch, revocation, expiry and key version before bounded streaming. | [Ticket contract](../../../../backend/app/security/export_ticket.py), [API/stream controls](../../../../backend/tests/test_export_download.py), [browser handoff tests](../../../../web/tests/remediationExport.test.tsx) |
| BE-01 | Transaction callbacks distinguish savepoint rollback, outer rollback and committed prefixes; publish committed journal/audio cleanup even after recovered nested failure. | [Transaction dependency](../../../../backend/app/deps.py), [real transaction controls](../../../../backend/tests/test_independent_remediation_2026_10_04_backend.py) |
| BE-02 | Signed entry guard binds account/identity/version, exact ciphertext and sticky modern-AAD observation. Guarded processing refuses legacy fallback after modern authentication and fails closed on missing/tampered guards. Explicit trusted offline bootstrap for existing databases. | [Signed guard](../../../../backend/app/security/entry_guard.py), [tamper/bootstrap controls](../../../../backend/tests/test_independent_remediation_2026_10_04_backend.py), [migration guide](../../../../backend/alembic/README.md) |
| BE-03 | Correct stale metadata test to the actual API description, preserving exact contract validation. | [Exact metadata contract](../../../../backend/tests/test_mutation_pins.py) |
| MOB-01 | Own native recorder and URI cleanup through queued prepare/stop/read/dispose work. Reset/unmount rejects late completion and removes active/finishing files before release. | [Recorder lifecycle](../../../../mobile/src/audio/recorder.ts), [adapter ownership tests](../../../../mobile/tests/audioRecorderOwnership.test.tsx) |
| MOB-02 | Account/key/preference ownership fences and a device-wide native queue prevent late or stale reminder work from surviving retirement or erasure. Native writes join the real cleanup drain. | [Reminder ownership](../../../../mobile/src/notificationOwnership.ts), [scheduling/retirement tests](../../../../mobile/tests/notificationOwnership.test.ts) |
| MOB-03 | Port documentation and tests accurately distinguish implemented component parity from pending full-engine parity. | [Port scope](../../../../mobile/src/brain/PORT.md), [actual vector consumers](../../../../mobile/tests/brainVectors.test.ts) |
| ANL-01 | Exclude unsupported/unrated text from mood evidence. No observation yields `null`; explicit finite ratings remain usable. Consumers validate and show source/count/exclusion metadata. | [Analysis engine](../../../../backend/app/services/brain.py), [eligible evidence/output cases](../../../../backend/tests/test_audit_analysis_remediation_2026_10_04.py) |
| ANL-02 | Include every Unicode letter in coverage and gate each entry conservatively before text estimation. Dominant unsupported-script prose cannot be enabled by a short supported quotation. | [Analysis engine](../../../../backend/app/services/brain.py), [script and mixed-window cases](../../../../backend/tests/test_audit_analysis_remediation_2026_10_04.py) |
| ANL-03 | EN/ES mobile/web and portal details label raw p-values as unadjusted; selection behavior unchanged. | [Portal rendering tests](../../../../portal/tests/views.test.tsx), [mobile rendering tests](../../../../mobile/tests/screens/insightsScreen.test.tsx) |
| OPS-01 | Exact-version release parser replaces both AWK gates; rejects missing/duplicate/empty notes and stops at the next heading. | [Version parser](../../../../tools/extract_release_notes.py), [parser/workflow tests](../../../../tools/tests/test_release_notes.py) |
| OPS-02 | Refresh all 220 semantic controls and selectors; read-only ordinary-CI applicability gate. Verify passing baselines, reject broken/empty/error runners, remove survivor exemptions and add meaningful regressions for observed coverage gaps. | [Behavioral gate](../../../../redteam/run_pr_mutation_gate.py), [preflight controls](../../../../tools/tests/test_mutation_preflight.py) |
| OPS-03 | Repair backup/config/MFA/export oracles to execute current contracts, including actual password-only journal and recording recovery. Timing/erasure wording follows measured outcomes. | [Current oracle regressions](../../../../backend/tests/test_audit_oracles_remediation_2026_10_04.py), [infrastructure probes](../../../../redteam/g_infra.py), [privacy/recovery probes](../../../../redteam/h_privacy.py) |
| OPS-04 | Exception matches one exact public historical digest assignment; unrelated and adjacent values remain detectable. Pinned real scanners exercised in all three modes. | [Real-scanner controls](../../../../tools/verify_secret_scan.py), [policy scope tests](../../../../backend/tests/test_repo_secret_scan.py) |
| DOC-01 | Describe durable encrypted drafts, RAM fallback and cleanup/recovery lifetimes accurately. | [Retention schedule](../../../../docs/DATA_RETENTION_SCHEDULE.md) |
| DOC-02 | Limit the four-week draft study to attainable outcomes; require a separately reviewed longer protocol for personal post-unlock experience. | [Study protocol](../../../../docs/IRB_STUDY_PROTOCOL.md) |
| DOC-03 | Replace unqualified zero-knowledge study copy with actual encryption, server-key, provider-consent and retention boundaries. | [Study processing/consent boundaries](../../../../docs/IRB_STUDY_PROTOCOL.md) |
| DOC-04 | Restore example verifies authenticated backup before decryption/pg_restore and requires pipeline failure propagation. | [Restore example](../../../../docker-compose.yml), [backup authentication helper](../../../../backup/backup_mac.py) |

## Verification summary

These are the completed remediation runs, before publication curation; they are not claims that every suite was rerun after these archive files were added.

| Check | Current result |
|---|---|
| Full backend SQLite | 2,217 passed, 6 existing skips; all late regressions collected. Application coverage 95.36%, passing the unchanged 95% CI floor |
| Full backend PostgreSQL | 2,171 passed, 2 skipped; later focused regression files passed separately |
| Web | 845 passed, 5 skipped; typecheck/build passed |
| Clinician portal | 538 passed; typecheck/build passed |
| Mobile | 2,343 passed, 1 skipped; redteam configuration 2,351 passed, 1 skipped (includes baseline cases); configured coverage floors passed |
| Android | Fresh debug build and emulator login/offline crisis-resource smoke passed |
| Backend image | Built; actual packaged trusted-bootstrap dispatch succeeded against a disposable empty database |
| Account export | Chromium downloaded a complete 358,463,942-byte JSON attachment at the default 256 MiB ciphertext quota; all 2,683 encrypted entries recovered using an incremental verifier |
| Analysis | New 13-case behavior suite passed; original audited engine failed all 13 in isolated copies. Additional effect/personal-baseline/lifecycle/language controls reject actual semantic faults |
| Frozen analysis diagnostic | Original held-out seed, 4,000 synthetic users, same generator/cells: cell results exactly reproduced the immutable audit. Additional seed retained separately |
| Release/tooling | 45 tooling tests passed; documentation check passed for 46 files and 53 API error codes |
| Secret scanning | Pinned 8.30.1: 96-commit history clean; nine positive/negative controls passed independently on Docker and checksum-verified native binaries. Closing maintained-source scan: zero findings; `reports/remediation-2026-10-04/evidence/gitleaks-maintained-source-final-snapshot.json` |
| Migration/backup | Real PostgreSQL upgrade, trusted bootstrap and authenticated backup/restore passed, including signed guards and marker; [upgrade/bootstrap procedure](../../../../backend/alembic/README.md) |
| Mutation effectiveness | 220/220 applicable and behaviorally verified: 210 KILLED, 10 CAUGHT. Passing baselines and actual faults required; zero exemptions or setup-error credits. Earlier genuine survivors retained locally; [per-control results](mutation-verification.json) |

The PostgreSQL total is its earlier complete run, with later focused batches recorded separately; the final therapist-measure revision and post-fetch byte-growth controls were covered on SQLite only. The quota export used a directly seeded disposable database containing real encrypted entries; it was a browser download and recovery check, not an HTTP write-throughput benchmark.

Counts above are runner-specific and must not be added as if overlapping suites were unique tests. Existing skipped tests remain visible. Failed initial invocations, configuration mistakes, stale test contracts and genuine mutation survivors are retained; none is counted as a successful check. The final covered backend run took 512.29 seconds. Its preceding candidate exposed a test helper mixing frozen and wall-clock TOTP time; deterministic regressions reproduced the mismatch, the helper was corrected, and the complete coverage-gated suite then passed without changing the authentication implementation or its concurrency assertions.

## Reproducing the maintained checks

Run from the repository root after installing the pinned backend development requirements into `backend/.venv` and each client's lockfile dependencies with `npm ci`. Use the Node version in `.nvmrc` and a supported Python version from the CI matrix. These commands rerun maintained gates; the large export, Android runtime, migration/restore and held-out statistical experiments above are separately recorded local experiments, not effects of these commands.

SQLite with the unchanged application-coverage floor (unset a previously selected PostgreSQL database):

```sh
(
  cd backend
  audit_lock_dir="$(mktemp -d)"
  trap 'rm -rf "$audit_lock_dir"' EXIT
  MINDPATTERN_LOCK_DIR="$audit_lock_dir" env -u MINDPATTERN_TEST_DB_URL \
    .venv/bin/python -m pytest tests/ -o addopts= -q \
    --cov=app --cov-report=term --cov-fail-under=95
)
```

For PostgreSQL, first export `MINDPATTERN_TEST_DB_URL` with an asyncpg URL for a **disposable test database** whose name contains `test`. The test fixtures create schema and delete table contents. Use a separate database and lock directory for each concurrent run; the full PostgreSQL suite does not impose a second coverage floor.

```sh
(
  : "${MINDPATTERN_TEST_DB_URL:?Set a disposable PostgreSQL test database URL}"
  export MINDPATTERN_TEST_DB_URL
  cd backend
  audit_lock_dir="$(mktemp -d)"
  trap 'rm -rf "$audit_lock_dir"' EXIT
  MINDPATTERN_LOCK_DIR="$audit_lock_dir" \
    .venv/bin/python -m pytest tests/ -o addopts= -q
)
```

Client suites include their configured coverage floors. The mobile red-team configuration includes baseline cases; its count must not be added to the ordinary suite as unique tests.

```sh
(cd web && npm test -- --maxWorkers=2 && npm run typecheck && npm run build)
(cd portal && npm test -- --maxWorkers=2 && npm run typecheck && npm run build)
(cd mobile && npm test -- --maxWorkers=2 && npm run typecheck)
(cd mobile && npx vitest run --config redteam.vitest.config.ts --maxWorkers=2)
(cd mobile && npm run verify:vectors && npm run verify:native-release)
(cd mobile && npm run verify:dependency-patches && npm run audit:dependencies)
backend/.venv/bin/python -m unittest discover -s tools/tests -v
python3 tools/check-docs.py
python3 redteam/run_pr_mutation_gate.py --preflight
```

The mutation preflight checks applicability and selectors without changing source; it does not demonstrate behavioral kills. In an isolated checkout with its own dependencies and no concurrent edits, `python3 redteam/run_pr_mutation_gate.py --all` executes the baselines and actual registered mutations. The archived [220-control verification](mutation-verification.json) comes from those behavioral checks and isolated replays, not from the preflight alone. Earlier survivors prompted new behavior tests; no survivor exemptions or runner/setup failures receive credit.

Secret-scan policy can be rechecked with the pinned Gitleaks 8.30.1 binary:

```sh
python3 tools/verify_secret_scan.py --binary gitleaks
(cd backend && .venv/bin/python -m pytest tests/test_repo_secret_scan.py -o addopts= -q)
gitleaks detect --source . --config .gitleaks.toml --redact --exit-code 1
```

The helper proves nine positive/negative controls across history, no-git and staged modes. The recorded clean **96-commit history** scan concerns the audit's then-existing Git history. The separate clean **maintained-source snapshot** scanned exact captured files from `git ls-files --cached --others --exclude-standard`, excluding ignored build/cache trees. A blanket `--no-git` scan of the entire local workspace is a different scope: ignored generated artifacts had false positives, and no clean full-workspace claim is made. The historical scans do not automatically certify later commits or a production environment; rerun the history and staged CI gates for the intended publication state.

## Deployment and remaining assurance work

BE-02 adds migration `f4a2d8c6b901`. Existing deployments must stop writers, verify their pre-upgrade snapshot, apply the migration and run the explicit one-time trusted bootstrap as documented in [the migration guide](../../../../backend/alembic/README.md). Normal requests/startup do not silently adopt missing seals. A coherent replay of an earlier valid signed entry record—including its ciphertext—still requires an independent freshness anchor to detect; the guard is not presented as that anchor.

The guard protects backend analysis, rekey, replacement and credential key proof. Opaque ciphertext reads do not independently validate this server guard; clients authenticate delivered ciphertext and retain their own observed modern-AAD boundary. This distinction scopes the fix to the audited backend downgrade defect.

The audit's separate assurance gaps remain separate: real iOS/physical microphone and notification behavior, accessibility/OS lifecycle, clinical and population-level statistical validation, institution-approved research, production provider/legal review, signed release installation, production monitoring and off-site disaster recovery are not certified by these local checks. Full-engine mobile parity remains explicitly pending. Raw npm advisory metadata still lists affected nodes whose reviewed source patches are checked by the existing custom dependency policy; this work does not claim an advisory-free dependency graph.

The locally retained component reports record commands, logs, isolated original/mutated negative controls, cleanup and limits. `reports/remediation-2026-10-04/evidence/delivered-state.json` records the source and audit artifacts at the end of remediation validation; the closing scanner snapshot independently records its scanned files. Those captures precede publication curation and are not manifests of a later commit. Owned temporary source copies, servers, emulator, database resources and inactive test locks were removed.
