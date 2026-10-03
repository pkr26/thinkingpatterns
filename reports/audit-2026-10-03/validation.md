# Fresh validation and evidence — October 3, 2026

Baseline commit: 9c1ba47508f474afc5f70588dd2771d80c2eece7. These are local audit results against the checked-out project. Original application source hashes were rechecked for all 781 tracked files. Only audit documentation/evidence was added. No fixes, release, deployment or production data changes were made.

## Validation ledger

| Area | Work performed | Outcome / evidence |
|---|---|---|
| Backend tests | Full pytest suite on SQLite; rerun on isolated PostgreSQL | [SQLite log](validation-logs/backend-pytest.log): 1,945 dots/pass, 5 skip markers; [Postgres log](validation-logs/backend-pytest-postgres.log): 1,948 pass, 2 skip. Both reach 100% without a failure section. Separate collection confirms 1,950 cases. Quiet configuration suppresses numeric summary. |
| Backend lint/types | Ruff check and mypy over app | [Ruff](validation-logs/backend-ruff.log) / [mypy](validation-logs/backend-mypy.log) pass; mypy reports 45 source files and untyped-body limitations. |
| Formatting | Ruff format --check | [Summary](validation-logs/backend-format-summary.log): ten files would be reformatted. Original full diff remains outside repo in /tmp. |
| Python dependency audit | Runtime closure via pip-audit | [Log](validation-logs/backend-pip-audit.log): no known vulnerabilities. Dev dependencies were not independently certified clean. |
| Mobile | Typecheck, main suite, crypto vectors, static native preflight | [Types](validation-logs/mobile-typecheck.log), [suite](validation-logs/mobile-test.log), [vectors](validation-logs/mobile-vectors.log), [native preflight](validation-logs/mobile-native.log). 2,099 pass/1 skip; 14/14 preflight checks. |
| Mobile extra suite | Additional Vitest configuration | 2,107 pass/1 skip; includes main suite. Full extra-suite log remains /tmp/mindpattern-mobile-redteam.log. |
| Native build | Offline Android debug build; Xcode toolchain check | [Android log](validation-logs/mobile-android-build.log): SDK missing. Active Xcode path is CommandLineTools, so full iOS build unavailable. These are unverified checks, not successful builds. |
| Objective-C contract | Isolated compiler check of category declaration | [Proof log](validation-logs/objc-category-proof.log) rejects category on undefined class. This is a language-contract proof, not a full archive build. |
| Mobile targeted components/state | Five isolated regression probes | [Log](validation-logs/mobile-regressions.log): confirms native-shaped questionnaire event failure, voice 404 deletion, replacement deletion, accepted-but-unreadable large row behavior under a simulated storage constraint, and safety-plan write/read mismatch. Passing proves current bad behavior. |
| Web | Typecheck, suite and build | [Types](validation-logs/web-typecheck.log) pass; [tests](validation-logs/web-test.log): 744 pass/2 fail/5 skip; [build](validation-logs/web-build.log) fails security.txt operator-placeholder gate after bundling. |
| Portal | Typecheck, suite and build | [Types](validation-logs/portal-typecheck.log), [tests](validation-logs/portal-test.log), [build](validation-logs/portal-build.log) pass. 477 tests; V8 lines 94.96%, branches 87.63%. |
| Independent web probes | Six storage/transport/recording/lock probes and two real-component probes | [Six-case log](validation-logs/web-audit-probe.log), [component log](validation-logs/web-audit-ui-probe.log); eight reproduced defects. |
| Independent portal probes | Real WebCrypto plus actual PatientsView actions, Unicode and transport | [Four-case log](validation-logs/portal-audit-probe.log): both note-loss workflows, offset error and late body completion reproduced. |
| Backend recovery/audit boundaries | Controlled isolated synthetic scenarios | [Recovery results](validation-logs/backend-repro.log): removed enrollment followed by live recovery token, and nonzero popped key after successful reset. [Audit result](validation-logs/backend-mac-repro.log): modified new MAC row accepted as legacy. Root reviewed source and results; these do not imply anonymous remote exploitation. |
| Live API clients | Real register/CRUD and dual-client drills against isolated localhost API | [Log](validation-logs/audit-live-client.log): two pass/one fail/one skip. Failing logout expectation is stale relative to per-token revocation contract. |
| Brain semantic checks | Existing probe, freshly executed | [Log](validation-logs/audit-brain-probe.log): eleven emitted verdicts pass. |
| Brain statistical diagnostic | mc_phi_eff.py final 2000 | [Log](validation-logs/audit-brain-mc.log): raw marginal detector check across lengths/autocorrelation. No clinical/end-to-end false-discovery guarantee. |
| Brain edge corpus | Pure update on 40 valid brief/ordinary text-only entries | [Stack and result](validation-logs/audit-brain-edge.log): ZeroDivisionError at brain.py3102. |
| Export JSON | Login to synthetic seed account and stream ciphertext export | [Shape-only result](validation-logs/audit-export-shape.log): HTTP200; audio appears twice. No real content or credential in log. |
| V2 offline export | Independently constructed valid v2 envelope/random-key entry; actual documented CLI from mobile working directory with correct synthetic password | [CLI log](validation-logs/audit-v2-export.log): 0/1 decrypted, exit1. Independent envelope/payload decryption succeeded; CLI uses legacy derived key. First run from repo root failed compilation due working-directory resolution; this report uses the corrected documented working-directory run. |
| Deployment monitoring | verify.sh --production | [Log](validation-logs/audit-monitoring-verify.log): structural YAML/alerts/dashboard/digest checks pass. No promtool or shellcheck; no operator metrics-token comparison. |
| Image registry drift | Drift self-test and actual registry check | [Self-test](validation-logs/audit-drift-selftest.log), [live check](validation-logs/audit-drift-live.log): pass under configured grace policy. |
| Dev Compose | docker compose -f docker-compose.yml -f docker-compose.dev.yml config --quiet; complete YAML parsing | Invalid indentation at audio-minio.image line49; parser reports expected key/block end. No Compose development containers started. |
| Mutation gate logic | Exact final awk AND-list semantics in a shell with error propagation | For the web/portal 65 floor, scores64/65/90 all exit1. Mobile uses84 but same logic; its healthy scores also return nonzero. No full mutation campaign executed. |
| Historical mutation verifier | Synthetic before Survived and after RuntimeError JSON reports in /tmp | verify_kills.js reports killed1, score0.0%, exits0. This tests report attribution only; no mutations applied to application source. |
| Backend services | Full source plus controlled provider-protocol stubs | [Probe log](validation-logs/services-audit-probe.log): finite narrative filter bypass, oldest-text budget consumption, and accepted partial translation. No real provider call; current web/portal do not render narratives. |
| Every-file structure | JSON/TOML/YAML/CSV parsing, Python/TypeScript AST scans, shell syntax, catalog/fixture consistency, sizes/hashes | [Manifest](file-coverage.json). Dev YAML fails; remaining checked formats parse. Twenty-eight migration revisions form a complete single-head graph. CSV/JSON totals consistent. Structural pass is not semantic correctness. |

## Current dependency advisory snapshot

The scan was performed against npm's current registry advisory data. Raw responses: [mobile](validation-logs/mobile-npm-audit.json), [web](validation-logs/web-npm-audit.json), [portal](validation-logs/portal-npm-audit.json).

Web and portal report zero affected packages. Mobile reports 30 affected package records: 29 high and one moderate. Npm propagates advisory severity up dependency paths; these are not 30 unique advisories or proof of 30 reachable shipped-app vulnerabilities. Several affected paths are Metro/Expo/React Native build tooling. Runtime reachability and exploitability require separate evaluation.

Underlying advisory families include braces recursion/stack exhaustion, brace-expansion recursion/resource exhaustion, node-forge signature verification and fast-uri normalization. Primary records: [braces GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm), [brace-expansion GHSA-q2hr-2g5m-vwhr](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr), [node-forge GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv), [fast-uri GHSA-hrr3-gc8f-f4qj](https://github.com/advisories/GHSA-hrr3-gc8f-f4qj).

Update through reviewed compatible dependency paths and revalidate native builds/tooling. Do not equate a registry recommendation to force a major downgrade/upgrade with a safe repair. Record any temporarily accepted unpatched tooling advisory with reachability, containment, owner and review date. No dependency versions were changed during this audit.

## Evidence boundaries

- Fresh tests and probes supplement complete production executable/type review; test counts do not establish every workflow or native SDK contract.
- Source-only risks are explicitly labeled in the primary report. Reproduction tests often assert undesirable behavior, so a green probe means a defect was confirmed.
- Generated catalogs have key/placeholder parity, not complete native-language clinical review. Lexicons/simulations are not efficacy evidence.
- No successful visual browser/device audit, real screen-reader session, native release/archive, real HealthKit/Face ID test, real provider transcription, full load/mutation campaign or production security/compliance certification occurred.
- Existing year/60-day simulations and prior audits were read/consistency-checked, not rerun. No existing historical results were overwritten.

The audit-only localhost API/client servers were stopped and the disposable audit PostgreSQL container was removed after validation. Unrelated processes, application source and existing databases were left unchanged.
