# Fathom remediation status

October 3, 2026. Original baseline: `9c1ba47508f474afc5f70588dd2771d80c2eece7`.

The identified engineering defects have received substantial fixes across the
mobile app, patient web, clinician portal, API, database and operational tools.
This report distinguishes implemented behavior from release evidence still
needed. **The app has not yet earned an independently verified 90+ score in
every area.** The original 61/100 assessment remains a historical baseline;
passing tests do not replace usability, device, security or clinical assessment.

The current roadmap is [PLAN_TO_90_PLUS.md](PLAN_TO_90_PLUS.md), with prospective
acceptance criteria in [VALIDATION_TO_90.md](docs/VALIDATION_TO_90.md). Original
audit evidence is preserved in [AUDIT_2026-10-03.md](AUDIT_2026-10-03.md).

## Engineering changes

| Area | Changes implemented | Remaining acceptance evidence |
|---|---|---|
| Patient UX | Accurate save/error states, retained writing during late saves, durable browser drafts, explicit audio retry/export, useful History readback, accessible labels and reactive English/Spanish copy | Representative task sessions, manual screen-reader/keyboard/large-text review and native-language review |
| Patient web | Durable IndexedDB errors, microphone cancellation, one validated insight response, bounded transport lifetime, page-scoped broadcasts, browser navigation, transactional local rekey/erasure checkpoints, persistent owner/key-generation write permits and smaller initial bundles | Real public release configuration, supported-browser microphone/offline/permission matrix, measured field responsiveness |
| Native mobile | Correct root registration, linked native crypto import, HealthKit/questionnaire/recovery contracts, ordered revision-aware audio custody, captured account/key-generation write permits and physical-write drains, fenced authentication/sign-out, localized deterministic insights, encrypted complete typed drafts and authoritative boot/unlock/post-save progress | Full Xcode/iOS build, signed release installs and real HealthKit, biometrics, notifications, audio and capture tests |
| Clinician portal | Independent random notes key and encrypted historical keyring; atomic password/custody protocol; verified note/revision preservation; durable scoped drafts, conflict retention, local TOTP QR and chart navigation | Human clinician workflow/accessibility evaluation, coordinated minimum supported client rollout |
| API/backend | Fresh recovery epoch checks, key zeroization, atomic corpus/credential/envelope/grant changes, lifecycle fencing, typed bodies, bounded admission, durable revocation fallback and monitored single-process guard | Production load/memory profiles, independent protocol/security review; multiple active API processes remain unsupported |
| Database | Three new migrations, transactional custody, exact-operation retry records, copy-on-write audio locators and leased object-deletion outbox | Production snapshot rehearsal, real configured object-store/offsite inventory and recovery exercise |
| State/sync | Parent-before-audio ordering, generation and revision guards through checkpoint cleanup, no queue eviction, chunked encrypted native checkpoints, registered-store rekey, retained conflicts and owner-scoped erasure tombstones | Complete physical process-death/permission/fault matrix; ambiguous or competing records remain recoverable and need the documented recovery procedure |
| Security/privacy | Recovery downgrade and stripped audit-MAC refusal; separately reviewed legacy sealing tool; consent-bound grant transitions; unnecessary narrative provider dispatch removed; fail-closed origins and release checks | Independent adversarial and record-retention/privacy-policy review; real operator values; inherent verifier/password and metadata risks remain documented |
| Analysis/safety | Empty-group crash fixed; entry/day units distinguished; bounded deterministic copy, signed direction consistency, complete translation checks and pre-cap question filtering; overstated historical evidence corrected | Held-out full-pipeline statistical calibration, supported-language/clinical review and prospective usefulness evidence |
| Delivery/operations | Fixed dev Compose, mutation-score/kill attribution, exact red-team verdict inventory, complete digest check, shared authenticated backup helper, real alert-rule fault tests and actual Android compilation in CI | All hosted CI/release gates, alert delivery, deployed TLS, signing, production RPO/RTO and forward-repair exercise |

Detailed finding-by-finding implementation evidence is in
[mobile.md](reports/remediation-2026-10-03/mobile.md),
[web-portal.md](reports/remediation-2026-10-03/web-portal.md) and
[backend.md](reports/remediation-2026-10-03/backend.md). The original audit's
AUD-01–AUD-12, M01–M25, WP-01–WP-20, S01–S05 and A01–A07 identifiers are retained.
Native source fixes are not counted as successful iOS hardware validation.

## Verification performed

Only the latest check for each scope supports its result; earlier failures
remain in the evidence directory so they cannot be mistaken for fresh passes.

| Check | Result and scope |
|---|---|
| Backend, PostgreSQL | **1,973 passed, 2 skipped** in 574s; full suite on an owned PostgreSQL16 container before the final translation-output guard; **38 post-change remediation/boundary tests pass** on PG. Two test-fixture session-lifetime warnings were then corrected and the affected tests pass with those warnings treated as errors. [Log](reports/remediation-2026-10-03/validation-logs/backend-postgres-final.log) |
| Backend, SQLite | **1,982 passed, 6 skipped**, **95.50% coverage**, in 420s; fresh run passes the unchanged 95% floor. [Report](reports/remediation-2026-10-03/backend.md) |
| Native mobile suite | **2,250 passed, 1 skipped**; statements **91.16%**, branches **85.72%**, functions **88.05%**, lines **94.97%**; unchanged coverage gates, final typecheck, vectors, dependency-patch verification and eight mobile red-team tests pass. The full suite was repeated after the publication privacy-heading correction. The skip is an opt-in interoperability fixture generator. [Latest full suite](reports/remediation-2026-10-03/validation-logs/mobile-publication-full-suite.log), [report](reports/remediation-2026-10-03/mobile.md) |
| Native ownership review | **358 common/rotation focused tests**, **146 authentication tests** and an independent **29-case generation-boundary rerun** pass. Captured ownership is checked through delayed native publication, credential adoption, recovery and failure cleanup. This establishes single-runtime behavior, not cross-process hardware durability. [Generation evidence](reports/remediation-2026-10-03/native-generation.md), [bounded review](reports/remediation-2026-10-03/native-write-guard-review.md) |
| Patient web suite | **788 passed, 5 skipped**; unchanged coverage gates and typecheck pass. Initial JS 98.13 KB gzip. Bundling/SRI pass; public security-contact gate remains blocked. [Report](reports/remediation-2026-10-03/web-portal.md) |
| Clinician portal suite | **501 passed**; unchanged coverage gates, typecheck, build and SRI pass. Initial JS 91.77 KB gzip. [Log](reports/remediation-2026-10-03/validation-logs/mindpattern-portal-full-final14.log) |
| Android compile | **PASS** after clean dependency installation: 272 executed Gradle tasks, 43 reused; real Kotlin/C++ application and native modules. Debug arm64 build on macOS; hosted Ubuntu and signed release builds are different scopes. [Log](reports/remediation-2026-10-03/validation-logs/android-build-reinstalled.log) |
| Android runtime | **PASS** native login, onboarding, encrypted save, progress 10→11 and decrypted History. Against the final frozen source, force-stop/unlock restores text, mood, energy, sleep and a tag; the acknowledged save decrypts in History; another restart does not resurrect the draft and reloads authoritative 11/30 progress. FLAG_SECURE remains enabled. [Core flow](reports/remediation-2026-10-03/validation-logs/android-native-journey-final.log), [final structured restart proof](reports/remediation-2026-10-03/validation-logs/android-structured-draft-final.log) |
| Actual Chrome functional flows | **PASS** patient encrypt/save/History and clinician draft navigation/save/reopen on HTTPS built artifacts; 390px layouts without horizontal overflow, JS errors or CSP violations. [Latest log](reports/remediation-2026-10-03/validation-logs/browser-functional-final-generation.log) |
| Actual Chrome security changes | **PASS** patient full legacy atomic password/key change with journal/draft/safety-plan preservation; clinician password change and separate sharing-identity rotation preserve notes and revision access after fresh login. [Clinician security log](reports/remediation-2026-10-03/validation-logs/browser-security-latest.log), [final patient generation/preservation](reports/remediation-2026-10-03/validation-logs/browser-patient-generation-final.log) |
| PostgreSQL upgrade | **PASS** previous head `a3f7c1d9b5e2`→`d6a0c4e8b213`; exact journal/note/revision ciphertext and full legacy audio row preserved and authenticated. Complete graph has 31 migrations. The utility rejects Python optimization that would disable verification. [Log](reports/remediation-2026-10-03/validation-logs/postgres-final-upgrade.log) |
| Real encrypted backup restore | **PASS** current Docker helper encrypts and tags with one resolved secret; authenticated private-snapshot decrypt feeds real pg_restore. All fixture rows and latest schema match; restored ciphertext authenticates. [Log](reports/remediation-2026-10-03/validation-logs/backup-restore-final.log) |
| Tooling adversarial contracts | **19 passed**: inclusive mutation floors, incomplete/runtime-error rejection, lost-kill rejection, exact campaign/verdict inventory, skipped-attack refusal, byte-exact AAD vectors, actual OpenSSL round trips, tampering, long-key rejection, in-place replacement and secret-rotation consistency. [Log](reports/remediation-2026-10-03/validation-logs/tooling-contracts-final.log) |
| Current red-team campaigns | **All 11 campaigns/108 expected verdicts complete; zero harness errors**: 92 BLOCKED, 4 FINDING, 10 INFO, 2 PARTIAL. Three architectural findings remain documented; mobile registry advisories remain a fourth finding and fail the hard release/audit policy. Completeness is not a clean-security claim. [Summary](reports/remediation-2026-10-03/redteam-summary.json) |
| Monitoring | Pinned real promtool validates configuration/rules and healthy/boundary/sustained-fault cases for eight alerts. This proves rule behavior, not delivered pages to an operator. [Log](reports/remediation-2026-10-03/validation-logs/promtool-alert-tests.log) |
| Development Compose | **PASS** `config --quiet` with documented local image tags, after repairing the dev overlay. Omitted required image inputs still fail as intended; no development stack is claimed deployed. [Log](reports/remediation-2026-10-03/validation-logs/compose-dev-configured-final.log) |
| Source/configuration | Backend Ruff formatting/lint and mypy across 46 application files; client typechecks; 234 project Python files, 21 YAML/workflow files and 58 JSON files parse, including publication evidence and the manifest; all ten shell scripts pass warning-level shellcheck. Source whitespace checks preserve verbatim terminal logs. |

The final client suite counts, coverage and asset sizes are recorded in their
reports. The latest actual browser run exercises transactional local migration
CAS and decrypts the original seeded clinician revision after security changes.
Earlier fresh-seed evidence also exercises active patient grant rewrapping.
The [local migration recovery guide](reports/remediation-2026-10-03/local-migration-recovery.md)
explains retained competing branches; an automatic reconciliation chooser has
not been implemented. No coverage floor, dependency audit, placeholder gate or
signing gate has been lowered to make a result green.

## Release work that remains

1. **Real operator configuration.** The patient build compiles and stamps SRI,
   then fails its unchanged `security.txt` placeholder check. Set the actual
   monitored security contact/canonical URL and deployed HTTPS API origin.
   Supply private signing material through the documented local/CI secret
   mechanisms. No example contact or key has been invented.
2. **Upstream dependency resolution.** Mobile npm audit still reports 28 high
   affected paths from two unpublished upstream fixes (`braces` and
   `node-forge`). Exact licensed/hash-verified backports and attack regressions
   mitigate the reviewed flaws, while the registry output and hard audit gate
   remain visible. Compatible published fixes or an explicitly reviewed
   release disposition are still needed; this is not a clean registry audit.
3. **Platform and operations evidence.** Complete iOS/signing and physical
   Android/iOS permission/background/biometric/HealthKit/audio/capture checks;
   supported-browser checks, production load, real object-store/offsite
   recovery, alert delivery and deployed TLS. Loopback/emulator drills do not
   certify those environments.
4. **People and analysis evidence.** Execute the published usability,
   accessibility, language, full-pipeline calibration and clinical/domain
   review protocol; resolve the documented patient-erasure/clinician-record
   retention policy before any deployment with those obligations. Historical synthetic simulations and detector-only
   Monte Carlo diagnostics cannot establish clinical benefit or a universal
   false-discovery guarantee.
5. **Independent reassessment.** Review the changed key-custody and recovery
   protocols, source and remaining failure matrix. Publish evidence and
   deductions for all ten areas against the original rubric. Every area
   must earn at least 92; the target remains open until that happens.

The supported architecture still exposes dates/sizes to the server and sends
a short-lived data key for requested server-side analysis. A captured client
auth verifier is password-equivalent until credentials rotate. Weak-password
guessing remains possible against exposed password envelopes/ciphertext at
the full KDF cost. UI throttling cannot prevent external guessing. These are
explicit architectural limits, not defects claimed eliminated by green tests.

Changes were implemented and verified locally; publication is recorded in
the repository's Git history. No production deployment, customer-data
mutation, remote message, independent certification or clinical study was
performed. The [evidence directory](reports/remediation-2026-10-03/README.md)
documents reproducible synthetic checks and their boundaries.

Owned loopback servers, the disposable PostgreSQL container and the read-only
test emulator have been stopped; temporary synthetic database, backup keys
and local TLS files were removed. Source, evidence, installed toolchains and
unrelated user containers were retained. [Cleanup log](reports/remediation-2026-10-03/validation-logs/owned-test-cleanup-final.log).
The [final manifest](reports/remediation-2026-10-03/source-manifest.json)
records SHA-256 hashes and the complete nonignored file/change inventory;
generated build trees, dependencies and temporary secrets are excluded.

Publication checks additionally pass the pinned Gitleaks 8.30.1 policy in
staged, existing-history, exact staged-tree and isolated staged-history modes.
A value-specific exception covers only the already published deterministic
audio fixture; a scratch replacement key remains detected. The privacy
heading was reworded without changing its disclosure. Reviewed synthetic
validation logs are explicitly included in Git. [Secret-scan evidence](reports/remediation-2026-10-03/validation-logs/gitleaks-publication-final.json).
