# Independent Audit Issue Register

Audit date: 2026-10-04
Audited commit: `5a02dbbb160f8cc62118eeb850fb4964ca6fed13`
Scope: backend, patient web app, mobile app, clinician portal, cryptography, privacy, clinical safety, accessibility, localization, CI/release, containers, backups, monitoring, dependencies, documentation, and deployment readiness.

This file is the pre-remediation baseline requested before implementation changes. “Open” means the issue existed at the audited commit; statuses may be updated only after a fix and its verification are recorded. Clinical, legal, vendor-contract, app-store, and real-device items are readiness findings rather than certifications.

## Audit coverage: 16 independent lenses

The project can be audited in 16 materially different, complementary ways. The issue register and remediation verification cover each lens independently where repository evidence is available:

1. Architecture, trust boundaries, and data-flow mapping.
2. Authentication, session management, authorization, and tenant isolation.
3. Cryptography, secret handling, recovery, and key lifecycle.
4. Audit logging, tamper evidence, custody, and non-repudiation.
5. Privacy, consent, data minimization, and subject-rights handling.
6. Retention, deletion, backups, storage lifecycle, and restoration.
7. Clinical safety, crisis handling, and human-workflow escalation.
8. Scientific validity, measurement integrity, bias, and fairness.
9. Patient web application security, resilience, accessibility, and offline behavior.
10. Mobile/native application security, privacy, accessibility, and release readiness.
11. Clinician portal safety, access control, and data-presentation integrity.
12. Localization, language quality, and error-message safety.
13. Automated testing, adversarial testing, mutation testing, and regression quality.
14. Dependency, build, artifact, and software-supply-chain integrity.
15. CI/CD, deployment, monitoring, incident response, and disaster recovery.
16. Documentation, legal/regulatory readiness, policies, and operator controls.

These lenses are not interchangeable: a clean dependency scan, for example, does not establish clinical validity, correct consent, tenant isolation, or recoverability. Findings below use one primary category even when more than one lens applies.

## Security, privacy, and audit integrity

### AUD-001 — Audit-chain prefix deletion can verify successfully

- Severity: High
- Status: Open
- Evidence: `backend/app/api/_audit.py` accepts a first surviving row with an arbitrary non-null `prev_hash`; the retention cutoff is checked only when no rows remain.
- Reproduction: create three current valid rows, seal the tail, delete sequence 1, and verify with a 730-day cutoff; verification returns success.
- Required remediation: cryptographically anchor the retained prefix, reject unexplained non-genesis starts, and add deletion regressions.

### AUD-002 — Audit-tail deletion can be hidden by sequence reuse

- Severity: High
- Status: Open
- Evidence: the next sequence is derived only from the database head; the external journal reader discards historical hashes/MACs and retains only the maximum sequence/time; verification checks only whether journal sequence exceeds database sequence.
- Reproduction: delete a sealed tail row, append a legitimate event that reuses its sequence, and verify; verification returns success despite two different seals at that sequence.
- Required remediation: make sequences monotonic outside the mutable log, compare journal seals to database seals, and prevent reuse.

### AUD-003 — Audit verification sweep can miss or starve accounts

- Severity: Medium
- Status: Open
- Evidence: the sweep selects only accounts with a database audit row in the last 24 hours, applies a limit of 500, and has no durable pagination/order cursor.
- Required remediation: durable round-robin pagination over all audit owners, including owners whose newest row was deleted.

### AUD-004 — `actor_role` is not authenticated by the audit hash/MAC

- Severity: Low
- Status: Open
- Evidence: the field is stored but omitted from the canonical hash input and verification input.
- Required remediation: include it in a versioned audit record format and provide backward-compatible verification for historical rows.

### SEC-001 — Web privacy-sensitive actions lack fresh-password step-up

- Severity: High
- Status: Open
- Evidence: the web app reuses the unlocked vault key for account deletion, AI/voice consent, share grant/revoke, and voice-scope changes. Mobile asks for a freshly typed password.
- Impact: a walk-up attacker at an unlocked browser session can permanently delete an account or alter disclosure/sharing state.
- Required remediation: require fresh credentials, bind a short-lived step-up proof to the intended action, and test expiry/replay/action mismatch.

### SEC-002 — Recovery endpoint reveals account/recovery-scheme state

- Severity: Low
- Status: Open
- Evidence: enrolled accounts with the wrong scheme receive `recovery_scheme_mismatch`; unknown accounts receive `invalid_credentials` before proof.
- Required remediation: return a uniform pre-authentication failure and record internal diagnostic detail only.

### SEC-003 — Legacy recovery requests default to the weaker v1 flow

- Severity: Medium
- Status: Open
- Evidence: omitted scheme fields default to v1, which sends recovery material also capable of opening the recovery-wrapped data key; the shipped mobile client already uses v2.
- Required remediation: require an explicit supported scheme and retire or tightly gate v1 compatibility.

### SEC-004 — Therapist MFA is optional

- Severity: Medium
- Status: Open
- Evidence: therapist registration immediately issues a bearer token; login requires TOTP only after voluntary enrollment.
- Required remediation: require MFA enrollment before access to patient data, with a documented recovery path.

### SEC-005 — Runtime plaintext has no hardened-memory/TEE guarantee

- Severity: Residual risk
- Status: Open
- Evidence: analyzer-created immutable Python strings can remain until garbage collection even though processing keys and mutable buffers are bounded and zeroized.
- Required remediation: document the boundary, minimize string creation/lifetime, and use a hardened execution boundary if the threat model requires it.

## Consent, data rights, and retention

### PRIV-001 — AI consent describes a dormant use instead of the active LLM use

- Severity: High
- Status: Open
- Evidence: production journal-pattern enrichment is disabled, while transcript translation is active; consent says decrypted journal entries are sent for pattern analysis and the web copy says this occurs only after 30 days.
- Required remediation: separate translation from journal-analysis consent and disclose actual purpose, timing, provider, retention, and policy fingerprint.

### PRIV-002 — Voice disclosure conflicts with actual upload timing

- Severity: High
- Status: Open
- Evidence: the iOS microphone purpose string says recordings remain on-device until save, but recording is uploaded automatically when recording stops. Client consent omits configured STT retention.
- Required remediation: correct the native purpose string and prominent in-app disclosure before any upload.

### PRIV-003 — Sharing consent under-describes shared measures

- Severity: High
- Status: Open
- Evidence: consent version v2 and patient copy name PHQ-9, while sharing can include PHQ-9, GAD-7, and PHQ-2.
- Required remediation: broaden the disclosed scope, bump the consent version, and require renewed consent.

### PRIV-004 — Consent withdrawal erases evidence of the accepted terms

- Severity: Medium
- Status: Open
- Evidence: disabling AI or voice consent clears timestamp, disclosure version, and provider fingerprint; the remaining audit event records only on/off. Actual STT/translation dispatch is not audited.
- Required remediation: retain immutable versioned consent events and audit each external processing dispatch without logging health content.

### PRIV-005 — Account export is incomplete despite claiming completeness

- Severity: Medium
- Status: Open
- Evidence: export omits voice-consent metadata, sharing-disclosure metadata, `share_voice`, and subject access history.
- Required remediation: include every server-held subject record or narrow the claim and document justified exclusions.

### PRIV-006 — Data-rights functionality is inconsistent across clients and roles

- Severity: Medium
- Status: Open
- Evidence: therapist deletion exists in the API but not the portal; full patient export is unavailable on mobile; recovery-kit reset is mobile-only; clinician data export is absent.
- Required remediation: provide safe UI/API parity or explicitly document supported channels with accessible handoffs.

### PRIV-007 — Dormant accounts can retain question data beyond 90 days

- Severity: Medium
- Status: Open
- Evidence: question purging occurs only when that account recomputes insights.
- Required remediation: scheduled global retention purge with metrics, retries, and tests.

### PRIV-008 — Audio deletion lacks an independent storage lifecycle backstop

- Severity: Medium
- Status: Open
- Evidence: deletion is retryable, but objects may remain indefinitely through persistent object-store failure and the local store has no lifecycle policy.
- Required remediation: reconcile object inventory, alert on deletion backlog, and configure a storage lifecycle ceiling.

### PRIV-009 — Age attestation is enforced only in client UIs

- Severity: Medium
- Status: Open
- Evidence: direct API registration has no age-attestation field or server-side enforcement/audit record.
- Required remediation: add versioned server-side attestation and store only the minimum evidence needed.

### PRIV-010 — iOS privacy manifest declares no collected data

- Severity: High release blocker
- Status: Open
- Evidence: `PrivacyInfo.xcprivacy` lists no collected data types despite server-retained account identifiers and user content.
- Required remediation: align the manifest and App Store privacy answers with verified production data flows.

## Clinical safety and scientific integrity

### CLIN-001 — Positive PHQ-9 item 9 has no monitored follow-up workflow

- Severity: High when deployed or marketed as clinical monitoring
- Status: Open
- Evidence: the server stores opaque ciphertext and cannot alert; clinicians see the flag only after opening and decrypting a patient; there is no queue, acknowledgment, escalation, response SLA, or patient-facing “not monitored” disclosure.
- Required remediation: either clearly position the feature as unmonitored self-reflection or implement an owned and tested clinical workflow. Do not imply emergency monitoring.

### CLIN-002 — Mobile crisis-prompt suppression is shared across different triggers

- Severity: High
- Status: Open
- Evidence: journal detection and PHQ-9 item 9 share one once-per-day prompt stamp, so an earlier lower-context prompt can suppress the later item-9 prompt.
- Required remediation: use trigger-specific state and never suppress the first item-9 safety response for a submission.

### CLIN-003 — Mobile safety-plan loading fails open and permits silent overwrite

- Severity: High
- Status: Open
- Evidence: missing, malformed, tampered, and wrong-key data all become `null`; the screen treats `null` as a new plan and can overwrite existing ciphertext. Web fails closed.
- Required remediation: distinguish absence from corruption/decryption failure, block overwrite, and provide recovery/export guidance.

### CLIN-004 — Portal accepts impossible or invented measure results

- Severity: Medium
- Status: Open
- Evidence: portal decryption accepts any instrument name and any finite score from 0 through 100, including PHQ-9=28, GAD-7=22, PHQ-2=7, and unknown instruments.
- Required remediation: enforce a known instrument enum, integer values, per-instrument score ceilings, item count/range, and schema version before display.

### CLIN-005 — Crisis confidentiality copy is absolute and inaccurate

- Severity: Medium
- Status: Open
- Evidence: web copy says “what you share stays with them,” but crisis services have emergency, legal, operational, and quality exceptions.
- Required remediation: use accurate language such as “confidential, subject to the service’s privacy and emergency policies.”

### CLIN-006 — Web emergency calling is prose-only

- Severity: Low
- Status: Open
- Evidence: 988/text/chat/global resources are actionable, while 911 appears only in prose; mobile exposes a direct telephone action.
- Required remediation: provide an accessible `tel:911` action where supported without hiding the existing alternatives.

### CLIN-007 — Clinical validity, fairness, and workflow evidence is incomplete

- Severity: Release-readiness blocker for clinical claims
- Status: External validation required
- Evidence: no completed prospective validation, subgroup/language fairness assessment, qualified Spanish clinical review, demonstrated clinical benefit, completed IRB study, or clinician response-SLA evidence is present.
- Required remediation: complete the planned human/clinical validation and governance work before making clinical-performance claims.

### CLIN-008 — Regulatory status is not formally assessed for actual intended use

- Severity: Release-readiness blocker
- Status: Qualified review required
- Evidence: named depression/anxiety screeners, clinician sharing, and C-SSRS follow-up references may exceed a purely general-wellness positioning depending on claims and deployment.
- Required remediation: obtain and record qualified medical-device, HIPAA/HBNR, and jurisdiction-specific assessments for the final intended use and marketing.

## Patient web, mobile, and portal quality

### WEB-001 — Production web build is intentionally blocked by placeholder security contacts

- Severity: High release blocker
- Status: Open
- Evidence: `web/public/.well-known/security.txt` contains example contact/canonical URLs and the SRI build step rejects them; CI and release run that exact build.
- Required remediation: inject validated deployment values or make the build generate the file from required release configuration.

### WEB-002 — Offline rejected-entry storage is not byte bounded

- Severity: Medium
- Status: Open
- Evidence: the rejected-entry store is unbounded by count and bytes; quarantine has only a count limit. Mobile has byte bounds.
- Required remediation: apply deterministic count/byte limits, surface evictions, and test oversized/corrupt records.

### WEB-003 — No service worker or cold-start offline shell

- Severity: Product limitation
- Status: Open
- Evidence: offline behavior works only after the application has loaded; there is no service-worker-backed cold-start shell.
- Required remediation: either implement a carefully scoped offline shell or keep the limitation explicit in product copy and requirements.

### WEB-004 — Web loads both language catalogs at login

- Severity: Low
- Status: Open
- Evidence: both catalogs are bundled eagerly rather than loaded by locale.
- Required remediation: lazy-load non-active locale resources if bundle budgets require it.

### MOB-001 — Mobile registry advisory gate is deterministically red

- Severity: High release blocker
- Status: Open
- Evidence: registry audit reports propagated high findings rooted in `braces@3.0.3` and `node-forge@1.4.0`; exact-source local backports pass, but CI/release still require the failing registry command.
- Required remediation: upgrade/override upstream packages where feasible and make the release gate verify both registry state and the reviewed backport policy without silently waiving unrelated findings.

### MOB-002 — Native dependency closure is not fully reproducible

- Severity: Medium
- Status: Open
- Evidence: no committed `Podfile.lock`, Gradle dependency locks, Gradle verification metadata, or Gradle wrapper distribution checksum; CI builds Android debug but not iOS.
- Required remediation: lock and verify native dependencies and add an iOS build/signing-independent compile job.

### MOB-003 — Accessibility scaling is capped on essential controls

- Severity: Medium
- Status: Open
- Evidence: bottom navigation and check-in labels cap `maxFontSizeMultiplier` at 1.3.
- Required remediation: remove or justify the cap, allow reflow, and test large-text and screen-reader paths on real devices.

### I18N-001 — Some user-visible errors and fallback UI are English-only

- Severity: Medium
- Status: Open
- Evidence: raw backend errors, the mobile error boundary, and clinician portal strings bypass locale catalogs; qualified Spanish review is absent.
- Required remediation: map errors to stable localized codes, localize fallback UI, and complete professional/clinical review.

### PORTAL-001 — Recovery-code download revokes its Blob URL immediately

- Severity: Low
- Status: Open
- Evidence: the object URL is revoked immediately after triggering download, which can abort on some browsers.
- Required remediation: revoke after a safe asynchronous delay or navigation completion and test supported browsers.

### TEST-001 — Live dual-client test encodes a false global-logout expectation

- Severity: Medium assurance defect
- Status: Open
- Evidence: the test expects logging out one device to invalidate another, while the documented product contract is per-device logout.
- Required remediation: test per-device logout and separately test explicit global revocation/account epoch changes.

## Deployment, operations, and supply chain

### OPS-001 — Compose does not wire documented split secrets

- Severity: High
- Status: Open
- Evidence: TOTP-wrap, pairing, decoy, and audit-MAC secrets documented for production are not passed/mounted, so they fall back to the root token.
- Required remediation: mount each secret independently, fail closed in production when missing, and test rendered Compose output.

### OPS-002 — Primary secrets are duplicated into container environment variables

- Severity: High
- Status: Open
- Evidence: token and backup secrets are interpolated into container environments even though secret files are mounted; environment values take precedence.
- Required remediation: use file-only secret delivery and ensure rendered Compose contains no secret value.

### OPS-003 — Root-token rotation can invalidate historical audit verification

- Severity: High
- Status: Open
- Evidence: audit MAC defaults to a derivation of the root token, rows have no key version, and the incident runbook omits audit-key preservation/migration.
- Required remediation: require a dedicated versioned audit key, support historical verification during rotation, and update the runbook.

### OPS-004 — Development/CI Compose references an unavailable MinIO image

- Severity: High CI blocker
- Status: Open
- Evidence: the pinned `minio/minio:RELEASE.2023-09-30T13-39-29Z` image cannot be pulled on a clean runner, while CI starts that overlay.
- Required remediation: pin an available immutable digest and add an image-availability verification.

### OPS-005 — Web/portal release archives lack authenticated publisher provenance

- Severity: Medium
- Status: Open
- Evidence: archives receive same-release SHA-256 files, while only container images receive signed provenance/digests.
- Required remediation: sign archives/checksums with identity-constrained verification instructions and publish provenance.

### OPS-006 — Vendor/region/DPA/BAA register remains incomplete

- Severity: Deployment blocker for affected integrations
- Status: Operator/legal action required
- Evidence: LLM, hosting, backup, STT, and object-storage entries retain operator placeholders.
- Required remediation: keep optional providers disabled until vendor, region, retention, DPA/BAA, and subprocessors are approved and recorded.

### OPS-007 — Real alert delivery and remote offsite restore are unverified

- Severity: Operational readiness gap
- Status: Environment verification required
- Evidence: local Prometheus rules and local encrypted backup/restore pass, but production TLS, alert delivery, and actual remote offsite restore were not exercised.
- Required remediation: run and retain evidence from a production-like disaster-recovery and alert-delivery exercise.

### OPS-008 — Full mutation testing was not rerun in this audit

- Severity: Assurance gap
- Status: Open
- Evidence: targeted adversarial probes and full functional suites passed, but no fresh complete mutation campaign was executed.
- Required remediation: schedule bounded mutation testing for security/crypto/consent modules and enforce a reviewed mutation threshold.

## Documentation and policy accuracy

### DOC-001 — Research and README descriptions conflict with current behavior

- Severity: Medium
- Status: Open
- Evidence: `RESEARCH.md` says screeners are not administered; README sections conflict about journal-text LLM analysis.
- Required remediation: describe the actual current feature set and clearly distinguish disabled, experimental, and production paths.

### DOC-002 — Privacy policy template is internally inconsistent and incomplete

- Severity: High release blocker
- Status: Open
- Evidence: it incompletely describes key derivation; its “complete” server-data list omits measures, voice, and consent metadata; it says there is no age gate; it promises mobile/web export while another document says mobile export is unavailable.
- Required remediation: reconcile the data inventory and actual client behavior, then have the deployer publish a completed jurisdiction-specific policy.

### DOC-003 — Store labels, public privacy URL, and operator fields are unfinished

- Severity: High release blocker
- Status: Operator action required
- Evidence: store/privacy checklists and operator pack retain unchecked items/placeholders.
- Required remediation: complete deployment-specific names, contacts, URLs, disclosures, retention, store declarations, and responsible owners before release.

## Verified strengths retained as regression requirements

- No cross-tenant/IDOR or consent-bypass path was found in the tested APIs.
- Authentication tokens enforce signature, purpose, epoch, revocation, and per-device logout.
- TOTP replay prevention is atomic and backup codes are single use.
- Payload cryptography uses AES-256-GCM with fresh nonces and AAD; P-256 inputs are validated.
- Processing keys are owner-bound, bounded, single use, TTL-purged, and mutable buffers are zeroized.
- Provider clients enforce HTTPS/no redirects and request/body/framing limits.
- Patient-side measure definitions and score bounds are correct.
- No automatic diagnosis or severity-band diagnosis is presented.
- Crisis resources work offline and journal crisis detection is local.
- Web safety-plan handling already fails closed.
- Statistical documentation disclaims clinical validity and user-level repeated-testing FDR.

## Baseline verification evidence

- Backend full suite: 1,997 tests collected; SQLite and fresh PostgreSQL 16 runs passed (expected dialect/environment skips only).
- Backend lint/type: Ruff and mypy passed.
- Backend adversarial/ground-truth tools: passed, except the two independently reproduced audit-chain bypasses recorded above.
- Web: 803 passed, 5 skipped; build blocked by placeholder `security.txt` values.
- Portal: 512 passed; production build passed.
- Mobile: 2,276 passed, 1 skipped; typecheck, crypto vectors, dependency-patch verifier, and native static preflight passed.
- Live patient-web API drill passed; dual-client drill failed because of the stale global-logout expectation.
- Dependency and provenance checks: backend, web, and portal vulnerability scans clean; mobile registry audit red as recorded; npm signatures/attestations and GitHub Action SHA pinning passed; all-history secret scan found no leak.
- Monitoring configuration/rules/tests and image-drift checks passed.
- Production-style base stack, migrations, health/readiness, encrypted backup, authenticated restore, and restored-user verification passed.
- Working tree was clean after audit and all disposable audit infrastructure was removed.

## Audit limitations

The audit could not independently complete or certify App Store Connect/Play Console declarations, real vendor retention/BAA/DPA terms, public production privacy pages, production marketing claims, clinician SOPs, real TLS/alert routing, remote offsite restore, Xcode signing, real-device biometrics/reinstall/reminder/screenshot-shield behavior, qualified Spanish review, clinical efficacy, or legal/regulatory classification. Those items require evidence or authority outside this repository.

## Remediation verification issue log

These defects were found by an independent integration pass after the baseline above was frozen and before the associated remediation was accepted. They are recorded separately so that fixing an audit finding cannot silently introduce a new defect. Final dispositions and verification evidence will be added after the remediation tree is stable.

### RVI-001 — Age-attestation schema width was shorter than its required literal

- Severity: High correctness defect
- Status: Open pending final verification
- Evidence: the new `minimum_age_confirmed_v1` literal is 24 characters, while the first remediation draft used `String(16)` in the `users.age_attestation_version` model and migration.
- Required remediation: widen both definitions consistently and test registration plus migration behavior.

### RVI-002 — Client remediation drafts did not type-check

- Severity: High integration blocker
- Status: Open pending final verification
- Evidence: independent TypeScript checks found an unsafe locale-module union index in web, undefined `api` references and stale age-attestation fixtures in portal, and a nonexistent mobile `./i18n` import.
- Required remediation: correct the implementations and fixtures, then pass each client's full typecheck, tests, and production build.

### RVI-003 — Generated `security.txt` helper and its tests temporarily disagreed

- Severity: Medium release-gate defect
- Status: Open pending final verification
- Evidence: the web test imported `renderSecurityTxt` while an intermediate helper revision did not export it.
- Required remediation: maintain one exported validation/rendering seam and exercise both generic and release builds.

### RVI-004 — Audit remediation initially had inconsistent verifier results and types

- Severity: High assurance defect
- Status: Open pending final verification
- Evidence: focused audit tests disagreed with the verifier's empty-database/tail-truncation classifications, while mypy found incompatible assignments in audit evidence reduction and export-query construction.
- Required remediation: define the intended classifications, make journal evidence order-independent or serialize writes, resolve the type failures, and add valid-out-of-order plus conflicting-duplicate regressions.

### RVI-005 — Android dependency locking used non-strict mode

- Severity: Medium supply-chain gap
- Status: Open pending final verification
- Evidence: the remediation draft used Gradle `LockMode.DEFAULT`; strict mode is incompatible with generated React Native/Expo subprojects unless additional lock ownership is designed.
- Required remediation: either make strict locking work or explicitly document the limitation and use a CI regeneration/diff gate plus strict artifact verification.

### RVI-006 — iOS Ruby lock metadata did not match the CI runtime

- Severity: Medium reproducibility defect
- Status: Open pending final verification
- Evidence: the generated `Gemfile.lock` records Ruby `2.6.10p210`, while the new macOS CI job selects Ruby 3.3 with deployment mode.
- Required remediation: regenerate or validate the lock under the selected runtime and pass the clean iOS dependency/compile job.

### RVI-007 — Mobile advisory exception matching was initially too permissive

- Severity: High supply-chain gate defect
- Status: Open pending final verification
- Evidence: the first registry-audit wrapper could accept an allowed advisory somewhere in a vulnerability tree without proving that every transitive cause was allowed, and did not robustly reject string-form nodes, missing references, or cycles.
- Required remediation: traverse the complete vulnerability graph, fail closed on malformed/unresolved nodes, and test unrelated, mixed, string, missing-reference, and cyclic cases.

### RVI-008 — Audio reconciliation did not initially backstop persistent tracked failures

- Severity: Medium retention defect
- Status: Open pending final verification
- Evidence: object keys with deletion tombstones were treated as known inventory, so a persistently failing tracked object could remain beyond the promised ceiling unless provider-native lifecycle enforcement was independently configured.
- Required remediation: force deletion past the ceiling where safe, require and verify a provider-native lifecycle backstop, and alert on old tombstones.

### RVI-009 — Therapist MFA enrollment needed a blocking portal flow

- Severity: High authorization integration defect
- Status: Open pending final verification
- Evidence: the backend began returning an enrollment-required state, but an intermediate portal draft did not carry that token field through `LoginView`/`App` and could proceed directly to patient views.
- Required remediation: block all patient-data views until TOTP enrollment completes, retain only the minimum in-memory enrollment state, and test registration and unenrolled-login flows.

### RVI-010 — Recovery clients retained obsolete downgrade-negotiation paths

- Severity: Medium security integration defect
- Status: Open pending final verification
- Evidence: after making recovery schemes explicit and failures uniform, client code and tests still recognized scheme-mismatch responses and weaker-scheme retry/default behavior.
- Required remediation: submit only the scheme encoded by the recovery kit, never retry a weaker scheme, and remove stale error allowlists and comments.

### RVI-011 — Recovery failure throttling reintroduced an enrollment oracle

- Severity: Medium authentication/privacy defect
- Status: Open pending final verification
- Evidence: an intermediate `/auth/recover` revision increments and enforces a username-keyed failure budget only after finding an active patient with a recovery kit. Distributed requests can therefore drive an enrolled username to a distinct 429 state while an unknown or unenrolled username continues through only the per-source limit.
- Required remediation: make throttling behavior indistinguishable for known, unknown, inactive, and unenrolled names (for example, a keyed decoy bucket derived from normalized input on every path), while preserving the same scrypt work and response envelope.

### RVI-012 — Retention could launder a deletion into a newly trusted prefix

- Severity: High audit-integrity defect
- Status: Open pending final verification
- Evidence: an intermediate `prune_access_logs` implementation authenticated the existing state row but advanced `first_retained_seq`/`first_retained_hash` to the first row after the cutoff before verifying that the old retained chain was intact. If an attacker deletes a middle/current row while an older row is eligible for retention, the sweep can delete the old prefix and seal the later row as the new boundary, erasing the gap that verification would otherwise detect.
- Required remediation: verify the complete pre-prune chain (including state and journal evidence) before any anchor advance/delete, fail the prune transaction closed on any discrepancy, and add a deleted-middle-row-plus-expired-prefix regression.

### RVI-013 — Journal compaction could lose concurrent appends

- Severity: High audit-integrity defect
- Status: Open pending final verification
- Evidence: request-time journal appends and daily `compact_audit_journal` rewrites were not serialized. Compaction can read the old file, a request can append to that inode, and `os.replace` can then publish the stale compacted copy without the committed line.
- Required remediation: serialize append and compaction across their complete file operations under the enforced single-process topology (or use an equivalent robust file-lock/rotation protocol), retain atomic replacement and durability calls, and exercise a deterministic append-versus-compaction race test.

### RVI-014 — A configured but unusable production audit journal could remain ready

- Severity: High operational-integrity defect
- Status: Open pending final verification
- Evidence: non-development configuration initially required only a non-empty journal path. Open/write failures were logged as best-effort and the service continued, with no startup writability proof or readiness/alert signal for a persistently missing, read-only, or full journal volume.
- Required remediation: validate the journal target and its durability boundary before serving in non-development environments, expose persistent append/compaction failures to readiness or a monitored metric, and test an unwritable/missing target without disclosing path contents.

### RVI-015 — Streamed access-log export lacked a stable membership check

- Severity: Medium data-portability correctness defect
- Status: Open pending final verification
- Evidence: the expanded account export paginated access-log rows by `(at, id)` but neither froze their membership nor included access-log retention in the export revision fence. A retention pass during a long export could delete not-yet-emitted rows and still allow a valid-looking, incomplete JSON bundle to finish.
- Required remediation: capture and verify stable access-log membership (for example, an initial expected count/range plus a final invariant, or a bounded snapshot mechanism), abort on concurrent retention/tampering, and add a between-pages deletion regression.

### RVI-016 — Re-granting a revoked share could silently restore voice scope

- Severity: High consent-scope defect
- Status: Open pending final verification
- Evidence: revocation cleared wrapped sharing keys but retained `Consent.share_voice`; the re-grant path reused the same row and did not reset that flag. A grant that previously allowed recordings could therefore be revoked and later reactivated with voice playback already enabled, without a new voice-specific toggle.
- Required remediation: preserve the historical voice state in the withdrawal event, reset live voice scope on revoke and re-grant, require an explicit fresh voice-scope action to enable it again, and add revoke/re-grant regressions.

### RVI-017 — Release integration probes used the pre-attestation registration schema

- Severity: High release-pipeline blocker
- Status: Open pending final verification
- Evidence: after registration began requiring `age_attestation`, the production release workflow's backup/restore seed still posted the old payload. It would receive 422 and never create the row used to prove restoration.
- Required remediation: update every CI/live/script registration fixture to send the exact versioned attestation literal and execute the production integration path.

### RVI-018 — `security.txt` validation accepted reserved example domains

- Severity: High release-gate defect
- Status: Open pending final verification
- Evidence: the release generator rejected only the exact strings `security@example.com` and `app.example.com`; its own passing fixture used `mindpattern.example.org`, even though `example.org` is reserved for documentation and cannot be a real deployment contact or canonical host. An operator could therefore publish a plausible-looking but unreachable disclosure channel while the release gate passed.
- Required remediation: reject reserved example/test/invalid/localhost hostnames (including subdomains), validate the `mailto:` address domain as well as HTTPS hosts, use non-reserved fixtures for success cases, and exercise both contact and canonical rejection paths.

### RVI-019 — Offline-queue eviction metadata escaped account erasure

- Severity: Medium privacy/correctness defect
- Status: Open pending final verification
- Evidence: the bounded web offline-queue remediation introduced the account-scoped key `mindpattern/queue.v1.evictions.<scope>`, while `web/src/localErasure.ts` recognized only `items`, `rejected`, and `quarantine` queue keys. The durable erasure tombstone therefore omitted the new counter, leaving user-scoped loss metadata behind after confirmed account deletion.
- Required remediation: include the eviction key in the same ownership/erasure contract, seed it in the exhaustive deletion regression, and prove that confirmed deletion removes it while interrupted deletion remains resumable.

### RVI-020 — `security.txt` validation still accepted local IP endpoints and bare reserved pseudo-TLDs

- Severity: High release-gate defect
- Status: Open pending final verification
- Evidence: after reserved documentation domains were rejected, `assertDeploymentHostname` still accepted loopback/link-local/private IP literals such as `127.0.0.1` and `[::1]`; it also rejected subdomains ending in `.test`, `.invalid`, and `.example` but not the bare hosts `test`, `invalid`, or `example`. Those values can pass syntax checks without providing the public, monitored operator contact promised by the release gate.
- Required remediation: require a genuine public deployment hostname for both contact forms and the canonical URL; reject IP literals, single-label/local names, and reserved pseudo-TLD roots as well as their subdomains; add regression cases for `mailto:` and HTTPS contacts plus the canonical URL.

### RVI-021 — Recovery throttling merged distinct case-sensitive account identifiers

- Severity: Medium authentication availability defect
- Status: Open pending final verification
- Evidence: the opaque recovery-failure bucket normalizes the supplied username with `strip().casefold()`, while registration accepts upper- and lower-case characters and account lookup compares the original value. Distinct valid accounts such as `Alice` and `alice` therefore share one failure budget; even whitespace variants of another account's exact name can spend its bucket.
- Required remediation: derive the opaque bucket from the exact identifier semantics used for account lookup (or consistently canonicalize registration, storage, login, and recovery as a separately migrated product decision), and add regressions proving distinct valid usernames cannot lock each other out while known/unknown responses remain indistinguishable.

### RVI-022 — Corrected transcript-translation terms reused the legacy journal-analysis consent version

- Severity: High consent-migration defect
- Status: Open pending final verification
- Evidence: the client disclosure is being corrected from dormant journal-pattern analysis to the active transcript-translation purpose, but `backend/app/services/llm.py` still defines `LLM_DISCLOSURE_VERSION = "v1"`. The processing-policy fingerprint includes that unchanged value, so an existing `v1` consent accepted under the materially different journal-analysis wording can remain current and authorize translation without the user accepting the corrected purpose and timing.
- Required remediation: assign the transcript-translation disclosure a new version/purpose identity, make every legacy journal-analysis consent stale for active translation, expose the new version consistently to clients, require fresh opt-in before dispatch, preserve the historical terms in consent events/export, and add migration/currentness and no-dispatch-with-legacy-consent regressions.

### RVI-023 — Corrected voice-upload terms reused the prior inaccurate disclosure version

- Severity: High consent-migration defect
- Status: Open pending final verification
- Evidence: the native and in-app voice disclosure is being corrected to state that audio uploads when recording stops, before review/save, and to surface provider retention/policy details; however, `backend/app/services/stt.py` still defines `STT_DISCLOSURE_VERSION = "v1"`. Existing consent recorded against the prior inaccurate timing language can therefore remain current after the material disclosure changes.
- Required remediation: bump the voice disclosure version, make prior consent stale until renewed, align server metadata and all clients, preserve the historical acceptance/withdrawal evidence, and test that old-version consent cannot authorize an STT dispatch.

### RVI-024 — Consent migration could manufacture an inaccurate historical voice scope

- Severity: Medium audit-evidence defect
- Status: Open pending final verification
- Evidence: the migration backfills every historical sharing `granted` event at `Consent.granted_at` while copying the row's current `share_voice` value. Voice scope can be enabled or disabled after the base grant, and the legacy row has no timestamp for that transition, so the new immutable event can falsely claim that voice access was accepted at the earlier grant time.
- Required remediation: never present unknown legacy history as observed fact; backfill the original grant with an unknown/null voice scope (or another explicitly marked migration representation), retain only state/times that can be proven, document the historical limitation, and test migration of an active grant whose voice scope changed after grant.

### RVI-025 — Malformed audit-journal evidence was silently discarded

- Severity: High audit-integrity defect
- Status: Open pending final verification
- Evidence: `_read_journal_evidence_unlocked` skips any line that does not split into five fields or whose sequence is not an integer, and it does not validate owner, sequence range, seal/MAC shape, or timestamp before treating a line as evidence. A truncated or deliberately corrupted line can therefore disappear without making readiness or chain verification fail; deletion of the corresponding database chain/state can then look like an owner that never existed.
- Required remediation: parse every non-empty journal line strictly, fail the journal health/readiness and verification path on malformed or truncated evidence, validate canonical owner/sequence/hash/MAC/time shapes, preserve the file for investigation, and add corrupt-line plus database-deletion regressions.

### RVI-026 — Audio lifecycle reconciliation materialized the full global inventory

- Severity: Medium availability/operations defect
- Status: Open pending final verification
- Evidence: both audio-store `inventory()` implementations build a complete list, while `reconcile_audio_inventory` also loads every current attachment key and deletion tombstone into in-memory sets/lists before processing. Per-account quotas do not bound the aggregate across all users or orphaned objects, so a periodic retention sweep can consume memory proportional to the entire object store and stall or terminate the API process.
- Required remediation: make reconciliation bounded and incremental with deterministic pagination/cursors (including fair progress past live/young objects), query matching database state in bounded batches, expose progress/backlog metrics, and test multi-page traversal without full-inventory materialization or starvation.

### RVI-027 — Backend failure paths logged account-linked identifiers

- Severity: Medium privacy/observability defect
- Status: Open pending final verification
- Evidence: a failed lifecycle deletion logged `audio lifecycle reconciliation deferred object %s` with an object key whose layout embeds owner and attachment identifiers. Independent review also found request/deletion paths logging raw `user.id`, `AudioAttachment.id`, or deletion-tombstone IDs on STT, object put/get, and deferred-delete failures. The audit-maintenance verification failure path in `backend/app/main.py` independently logs the raw affected `uid`. These values leak account-linked processing and retention metadata into ordinary application logs contrary to the no-content/minimal-metadata posture.
- Required remediation: log only aggregate counts and allowlisted safe error classes, never object keys, owner IDs, attachment IDs, or tombstone IDs, and add logging regressions that exercise provider, object-store, deletion, and audit-verification failures and assert every identifier is absent.

### RVI-028 — Global question retention used an unbounded startup delete

- Severity: Medium availability/operations defect
- Status: Open pending final verification
- Evidence: the new global question purge runs `DELETE` across every expired question row in a single transaction, and the first retention pass is awaited during application startup. A large dormant legacy backlog can therefore create an unbounded lock/WAL transaction and delay or prevent readiness.
- Required remediation: purge deterministically in bounded batches with observable catch-up progress and prompt follow-up while a backlog remains, preserve the retention deadline at steady state, and test that a backlog larger than one batch is eventually removed without a single unbounded startup transaction.

### RVI-029 — The remediated iOS privacy manifest still omitted retained activity and other metadata

- Severity: High release-compliance defect
- Status: Open pending final verification
- Evidence: the manifest now declares linked user ID, health, other user content, and audio, but the service also retains user-linked access/action history for up to 730 days and account/consent/age-attestation metadata. Apple's current taxonomy identifies retained app-interaction events as `NSPrivacyCollectedDataTypeProductInteraction` and provides `NSPrivacyCollectedDataTypeOtherDataTypes` for collected data without a closer category; neither is declared.
- Required remediation: add the applicable linked, non-tracking App Functionality categories to the manifest, reconcile the same inventory in the privacy-policy template and App Store Connect answers, validate the plist/package, and retain operator review because repository changes cannot submit or certify the store declaration.

### RVI-030 — Offline-queue eviction metadata bypassed the local write-generation fence

- Severity: Medium privacy/correctness defect
- Status: Open pending final verification
- Evidence: the bounded queue added `mindpattern/queue.v1.evictions.<scope>`, and account erasure was updated to recognize that key, but `web/src/kvstore.ts` still treated only `items`, `rejected`, and `quarantine` queue keys as account-owned. A delayed queue operation could therefore write eviction metadata after the account's deleted-generation fence was committed, recreating account-scoped state after confirmed local erasure.
- Required remediation: include eviction metadata in the same owner/generation and rotation transaction contract as every other queue record, and add a regression proving stale or post-erasure writes are refused rather than recreating the key.

### RVI-031 — Audit retention had unauthenticated link-only pruning paths

- Severity: High audit-integrity defect
- Status: Open pending final verification
- Evidence: `_prune_access_log_once` catches an invalid/unavailable audit MAC key ring, substitutes an empty key map, and continues into `prune_access_logs`. Independently, `create_pairing_code` calls `prune_access_logs` without passing any authenticated MAC keys even when the application has a valid configured ring. Both paths turn the pre-prune check into link-only SHA-256 verification, under which a database writer can recompute altered rows and have retention advance the trusted prefix over them. Normal startup validation does not protect these call sites.
- Required remediation: require authenticated keys at every retention entry point, abort maintenance before any mutation when they are unavailable, remove request-path pruning or supply its validated key ring, surface scheduled-maintenance failures through readiness/metrics, and add regressions proving no row or anchor changes under missing/invalid-key faults.

### RVI-032 — Audit maintenance remained globally unbounded despite its durable cursor

- Severity: Medium availability/operations defect
- Status: Open pending final verification
- Evidence: the round-robin sweep loads every `AuditChainState.user_id`, every journal owner, and the journal's `(owner, sequence)` history into in-memory collections before selecting 500 owners. Separately, pre-prune verification can re-read the complete journal once per owner, and compaction begins with `list(handle)`. User count and audit events within the retention window have no aggregate repository-enforced bound, so startup/daily maintenance can consume memory or I/O proportional to the whole deployment even though the visible verification batch is capped.
- Required remediation: page owner selection at the database/file boundary, share or externally spool journal evidence without per-owner rescans, stream compaction with bounded working memory, keep corruption/conflicting-seal detection fail-closed, and add multi-page/resource-bound regressions.

### RVI-033 — Other account-scoped browser metadata could also be recreated after erasure

- Severity: Medium privacy/correctness defect
- Status: Open pending final verification
- Evidence: the local deleted-generation fence recognizes encrypted drafts and three queue collections, but account-scoped IndexedDB keys for measure cadence, threshold notices, analysis sequence high-water marks, and rotation checkpoints/salts/seeds were outside that ownership policy. In addition, rotation pending-salt, rekey-hint, and per-account onboarding markers are written through an unfenced `localStorage` seam. Erasure enumerates and removes the current values, yet a delayed callback or another tab can write one again after the erasure tombstone is removed because those storage paths do not consistently associate the key with the durably deleted owner. Some values reveal health-feature interaction timing or account presence; others are key-lifecycle security state.
- Required remediation: define one exhaustive account-key ownership registry used by writes, rotation, and erasure across IndexedDB and `localStorage`; require a current permit for key-bound records and at minimum reject all writes for a durably deleted generation; move security-critical owner records behind the durable transactional fence, retain explicit exceptions only for the erasure protocol itself, and test delayed/cross-tab writes for every account-scoped key family.

### RVI-034 — Remote account deletion locked other clients but left their local personal data behind

- Severity: High privacy/erasure defect
- Status: Open pending final verification
- Evidence: both clients recognize an authenticated `410 account_deleted`/`gone` as account death from another device, but their global handlers only clear the session and lock the in-memory vault. The web handler never stages/confirms `localErasure`; the mobile unauthorized hook receives no error classification and only calls `vault.lock()`. Encrypted drafts, offline queues, recordings, health-adjacent stamps, consent markers, and other account-scoped records on that device can therefore remain indefinitely even after the client has authoritative server confirmation that the account was erased. Ordinary `401` expiry must not trigger this behavior, and unrelated resource-level `410` responses must remain excluded.
- Required remediation: carry the authenticated account-death classification and captured owner/origin into each global session-death funnel; durably fence new writes, run the same retryable local-erasure inventory used by an on-device deletion, preserve a cleanup checkpoint across interruption, surface incomplete cleanup without restoring access, and add remote-delete, ordinary-401, unrelated-410, restart-resume, and in-flight-write regressions.

### RVI-035 — Mobile account erasure neither cleared nor fenced every account-scoped record

- Severity: Medium privacy/correctness defect
- Status: Open pending final verification
- Evidence: mobile erasure calls `markAccountDeleted` and waits for operations registered through `commitLocalWrite`, but several account-scoped writers bypass that lifecycle entirely and write directly to `AsyncStorage` or `secureStore`. Examples include onboarding and key-shipment consent markers, daily/check-in reminder preferences, last-measure dates, crisis/threshold stamps, the Health mirror preference, and the offline-unlock proof. A write that has passed its read/decision point before cleanup can commit after its matching clear operation and recreate health, consent, account-presence, or security state after erasure; it is also absent from `waitLocalWriteCommits`. Separately, the cleanup inventory omits `mindpattern.rotatePendingSalt.<userId>`, and biometric cleanup deliberately writes but does not later remove `@mindpattern/biometric.legacy-disabled.<userId>`, so even a race-free successful pass can retain account-linked key-lifecycle metadata.
- Required remediation: route every account-scoped mobile mutation through one active-owner/generation permit and tracked-commit contract (with an explicit administrative-erasure lane), make the inventory exhaustive, clear or privacy-preservingly replace intentional compatibility markers after their purpose ends, retain the deleted fence for the process lifetime and durable cleanup lifecycle, and add deterministic inventory plus delayed-write-versus-erasure tests for each storage family.

### RVI-036 — Mobile origin switching used an incomplete account-data inventory

- Severity: High tenant-isolation/privacy defect
- Status: Open pending final verification
- Evidence: `api/client.ts:isOriginBoundKey` is described as covering every per-account/per-origin value, but its allowlist omits multiple key families: onboarding and key-shipment consent, reminder and measure-reminder preferences, last-measure and threshold stamps, Health mirror settings, entry-v2 bounds, the pending rotation salt, local-rekey checkpoints, origin-scoped journal/audio/offline queues, and biometric state. Many omitted records are keyed only by `userId`, so switching to another server that assigns the same identifier can inherit old consent/security/health behavior; origin-encoded records do not cross-read but remain as undisclosed personal data. The origin-change hook aborts flushes and locks memory but does not close this disk inventory gap.
- Required remediation: replace the duplicated prefix allowlist with one exhaustive registry shared by all mobile storage producers, erasure, and origin transition; remove or explicitly preserve each old-origin artifact under a documented policy, cancel old-origin notifications, prevent identifier-collision reuse, and add an inventory test that seeds every account storage family before a server switch and proves no old-origin state is readable or orphaned afterward.

### RVI-037 — Asynchronous web sign-out cleanup could delete state from the next session

- Severity: Medium security/correctness regression
- Status: Open pending final verification
- Evidence: after onboarding and the post-password-change rekey warning moved from synchronous `localStorage` to IndexedDB, `App.signOut` launches their `kv.removeItem` operations with `void Promise.all(...)` and immediately returns to the login view. A rapid sign-in to the same account can therefore enter a new session while the old session's unawaited cleanup is still pending; that cleanup can then delete a newly written onboarding marker or, more importantly, the new session's `rekeyHint` that tells the user to rotate a potentially compromised data key.
- Required remediation: make sign-out cleanup an owned transition that must settle before a replacement session can publish account-scoped state (while still locking plaintext immediately), bind cleanup to the retiring session, and add a deterministic delayed-IndexedDB sign-out/sign-in regression proving the successor's records survive.

### RVI-038 — Retained sharing history was only partly paged and remained unbounded in critical paths

- Severity: High availability/sharing-correctness defect
- Status: Open pending final verification
- Evidence: consent rows are unique per patient/therapist pair but only **active** relationships are capped; the number of distinct revoked lifetime relationships remains unbounded, and append-only grant/revoke/voice `ConsentEvent` history is likewise unbounded over an account lifetime. Patient `GET /consents` was changed to return a 200-row page, but shipped clients still treat one response as the complete set, so recent revoked history can displace older active grants and cause incomplete sharing UI or missed key re-wraps. Therapist `GET /therapist/patients` still materializes and audits the entire lifetime list and acquires per-patient locks for active rows. Account export materializes every consent ID into `share_snapshot` before streaming, and corpus rotation builds an in-memory set of every owned consent ID before validating active wraps. Finally, patient and therapist deletion rely on database cascades across the unbounded retained consent/event history (and a therapist's retained per-patient notes), so an erasure request can still become an arbitrarily large transaction. Requiring each counterpart to have registered slows abuse but does not impose a repository-enforced aggregate bound.
- Required remediation: define a stable paginated/snapshot contract for retained relationships, update every web/mobile/portal caller and rotation validator to walk it with page/byte/restart caps and deduplication, keep active grants from being silently omitted, make therapist audit work bounded per page, and freeze export/rotation membership with a bounded revision, database-side validation, or disk-spooled snapshot rather than an in-memory all-ID list. Define and enforce a documented lifetime-retention/cardinality policy for revoked relationships, consent events, and retained clinician notes, or move account erasure to an immediately inaccessible, durable, retryable bounded deletion state machine that cannot strand rights requests. Add histories larger than one page, concurrent revoke/re-grant, active-row-displacement, rotation, export, and over-batch patient/therapist deletion resource-bound regressions.

### RVI-039 — Client diagnostic logging exposed account-linked identifiers or unconstrained exception text

- Severity: Medium privacy/observability defect
- Status: Open pending final verification
- Evidence: `portal/src/views/PatientView.tsx` logs the server note identifier when note-history decryption fails. `mobile/src/ErrorBoundary.tsx` logs `String(error)` for an arbitrary render exception; the boundary cannot prove that every present or future thrown message excludes user-supplied or health-related values. Browser/device consoles can be collected by extensions, connected diagnostic tooling, or platform crash/log pipelines, so “local only” is not a reliable minimization boundary.
- Required remediation: emit only a fixed, non-identifying failure class at these client boundaries (or no diagnostic at all), never note/account IDs or arbitrary exception messages, and add regressions that trigger both failures and assert sentinel identifiers/content are absent from console output.

### RVI-040 — Bounded audit maintenance had no bounded-time catch-up schedule

- Severity: High retention/integrity operations defect
- Status: Open pending final verification
- Evidence: the resource-bounded draft caps each pass at `AUDIT_MAINTENANCE_OWNER_BATCH = 500` owners and `AUDIT_PRUNE_TOTAL_ROW_BATCH = 5_000` expired rows, while `_access_log_retention_sweep` normally invokes it only once per 24 hours. The return value and short catch-up interval track only the question-retention backlog. Account/owner cardinality and global access-log write rate are not repository-bounded, so more than 5,000 newly expired rows per day can make the deletion backlog grow forever; one million owners would take roughly 2,000 daily passes to receive one verification opportunity. A durable cursor prevents starvation in ordering but does not establish a finite retention or detection lag.
- Required remediation: keep each transaction/page bounded, but return and expose audit prune/verification backlog separately, schedule prompt cooperative follow-up pages until caught up (with a time/rate budget and ordinary request headroom), retain durable independent cursors where work classes can advance at different rates, and alert on oldest-unprocessed age/backlog. Add more-than-one-page tests proving deterministic eventual drain and owner coverage without restoring an unbounded startup transaction.

### RVI-041 — Auxiliary retention cleanup still used unbounded global deletes, including on a request path

- Severity: Medium availability/operations defect
- Status: Open pending final verification
- Evidence: `create_pairing_code` deletes every pairing-code row older than the retention window before issuing a new code. The daily `_prune_access_log_once_with_evidence` transaction independently deletes all expired pairing codes, all expired durable token revocations, and all rekey journals whose owner no longer exists. None of those statements has a row/transaction bound, and pairing-code generation is an interactive request path. Aggregate deployment cardinality is not bounded, so a legacy backlog or delayed maintenance pass can turn one request/startup sweep into an arbitrarily large lock/WAL transaction.
- Required remediation: remove global retention work from the pairing-code request, delete deterministic ID-keyset batches in scheduled maintenance, expose per-class backlog/oldest-age and use bounded catch-up scheduling, and add over-batch regressions proving ordinary pairing issuance does not perform global cleanup while every backlog eventually drains.

### RVI-042 — Request metrics rendered an invalid concatenated Prometheus sample

- Severity: High observability defect
- Status: Open pending final verification
- Evidence: an intermediate `MetricsRegistry.render` implementation placed two adjacent formatted `mindpattern_requests_total{status="..."}` samples inside one `lines.append`, with no newline between them. As soon as any request-status family existed, the exposition line became two metric samples concatenated together, which a Prometheus parser/scrape rejects; that can suppress the very alerts expected to detect the other remediation failures.
- Required remediation: emit exactly one sample per line and add an end-to-end/text-parser regression with non-empty request families plus every newly added maintenance metric, rather than validating only substring presence.

### RVI-043 — Interrupted mobile remote-deletion cleanup could restore a stale logged-in session on restart

- Severity: High privacy/session-lifecycle defect
- Status: Open pending final verification
- Evidence: `eraseDeletedAccountLocals` clears the durable token/user/username only after every local cleanup task succeeds. If storage, notification, file, or biometric cleanup fails, the retry checkpoint remains **and so do the credentials**. On cold start, `mobile/src/store.tsx` launches `api.isLoggedIn()` and `retryPendingAccountErasures()` concurrently; the former can observe the retained token and publish `loggedIn` before the latter retires or again fails the cleanup. That can re-expose the deleted account's unlock/navigation path, and it contradicts the requirement that incomplete cleanup remain retryable without restoring account access.
- Required remediation: retire the authenticated credentials immediately through a deletion-administrative transition that does not depend on the success of personal-data cleanup, preserve the captured owner/username/origin only in the opaque retry checkpoint, and order cold-start authentication behind pending-erasure recovery/fencing. Add deterministic partial-failure plus restart races proving the app never publishes `loggedIn`, never reinstalls a deleted owner's data key, and still retries all remaining local/native cleanup.

### RVI-044 — Generic `410 gone` responses could trigger destructive whole-account local erasure

- Severity: High privacy/data-loss defect
- Status: Open pending final verification
- Evidence: the web and mobile generic request funnels classify any authenticated `410` whose code is `account_deleted` **or `gone`** as authoritative account death. `gone` is also the backend's status-default code for a 410 response and is not intrinsically account-scoped; current recording-expiry routes use `audio_expired`, but a legacy or future resource-level endpoint can legitimately fall back to `gone`. The classifier has the request path but does not constrain this compatibility value, so an unrelated response can fence and delete every local record for the account.
- Required remediation: reserve whole-account erasure for the explicit stable `account_deleted` code; if legacy `gone` compatibility is required, accept it only on an allowlisted account-lifecycle operation whose semantics prove account death, never in the generic request funnel. Add web/mobile regressions for arbitrary-path `410 gone`, `410 audio_expired`, true `410 account_deleted`, and the explicit account-delete/export compatibility path.

### RVI-045 — The sharing grant path added a new consent object to one ORM session twice

- Severity: Low implementation/integration defect
- Status: Open pending final verification
- Evidence: an intermediate `grant_consent` revision invoked `session.add(consent)` twice for the same newly constructed `Consent` before its flush. SQLAlchemy normally treats repeated addition of the same object identity as idempotent, so this did not independently prove a duplicate database row, but the redundant state transition obscured the transaction contract in a security-sensitive grant path and made future refactors/mocks more error-prone.
- Required remediation: add the new consent exactly once, retain the single atomic flush/commit with pairing-code consumption, consent event, revision advance, and audit row, and keep a focused new-grant regression proving one relationship/event/audit fact is produced.

### RVI-046 — The server did not durably signal account death to clients that were offline during deletion

- Severity: High distributed-erasure defect
- Status: Open pending final verification
- Evidence: `_authenticate_user` verifies the bearer and then returns the ordinary 401 failure whenever its `User` row is missing/inactive. Account deletion hard-deletes that row. The explicit `410 account_deleted` responses exist only in operations that authenticated before deletion and then discover the missing row/FK while already inside a lifecycle fence. A second device that was offline—or simply issued no request during that narrow race—therefore sees only 401 on its next request; correctly, clients must not erase local data for an ordinary expired/revoked 401, so the new RVI-034 cleanup funnel never runs and that device can retain local personal data indefinitely.
- Required remediation: after signature/purpose validation, distinguish a genuinely deleted account using a minimal durable, integrity-protected deletion tombstone or the retained terminal audit fact, bounded to at least the maximum bearer/offline-client decision window and containing no unnecessary PII. Return explicit `410 account_deleted` only for a bearer whose subject is proven deleted; keep unknown, expired, forged, logged-out, and epoch-invalid tokens on the uniform 401 path. Add deletion-while-offline, restart, tombstone-retention-boundary, forged-UID, ordinary-expiry, and multi-device cleanup regressions.

### RVI-047 — The retained consent-event ceiling could be bypassed with repeated no-op withdrawals

- Severity: Medium retention/availability defect
- Status: Open pending final verification
- Evidence: the intermediate `add_consent_event` helper checks history cardinality only when `permission_increasing=True`; withdrawal events are always appended to preserve a safety reserve. Account-level LLM/voice setters and some sharing withdrawal/toggle paths also still add `ConsentEvent` directly. Repeatedly submitting “disabled” for an already-disabled consent (or an equivalent no-op scope reduction) can therefore append unlimited withdrawal rows without consuming any permission-increasing capacity, defeating the new finite cascade/export bound.
- Required remediation: route every consent-event producer through one bounded append contract, make repeated requests that do not change effective authorization idempotent (no new event/audit revision), reserve enough finite capacity for every **real** first withdrawal implied by the bounded active state, and fail closed on permission increases before that reserve. Add over-limit and repeated-no-op tests for LLM, voice, grant/revoke, voice-sharing, and migration/import paths, while proving an actual withdrawal always remains possible.

### RVI-048 — Multi-worker grants could race past retained-sharing and active-caseload ceilings

- Severity: Medium availability/integrity defect
- Status: Open pending final verification
- Evidence: the in-progress grant path counts the patient’s and therapist’s retained/active relationships before `add_consent_event` acquires a database `FOR UPDATE` lock on the patient row. The application’s sharing locks are process-local. Two or more workers granting different pairs can therefore all observe a value below the ceiling, serialize only after those stale decisions, and each commit; the therapist-side ceiling is not protected by a therapist database-row lock at all. The same ordering makes the consent-event ceiling decision occur too late to validate the earlier relationship-limit reads. This defeats the hard cardinality bound used to justify bounded listing/export/deletion.
- Required remediation: lock both authoritative account rows in one fixed database order before any relationship/event cardinality read or permission-increasing mutation, re-read all limits while those locks are held, and retain database uniqueness as a separate invariant. Add genuine multi-session/PostgreSQL races at `limit - 1` for one patient with multiple therapists and one therapist with multiple patients, proving at most the configured number commits and losers fail without consuming pairing codes or partially advancing revisions/audit history.

### RVI-049 — Paged account export rescanned the complete audit history before every page

- Severity: Medium availability/data-rights defect
- Status: Open pending final verification
- Evidence: the in-progress v3 export captures an access-log `(count, min(chain_seq), max(chain_seq))` aggregate and `check_access_log_snapshot` recomputes that full aggregate before every 200-row access-log page. The retained log can contain a large number of events over two years. Even though each response page has bounded memory, an `N`-row history now performs roughly `N / 200` full-history aggregate scans in addition to the page reads, producing quadratic database work and making a valid subject export increasingly likely to monopolize resources or fail its delivery window.
- Required remediation: freeze audit membership with bounded/indexed metadata (for example immutable minimum/maximum sequence bounds plus strict contiguous-sequence checks, or a maintained revision/anchor), scan each row at most once with an indexed keyset, and detect concurrent prefix pruning without a repeated whole-history aggregate. Add query-count/plan or instrumented regressions across multiple pages and a concurrent-prune case proving linear traversal, complete-or-fail behavior, and bounded per-page work.

### RVI-050 — A new owner’s first audit append synchronously scanned the global journal

- Severity: High request-availability defect
- Status: Open pending final verification
- Evidence: when `append_access_log` finds no `AuditChainState`, it calls `journal_owner_status`, which opens and parses the complete append-only journal synchronously inside the async request path. New patient/therapist registration necessarily starts without a state row. Journal compaction deliberately retains at least the newest seal for every historical owner, so the first audited action for account `N` performs work proportional to all prior owners/events and blocks the event loop while doing it. The disk-spooled index used by scheduled maintenance does not protect this path.
- Required remediation: make new-chain authorization an indexed, bounded operation without weakening deletion detection—for example maintain and transactionally query a durable/integrity-protected owner registry or a safely updated disk-backed journal index, while allowing only an explicitly proven fresh-account transaction to create a new chain. Never perform a full journal scan on an interactive request or hold the event loop during file I/O. Add a large-journal first-append regression that instruments lines/queries and proves constant/logarithmic request work, plus deleted-state/journal-only-owner tests that remain fail closed.

### RVI-051 — A bounded audit-prune batch still verified an owner’s complete retained chain

- Severity: High maintenance-availability defect
- Status: Open pending final verification
- Evidence: `prune_access_logs` limits deletion to 500 rows per owner and 5,000 rows globally, but calls `verify_access_log_chain` first; that verifier streams every retained row for the owner with no row/time ceiling. The separate round-robin verification pass has the same whole-owner walk. For a large valid chain, one supposedly cooperative pass can still monopolize the event loop/database for an arbitrary duration. Repeating the full walk before each 500-row prefix deletion also makes catch-up approximately quadratic in that owner’s history size.
- Required remediation: verify only the bounded prefix about to be pruned against the authenticated retained-prefix anchor, its row MACs/links, the first surviving row, and the authenticated head state; advance the anchor atomically with deletion. Make the independent full-chain audit incremental with a durable MAC-protected `(owner, snapshot head, next sequence, prior hash)` checkpoint and a fixed row/time budget, restarting safely when the head/snapshot changes and eventually cycling every owner. Add large single-owner tests proving a strict rows-per-pass ceiling, linear eventual drain/full verification, corruption detection on page boundaries/already-verified regions, and no anchor advance on failure.

### RVI-052 — Every cooperative audit catch-up page rebuilt the complete journal index

- Severity: High maintenance-availability defect
- Status: Open pending final verification
- Evidence: `_prune_access_log_once` calls `build_journal_evidence_index` at the start of every pass. A pass handles at most 500 owners/5,000 pruned rows; while backlog remains, `_access_log_retention_sweep` invokes another pass after one second. Each pass rereads every journal line and recreates the complete disk-spooled SQLite index. A million-owner sweep therefore performs roughly 2,000 complete global-journal scans even before per-owner database verification, defeating the intended cooperative bounded-time catch-up and causing superlinear disk/CPU load.
- Required remediation: maintain or safely reuse an indexed journal view across catch-up pages, update it atomically after fsynced appends/compaction, and invalidate/rebuild only on a detected file identity/generation change or corruption. The reusable index must remain disk-bounded, mode-restricted, crash-recoverable, and must never hide a conflicting seal or malformed/truncated line. Add multi-page instrumentation proving one full source scan per stable catch-up generation (not per page), concurrent append/compaction invalidation tests, and cleanup/restart tests for the index artifact.

### RVI-053 — Local audio inventory pagination rescanned the complete object tree for every page

- Severity: Medium self-hosted availability defect
- Status: Open pending final verification
- Evidence: `LocalAudioStore.inventory_page` uses `heapq.nsmallest(limit + 1, self.root.glob("audio/**/*.enc") filtered after the cursor)`. The heap bounds retained path strings, but `glob` still visits the complete tree on every call. `reconcile_audio_inventory` persists a cursor and requests one page per sweep, so a full `N`-object cycle performs approximately `N / INVENTORY_BATCH` complete directory traversals. The S3 adapter uses genuine provider pagination; the supported local/self-host adapter does not.
- Required remediation: give the local store a durable, crash-reconciled ordered manifest/index or a directory traversal scheme whose cursor resumes without revisiting the complete earlier/global tree, while preserving orphan discovery, deterministic progress under concurrent put/delete, and bounded memory. Add filesystem-walk instrumentation over multiple pages proving near-linear total visits, plus restart, missing-file, new-object-before/after-cursor, and index-rebuild corruption tests.

### RVI-054 — A transient startup-maintenance failure could hold readiness down for 24 hours

- Severity: High recovery/availability defect
- Status: Open pending final verification
- Evidence: `_prune_access_log_once` marks `audit_maintenance_healthy = False` on a failure. The awaited startup caller catches that failure, but the initial `audit_prune_backlog`, `audit_verification_backlog`, and `auxiliary_retention_backlog` flags remain false. `_access_log_retention_sweep` therefore classifies the next iteration as ordinary steady state and sleeps `ACCESS_LOG_SWEEP_INTERVAL_SECONDS` (24 hours) before retrying. `/readyz` remains 503 even if the database, MAC key source, or journal recovered seconds later.
- Required remediation: represent maintenance failure/retry-needed as its own state, schedule a prompt bounded retry with capped backoff and jitter while preserving request headroom, clear the unhealthy latch only after a complete authenticated pass, and keep failure/backoff metrics alertable. Add a startup transient-failure/recovery test proving no 24-hour sleep path, plus persistent-failure tests proving no tight loop and no false-ready interval.

### RVI-055 — The constant-time fresh-chain marker was not authenticated

- Severity: High audit-integrity defect
- Status: Open pending final verification
- Evidence: the in-progress RVI-050 remediation replaces an interactive full-journal scan with `users.audit_chain_initialized`, but that boolean is ordinary mutable database state and is not covered by an out-of-database MAC. An attacker capable of deleting an owner's `AuditChainState` and `AccessLog` rows can also clear this bit; the next interactive append then treats the owner as genuinely fresh and creates a new genesis chain without consulting the historical journal. Detection may be delayed until maintenance and can disappear altogether after retention-aligned journal compaction removes the old owner evidence.
- Required remediation: authenticate the durable ever-initialized/fresh-owner decision with the audit MAC key (including stable owner identity and an explicit version), or derive it from another constant-time integrity-protected registry that is atomically established with account/chain creation. A missing, malformed, unverifiable, or downgraded marker must fail closed without synchronous journal I/O. Add database-tamper tests covering state/log deletion plus marker clearing, legitimate first append, migration backfill/sealing, key rotation, and deletion/recreation boundaries.

### RVI-056 — Mobile plaintext voice scratch files could survive a crash or account erasure

- Severity: High local-privacy defect
- Status: Open pending final verification
- Evidence: recording uses Expo Audio's cache-backed native `recording-*` files and kept-recording playback writes decrypted bytes to `cacheDirectory/voice-*.m4a`. Normal stop/unmount paths delete them, but an OS kill or process crash bypasses those callbacks. Cold-start recovery, account erasure, and origin retirement inventory the persistent encrypted audio queue under `documentDirectory` but never scrub the native recording directories or playback cache pattern, so plaintext audio can remain in the app sandbox until discretionary OS cache eviction.
- Required remediation: centralize voice-scratch ownership, use cryptographically unpredictable owner-scoped playback paths, scrub all app-created playback and Expo Audio recording scratch at cold start before authentication, and repeat the scrub during account erasure/origin retirement. Fail closed before creating a new scratch file if the cache root is unavailable. Add interrupted-recording/playback restart tests, partial-delete retry tests, account-deletion/origin-switch tests, and regressions proving normal release remains idempotent without deleting unrelated cache content. Document the unavoidable live-playback plaintext window and platform sandbox/data-protection boundary.

### RVI-057 — Portal draft write chains could cross test-backend generations and make lifecycle assurance nondeterministic

- Severity: Medium assurance/lifecycle defect
- Status: Open pending final verification
- Evidence: `portal/src/noteDrafts.ts` retains per-draft promise chains in a module-global map, while `portal/tests/helpers/setup.ts` replaces the key-value backend before every test without first draining those chains. A delayed write queued by an earlier mounted chart can therefore execute after the backend swap and publish the earlier test's encrypted draft into the next test's otherwise fresh store. The full portal suite reproduced this as the lifecycle regression `does not create a note after the chart unmounts during durable draft publication`: the new test expected `private pending creation` but read the stale prior-test value `general draft`; the same test passed in isolation, confirming order-dependent cross-lifecycle contamination.
- Required remediation: provide an explicit test lifecycle contract that drains all outstanding encrypted draft writes before replacing the backend, then clears settled chain bookkeeping without weakening production per-draft serialization. Add a deterministic cross-backend-generation regression and rerun the affected lifecycle test repeatedly and within the complete portal suite, proving an earlier test's delayed draft cannot overwrite the successor backend.

### RVI-058 — New non-secret release artifacts made the pinned secret-scanning gate fail

- Severity: Medium CI/supply-chain assurance defect
- Status: Open pending final verification
- Evidence: the pinned Gitleaks 8.30.1 working-tree scan reports two `generic-api-key` findings: the `PRIVACY_POLICY_TEMPLATE.md` documentation link at `docs/OPERATOR_PACK.md:13` and the public CocoaPods `React-cxxstableapi` checksum at `mobile/ios/Podfile.lock:2285`. Neither value is a credential, but both files are part of the remediation output and would make the required working-tree/history secret gate fail once submitted, preventing the repository from accepting otherwise valid release controls.
- Required remediation: add narrowly scoped, reviewed allowlist rules that require both the exact file and exact non-secret syntax; do not exempt either whole file, documentation generally, lockfiles generally, or arbitrary hexadecimal values. Re-run both full-history and working-tree scans with the exact version/checksum-pinned scanner and retain a planted-real-secret regression that remains detectable.

### RVI-059 — Account-deletion consent purge could remove sharing rows without advancing an exhausted counterpart revision

- Severity: High sharing/snapshot-integrity defect
- Status: Open pending final verification
- Evidence: the consent phase in `backend/app/services/account_deletion.py` updates counterpart revisions only where the revision column is below `2**63 - 1`, then unconditionally deletes the selected consent IDs. If an active counterpart is already at the maximum revision, its update affects zero rows but the consent can disappear in the same transaction. A client using the expected-revision contract could therefore observe changed sharing membership under an unchanged revision, defeating snapshot and cache invalidation guarantees.
- Required remediation: lock the bounded set of selected counterpart `User` rows before mutation; if any active counterpart revision is exhausted, fail that purge page before deleting any consent. Otherwise, bump every active counterpart revision and delete the bounded consent page atomically. Add max-revision/no-delete regressions in both patient-to-therapist and therapist-to-patient deletion directions.

### RVI-060 — Sharing-list finalization could race logical retirement and return a retired counterpart under an unchanged revision

- Severity: High erasure/privacy and snapshot-integrity defect
- Status: Open pending final verification
- Evidence: `backend/app/api/consents.py:list_consents` and `backend/app/api/therapist.py:list_patients` probe for inactive relationships only before their paged query. Account retirement can commit after that probe, while the counterpart revision is not advanced until the later consent-purge phase. The patient list can then render a pre-scrub therapist row; the therapist list can cache and render a revoked patient's username without holding that patient lock, and active rows can race around the bulk page. The response can disclose stale identity/key-adjacent sharing data and page membership after logical erasure while the caller's expected revision still matches.
- Required remediation: repeat the inactive-relationship existence probe at the final revision fence after all awaited work and immediately before response rendering/return, and return `collection_changed` if any inactive relationship remains. If bounded purge has already removed the row, require its atomic counterpart revision bump to detect the membership change. Add deterministic retirement-race tests for both list directions, including revoked therapist history.

### RVI-061 — Staged patient erasure did not fence direct therapist-note routes

- Severity: High erasure/privacy defect
- Status: Open pending final verification
- Evidence: immediate logical retirement leaves `TherapistNote` and its revision rows for bounded background purge, but direct note target, update, rekey, revision-read, and delete queries selected by note or patient IDs without joining the patient `User` under an `is_active = true` condition. Critical rereads also lacked a database row lock coordinated with deletion. A therapist with a formerly active relationship could therefore read or mutate retained encrypted-note state after the patient received deletion success but before the worker reached the note phases, and an in-flight mutation could race retirement. Logical erasure was not immediate for clinician-note ciphertext/history, and post-retirement child writes could delay or complicate physical purge.
- Required remediation: join the patient `User` and require active status on every direct note target/query; use `FOR UPDATE` on authoritative mutation and revision rereads so they serialize with the deletion parent-row lock; make missing or inactive targets fail closed. Add staged-deletion direct-read and in-flight mutation regressions.

### RVI-062 — Sharing mutations could target a logically retired therapist and recreate scrubbed state

- Severity: High erasure/privacy and authorization defect
- Status: Open pending final verification
- Evidence: the revoke and voice-sharing mutation paths in `backend/app/api/consents.py` select `Consent` without joining the therapist `User` under an `is_active = true` condition. Between therapist logical retirement and bounded consent purge, a patient can therefore mutate the inert relationship; the voice path can even increase its scope. Both revision helpers can increment the freshly scrubbed inactive therapist's `patients_revision` from zero, recreating activity metadata after deletion success.
- Required remediation: require an active therapist for permission-increasing or toggle operations, define withdrawal semantics against a retired counterpart explicitly, and never mutate an inactive counterpart's revision. Add staged-therapist-deletion regressions for revoke and voice-scope mutation.

### RVI-063 — Insight recomputation and key rotation treated retired therapists as active

- Severity: High erasure/privacy and availability defect
- Status: Open pending final verification
- Evidence: summary recomputation reads active `Consent` rows and later updates them without requiring an active therapist `User`. Therapist retirement can commit between that read and write, after which recomputation stores new summary ciphertext and bumps the inactive therapist revision. Key rotation likewise validates active consent rows for inactive therapists, so a retired therapist can block an unrelated patient's rotation until the bounded consent purge eventually reaches that relationship.
- Required remediation: join and filter active therapist users during recomputation selection, guard the update with an active-owner existence condition, and exclude inactive therapists consistently from rotation selection and validation. Add retirement-interleaving and staged-deletion regressions proving no ciphertext/revision is recreated and no dead relationship blocks rotation.

### RVI-064 — Streamed patient export could emit retired therapist identity under an unchanged snapshot

- Severity: High erasure/privacy and export-integrity defect
- Status: Open pending final verification
- Evidence: account-export share pages join the therapist `User` without checking `is_active` or taking therapist sharing locks. Therapist retirement can commit after the export snapshot check—which locks only the patient—while a page is being assembled; cached pre-scrub username or display name can then be yielded, while the patient's `consents_revision` advances only during later consent purge. Eventual physical `User` removal also silently changes membership because the inner join drops retained history. The export can therefore disclose identity after logical erasure and produce an internally valid-looking but temporally inconsistent share snapshot.
- Required remediation: define the deleted-therapist export-history policy; filter active users and apply a final inactive/revision fence to every bounded page, or serialize each page against bounded counterpart locks. Add a deterministic retirement-between-check-and-yield regression and prove membership changes are complete-or-fail rather than silently omitted.

### RVI-065 — Therapist reads could execute after the authenticated therapist was logically deleted

- Severity: High authorization/erasure defect
- Status: Open pending final verification
- Evidence: therapist patient-data routes acquire `sharing_therapist_lock_key(user.id)` but do not freshly read the therapist's active state and token epoch after acquiring it. A request authenticated before deletion can queue behind `DELETE /therapist/account` on that same lock, then continue after deletion commits; `_active_consent` validates only the patient. `list_patients` has the same stale-caller gap. Direct note routes already use `_notes_guard`, which demonstrates the missing reread contract. A retired therapist session can therefore serve patient insights, measures, entries, audio, or list metadata after deletion success.
- Required remediation: centralize an active-and-current-epoch therapist reread immediately inside the therapist lock for every data/list route, fail closed on retirement or changed epoch, and add a deterministic read queued behind therapist deletion.

### RVI-066 — Patient consent listing could execute after the caller was logically deleted

- Severity: High authorization/erasure defect
- Status: Open pending final verification
- Evidence: `list_consents` neither acquires the patient sharing lock used by account deletion nor freshly rechecks the caller after admission. A request authenticated before deletion can resume after deletion commits and return still-pending consent and counterpart metadata before the bounded worker reaches the consent phase. The RVI-060 final inactive-counterpart fence checks therapists, not the patient caller, so it does not close this race.
- Required remediation: run the listing operation inside the patient sharing fence, reread active state and token epoch after acquiring it, fail closed on retirement or epoch change, and add a deterministic request queued behind its own account deletion.

### RVI-067 — Account-deletion failures and delayed audio completion lacked actionable bounded monitoring

- Severity: Medium data-rights operations defect
- Status: Open pending final verification
- Evidence: the deletion worker retries backlog every second, including hour-delayed audio tombstones and systemic failures, but exposes no deletion-job count, oldest-request age, phase, or failure metric/alert; unexpected failures also lack a fixed, non-identifying error category. A stranded rights request is difficult to detect, while a single intentionally delayed job can cause thousands of unnecessary database polls during provider backoff.
- Required remediation: schedule from the earliest due work or use a bounded slower backoff for the `audio_wait` phase; expose aggregate backlog, oldest-age, and failure metrics without identifiers; add alert thresholds tied to the deletion SLA and persistent failures; and test retry cadence, metric exposition, alert grounding, and safe failure logging.

### RVI-068 — The complete backend suite diverged from the remediated contracts and no longer provided a green integration gate

- Severity: High integration/assurance defect
- Status: Open pending final verification
- Evidence: the first independent complete SQLite run after the focused remediation suites finished with **142 failed, 1,912 passed, and 6 skipped**. Failure clusters include deliberately changed contracts that were never propagated to legacy tests (explicit `410 account_deleted`, mandatory therapist MFA, sharing disclosure v3, richer paged/export records, retained-history ceilings, request-path retention removal, and staged bounded deletion), production-settings fixtures missing newly mandatory split secrets, stale mocks around the new lock/fence boundaries, and frozen error/log/constant registries that were not re-reviewed after source changes. Because genuine regressions and obsolete expectations are mixed together, the previously green focused selections cannot establish whole-project compatibility.
- Required remediation: triage every failing test against the documented intended contract; update expectations or fixtures only where the new behavior is intentional and security-preserving, fix source behavior where it is not, refresh frozen registries from reviewed semantics rather than blindly accepting hashes, and rerun the entire SQLite and PostgreSQL suites. Preserve explicit regressions for every changed security, consent, deletion, export, and MFA contract.

### RVI-069 — Backend coverage fell below the enforced release floor after remediation growth

- Severity: Medium test-quality/release-gate defect
- Status: Open pending final verification
- Evidence: the same complete run measured **92.08%** line coverage against the repository's enforced 95% minimum. The largest new gaps are in `app/api/_audit.py` (79%), `app/services/audio_store.py` (82%), `app/main.py` (84%), `app/api/_sharing_state.py` (82%), and the expanded account/insight/deletion paths. Test failures account for part of the lost execution, but the new bounded checkpoint, index, manifest, retry, and staged-deletion branches also need deliberate fault-path coverage.
- Required remediation: first restore the full functional suite, then add meaningful branch/fault regressions for the new code until the unchanged 95% gate passes; do not lower or exclude the new security/retention modules from coverage.

### RVI-070 — Four backend test files failed the repository formatting gate

- Severity: Low CI hygiene defect
- Status: Open pending final verification
- Evidence: `ruff format --check app tests` reported formatting drift in `tests/test_audit_2026_09_21_backend.py`, `tests/test_independent_commit_audit_2026_10_03.py`, `tests/test_migrations.py`, and `tests/test_voice_remediation_2026_09_29.py`, even though lint and mypy remained green.
- Required remediation: apply the pinned formatter after semantic test repairs, review the resulting diff, and rerun both formatting and lint gates across all backend source and tests.

### RVI-071 — Backend tests leaked SQLite connections across the complete run

- Severity: Medium test-isolation/resource-hygiene defect
- Status: Open pending final verification
- Evidence: the complete SQLite run emitted **122 warnings**, dominated by `ResourceWarning: unclosed database in <sqlite3.Connection ...>` across audio, audit, export, and staged-deletion tests. Even where a failing assertion short-circuits ordinary cleanup, the fixture/application lifecycle should dispose engines and close sessions deterministically; leaked connections can contaminate later tests, hide locking defects, and exhaust descriptors in repeated CI or mutation runs.
- Required remediation: identify the fixture/application engines and direct test engines that survive teardown, close sessions and `await engine.dispose()` in `finally`/yield-fixture teardown paths, and add a focused repeated-lifecycle run with resource warnings promoted to errors. Re-run the complete suite and confirm no unclosed-database warnings remain rather than suppressing the warning category.

### RVI-072 — The frozen error/log registry did not fail when new modules or contract families were omitted

- Severity: Medium test-assurance defect
- Status: Open pending final verification
- Evidence: `backend/tests/test_contract_registry_2026_09_30.py` extracts current contracts from a `MODULES` inventory, but its tests parametrize only the keys already present in `FROZEN_REGISTRY` and `FROZEN_LOGS`. A new module—or a module that gains its first error/log contract—can therefore remain absent from the frozen maps without failing the suite. The remediation added new security/lifecycle modules and a new account-purge log, yet those surfaces were silently unpinned while existing-key mismatches failed.
- Required remediation: assert the reviewed module inventory itself is complete, assert the frozen error/log key sets exactly equal the non-empty extracted key sets, then pin the newly introduced literals after privacy and client-contract review. Add a regression proving a temporary/new module or first contract cannot evade the registry merely because no frozen key exists.

### RVI-073 — Offline legacy-audit sealing could no longer snapshot genuine pre-MAC rows

- Severity: High audit-migration/integrity defect
- Status: Open pending final verification
- Evidence: `backend/scripts/seal_legacy_audit.py::snapshot_rows` calls `verify_access_log_chain(...)` without an explicit key, expecting an intentionally link-only legacy walk. However, `_audit._effective_mac_keys(None, None, None)` substitutes the process-global configured keyring. Importing `app.main` or the module-level application configures that keyring—including in the CLI subprocess—so a valid v1 row whose `entry_mac` is null fails the snapshot with `audit hash/link/journal verification failed`. Both the in-process attestation regression and the real subprocess path reproduce the failure. After bypassing that first defect explicitly, the next stage also fails: `seal` writes row MACs but creates no HMAC-authenticated `AuditChainState`, so ordinary keyed verification rejects the supposedly migrated owner with `durable audit chain state is missing`. The independently reviewed migration escape hatch is therefore unusable for exactly the historical rows it exists to authenticate and seal, and its partial output is not acceptable to the remediated runtime.
- Required remediation: add an explicit verifier mode or argument representing an intentionally empty keyring with no ambient fallback; use it only inside `snapshot_rows` after its separate existing-MAC validation, while retaining keyed fail-closed defaults everywhere else. During sealing, atomically create or update the owner's authenticated durable chain state—including the correct retained-prefix/head anchors, sequence, version, and MAC—together with row MACs, and fail without partial migration if any snapshot fact changed. Add in-process and real subprocess snapshot/seal/reverify regressions proving legacy rows become normally keyed-verifiable without permitting any runtime or maintenance caller to downgrade verification.

### RVI-074 — An audio-deletion concurrency regression ran on a single-connection SQLite topology

- Severity: Medium test-assurance defect
- Status: Open pending final verification
- Evidence: `test_audio_cleanup_uses_authoritative_attempts_after_another_drains_retry` opens two nominally independent sessions through the default in-memory SQLite `StaticPool`. The database layer explicitly documents that this topology shares one DBAPI connection and cannot model concurrent transaction isolation; the targeted interleaving therefore lets one session's commit alter the other session's transaction boundary and deterministically reports a zero deletion count. The identical test passes on file-backed SQLite, whose per-checkout connections match the production transaction model.
- Required remediation: run this genuine multi-session claim/retry probe on file-backed SQLite when the default suite uses the in-memory topology, while continuing to exercise the production implementation unchanged and retaining the PostgreSQL run. Dispose the dedicated engine deterministically and keep the assertions for lease ownership, authoritative retry count, and exponential backoff.

### RVI-075 — A legacy-sealing coverage test leaked a committed invalid state into its next scenario

- Severity: Low test-isolation defect
- Status: Open pending final verification
- Evidence: `test_legacy_audit_sealing_authenticates_rows_and_rejects_bad_or_oversized_chains` reuses one database for three scenarios. Its successful first seal is only flushed and is rolled back when that session closes, leaving the first state unsealed. It then commits an intentionally empty, unsealed `AuditChainState`, verifies that sealing rejects it, and only rolls back the failed transaction; the already committed invalid state remains. The following oversized-chain case queries all unsealed states ordered by randomly generated owner ID, so it can encounter the leaked empty state first and raise `legacy audit state failed authenticated verification`, encounter the rolled-back first state and exhaust the tiny budget without raising, or reach the intended oversized chain.
- Required remediation: commit the successful seal, explicitly remove and commit removal of the invalid fixture after its expected failure (or isolate each case in a fresh database), then prove the oversized-chain branch deterministically. Keep the production fail-closed behavior unchanged.

### RVI-076 — A legacy-snapshot regression assumed an unordered database row was the first chain row

- Severity: Low cross-database test-assurance defect
- Status: Open pending final verification
- Evidence: the complete PostgreSQL profile failed `test_legacy_audit_sealing_requires_exact_attestation_and_refuses_bad_existing_mac` while the SQLite profile passed. The test selects one owner's `AccessLog` without `ORDER BY`, clears that arbitrary row's MAC, then assumes `snapshot_rows`—which deliberately orders by owner and chain sequence—will return the modified object at `rows[0]`. PostgreSQL selected a later audit row, so the first ordered row correctly retained its valid MAC and the assertion failed; the test's later invalid-MAC probe still targets the intended modified object.
- Required remediation: retain the selected row's stable identifier and assert that exact snapshotted row remains unsealed, rather than relying on backend-specific unordered row selection. Re-run the isolated case and the full PostgreSQL profile without changing the production snapshot/sealing behavior.

## Final remediation disposition — 2026-10-04

The per-finding `Open` labels above intentionally preserve the requested pre-remediation baseline: they describe the state at audited commit `5a02dbbb160f8cc62118eeb850fb4964ca6fed13`. This section is the authoritative disposition of the remediated working tree.

- **124 findings total:** 48 baseline findings plus 76 independently discovered remediation-validation findings (`RVI-001` through `RVI-076`).
- **109 fully repository-remediated and verified:** every `RVI` finding, plus `AUD-001..004`, `SEC-001..004`, `PRIV-001..005`, `PRIV-007`, `PRIV-009`, `CLIN-001..006`, `WEB-001`, `WEB-002`, `WEB-004`, `PORTAL-001`, `TEST-001`, `OPS-001..005`, and `DOC-001..002`.
- **4 repository-side controls implemented; external completion evidence still required:** `PRIV-008` (deploy the provider lifecycle backstop and observe it), `PRIV-010` (submit/verify the store privacy answers), `MOB-002` (reproduce the locked native builds on supported release hosts), and `MOB-003` (real-device accessibility verification).
- **11 residual or external-scope findings:** `SEC-005`, `PRIV-006`, `CLIN-007`, `CLIN-008`, `WEB-003`, `MOB-001`, `I18N-001`, `OPS-006`, `OPS-007`, `OPS-008`, and `DOC-003`. These require a product decision, independent clinical/regulatory/vendor evidence, real infrastructure/device execution, or a broader full-tree mutation campaign; repository changes alone cannot honestly close them.

### Final verification evidence

- Backend, SQLite: **2,099 passed, 6 skipped, 0 failed**; application coverage **95.18%** against the unchanged 95% release floor.
- Backend, PostgreSQL 16: **2,103 passed, 2 skipped, 0 failed** on a fresh digest-pinned database container; this includes PostgreSQL-only migrations and genuine multi-connection concurrency behavior.
- Patient web: **824 passed, 5 skipped**; coverage **86.71% statements / 81.48% branches / 85.62% functions / 91.13% lines**; typecheck, production build, SRI stamping, and dependency audit passed.
- Mobile: **2,314 passed, 1 skipped**; coverage **91.30% / 86.01% / 88.40% / 95.07%**; typecheck, 25 native static-release checks, crypto interoperability vectors, and the dependency-backport policy passed. The scoped voice-scratch mutation campaign killed **79/79 mutants**.
- Clinician portal: **523 passed**; coverage **92.01% / 85.30% / 90.46% / 95.80%**; typecheck, production build, SRI stamping, and production dependency audit passed.
- Backend static gates: Ruff formatting and lint passed across all `app` and `tests` files; mypy passed across **50 source files**; `git diff --check` passed.
- Secret assurance: checksum-verified Gitleaks **8.30.1** found no leaks in **94 commits** or the complete working tree; its narrow-allowlist regression still detected **2/2 planted secrets**. The repository-specific secret-location tests also passed.
- Monitoring: production digest policy, YAML/structure/metric grounding, **18 Prometheus alert rules**, **15 dashboard panels**, and all pinned-Prometheus `promtool` rule/fault-scenario tests passed.

### Boundaries not represented as certifications

No repository test can certify clinical efficacy or fairness, determine legal/regulatory status, execute vendor contracts or BAAs, prove live alert delivery/offsite recovery, submit store disclosures, or replace real iOS/Android device and release-host builds. Android compilation remains dependent on a configured SDK; complete iOS compilation remains dependent on a full Xcode workspace/toolchain. The raw mobile registry still reports 28 high-severity dependency nodes, all mapped by the repository policy to two exact reviewed backports; that is a documented supply-chain residual, not a claim of a clean upstream registry.
