# Operator & compliance pack — Fathom

Everything an operator needs to review, complete, and sign before
serving this product to the public. Each document states what the
PRODUCT already does (verified against the tree, 2026-09-28) and what
the OPERATOR must decide, fill, or sign. Items marked `OPERATOR-FILL`
or `LEGAL-REVIEW` are deliberately incomplete: inventing a controller
identity or a legal determination in source control would be worse
than leaving the blank.

| Document | What it is | Operator action |
|---|---|---|
| `PRIVACY_POLICY_TEMPLATE.md` | Plain-language privacy policy mapped to the actual data flows (journal/measure/audio ciphertext, metadata, audit log, therapist linkage, speech/translation processing, export/delete) | Complete `LEGAL-REVIEW`/`OPERATOR-FILL` blanks, legal review, publish; mirror the in-app copy |
| `DATA_RETENTION_SCHEDULE.md` | Every retention number found in code/config in one table: what, where, how long, deletion path | Verify against your deployment's actual env values; attach to the RoPA |
| `SUBPROCESSOR_BAA_REGISTER.md` | Subprocessor register template (LLM provider, hosting, backup target) with BAA-required flags | Fill per deployment; execute DPAs/BAAs before enabling each processor |
| `SECURITY_POLICY.md` | The operator-side security policy: what this repo enforces in code vs. what the operating organization must own (secrets custody, patching, branch protection, monitoring, incident clocks) | Adopt, adapt to your organization, sign |
| `../web/tools/securityTxt.mjs` | Fail-closed RFC 9116 release generator | Set the three validated repository variables; tagged release builds fail when contact/canonical/expiry is missing, stale, or placeholder |
| `DPIA_SKELETON.md` | Signable DPIA template (Art. 35(7) elements from code reality, age-gate control, Art. 36 trigger, signature blocks) | Fill §0 and the risk-table residuals; sign §6 |
| `INCIDENT_RUNBOOK.md` | Severity ladder, first-five-minutes, breach clocks (GDPR 72h + FTC HBNR 60-day), contact-role table | Fill every `OPERATOR-FILL` contact at deploy time; rehearse |
| `../deploy/README.md` | Digest-pinned deployment contract, secrets files, branch-protection setup, rollback | Follow; keep digests re-pinned deliberately |

Reading order for a first deployment: SECURITY_POLICY (can we operate
this safely?) → DATA_RETENTION_SCHEDULE + SUBPROCESSOR_BAA_REGISTER
(what do we retain and who processes it?) → PRIVACY_POLICY_TEMPLATE
(what do we tell users?) → DPIA_SKELETON (sign it) → INCIDENT_RUNBOOK
(fill the contacts, rehearse the restore).

Product-side facts these documents rely on (all code-verified
2026-09-28): client-side AES-256-GCM everywhere, random data-key
envelope v2 (v1 legacy supported), server-side scrypt N=2¹⁷ verifiers,
purpose-split server secrets, exact sliding-window rate limits, forward
hash-chained access audit log, hard cascade account deletion with a
surviving 730-day audit trail, deterministic journal analysis (no active
journal-text LLM dispatch), consent-gated speech/translation processing,
offline crisis resources in every client. The honest residual
set lives in `SECURITY_RESIDUALS.md` — read it alongside this pack; a
compliance story that hides the residuals is not this product's story.

## Public-release evidence gate

Every row below is deliberately unchecked. A source checkout cannot prove an
operator identity, public URL, vendor contract, store-console declaration,
clinical workflow, or production drill. The release owner must add a dated,
reviewable evidence link or mark the release blocked; prose such as "done" is
not evidence.

| Done | Release prerequisite | Required evidence | Owner | Evidence link / date |
|---|---|---|---|---|
| [ ] | Legal controller/operator identity, privacy contact, request channel, effective date, jurisdictions, and supervisory-authority details completed | Published policy snapshot and counsel approval | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Stable public privacy-policy URL and support URL resolve over valid production TLS | URL capture plus external TLS probe result | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Apple/Google app name, subtitle/description, age rating, privacy labels/data-safety answers, voice/HealthKit declarations, screenshots, and reviewer notes match the candidate build | Store-console export/screenshots tied to build/version | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Store privacy inventory covers account-linked access/action history and consent-event history (Apple **Product Interaction**) plus linked age-attestation/account-security metadata (Apple **Other Data Types**, or a documented current-taxonomy mapping); Google Data safety answers carry the equivalent disclosures | Dated Store Connect and Play Console exports/screenshots, reviewed against `PRIVACY_POLICY_TEMPLATE.md` and the release build | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | RFC 9116 contact is staffed and release variables `SECURITY_TXT_CONTACT`, `SECURITY_TXT_CANONICAL`, `SECURITY_TXT_EXPIRES` are set | Successful tagged `build:release`, fetched public file, and monitored-contact test | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Every enabled hosting, object-storage, backup, STT/translation, monitoring, or other vendor has region, retention/deletion, subprocessors, DPA, and BAA determination recorded | Completed `SUBPROCESSOR_BAA_REGISTER.md` row plus executed agreements | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Audio object storage has a provider/host-native expiry rule no later than `MINDPATTERN_AUDIO_LIFECYCLE_CEILING_DAYS` and backlog alerts route to a human | Lifecycle-rule export, synthetic expired-object drill, alert receipt | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Production alert delivery, external TLS probes, backup freshness, and a host-gone off-site restore have been exercised | Timestamped drill log, received page, restored row/schema comparison, incident follow-up | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Clinical positioning is supported by completed prospective validity, subgroup/language fairness, qualified Spanish review, and clinician response-workflow/SLA evidence—or all unsupported clinical-performance claims are removed | Approved study/report/SOP references tied to intended use | `OPERATOR-FILL` | `OPERATOR-FILL` |
| [ ] | Qualified reviewers assessed medical-device status, HIPAA/HBNR applicability, research/IRB requirements, and each launch jurisdiction for final intended use/marketing | Signed legal/regulatory memoranda with version/date | `OPERATOR-FILL` | `OPERATOR-FILL` |

Any unchecked row is an explicit release blocker for the affected feature,
claim, integration, or jurisdiction. Keeping a provider disabled or removing a
claim is an acceptable fail-closed outcome; inventing evidence is not.
