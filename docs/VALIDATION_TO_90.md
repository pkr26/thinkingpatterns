# Evidence required before a 90+ assessment

Created October 3, 2026. This is a prospective validation protocol, not a
completed study or certification. Freeze the candidate commit, supported
platforms and acceptance criteria before collecting results. Keep the audit
baseline and raw failures; publish deductions as well as successes.

## Engineering acceptance

Run the complete backend suite on supported Python versions, SQLite and
PostgreSQL; client suites with their existing coverage thresholds; type and
lint checks; strict crypto/analysis vectors; dependency scans; production
build and native release preflight. Require no new high-severity reachable
dependency issue. A tested tooling mitigation must retain the upstream
advisory and its scope, provenance and review date.

Upgrade the previous production schema with representative legacy journal,
note, revision, recovery and audio records. Verify exact ciphertext and
authenticated opening after upgrade. Also test a fresh migration chain.
Restore an authenticated encrypted real pg_dump into an isolated database;
compare rows, ciphertext, schema head and required constraints. Never run
destructive fixtures against customer databases.

For patient/clinician key changes, test every interruption boundary:
preparation, each server batch, credential commit, lost response, each local
replacement and cleanup. Repeat after process death and fresh login. Test
wrong retry passwords, changed origins, revoked sessions, competing edits,
consent/public-key changes and unavailable storage. Confirm that an old
client cannot write into a completed new-key generation. Saved authored
content and every clinician revision must remain recoverable.

Exercise admission limits, slow request bodies, provider deadlines,
PostgreSQL advisory-lock connection loss and restart revocation hydration.
With the object store unavailable during account/attachment deletion,
confirm durable retries remove the exact objects after recovery and do not
remove a replacement. Prove monitoring alerts fire on sustained synthetic
faults and remain quiet on healthy/boundary cases. Alert delivery requires
a separate operator-controlled drill.

## Native and browser journeys

Record OS, browser, device, build, network profile and tool versions. Cover
Android and iOS release cold boots, screen capture/background shielding,
native microphone acquisition/cancellation, biometric presence, notification
taps, HealthKit permission denial/grant, and supported language changes.
An Android emulator or source pin cannot close an iOS hardware finding.

In each supported browser, verify registration, login/unlock, offline
journal/audio, newer writing during save, history edits/conflicts, safety
plans, questionnaires, recovery, sharing, notes/revisions, credential
changes and deletion. Include reload, multi-tab contention and storage
quota/read/write failures. Use real crypto and persistent storage. Confirm
that displayed save states match actual custody, and that a lost response
offers a recoverable continuation.

Inspect 390px, 768px and desktop layouts at 200% zoom with long English and
Spanish text. Check keyboard focus, labels, live regions, dialog escape,
44px touch targets where applicable and screen-reader task completion.
Automated accessibility checks supplement manual review.

Freeze initial-JS budgets at patient ≤150kB gzip and portal ≤100kB gzip.
Measure typing, warm save, sync and large-history navigation on named
profiles, including 1,000/10,000 entries. Separate lab results from field
Core Web Vitals; record distributions and failed tasks, not averages alone.

## Analysis calibration and language safety

Separate direct counts from statistical claims. Repeated qualification on
overlapping windows is a persistence gate, not independent replication.
Register the complete claim family, recompute cadence, missingness,
duplicated-day handling, number of candidate themes and filtering rules.

Use independent generators and frozen held-out seeds for stationary nulls
(independent and serially correlated channels, weekday confounding,
irregular cadence, sparse/duplicate entries, mixed tags and language).
Run the full production update and lifecycle sequence, including candidate
selection, correction and surfacing. Report both per-recompute and per-user
ever-surfaced false claims over the specified monitoring horizon, with
confidence intervals. Use at least 1,000 independent users per predeclared
cell for the confirmatory run, after a runtime pilot; more may be needed to
bound rare errors. Do not tune on the confirmation cells.

Separately plant known sustained level, association and timing changes;
measure precision, recall, delay and uncertainty calibration against the
generator's truth. Evaluate phrase-cluster precision/recall with an
independently labeled corpus, rather than same-engine replay. Include
negation, irony, idioms, spelling variants, code switching, unknown
languages and truncation. Unsupported language must surface uncertainty.

Have qualified English/Spanish reviewers assess crisis-resource copy,
question wording, score interpretation boundaries and comprehension of
observational cards. Generated text remains disabled until its feature,
privacy cost and supported-language safety have independent evidence.
Real STT/translation quality needs a separately consented provider study;
fake-provider tests establish transport behavior only.

The October 3 detector-only diagnostic (nine AR(1) cells, 1,000 repetitions
per cell, existing seeded harness) observed nominal p≤.05 frequencies from
0.4% to 6.7%. It does not demonstrate universal 5% calibration, full-pipeline
false-discovery control or clinical benefit. Do not publish those claims
until the prospective evaluation supports them.

## People and independent assessment

Start formative task sessions with at least five patients and five
clinicians in each supported language; record unassisted task success,
failure severity and comprehension of saving, recovery, sharing and
uncertainty. This small sample informs fixes, not population-level claims.
Preregister a later task-success target of ≥90%, no acknowledged-data loss,
and ≥90% correct boundary comprehension, with sample size determined before
the confirmatory study. Institutional/privacy/clinical review determines
whether and how participant research may proceed; see the separate draft
study protocol. Never solicit journal plaintext solely for engineering QA.

Have reviewers who did not implement the changes assess the ten original
areas against the published rubric. A coverage percentage, successful
simulation or weighted average cannot replace an area's score. Release
inputs still need real operator contact, deployment origins, privacy/legal
decisions and signing material. Mark unrun evidence explicitly and retain
the corresponding score deductions.
