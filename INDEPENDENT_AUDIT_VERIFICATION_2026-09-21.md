# Independent Audit Verification — Deep-Audit Remediation Series (2026-09-21)

Independent verification of the Phase 1–3 remediation commits against
`AUDIT_2026-09-21.md`. Performed fresh on the working tree at `6842896`
(= `main` HEAD, clean): every verification command re-run, every claim
traced to code, no commit-message statements taken on trust.

## Scope note

The "last 3 commits" are actually a **5-commit series** covering the three
phases (Phase 2 shipped as three wave commits):

| Commit | Claims |
|---|---|
| `b9c9f7e` | Phase 1 complete — all 33 planned items + 7 unscheduled gaps |
| `cecc448` | Phase 2 waves 1–3 + audit-trail read path |
| `417b8dd` | Phase 2 waves 4–5 |
| `a176b3b` | Phase 2 waves 6–8 |
| `6842896` | Phase 3 |

All five were audited.

## 1. Independent execution results (re-run from scratch)

| Verification command (audit doc §"Verification commands") | Result |
|---|---|
| `backend/.venv/bin/python -m pytest` | **PASS** — 1,297 tests collected, 0 failures |
| `backend: probe_brain.py` | **PASS** — 9/9 (verified by counting all output lines, not the tail) |
| `mobile: npm test` | **PASS** — 1569/1569 (exactly matches the Phase 3 commit claim) |
| `portal: npm test` | **PASS** — 185/185 (exactly matches the claim) |
| `node mobile/tools/verify_vectors.mjs` | **PASS** — 4 vectors + 6 encrypt + 3 wrap + 16 AAD edges |
| `bash deploy/monitoring/verify.sh` | **PASS** — ALL CHECKS PASSED |
| `bash redteam/run_all.sh` | **96 verdicts: BLOCKED=73, FINDING=9, INFO=9, NOT-RUN=1, PARTIAL=4** — see Finding V-1: the 9th FINDING is unregistered, so the weekly CI gate would FAIL |

## 2. Findings of this independent audit

### V-1 (process, Medium) — The weekly red-team CI gate is currently red: an unregistered FINDING

`mobile/ios/.xcode.env` — committed in Phase 1 (`b9c9f7e`) together with the
native projects — is matched by the `G3.tracked-secrets` harness rule
(`redteam/g_infra.py:195-198` flags any git-tracked path starting with
`.env`). Verified empirically: a fresh `run_all.sh` reports
`FINDING G3.tracked-secrets`, the finding appears **nowhere** in
`docs/SECURITY_RESIDUALS.md` (8 registered residuals) or the
`DOCUMENTED_RESIDUALS` allowlist in `.github/workflows/redteam.yml`, and the
gate asserts `set(findings) - DOCUMENTED_RESIDUALS == {}`
(`redteam.yml:160-164`) — so the next scheduled weekly run fails.

The file itself is a benign React-Native Xcode template (a `NODE_BINARY`
export, no secrets), so this is a false-positive class — but two claims are
broken by it:

1. Phase 1's "Verified green: … redteam run_all (8 registered residuals, no
   new findings)" did not hold for its own tree (the file landed in that
   same commit).
2. H-1's mechanism ("the weekly gate fails on any FINDING not registered")
   is now failing on the repo as committed.

Remediation is trivial either way: register the id with a written defense
(the harness pattern is over-broad for `.xcode.env`), or narrow the harness
rule / untrack the file.

### V-2 (disclosed deferral, not a false claim) — ES theme lexicon still absent

AUDIT Phase 2 workstream 1 demanded "ES theme lexicon (temporal/
mood_correlation/link cards in Spanish)". Verified: `THEME_LEXICON`
(`backend/app/services/brain.py:302-494`) is still English-only (173 words,
9 themes); pure-Spanish corpora therefore still get **zero**
lexicon-derived temporal/mood_correlation/link cards. The README honestly
discloses this (README.md:126-128: "a Spanish theme set is tracked as
follow-up work"), and the wave 6–8 commit message did not claim it. What
WAS delivered for E-3: the localized 30-day baseline loop
(`shared/generic_questions_es.json`, 60 questions, position-parity pinned)
and the Spanish prompt-chip pool, both locale-keyed — verified.

### V-3 (disclosed deferral) — Grafana dashboard provisioning + Alertmanager example not delivered

Audit workstream 6 sub-item. `deploy/monitoring/grafana/provisioning/`
contains only a datasource; no dashboards directory, no Alertmanager
anywhere. Documented as absent in `deploy/monitoring/README.md:124-127,167`
rather than delivered; the commit message omitted it. All other workstream-6
items verified (rollback section, hardening quartet on both overlays, fetch
`restart: no` default, Trivy in CI+release failing on fixable HIGH/CRITICAL,
rclone `.tmp` exclusion, json-file log rotation everywhere, `verify.sh
--production` digest pinning, 25-survivor mutation ceiling, per-file mobile
coverage floors, release gate on Python 3.14, portal Stryker weekly with
`break: 1`).

### V-4 (minor code gap) — Note-edit history misses the POST idempotent-retry path

"Every CHANGING note update preserves the superseded blob" holds for PATCH
(`backend/app/api/therapist.py:1566-1581` inserts a `TherapistNoteRevision`
before the blob swap), but the POST retry branch (`therapist.py:1453-1458`)
rewrites an existing note's blob in place on content change **without**
writing a revision — a create-retry with different content silently replaces
history. Edge path, but it contradicts the blanket claim.

### V-5 (claim-wording nuances, behavior itself correct)

- `decryptMeasure` **rejects** out-of-range scores by returning `null`
  (`portal/src/crypto.ts:263-265`, callers drop null rows) — it does not
  throw; reject-not-clamp is real, "throws" is not.
- The portal print tests assert `no-print` classes and the stylesheet rules
  verbatim (react-test-renderer applies no CSS — acknowledged in the test
  file), not an actually rendered print tree.
- `PUT /account/credential` for therapists was enabled by swapping the
  dependency to `require_user` (`account.py:585`), not by changing
  `require_regular_user` — effect as claimed.
- Time-of-day `tod` rides inside the client-encrypted payload; its "strict
  400" is enforced at analysis time in `_parse_entries`
  (`insights.py:700-706`), the only place the server can see it.

### V-6 (not verifiable here) — "App builds and installs" exit criterion

Phase 1's exit criteria include a buildable/installable app. Native
projects, the two missing native modules, manifest/plist hardening
(`allowBackup=false`, FLAG_SECURE in `MainActivity.kt`, adjustResize,
Health usage strings) and the `verify:native-release` CI preflight are all
committed and verified **statically** — but no actual Xcode/Gradle build was
executed during this verification (needs macOS toolchain invocation beyond
this audit's scope). Treat "builds" as verified-by-tooling, not
verified-by-build.

### Disclosed Phase 3 deferrals (verified as tracked, not silently dropped)

On-device TS brain port (protocol + golden-vector acceptance gate
`shared/brain_vectors.json` v2 + `mobile/src/brain/PORT.md` shipped; the
port itself pending), multi-device sync conflict model, clinician-configured
measure cadence, multi-therapist orgs/handoff, TEE attestation
(`docs/TEE_ATTESTATION_DESIGN.md`, design only), IRB study
(`docs/IRB_STUDY_PROTOCOL.md`, protocol draft only — substantive and
zero-knowledge-consistent). All named in CHANGELOG/PORT.md.

## 3. Claim-by-claim verification summary

### Phase 1 (`b9c9f7e`) — 33 items + 7 gap closures: **VERIFIED (40/40)**

Every item traced to code with the fix present and a regression test
naming the finding:

- **Brain D-1..D-6**: replication gate compares against the newest stored
  evidence day via a pre-merge `prior_evidence` set (`brain.py:3367-3409`,
  `3506-3511`) — the regression test reproduces the audit's exact PoC
  (100-day corpus, 70 evidence days, second identical recompute stays
  candidate; fresh-evidence positive control included). Spanish function
  words unioned into eligibility (`brain.py:3162-3164`); empty-text
  entries out of mood/PA/NA series but kept for cadence (`brain.py:3788-3832`);
  person anchoring English-only (`brain.py:3760`); `first_qualified`
  restarts at emerging (`brain.py:3544-3545`); phrase-pid re-linking
  (`brain.py:3418-3426`); `_FOLD_CACHE` bounded at 4096 (`brain.py:1477-1478`);
  README Spanish claims narrowed.
- **Security C-1/C-3/C-4**: rotation locks vault + drops biometric wrap
  unconditionally inside `rotatePassword` before any alert
  (`rotation.ts:230-231`; the alert button only signs out); biometric
  unwrap proof-verified with stale-wrap auto-delete
  (`UnlockScreen.tsx:110-116`); `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY`
  (`secureStore.ts:63`). The rotation test deliberately never presses the
  alert's OK.
- **Backend A-1/A-2/A-3/A-5/A-6, B-2**: rekey increments entries+measures
  revisions inside its commit (`insights.py:574-575`); export keeps the
  unprocessed tail — byte-for-byte the audit's suggested expression
  (`account.py:477-479`); `StaleDataError`→404 (`consents.py:507-514`);
  share ids frozen in the head transaction (`account.py:210-216`);
  measures byte-bounded `page_bytes`/`X-Next-Offset`/revision contract on
  both routes + migration `c8d2f6b1a9e4`; alembic
  `compare_type`/`compare_server_default` on both offline/online
  (`alembic/env.py:81-82,105-106`).
- **Portal F-1/F-2/F-5/F-6**: print hides everything but `.print-only`
  (evidence card additionally `no-print`); `pre-wrap` on notes/entries/print;
  retry affordances on list + chart; form-`onSubmit` login/register +
  `role="status"`. Tests exist for each (see V-5 print-test nuance).
- **Mobile E-2/E-4..E-7/E-10/E-11 + ship blockers**: localized check-in
  vocabulary (wire values stay English); haptics loaded at provider mount;
  `t.colors.error` on the phishing warning; localized reminder copy; 44pt
  targets via `t.minTouch` on all flagged controls; `muteNote` timer; native
  ios/android projects with manifest/plist hardening; notifee + health deps;
  `verify:native-release` CI preflight.
- **Ops/docs 29–33 + gaps A-7/A-8/B-8/H-8/H-1**: runbook `basename` +
  `/restore/$NEWEST` with `--remote` rehearsal mode; monitoring-verify +
  shellcheck CI job; weekly redteam CI gate (see V-1 for its current
  state); README rotation/LLM/error-code/budget claims corrected (all
  grepped); config upper bounds + `analysis_blob_budget >= max_body_bytes`
  floor + 413 empty-corpus refusal + legacy `/api` `Deprecation` header;
  empty-read audit comments corrected; `users.is_active` documented;
  runbook Detection & escalation section; SECURITY_RESIDUALS register (8
  entries, workflow cross-asserted).

### Phase 2 wave 1–3 (`cecc448`) — **VERIFIED (12/12)**

Credential rotation open to therapist tokens; verifier-gated
`PUT /therapist/wrap-key` with `wrap_key_rotate` audit; patient re-wrap via
live `therapist_wrap_pub_key` in `ConsentOut`; asyncpg statement/idle-in-tx
timeouts (env-tunable, bounded); rekey executemany batching; consent caps
count ACTIVE only; prefix index dropped (`a3e7c9d5f1b2`, models cleaned);
pairing-code prune in daily sweep; feedback AAD carries seal date
(today-or-yesterday, replay-pinned); `MINDPATTERN_DECOY_SECRET` (>=32 chars
validated, masked repr); explicit fingerprint-match attestation tap;
`GET /account/access-log` + `GET /therapist/access-log` cursor-paginated
and strictly principal-scoped.

### Phase 2 wave 4–5 (`417b8dd`) — **VERIFIED (6/6)**

Portal "My access history" panel → `/therapist/access-log?limit=100`; DPIA
erasure residual disclosed + subprocessor/international-transfer table +
Art. 30 RoPA section; banner folds fresher scan rows; per-context note
drafts; print/randomness through the platform seam (one legitimate
in-module `crypto.getRandomValues` for nonces remains);
`decryptMeasure` reject-not-clamp; loading state kills the empty flash;
username search + newest/username/triage ordering. jest-axe deferred —
admitted in the commit, absence confirmed.

### Phase 2 wave 6–8 (`a176b3b`) — **VERIFIED except V-2/V-3 above (14/16)**

ES question pool + chips + usted normalization (six strings confirmed
normalized; no tu-register stragglers found in a multi-pattern sweep); dead
ES lexicon entries gone; windowed History FlatList; human-spoken calendar
dates; foreground `activeDays` refresh; onboarding panel resume; README
screens table; plus the ops quartet listed under V-3.

### Phase 3 (`6842896`) — **VERIFIED as scoped (7/7 claims as written)**

`POST /insights/local-recompute` protocol (client-encrypted blobs,
`base_state_seq` 409 concurrency, dates grounded to real entry dates, no
processing session/key shipment — endpoint logic read in full);
`brain_vectors.json` v2 with three full-engine corpora at 9-decimal
precision + regeneration pin; note history (see V-4 edge); measures
registry PHQ-9/GAD-7/PHQ-2 with per-instrument ceilings + portal per-
instrument trend labels; time-of-day bucket channel with strict validation
and the >=70% weekday-window narrowing; IRB + TEE docs; deferrals tracked.

## 4. Verdict

The commit messages are **substantially accurate**: 40/40 Phase 1 items,
all Phase 2 wave items as claimed, and Phase 3 exactly as scoped (design
docs + protocol + three implemented features). All five suite/probe/vector
claims reproduce exactly (1569 and 185 are the real counts). The one
integrity break is **V-1**: the weekly red-team CI gate would fail today on
an unregistered FINDING introduced by Phase 1 itself — benign in content,
real in process, trivial to fix. The remaining deltas (V-2…V-6) are
disclosed deferrals or edge-path nuances, not misrepresentations.

---

## 5. Remediation addendum (same day, post-audit)

Every fixable finding was fixed after this report was issued; V-5 needed
no code (behavior already correct) and V-6's static preflight passes while
a full native build remains a machine-setup step (CocoaPods + Android SDK
are not on the auditing machine).

| Finding | Resolution |
|---|---|
| V-1 | `G3.tracked-secrets` registered as the ninth residual with a written defense (docs/SECURITY_RESIDUALS.md + the workflow's `DOCUMENTED_RESIDUALS`); the gate logic simulates green against a fresh `run_all.sh` (9/9 FINDINGs registered) |
| V-2 | `THEME_LEXICON_ES` shipped (226 words across the nine themes, language-gated); language detection reordered ahead of theme extraction; topic eligibility excludes ES theme words; golden `spanish-mixed` vector case strengthened to 70 days and now pins ES-derived `temporal:work` + `mood_correlation:work` candidates; mobile renders theme/tag labels localized (`insights.theme.*`, en/es) with raw passthrough for unknown labels; README updated. New suite: backend/tests/test_es_themes.py (9 tests) + 2 mobile tests |
| V-3 | Provisioned Grafana dashboard as code (`mindpattern-overview.json`, 8 panels / 9 expressions) with a read-only provider; `verify.sh` extended to JSON-parse and metric-ground every dashboard expression like alerts.yml; minimal Alertmanager example at `deploy/monitoring/alertmanager/alertmanager.example.yml` with runbook-mirroring severity routing; monitoring README updated |
| V-4 | The POST idempotent-retry path now writes a `TherapistNoteRevision` when content changes (byte-identical replays still write none); regression test added (backend/tests/test_note_history.py) |
| V-5 | No code change — the three nuances were claim-wording, and the one behavioral question (reject-not-clamp) was already the desired behavior with a pinning test |
| V-6 | `npm run verify:native-release` passes 5/5 on this machine; a full build requires toolchains absent here, so "builds and installs" stays verified-by-tooling |

Full re-verification after remediation: backend pytest green (1,307
tests), mobile 1571/1571, portal 185/185, probe_brain 9/9, crypto vectors
pass, brain vectors regenerate deterministically,
deploy/monitoring/verify.sh passes with dashboard grounding live, redteam
`run_all.sh` 96 verdicts with all 9 FINDINGs registered.
