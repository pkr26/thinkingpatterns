# Independent Audit — Round 2 (2026-09-21)

Second, fully independent audit of the deep-audit remediation series
(`b9c9f7e` → `cecc448` → `417b8dd` → `a176b3b` → `6842896` → `fefcdec`)
against `AUDIT_2026-09-21.md`. Nothing from the commit messages,
`CHANGELOG.md`, or the first-round `INDEPENDENT_AUDIT_VERIFICATION_2026-09-21.md`
(including its self-reported remediation addendum) was taken on trust:
every verification command was re-run from scratch on a clean tree at HEAD
`fefcdec`, every claim was traced to code by fresh reviewers, and the
round-1 findings V-1..V-6 were re-checked independently.

## 1. Independent execution results (all re-run at HEAD fefcdec)

| Command | Result | Matches claim |
|---|---|---|
| `backend/.venv/bin/python -m pytest` | **PASS** — 1,307 collected (counted via `--collect-only`), full run exit 0 | ✅ "1307" exact |
| `backend/.venv/bin/python probe_brain.py` | **PASS** — 9/9 (all verdict lines counted) | ✅ |
| `mobile: npm test` | **PASS** — 1571/1571, 71 files, coverage floors enforced (exit 0) | ✅ "1571/1571" exact |
| `portal: npm test` | **PASS** — 185/185, 8 files | ✅ exact |
| `node mobile/tools/verify_vectors.mjs` | **PASS** — 4 vectors + 6 encrypt + 3 wrap + 16 AAD edges | ✅ |
| `bash deploy/monitoring/verify.sh` | **PASS** — "ALL CHECKS PASSED", incl. "dashboard … 8 panel(s), 9 grounded expression(s)" | ✅ |
| `bash redteam/run_all.sh` | 96 verdicts: BLOCKED=73, **FINDING=9**, INFO=9, NOT-RUN=1, PARTIAL=4 | ✅ exact |
| Red-team gate arithmetic | All 9 FINDING ids ∈ `DOCUMENTED_RESIDUALS` (redteam.yml) with written defenses cross-asserted in `docs/SECURITY_RESIDUALS.md` → `set(findings) − residuals = ∅` → **gate green** | ✅ V-1 closed for real |
| `python scripts/gen_brain_vectors.py` | Regenerated `shared/brain_vectors.json` is **byte-identical** (empty git diff) | ✅ deterministic |
| `npm run verify:native-release` | 5/5 PASS | ✅ |

Every quantitative claim in the six commit messages and the round-1
remediation addendum reproduces exactly.

## 2. Claim-by-claim verdicts

### Phase 1 (`b9c9f7e`) — VERIFIED (40/40 as claimed, one sub-item partial)

- **Brain D-1..D-8**: all present with genuine, non-vacuous regression tests
  (the D-1 test reproduces the audit's exact >60-evidence-day PoC with a
  positive control; D-5 emerging-restart test runs a 22-day simulation).
  Partial: the "dead ES lexicon entries" item removed only the 3 entries the
  audit named by line — **~27–28 equally dead multi-word keys remain** (see
  F-5 below).
- **Security C-1/C-3/C-4, backend A-1/A-2/A-3/A-5/A-6/A-8, alembic B-2**:
  all VERIFIED; A-2's tail re-enqueue traced through the loop control
  variable; A-1's revision increments confirmed inside the single rekey
  commit; A-3 byte-bound mirrors entries' (ciphertext-bytes) semantics on
  both routes + migration; alembic compare flags confirmed in both
  offline/online branches with a spy test.
- **Portal F-1/F-2/F-5/F-6, mobile E-2/E-4..E-7/E-10**: all VERIFIED with
  interaction-level tests (rotation test deliberately never presses the
  alert OK; wire-value parity pinned on `encryptEntry` args).
- **Ship blockers**: native projects, both modules, hardening flags
  (FLAG_SECURE, allowBackup=false, Health strings, adjustResize), and the
  CI preflight all present. `ios/.xcode.env` confirmed benign (NODE_BINARY
  export only). "Builds/installs" remains **verified-by-tooling, not
  by-build** (no Xcode/Gradle invocation possible on the auditing machine) —
  same honest caveat as round 1.
- **Ops 29–33 + gap closures**: runbook restore paths + `--remote` rehearsal,
  monitoring-verify + shellcheck CI job, weekly red-team gate (weekly cron,
  real set-subtraction failure mode), README claims corrected (error-code
  list is now **CI-enforced complete** via a grep gate), config bounds,
  413 empty-corpus refusal, Deprecation header, SECURITY_RESIDUALS register
  cross-asserted by the workflow — all VERIFIED.

### Phase 2 waves 1–3 (`cecc448`) — VERIFIED 13/14; TOTP silently dropped

Therapist credential rotation (verifier-gated, epoch-kills old bearer),
wrap-key rotation endpoint with audit event, patient re-wrap end-to-end
(successor key unwraps the data key in a test), asyncpg timeouts
(env-tunable + bounded), pairing-code sweep, ACTIVE-only grant caps,
feedback AAD date-seal, decoy secret (validated, masked), fingerprint
attestation tap, and both access-log read endpoints. The access-log
scoping is genuinely principal-bound (token-derived predicate only; no
request parameter can widen it; malformed cursors 422). **Missing: optional
TOTP for therapists** (workstream 2) — not implemented and not recorded as
deferred anywhere (contrast jest-axe, whose deferral is disclosed).

### Phase 2 waves 4–5 (`417b8dd`) — VERIFIED with test-gap caveats

Access-history panel, DPIA (erasure residual, subprocessor/international-
transfer table, Art. 30 RoPA pointer), platform seam, decryptMeasure
reject-not-clamp (tested with 140/−7), empty-flash fix, search. Caveats:
the banner fold and the caseload ordering branches have **no tests**; the
failed-scan override quirk is unpinned (F-8 below).

### Phase 2 waves 6–8 (`a176b3b`) — VERIFIED except the known deferrals

ES question pool (60/60 with true index parity pin), ES chips, usted
register (fresh 32-pattern sweep: zero stragglers), windowed History
FlatList, spoken calendar dates, README screens table, rollback section
(substantive), hardening quartet on all three compose files, Trivy
(fixable HIGH/CRITICAL fail) in CI + release, rclone tmp exclusion, log
rotation, `verify.sh --production` digest assertion, mutation floors
(backend ceiling 25 enforced; portal `break: 1`), per-file mobile coverage
floors, release on Python 3.14. Caveats in §3.

### Phase 3 (`6842896`) — VERIFIED as scoped; one commit-message inaccuracy

Measures registry (PHQ-9/GAD-7/PHQ-2 ceilings — client/portal-side; the
backend is instrument-blind **by design** under the zero-knowledge charter,
so "backend measures model/validation" in the claim is wording drift, not a
defect), time-of-day v2 (strict 400, ≥70% narrowing, v1 compat), note edit
history, local-recompute protocol (read in full: no key/plaintext field
exists, 409 on stale seq, ghost-date rejection, no processing session),
TEE/IRB design docs (disclosed as design/draft), deferrals tracked. **The
commit's "backend regeneration test extended" claim is not backed**: no
test change accompanies `brain_vectors.json` v2 (F-1 below).

### Remediation (`fefcdec`) — V-1..V-4 all VERIFIED independently

- **V-1**: 9/9 FINDING ids registered (id format byte-matches the harness
  emitter), defenses written, gate arithmetic re-verified against my own
  fresh `run_all.sh` output.
- **V-2**: THEME_LEXICON_ES = 226 words across the same nine themes;
  separate-map gating verified in both directions ("son las cinco" mints no
  family theme; "fiesta" mints nothing in English corpora; "other" keeps
  historical English behavior); detection reordered ahead of extraction;
  ES theme words excluded from topic eligibility; `spanish-mixed` 70-day
  golden case pins ES-derived `temporal:work` + `mood_correlation:work`
  candidates (read directly from the JSON); 9 backend tests + 2 mobile
  tests present and genuine; lexicon spot-check clean (no mis-themes, no
  cross-language contamination; EN∩ES collisions `social`/`doctor`/`yoga`
  share the same theme in both maps).
- **V-3**: 8-panel/9-expression dashboard, read-only provisioning, stable
  datasource uid, `verify.sh` grounding live (verified by running it), the
  alertmanager example mirrors runbook severities with an inhibit rule.
- **V-4**: POST idempotent-retry writes a revision on content change,
  byte-identical replays write none — all four cases tested in
  `test_note_history.py`.
- **V-5/V-6**: no code needed / preflight 5/5 (re-run: PASS).

## 3. New findings of this round (none known to round 1)

**F-1 (Medium — test gap + claim inaccuracy).** The full-engine golden
vectors (`shared/brain_vectors.json` `updates`, the Phase-3 "acceptance
gate" for the on-device port) are pinned by **no test on either side**:
`backend/tests/test_brain_vectors.py` and `mobile/tests/brainVectors.test.ts`
still cover only sentiment/stats/lexicon and were not touched by `6842896`.
A hand-edit or engine regression in the `updates` payloads would keep every
suite green. (Regeneration *is* deterministic — I regenerated byte-identical —
but nothing automates that for the full-engine cases.) The `6842896` message
"backend regeneration test extended" is therefore inaccurate.

**F-2 (Medium — D-3 fabrication class survives in `stats.avg_sentiment`).**
`brain.py:~4448-4459` computes `avg_sentiment` from the **unfiltered**
`per_entry` list, so budget-truncated entries (text blanked, no mood tag)
still contribute a fabricated neutral 0.0 — the exact defect D-3 fixed for
the mood series — and the value is rendered to therapists ("average
reading") in the portal. Same class in `patterns.py:493-498`.

**F-3 (Medium-Low — D-3 class via tagged truncated entries).** Truncation
keeps client tags (`insights.py:~714-726` replaces only `text`); themes
include `entry.tags` and mood-correlation residuals are built from the
unfiltered series, so a blanked-but-tagged entry joins its theme group
scored 0.0. Unpinned by the D-3 tests (which use untagged entries).

**F-4 (Medium-Low — rotation failure paths leave the vault on the old key).**
`mobile/src/rotation.ts`: `vault.lock()` + `disableBiometricUnlock` run only
on the success path. If `rotateCredential` or the re-login fails *after* the
server rekeyed, the function returns `{ok:false}` with the vault still
unlocked holding the OLD data key (wrap still present). An entry written in
that window seals under the old key and the retry ladder dead-ends at
"already-rotated-unverifiable". Mitigations exist (epoch bump → 401 → client
locks vault), but the fix's own comment ("must not depend on anything
dismissible") argues for locking in the failure branches too.

**F-5 (Low — dead ES lexicon class persists).** ~27–28 multi-word
`VADER_BASE_ES` keys ("sin esperanza" −3.2, "sin dormir" −2.4, "te quiero",
"me duele", "un poco"…) can never match under per-token lookup; only the 3
entries the audit named by line were removed. No no-spaces-in-keys
invariant test exists. The dead weight is also baked into
`shared/brain_lexicon.json` and the mobile port.

**F-6 (Low — silently dropped scope).** Optional TOTP for therapists
(Phase 2 workstream 2) is neither implemented nor registered as deferred.

**F-7 (Low — mutation gate can pass vacuously in one mode).** `mutation.yml`
runs `mutmut results > file || true` and then counts "survived" lines; a
results file that is empty or contains only error text (cache corruption,
`mutmut results` failing while exiting 0) counts 0 survivors and passes the
ceiling. A hard timeout does fail the job at the run step, so the window is
narrow — but a minimum-processed-mutants assertion would close it.

**F-8 (Low — portal banner fold).** A **failed** scan row unconditionally
overrides a server summary that says `sensitive: true` (in-session
undercount); the "whichever exists latest wins" comment compares no
timestamps; the fold has zero test coverage.

**F-9 (Low — B-5 half-fixed on the read side).** Granting counts ACTIVE
consents only, but `GET /consents` still counts ALL rows toward its 413, so
a patient with 100+ historical (revoked) therapists gets a load failure on
the share screen.

**F-10 (Low — overstated claims, behavior bounded).** Feedback-blob AAD
gives a ~48h replay window with unlimited replays inside it (CHANGELOG's
"cannot be replayed across recomputes" overstates); `BACKUP_OFFSITE_RESTART`
gating is by operator convention, not keyed on `MODE=fetch` (README of the
overlay doesn't document the variable); language gating for themes is
per-corpus, not per-entry (disclosed, but mixed-language users lose
minority-language themes).

**F-11 (Info — shipped-without-test fixes).** Rekey executemany batch form,
per-context note drafts, onboarding panel persistence, foreground
`activeDays` wiring, caseload ordering branches, and the A-1 test's
`version_conflict` half are all unpinned (fixes verified present by direct
code read).

## 4. Verdict

The six-commit series is **substantially as claimed**. Every quantitative
verification claim reproduces exactly; Phase 1's 33+7 items, Phase 2's
workstreams, Phase 3's scoped deliverables, and the V-1..V-4 remediations
are all real, most with genuine regression tests. The audit trail
(SECURITY_RESIDUALS ↔ red-team gate ↔ CI) is mutually enforcing in a way
few repos achieve.

Deltas found by this round, none blocking:
- one inaccurate commit-message claim (F-1: "regeneration test extended"),
- two survivors of the D-3 fabrication class the audit called Medium (F-2,
  F-3),
- one Medium-Low residual window on rotation failure paths (F-4),
- a tail of Low items: the dead-lexicon class (F-5), dropped TOTP (F-6),
  the vacuous-pass mode in the mutation gate (F-7), portal/test gaps
  (F-8–F-11).

Recommended next actions, in order: pin the `updates` vectors with a
regeneration test (F-1), filter `avg_sentiment`/residual paths the way D-3
filtered the mood series (F-2/F-3), lock the vault in the rotation failure
branches (F-4), add the no-spaces lexicon invariant while purging the dead
ES keys (F-5), and register TOTP as a deferred residual (F-6).

---

## 5. Remediation addendum (same day, post-report)

Every finding F-1..F-11 was fixed after this report was issued, and the
full re-verification surfaced one additional pre-existing harness defect
(F-12) which was fixed too:

| Finding | Resolution |
|---|---|
| F-1 | `gen_brain_vectors.py` refactored into importable builders; `test_brain_vectors.py` now regenerates the full-engine `updates` payload in-process and asserts float-for-float equality with the committed JSON |
| F-2 | `stats.avg_sentiment` (brain.py) and the legacy analyzer (patterns.py) apply the D-3 predicate — blank-untagged entries contribute no mood value; tests pin both, including the tagged-entry positive |
| F-3 | Theme mood-correlation residuals built from the blank-untagged-filtered pairs (prevalence/cadence keep tagged days); the fix also closed a latent `KeyError` crash in `_detect_links` for tag-only theme days |
| F-4 | `rotatePassword` locks the vault and drops the biometric wrap in the credential- and relogin-failure branches before returning `{ok:false}`; both branches tested |
| F-5 | 28 proven-dead multi-word ES keys removed; invariant test forbids whitespace in every per-token-consumed lexicon map; artifacts regenerated (vectors stayed byte-identical) |
| F-6 | TOTP registered as a tracked deferral in docs/SECURITY_RESIDUALS.md with standing controls named |
| F-7 | Mutation gate asserts recognizable mutmut status lines + a processed-mutants floor before judging the ceiling; the step's missing `working-directory: backend` (which made the old check inert) fixed |
| F-8 | Banner fold: successful scan wins, failed scan (`patterns: -1`) falls back to the summary, matching the per-row display; four fold tests added |
| F-9 | `GET /consents` cap counts ACTIVE consents only; retained (unique-per-therapist) history still lists; regression test with 100 revoked + 1 active |
| F-10 | CHANGELOG feedback-replay wording states the bounded ~48h window; UTC-seal comment corrected; `BACKUP_OFFSITE_RESTART`/fetch trap documented in the overlay README; README states per-corpus language gating |
| F-11 | New pins: rekey executemany batching (130 entries → exactly 2 UPDATE executions), rekey-preserves-`content_version`, onboarding panel persistence (7 tests), foreground `activeDays` wiring, portal note-draft context isolation, caseload ordering branches |
| F-12 (new) | The C3 red-team harness anchored date offsets to local `date.today()` against the server-UTC ±1 contract — a timezone flake that flipped the verdict to a false FINDING after 17:00 local on UTC-offset machines (UTC CI runners never saw it); harness re-anchored to server-UTC, verified BLOCKED at the failing hour |

Full re-verification after remediation: backend pytest green (1,323
tests, +16), mobile 1581/1581 (+10), portal 191/191 (+6), probe_brain
9/9, crypto vectors pass, `gen_brain_vectors.py` regeneration
byte-identical, `deploy/monitoring/verify.sh` all checks passed, and the
red-team suite back to 96 verdicts with exactly the 9 registered
residuals — the weekly CI gate green.
