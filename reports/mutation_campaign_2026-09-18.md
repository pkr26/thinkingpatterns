# Mutation campaign 2026-09-18 — behavioral mutants over the non-negotiables

A targeted behavioral mutation campaign over the properties this product
cannot afford to lose: the zero-knowledge cryptographic boundaries, the
statistical honesty of the mini-brain (BH/FDR, effect gates, the 30-day
threshold, ground truth), the clinical boundaries (no advice, no
diagnosis, evidence-bound cards), crisis handling, and the sharing
architecture. 36 hand-written semantic mutants across six campaigns,
each applied to production code, run against the test suites, then
reverted byte-for-byte.

**Scorecard: 31/36 killed by the existing suites. 5 genuine survivors —
every one now pinned by a new regression test (`backend/tests/
test_mutation_pins_2026_09_18.py`, `mobile/tests/secureStore.test.ts`),
re-verified as killed: 36/36 post-remediation.**

Harness & raw verdicts: `redteam/mutation_campaign_2026-09-18/`
(`harness.py`, `verify_survivors.py`, `results/*.json`).

## Method

- One mutant = one semantic edit (constant, operator, condition, or
  deleted check) at the exact enforcement site, chosen to weaken the
  guarantee in the direction an attacker or regression would:
  looser FDR, smaller effect floors, earlier unlock, unpinned AAD,
  fail-open storage, quoting crisis text, role gates off.
- Verdict protocol: run the targeted suite first; every survivor is
  re-run against the FULL suite (`-m "not slow"` backend / complete
  vitest projects) before it counts as a gap. Timeouts count as killed
  (a hang is an observable behavior change).
- Restoration is byte-wise from a pre-mutation snapshot — never git —
  because the work tree carries uncommitted work. The harness asserts
  the restore after every mutant.
- Baselines ran green before any mutation (probe 9/9, both vitest
  projects, backend suite).

## Campaign A — mini-brain statistics

| Mutant | Verdict | Killed by |
|---|---|---|
| A1 BH q-threshold doubled (0.05→0.10) | KILLED | `test_partial_rejection_step_up` |
| A2 BH rank multiplier dropped (`p <= q`) | KILLED | `test_partial_rejection_step_up` |
| A3 BH rejects one hypothesis past the cutoff | KILLED | `test_none_rejected` |
| A4 engine ALPHA 0.05→0.25 | KILLED | `test_daily_cadence_pure_noise_replication_bound` |
| A5 Cohen's d floor 0.5→0.0 | **SURVIVED → pinned** | `test_trivial_standardized_effect_never_surfaces` |
| A6 effect gate AND→OR (correlation + link) | KILLED | `test_mood_tie_is_emitted_pre_gate` |
| A7 30-day gate → `>= 1` active day | KILLED | `test_phase_boundary[1-baseline]` |
| A8 temporal weekday gate off (production code) | KILLED | `probe_brain.py` (9/9 harness, exit 1) |
| A9 probe corpus: Sunday 'work' plant neutered | KILLED | `probe_brain.py` (self-check) |

A8/A9 validate the ground-truth probe itself: it detects a disabled
detector in production code AND a destroyed plant in its own corpus —
the 9/9 harness is a killing test, not a rubber stamp.

**A5 survivor analysis:** the only prior pin
(`test_effect_and_significance_gates`) asserts the surfaced card's
`detail["cohens_d"] >= brain.MOOD_MIN_EFFECT` — true for ANY value of
the constant, so zeroing it changed nothing observable. The new pin
builds the corpus the gate exists for: a small, tight, low-mood Sunday
group inside a wide noisy majority (seeded, deterministic) — reported
mood_delta ≈ 0.25 (clears the delta gate) with |d| ≈ 0.42 (under the
floor), presented across two qualification days. The healthy engine
refuses the card; with the floor zeroed it promotes on day two. A
canary test re-runs the corpus with the floor monkeypatched to 0.0 and
asserts the card DOES appear, so the corpus can't silently lose
discriminating power. The floor value itself is also pinned as a
product decision.

## Campaign B — pattern lifecycle

| Mutant | Verdict | Killed by |
|---|---|---|
| B1 statistical kinds promote without replication | KILLED | `test_true_sunday_concentration_is_detected` |
| B2 replication spread requirement dropped | KILLED | `test_sustained_decline_is_detected` |
| B3 GRACE_DAYS 7→7000 (never fade) | KILLED | `test_statistical_candidate_fades_to_archived_without_a_card` |
| B4 ARCHIVE_DAYS 45→4500 (never archive) | KILLED | `test_fading_then_archived_then_dropped` |
| B5 evidence half-life 45→45000 (no decay) | KILLED | `test_strength_decays_with_half_life` |

## Campaign C — crypto & memory boundaries

| Mutant | Verdict | Killed by |
|---|---|---|
| C1 `zeroize()` body removed | KILLED | `test_one_key_buffer_drives_every_decryption_and_is_zeroized` |
| C2 `run()` no longer scrubs its key copies | KILLED | same |
| C3 `pop()` doesn't consume the token | KILLED (full suite) | `test_keystore_pop_is_atomic_single_use` |
| C4 decrypt ignores AAD | KILLED | `test_roundtrip_with_and_without_aad` |
| C5 `build_aad` drops the first binding part | KILLED | `test_build_aad_canonical_and_unambiguous` |

C3 is a good advertisement for full-suite verification: it survived the
targeted `test_enclave.py` subset (which pins cross-owner behavior, not
reuse) and was killed by an audit-regression test elsewhere in the
suite.

## Campaign D — clinical boundaries

| Mutant | Verdict | Killed by |
|---|---|---|
| D1 diagnosis words removed from `_CLINICAL_TERMS` | **SURVIVED → pinned** | `test_narrative_rejects_diagnosis_language` |
| D2 narrative digit ban removed | **SURVIVED → pinned** | `test_narrative_rejects_digits_alone` |
| D3 narrative may echo crisis language | KILLED | `test_narrative_rejects_crisis_language` |
| D4 surfaced cards ship empty `evidence_dates` | KILLED (full suite) | `test_patterns_carry_evidence_dates` |

**D1/D2 survivor analysis:** the sanitizer tests exercised every rule,
but through inputs where several rules overlap — the audit's hostile
narrative contains digits AND "medication" AND a bare domain, so
removing any single rule changed no verdict. The new pins use inputs
that trip exactly one rule each ("a doctor would diagnose this pattern
quickly"; "your darker Saturdays came to 87 percent of them").

**Design observation (no mutant needed):** `_clean_narrative`'s
mechanical rules ban medication/diagnosis vocabulary, digits, contacts,
domains, and crisis echo — there is no general advice-language filter
("you should…", "you might suffer from…"). Plain advisory prose with
none of those markers would pass the sanitizer; the containment is
architectural (the INVERTED LLM path only annotates the deterministic
brain's own findings, and the author prompt forbids advice). If the
narrative path ever gains autonomy, an advice-language denylist is the
missing tripwire — noted here rather than fixed, because today the
model cannot mint claims the statistics didn't.

## Campaign E — crisis handling

| Mutant | Verdict | Killed by |
|---|---|---|
| E1 backend suppress tier → False | KILLED | `test_suppress_only_fixtures` |
| E2 backend dialog tier → False | KILLED | `test_dialog_fixtures_fire` |
| E3 question-interlock label tripwire off | **SURVIVED → pinned** | `test_label_tripwire_fires_without_the_sensitive_flag` |
| E4 mobile `detectCrisisLanguage` → false | KILLED | mobile crisis suites |
| E5 mobile `matchesCrisisSuppress` → false | KILLED | mobile crisis/redteam suites |

**E3 survivor analysis:** this is defense-in-depth working, not a hole
that leaked — disabling ONE of the three tripwires of
`pattern_is_sensitive` (label check) stayed safe because the
`sensitive` flag (brain-side) covers brain patterns and
`build_pool`'s belt-and-braces filter re-checks every rendered
question. But the label tripwire is the only layer covering patterns
that arrive WITHOUT the flag (LLM extras, legacy payloads), and no test
pinned it in isolation. The new pin does (both the predicate and the
end-to-end pool).

## Campaign F — zero-knowledge sharing & clients

| Mutant | Verdict | Killed by |
|---|---|---|
| F1 mobile fingerprint hashes base64 text, not DER | KILLED | mobile crypto/redteam pins |
| F2 portal fingerprint hashes base64 text, not DER | KILLED | portal crypto tests |
| F3 journal role gate off (therapist writes entries) | KILLED | `test_therapist_cannot_use_journal_endpoints` |
| F4 therapist role gate off (patient reads portal routes) | KILLED | `test_patient_cannot_use_therapist_endpoints` |
| F5 mobile PBKDF2 600k→1k | KILLED | mobile crypto/vector tests |
| F6 portal PBKDF2 600k→1k | KILLED | portal crypto tests |
| F7 backend KDF floor 100k→1 | KILLED | `test_iteration_floor_is_enforced` |
| F8 keychain rejection falls back to plaintext AsyncStorage | **SURVIVED → pinned** | secureStore custody test |

**F8 survivor analysis:** the custody test covered a backend that
THROWS, but the production `keychainBackend.writeDeviceKey`'s own
fail-closed seam — `react-native-keychain` returning `false` — was
never exercised (the node mock always succeeded). The shared
`keychainMock` gained a `__failWrites` seam (mirroring `__reset`), and
the new test asserts the reject AND that no device key lands in
AsyncStorage.

**Read-only portal, verified structurally:** every patient-data route
on the therapist router (`/therapist/me`, `/patients`, insights,
entries) is GET-only; the only mutating routes operate on the
therapist's OWN resources (`POST /register`, `DELETE /account`,
`POST /pairing-codes`, notes CRUD). The portal client's write verbs map
exactly onto those — there is no portal code path that writes patient
data, and the backend role gates (F3/F4) are independently pinned.

## Remediation added by this campaign

- `backend/tests/test_mutation_pins_2026_09_18.py` — A5 (behavioral +
  canary + floor pin), D1, D2, E3 (predicate + end-to-end).
- `mobile/tests/secureStore.test.ts` + `mobile/tests/helpers/
  keychainMock.ts` (`__failWrites` seam) — F8.
- Full suites re-run green with the pins in place (backend `-m "not
  slow"`, mobile 60 files / 1177 tests, ruff + mypy clean on the new
  file).

## Reproduce

```bash
backend/.venv/bin/python redteam/mutation_campaign_2026-09-18/harness.py   # all 36
backend/.venv/bin/python redteam/mutation_campaign_2026-09-18/harness.py A C
backend/.venv/bin/python redteam/mutation_campaign_2026-09-18/verify_survivors.py
backend/.venv/bin/python -m pytest backend/tests/test_mutation_pins_2026_09_18.py -q
cd mobile && npx vitest run tests/secureStore.test.ts
```

(Frontend mutants need `node` on PATH — e.g. `~/tools/node22/bin`.)
