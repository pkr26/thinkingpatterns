# Behavioral mutation campaign, round 4 — 2026-09-22

## Scope

Rounds 1–3 (2026-09-18/19, see `../mutation_campaign_2026-09-18*` and
`../mutation_campaign_2026-09-19/`) froze the mutation baseline as of
2026-09-19. The 2026-09-21/22 deep-audit waves then landed large NEW
backend surfaces those campaigns never saw. Round 4 mutates exactly those
surfaces, fresh, on the current tree (commit `0eb9574`):

| Campaign | Surface | Mutants |
|---|---|---|
| U | TOTP second factor (login gate, replay fences, enrollment ladder) | 9 |
| V | Measures / measurement-based care (quota, dates, pagination contract, revision marker, disclosure gate, both read paths) | 13 |
| W | Therapist note edit history (revision append, marker coupling, history read) | 9 |
| X | Entry content versioning (create/replace guards, monotonic advance, v2 AAD, rekey generation) | 5 |
| Y | Time-of-day narrowing + Spanish parity (tod validation, evidence bars, language gate, ES topic eligibility, crisis regex) | 9 |
| Z | Audit-trail read path + lifecycle re-auth (scoping, redaction, keyset cursor, deactivated routing, verifier gate) | 7 |

**52 mutants.** Same discipline as rounds 1–3: snapshot the target file's
bytes, apply ONE semantic mutation, run the targeted suite(s) (`-x`,
`not slow`, root venv, `PYTHONDONTWRITEBYTECODE=1`), restore byte-wise
(never git), record killed/survived. Oracle-rot exits (pytest 2/3/4/5,
"no tests ran") are SETUP-ERRORs, never kills. Baseline suite verified
100% green before the campaign.

## Results

| Stage | Count |
|---|---|
| Mutants queued | 52 |
| KILLED by targeted suites | 33 |
| Survived targeted suites | 19 |
| Of those, killed by the FULL fast suite | 1 (Y6 — `test_brain_vectors.py`'s byte-exact sentiment vectors pin the EN-wins merge order) |
| **Genuine survivors** | **18** |
| Pins added (`backend/tests/test_mutation_round4_pins.py`) | 18 |
| Pins verified to kill their mutant (`pin_check.py`) | **18/18** |
| Documented residuals | 0 |
| Full fast suite after pins | green |

Per-campaign kill counts (targeted stage): U 7/9, V 8/13, W 6/9, X 3/5,
Y 5/9, Z 4/7.

## The 18 genuine survivors and their pins

Every survivor is now killed by exactly one deterministic pin; the
campaign directory's `pin_check.py` re-applies each mutant and requires
its pin to fail under it.

- **U7** enable does not consume its timestep — the confirm code could
  immediately log in. Pin freezes the RFC clock (no 30 s waits) and
  requires 401 `totp_code_invalid` for the enable code at login.
- **U8** disable replay fence relaxed (`<=` → `<`) — the code that just
  logged in could also strip the factor. Pin: frozen-clock ladder
  enable → login → disable-with-the-login-code → 403.
- **V1** measure quota guard unpinned. Pin shrinks
  `MAX_MEASURES_PER_USER` to 2 and requires 413 at the boundary.
- **V8** measures increment fail-closed guard unpinned. Pin seeds
  `measures_revision = 2**63-1`, requires 503 and zero stored rows.
- **V9 / V11** the patient read and the therapist mirror dropped their
  final revision drift fences. Pins monkeypatch
  `current_measures_revision` to move mid-read; both paths must 409
  `collection_changed`.
- **V12** mirror post-fetch byte sanity unpinned. Pin under-reports the
  metadata blob length to zero (dialect-drift shape) and requires the
  post-fetch real-byte check to refuse the page.
- **W7** revision-read therapist scoping unreachable behind the
  still-scoped note fetch — pinned as defense-in-depth by seeding a
  foreign-`therapist_id` revision row directly in the DB (the API cannot
  produce one) and requiring it to stay invisible.
- **W8** history order only weakly pinned (single-revision tests). Pin:
  two edits, revisions must decrypt newest-first `[v2, v1]`.
- **W9** history page ceiling unpinned. Pin: `limit=201` → 422.
- **X4** the v2 AAD version binding is a cross-platform byte contract —
  every in-repo encrypt/decrypt pair routes through the same function, so
  constant-binding mutants are self-consistent. Pin constructs the
  expected AAD independently (`build_aad(ENTRY_CONTEXT, …, "2")`) the
  way mobile/portal do.
- **X5** rekey output generation unpinned. Pin calls
  `_rekey_entry_batch` directly and requires the output to authenticate
  only under the v2 AAD of the row's version (both v2 and v1 inputs).
- **Y2** the N≥3 tod-evidence bar unpinned. Pin: two tod-bearing
  Sundays must NOT narrow the temporal card.
- **Y4** no corpus sat exactly at the 0.7 dominance bar. Pin: 7-of-10
  evening (exactly 0.7) must narrow — the comparison is inclusive.
- **Y8** the 50-token language floor unpinned. Pin: a 4-entry Spanish
  corpus keeps the historical English default (`stats["language"] ==
  "en"`).
- **Z3** the keyset cursor id tiebreak unpinned (rows sharing one
  timestamp could be skipped). Pin seeds two same-`at` rows and walks
  the cursor across them.
- **Z4** therapist access-log actor scoping unpinned (fixtures never had
  two acting therapists). Pin: two therapist/patient pairs, one audited
  read each; the other therapist's patient name must not leak.
- **Z6** the wrap-rotation deactivated recheck is unreachable through
  the API (`require_user` 401s deactivated accounts at the door). Pin
  drives the handler directly with a deactivated user (the round-3 O2
  pattern) and requires 404.

The one non-genuine survivor, **Y6** (lexicon merge order), is killed by
the full suite's byte-exact sentiment vectors — no pin needed; recorded
here so the targeted-suite gap is not re-litigated.

## Artifacts

- `harness.py` — the 52 mutants and the round-3 harness machinery.
- `verify_survivors.py` — full-suite re-verification of survivors.
- `pin_check.py` — (mutant, pin) kill verification, 18/18.
- `results/mutation_results_*.json` — targeted-stage verdicts.
- `results/survivor_full_suite_verification.json` — full-stage verdicts.
- `results/pin_kill_verification.json` — pin kill verification.
- `backend/tests/test_mutation_round4_pins.py` — the pins.

The per-PR gate (`../run_pr_mutation_gate.py`) now loads this campaign;
round 4 carries **no documented residuals** — every mutant is killed by
the current suite.

## Reproduce

```bash
cd redteam/mutation_campaign_2026-09-22
../../.venv/bin/python harness.py        # full campaign (~35 min)
../../.venv/bin/python verify_survivors.py
../../.venv/bin/python pin_check.py
```
