# Therapist-Portal Multi-Patient E2E Suite — 2026-09-28

**Scope:** the requested end-to-end verification of the therapist portal —
multiple patients linked to ONE therapist, everything the therapist can see,
and every data-movement scenario around that link.

**Deliverable:** `backend/tests/test_therapist_e2e_multipatient.py`
(13 scenario tests, all green; ~2 s each; standard `pytest` gates apply).

Unlike the primitive-level suites (`test_therapist_api.py`,
`test_measures_api.py`, …) which pin each endpoint in isolation, this module
runs the **product story** against one coherent world per act. Every crypto
operation is the real client construction (`tests/helpers.py` emulators +
`security.sharing` reference implementation): real ECDH wraps, real AADs,
real GCM failures. Nothing is mocked except the recompute-day shim the
statistical patterns need to qualify (the established suite idiom).

## The cast (rebuilt fresh per test — repo fixture convention)

| Actor | State at world-build |
|---|---|
| `Dr. E2E` (dre2e) | the therapist under test |
| `Dr. Rival` (drother) | second therapist — isolation act |
| alice | **insight phase**: 70 seeded days, patterns + evidence dates, PHQ-9 (score 14, **item 9 = 2 — flagged**) + GAD-7 + older PHQ-9 |
| bob | **baseline phase**: 10 days, one GAD-7 |
| carol | **insight phase**: 40 days — the revoke/re-grant target |
| dave | registered, never paired |

alice/bob/carol grant consents to `Dr. E2E` through the full pairing flow
(code → lookup → wrap → grant); alice and carol recompute post-grant so
their caseload summaries exist.

## Scenario coverage map

### Act 1 — LINKING (multiple patients → one therapist)
- **SAS agreement on both screens**: the patient's `pairing/lookup` response
  and the therapist's `pairing/sas` read derive the SAME 6-digit SAS for the
  same live pairing session; the server-reported fingerprint equals the
  honest SHA-256 identity of the therapist's registered key (the
  load-bearing substitution check).
- **Caseload list is exactly the linked set**: {alice, carol, bob}, all
  active, each row carrying key material; dave absent, and every direct
  read against dave is the flat 404. Patient-side consent lists name
  "Dr. E2E" with the right wrap key.
- **Single-use + verifier gates**: a grant without the password verifier is
  422 (a stolen bearer cannot widen disclosure); after a successful grant
  the code is burned — a second patient replaying it gets 404.

### Act 2 — VISIBILITY (what the therapist can see)
- **Insight-phase patient, full loop**: unwrap the per-consent data key →
  decrypt the patterns blob → patterns non-empty with evidence dates →
  `state_seq` inside the ciphertext equals the plaintext echo (rollback
  sentinel) → drill into the journal behind a pattern's evidence window and
  decrypt the patient's actual seeded words → read the measures trail
  (newest-first: PHQ-9 14 w/ item9=2, GAD-7 9, PHQ-9 5 w/ item9=0; GAD-7
  carries no item 9).
- **Baseline patient is phase-gated**: `phase=baseline`, `blob=None`,
  `days_remaining>0`, no caseload summary — while his consented measures
  and journal entries remain decryptable (the disclosure covers them; only
  insights are phase-gated).
- **Caseload summaries served only where valid**: alice/carol summaries
  decrypt (patterns > 0, sensitive=False, newest date); bob gets none.

### Act 3 — ISOLATION
- **Patient keys cannot cross**: alice's unwrapped key fails GCM on bob's
  entry blobs; alice's own blob fails under bob's identity in the AAD
  (relocation rejected); bob's key cannot open alice's insights blob.
- **Rival therapist sees nothing**: empty caseload, every read against
  alice 404, note-write into her chart 404, and the patient's consent list
  names only their own therapist.

### Act 4 — NOTES (the therapist's own chart)
Create (anchored to a real surfaced `pattern_pid`) → decrypt round-trip →
changing PATCH bumps version to 2 → stale `base_version` is 409
`version_conflict` → the prior text survives as a decryptable revision →
a note id reused for another patient is a loud 409 → delete empties the
chart.

### Act 5 — DATA MOVEMENT
- **Revoke → re-grant on the SAME row**: after revoke the list shows the
  pair as revoked with NO key material and NO summary; insights/entries/
  measures all 404; the therapist's own notes stay readable and
  decryptable; carol journals while unlinked and the therapist stays blind;
  re-grant reactivates the SAME consent row id, restores full visibility
  INCLUDING the entry written while unlinked (decrypts), keeps note
  continuity, and the summary re-arms only after the next recompute.
- **Key rotation**: patient rekey makes the stored wrap dead (the therapist
  still unwraps the OLD key, which now fails GCM on the re-encrypted
  corpus) → `PUT /consents/{id}/rewrap` publishes the new key → the chart
  opens again end to end (entries + insights decrypt under the fresh key).

### Act 6 — AUDIT
One representative therapist session produces every action —
`list_patients`, `read_insights`, `read_entries`, `read_measures`,
`read_notes`, `write_note`, `update_note`, `delete_note` — visible from
BOTH sides: the therapist's own `/therapist/access-log` (with patient
names) and the patient's `/account/access-log` (grant by self; every
therapist row labeled actor `therapist`, actor_name `Dr. E2E`). The stored
trail is a contiguous hash-chained, MAC-sealed record that passes
`verify_access_log_chain`.

### Act 7 — the whole story in one world
Link three patients → per-patient visibility with three independently
unwrapped keys (all distinct) → note the chart → carol revokes (therapist
keeps only the note) → carol re-grants on the same row → alice rotates and
re-wraps → every active chart still opens with the CURRENT key material →
the audit trail carries the story.

## Results

- New suite: **13 passed**, 0 failed (≈ 24 s wall).
- `ruff check` + `ruff format --check`: clean (CI parity); mypy scope (`app/`) unaffected.
- Full backend suite: **1642 passed, 4 skipped** (4 min 26 s) — no regressions.
- Portal vitest suite: **413 passed** — no regressions.
