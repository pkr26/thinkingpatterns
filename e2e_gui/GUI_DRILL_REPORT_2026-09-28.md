# Live Portal GUI Drill — 2026-09-28

**Scope:** click-through browser automation against the LIVE stack — real
backend API (:8000, file-backed sqlite), real patient web app (:5173), real
therapist portal (:5174), driven in a real browser (in-app browser,
Playwright surface). Real crypto everywhere: the therapist's P-256 wrap
keypair was generated IN the browser at registration; the patient's data
key was wrapped IN the browser at grant; every chart render decrypted in
the tab. Nothing mocked.

**Artifacts:**
- `e2e_gui/seed_patients.py` — live seeder (real 600k-iteration client
  KDF, direct-sqlite created_at backdate, journal + recompute + measures)
- `e2e_gui/screenshots/01…10-*.png` — one screenshot per walkthrough state
- `e2e_gui/backend.log`, `web.log`, `portal.log` — server logs for the run

**Cast:** therapist `dre2egui` (created through the portal UI),
`e2e-alice` (70 journal days, 4 patterns, PHQ-9 14 w/ item 9 = 2, GAD-7 9,
PHQ-9 5), `e2e-bob` (10 days, baseline, GAD-7 4).

## The walkthrough, as executed

| # | Step | Result |
|---|---|---|
| 1 | Portal registration through the UI (name/username/password) | ✅ keypair generated in-browser; landed on empty caseload with wrap-key fingerprint `F5E7 B89F … 4DCE` |
| 2 | Seed two patients against the live API | ✅ alice: 70 days, 4 patterns; bob: baseline |
| 3 | Portal "Generate pairing code" | ✅ code `WMSFBYHC` + fingerprint displayed |
| 4 | Web app: alice login (600k PBKDF2, onboarding) | ✅ signed in, 70-entry sync |
| 5 | Share screen: code → Look up | ✅ "Therapist: Dr. E2E Gui", SAS `081 223`, pairing id, fingerprint **identical to the portal's** |
| 6 | Portal SAS read (patient's id entered) | ✅ **portal SAS = patient SAS = `081 223`**; server key id `f5e7b89f24f6d4a4` = fingerprint prefix |
| 7 | Patient: both confirmation boxes → "Confirm and share" | ✅ "Shared with Dr. E2E Gui…" + grant listed with Revoke |
| 8 | Post-grant recompute (script) → portal caseload | ✅ "e2e-alice · sharing since 2026-09-28 · **4 patterns as of 2026-09-28**" (summary decrypted in-browser) |
| 9 | Open alice's chart | ✅ measures card (PHQ-9 `09-18: 5 · 09-28: 14` + **item-9 endorsed safety row**, GAD-7 `09-25: 9`), account summary (70 entries · 70 active days · avg 0.71 · 07-20 → 09-27), 4 pattern cards |
| 10 | "See the evidence" drill-down | ✅ **10 journal entries decrypted in the tab** — alice's actual seeded words, pattern stats (state emerging, first seen 07-26, evidence density 80%) |
| 11 | Pattern-anchored note: create → edit → history | ✅ saved; edit landed (optimistic versioning); "previous (1)" revision decrypted |
| 12 | Second pairing code → bob grants via web UI | ✅ same flow, second patient |
| 13 | Portal caseload with both patients | ✅ bob (no summary — baseline) + alice (4 patterns) |
| 14 | Open bob's chart | ✅ **"Still in the baseline phase — 20 active day(s) until patterns surface"** — no patterns rendered, GAD-7 visible, notes available |
| 15 | Alice revokes via web UI (two-step) | ✅ "Revoked — Dr. E2E Gui loses access immediately. What they already read cannot be unread." |
| 16 | Portal after revoke | ✅ alice moved to **STOPPED SHARING** ("access ended … Your notes about this patient stay"), bob still ACTIVE |
| 17 | Alice's notes-only chart | ✅ honest "Sharing ended" card + notes composer |
| 18 | Portal "My access history" | ✅ every action rendered (list_patients / read_insights / read_entries / read_measures / read_notes / write_note / update_note / read note revisions), per patient, newest first |
| 19 | Patient Settings "Who accessed your data" | ✅ the mirror: every therapist action labeled `(therapist)` + alice's own grant/revoke |

## Findings

**F1 (LOW, UX continuity — pattern-anchored notes invisible after revoke) —
FIXED same day, verified live.** The drill wrote a note anchored to
alice's rumination pattern. After she revoked, the notes-only chart
rendered only GENERAL notes (`PatientView` filtered `pattern_pid !== null`
behind a pattern selector that no longer exists), so the pattern-anchored
note — still stored and still served by the API (verified in the DB:
`phrase:a4adc4d084fc`) — had no UI surface. The portal's own copy ("Your
notes about this patient stay") was true at the data level but not fully
at the UI level.

*Fix (2026-09-28, same session):* the notes-only card now renders the
WHOLE chart chronologically under "My notes about this patient"; each
anchored note carries its pid as a quiet anchor label
(`on pattern phrase:…`); "copy forward last note" and the printed summary
("Therapist notes (all)") cover the same set. Pinned by two new `F1`
tests in `portal/tests/views.test.tsx` (anchored note renders with its
anchor + full affordances; the ACTIVE chart's general card is
unchanged); the M-22 mock was made contract-shaped along the way.
Gates after the fix: portal **415/415** tests, typecheck clean,
coverage above floors. Live re-verified against the exact drill state
that exposed the bug — screenshot
`screenshots/11-fix-F1-anchored-note-visible-after-revoke.png` shows the
anchored note, its pid anchor, and its Edit/View-history/Delete
affordances rendering post-revoke.

**F2 (note, environment):** the dev servers must outlive the shell that
launched them for a drill of this length — the initial background-task
backend was reaped at the 10-minute cap mid-drill (clean shutdown; the
browser sessions dropped to their login screens, as designed for a
server loss). Restarted under `nohup`; no app defect involved. The
portal's memory-only session correctly forced re-login after every
reload — expected, by design.

**F3 (fixed during the drill, harness):** the first seed used the pytest
emulator's fast KDF (1k iterations) — the real web client derives at
600k, so alice's first UI login failed with "invalid credentials" until
the seeder switched to the real schedule (`LiveClientEmulator`). Live
GUI drills must seed with production KDF parameters.

## What this drill adds over the pytest E2E suite

The API-level suite (`test_therapist_e2e_multipatient.py`) proves the
protocol; this drill proves the PRODUCT: the real registration form
generates usable key material, the two pairing screens agree for two
humans, the caseload summary decrypts and renders, pattern cards and
decrypted journal text paint in the chart, the item-9 safety row renders,
the baseline gate renders honestly, revoke propagates to the portal list
within one reload, and BOTH audit views render the same trail.
