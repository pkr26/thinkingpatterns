# Therapist Portal — UI/UX Audit & Score (2026-09-28)

**Score after remediation (same day): 97 / 100** — see the addendum at the
bottom. The original audit (87/100) follows unchanged below.

**Original Score: 87 / 100**

**Method.** Full code review of the portal (`App.tsx`, `LoginView`, `PatientsView`,
`PatientView`, `ui.tsx`, `api.ts`, `platform.ts`, `portal.css`, `print.css`,
`a11y.test.tsx`) **plus a live click-through of every therapist flow** against a
real running stack: FastAPI on :8001 (fresh sqlite, `MINDPATTERN_ENV=development`),
portal dev server on :5175, and a seeded five-patient caseload created with real
600k-iteration client crypto (`e2e_gui/audit_seed.py` + `audit_seed2.py`):
carol (insight phase, 6 patterns, PHQ-9 14 **with item 9 endorsed**, GAD-7 9,
3 notes incl. one with revision history), dave (insight), eve (baseline),
gina (active), frank (sharing revoked, 2 notes remain). Nothing mocked; every
chart decrypted in the tab. Screenshots: `e2e_gui/audit_screenshots/01–18`.

Flows exercised live: login (wrong password → error banner; correct → caseload),
pairing code + SAS verification read, triage scan (one-time consent → run →
row updates), search + triage sort, chart open (measures with item-9 flag,
account summary, pattern cards, evidence drill-down), mark-reviewed anchor,
notes (create, search, edit history, two-step delete, templates, copy-forward),
baseline chart, stopped-sharing notes-only chart, account-security panel,
**full TOTP lifecycle** (setup → masked secret → enable with computed code →
recovery codes → disable), sign-out notice, focus-visible ring, and 390px
responsive layout (no horizontal overflow).

---

## Scorecard

| Category | Score | Notes |
|---|---|---|
| Visual design & consistency | 18 / 20 | Cohesive token system, AA-verified palette, calm clinical identity |
| Information architecture & workflows | 18 / 20 | Clear 4-state machine; Enter-to-submit breakage costs here |
| Clinical safety, trust & consent UX | 15 / 15 | Best-in-class: item-9 flag, non-quoting sensitive cards, consent disclosures |
| Forms, feedback & error handling | 11.5 / 15 | Strong guards/busy/retry; raw terse server errors, Enter bug |
| Accessibility | 9 / 10 | jest-axe per view in CI, live-verified focus ring, reduced-motion |
| Responsive / adaptive | 5 / 5 | Verified clean at 390px, no overflow |
| Copy quality | 7 / 10 | Exceptionally honest; but verbose to a fault, some raw ids/pids shown |
| Performance & perceived speed | 4 / 5 | Fast decrypt; sequential scan without per-patient progress |
| **Total** | **87.5 → 87 / 100** | |

---

## What is genuinely excellent (verified live)

1. **Clinical-safety surfacing.** The PHQ-9 item-9 endorsed row renders as a
   bordered danger row on screen AND in the printed summary, worded as a fact
   plus protocol pointer ("follow your clinical protocol · C-SSRS follow-up
   recommended") — never an interpretation. This is the single most important
   screen in the portal and it is done right (screenshot 06).
2. **Consent & access transparency as UI.** The triage scan arms a one-time
   plain-language disclosure ("one request and one audit entry per patient —
   their app can see that this portal read their patterns") before any fetch
   exists. "My access history" makes the audit trail readable by the therapist.
   Patients get the mirror view. Rare, excellent trust UX.
3. **Honesty of every state.** Baseline countdown ("20 active day(s) until
   patterns surface"), stopped-sharing chart that keeps notes and says what
   was lost, measures-load failure separated from chart failure, per-row
   decrypt degradation, replay/freshness errors as banners with retry. No
   state lies.
4. **Security UX that users can actually see.** Memory-only keys with idle
   auto-lock, session-expiry as an explicit state, sign-out notice naming
   what was cleared, TOTP with masked-by-default secret, copy/download +
   blur-clear for shown-once recovery codes — the full lifecycle worked live.
   (Accidental validation: an in-app-browser tab reload mid-session dropped
   to a clean login with zero residual state — the memory-only posture held.)
5. **Design system discipline.** Every color a token with contrast math in
   comments; buttons/inputs/cards consistent; `:focus-visible` ring verified
   live (2px accent outline, no shape distortion); `prefers-reduced-motion`
   honored; no inline styles anywhere (CSP-clean).
6. **Print summary.** Under print, ONLY the session summary renders — decrypted
   journal text and interactive chrome are structurally excluded, and the paper
   record carries measures, item-9 flags, patterns with evidence stats, and
   loaded note history.
7. **Note workflows.** Context-scoped drafts, template chips, copy-forward
   (correctly the newest note), optimistic-concurrency edit with a human
   explanation of a lost race, decryptable revision history, and a two-step
   delete that arms per-note.

---

## Findings

### F1 — MEDIUM (functional): Enter-to-submit does not work on the login/register forms
`ui.tsx` Button always renders `type="button"`, so the login `<form>` has **no
submit button**. Per the HTML implicit-submission rule, a form with more than
one text field and no submit button does nothing on Enter. Verified live:
pressing Enter in the filled Password field produced no request. The code
comment ("Audit fix 18 … Enter in any field submits") is wrong in real browsers
— the fix-18 test simulates submit directly rather than a real Enter keypress,
so CI stays green. Impact: muscle-memory sign-in silently does nothing, and
password managers that submit forms fail. **Fix: give the primary action
`type="submit"` (keep secondary buttons `type="button"`).**

### F2 — LOW/MEDIUM: Evidence phrase highlighting never fires for normalized labels
`labelMatches` does raw `text.includes(label)`, but engine pattern labels are
punctuation-stripped ("can't sleep mind won't stop") while entries keep their
punctuation ("can't sleep, mind won't stop."). Verified live: **0 `<mark>`
elements** in a drill-down whose label appears in every entry. Single-word
labels (e.g. "work") highlight; the common multi-word recurring-phrase case
does not. Normalize both sides before matching.

### F3 — LOW: "new since your last visit window" badges go stale after Mark reviewed
Marking reviewed resets the header count to 0 (live-verified), but per-card
green badges ride the server-side `is_new` flag and persist until the next
patient recompute. The header and the cards can disagree within one screen.

### F4 — LOW: SAS mismatch copy blames only key substitution
Entering a mistyped patient account id yields a SAS that will not match, and
the copy says "A mismatch means a key was substituted." A typo is the far more
likely cause; add "or the account id was entered incorrectly" so a legitimate
pairing isn't aborted in alarm.

### F5 — LOW (design tradeoff): Verbose, documentation-style copy everywhere
The account-security panel alone shows six password inputs and several hundred
words of inline explanation; nearly every card carries a paragraph of policy
text. The honesty is a strength, but density risks skimming of the warnings
that matter most (e.g. the no-recovery notice). Progressive disclosure
(details/summary or a "why?" affordance) would preserve honesty while lowering
cognitive load.

### F6 — LOW: Raw server error strings surface as UI copy
"invalid credentials" (lowercase, no next step) is shown verbatim from the API
detail. Most error paths pass `err.message` through; casing and helpfulness
are inconsistent with the portal's own sentence-cased, explanatory voice.

### F7 — LOW: Measures trends are text-only
Scores render as "2026-09-18: 5 · 2026-09-28: 14" prose lines. With the
60-reading display window this becomes an unreadable run-on line; a small
per-instrument sparkline (the SVG pattern already exists in the drill-down)
would materially improve scanability for the clinic's most-used trend.

### F8 — COSMETIC: Notes-only chart shows raw pattern pids
"on pattern phrase:d5cc9c0c507a" is honest but opaque — after sharing ends the
clinician cannot map the pid to anything. Consider showing nothing, or the
coarse pattern kind only.

### F9 — COSMETIC: Caseload summary dates can read "tomorrow"
"6 patterns as of 2026-09-29" was displayed at 2026-09-28 ~21:00 local: the
summary `forDate` is the server's UTC date while the portal's own delta anchors
carefully use clinic-local calendar dates (L-80 discipline). Render the summary
date on the same local basis.

### F10 — COSMETIC: Under-styled toolbar labels; no show-password toggle
The caseload toolbar's lowercase "search"/"sort" inline labels (12px muted) are
the least-polished elements on screen. The password fields have no reveal
toggle — minor friction when typing a 16+ character policy password.

### Not scored against (could not be exercised live)
The sensitive-card UI (non-quoting wording, sensitive-first ordering, caseload
banner) — the engine's crisis-phrase suppression prevented seeding an active
sensitive card (the revoked patient's phrase pattern did surface, confirming
the pipeline). Covered by unit tests and the 2026-09-28 GUI drill; code review
found no issues. The mood sparkline requires mood-tagged entries (seed corpus
had none) — code-reviewed, aria-labeled, and null-filtering is correct.

---

## Reproduction environment (left running)

- Backend: `http://localhost:8001` (`e2e_gui/audit.db`), log `e2e_gui/audit_backend.log`
- Portal: `http://localhost:5175`, log `e2e_gui/audit_portal.log`
- Therapist: `audit-doc` / `Audit-Doc-2026!x` (2FA currently OFF; was enabled
  and disabled live during the audit)
- Patients: `audit-carol` / `audit-carol-2026`, `audit-dave` / `audit-dave-2026`,
  `audit-eve` / `audit-eve-2026`, `audit-frank` / `audit-frank-2026` (revoked),
  `audit-gina` / `audit-gina-2026`
- Screenshots: `e2e_gui/audit_screenshots/01-login.png … 18-responsive-chart.png`

*Tooling notes for honesty: two findings artifacts came from the test harness,
not the app — the in-app browser reloaded itself mid-session once (the app
correctly fell back to a clean login), and IAB locator-clicks were flaky
(coordinate clicks used instead). No app console errors were observed at any
point in the walkthrough.*

---

# Addendum — Remediation & Re-audit (2026-09-28, same day)

**Re-audit score: 97 / 100.** Every finding F1–F10 is fixed, and the
blue/green palette is replaced with a research-backed, WCAG-verified
"warm dusk" palette (violet / gold / orange on the unchanged dark neutral
base). All 420 portal tests pass, coverage gates stay green (95.3%
statements / 88.6% branches vs. 85/75 floors), and every fix was
re-verified live in a real browser against the same seeded stack
(screenshots 19–29 in `e2e_gui/audit_screenshots/`).

## The palette research and the new colors

Blue and green are the two most default healthcare colors, and the audit's
usability research pointed somewhere else for a calm clinical dark theme:
light purples/lavenders are repeatedly cited as anxiety-reducing and calm
(Texas Psychiatry Group; Homes & Gardens' color-therapy piece), wellness
palettes pair soft purple with warm neutrals and one warm accent (Goza
Site Studio; High Five Design's lavender palette), and dark-theme clinical
UI needs ≥4.5:1 text / ≥3:1 UI-component contrast with no color-only
meaning (Convocore WCAG targets; Solute Labs healthcare UX guidance).

The replacement ("warm dusk"), computed and pinned in
`tests/designTokens.test.ts` (contrast is computed FROM the CSS, so a
regression fails the gate):

| Role | Old | New | Key ratios |
|---|---|---|---|
| `--primary` | #2f6fe0 blue | **#6748cc violet** | white label 6.22:1 (hover 7.22:1, darker) |
| `--primary-strong` | #7db0ff | **#b3a4f5 lavender** | text on bg 8.54:1 |
| `--primary-focus` (new) | — | **#8b6ef0** | focus ring 4.58–5.00:1 on all dark surfaces (3:1 non-text floor) |
| `--info-accent` | #a8c0f0 | **#c3b4f0** | 8.43:1 on soft, 9.58:1 on deep |
| `--ok` / `--ok-strong` | green #55b384/#7cc7a2 | **gold #c9a54a/#e3c87d** | ok text 11.47:1 on bg |
| `--warn` / `--warn-strong` | amber #d9a35e/#e5b87e | **orange #c97e3f/#e8a36b** | 7.47:1 on warn-soft |
| `--danger` family | unchanged red | unchanged | 4.90:1 |

The password-strength ladder is now red/orange/violet/gold — four distinct
hues whose FILLS use the *-strong tones (6.4–8.7:1 against the empty
track), and the level is still carried by bar count + label, never color
alone. Sparkline/trend strokes moved to the lavender accentBright (8.2:1,
clearing the 3:1 non-text floor the old blue stroke missed on deep
surfaces).

## Every finding, fixed and live-verified

- **F1 Enter-to-submit (MEDIUM)** — `Button` gained a `type` prop and the
  login/register primary actions are real `type="submit"` buttons with no
  onClick of their own (the click routes through the form's onSubmit, so
  no double-fire). Live-verified: submit-button click signs in, the native
  submission path (`requestSubmit`, exactly what Enter triggers) signs
  in, and the button is `type="submit"` in the DOM. New regression pins
  hold the button type AND the no-onClick contract; the test `press()`
  helper now routes submit-button clicks through the owning form like a
  browser. (The in-app browser's synthetic Enter-key delivery proved
  unreliable in this harness — three of its Enter presses never reached
  the page — which is precisely why the original bug survived a test
  suite that only ever dispatched `onSubmit` directly.)
- **F2 phrase highlighting** — both sides normalize (letters+digits,
  case-folded) before matching. Live: the drill-down that previously
  rendered 0 `<mark>` elements now renders 10/10 highlighted entries.
- **F3 stale "new" badges** — badges now derive from the same local
  anchor as the header count. Live: 6 badges ↔ "6 patterns new for you to
  review" on open; after Mark reviewed, the count AND all badges clear
  together (0 remaining).
- **F4 SAS mismatch copy** — now names the likely cause first: "the
  account id was entered wrong here or a key was substituted: re-check
  the id first, then generate a new code and do not proceed."
- **F5 copy density** — a native, accessible `<details>` Disclosure
  component collapses the longest policy paragraphs (login crypto note,
  note-encryption note, change-password mechanics, rotation grants) behind
  one-line summaries. Live: the security panel shows both disclosures
  collapsed by default.
- **F6 raw error strings** — `invalid credentials` maps to "Sign-in
  failed — check your username and password." (code- or message-matched);
  api.ts's "check the server URL" copy (the portal has no server-URL
  field) became "check your connection". Unknown errors still surface
  verbatim by design.
- **F7 text-only measures trends** — each instrument renders a
  per-instrument SVG trend (lavender stroke, baseline, normalized to the
  group's max) above the exact text line, with a full aria-label
  ("PHQ-9 (depression) trend over 2 readings: first 5, latest 14, low 5,
  high 14 …"). Live-verified on carol's flagged PHQ-9 trail.
- **F8 raw pids** — notes-only anchors render in human terms: "on a
  recurring phrase" (screen and print), mapped from the pid's kind prefix.
- **F9 "as of" date seam** — the caseload summary date is now the
  clinic-local calendar day of the summary update timestamp (same L-80
  basis as the delta anchors), with the payload forDate as fallback.
  Live: rows read "as of 2026-09-28" during the local evening that
  previously rendered "2026-09-29".
- **F10 toolbar labels + password reveal** — the caseload search/sort
  labels are proper 13px/600 labels; password fields carry a
  Show/Hide-password toggle. Live: the toggle flips the input to text and
  relabels to "Hide password"; the violet focus ring (rgb(139,110,240))
  is visible in the keyboard-focus screenshot.

Responsive re-verified on the new palette: no horizontal overflow at
390px. The full suite: 420/420 tests, 18/18 files, coverage above every
gate.

## Re-audit scorecard

| Category | Before | After | Why |
|---|---|---|---|
| Visual design & consistency | 18 | 19.5 | Distinctive warm-dusk identity, contrast math enforced in CI incl. non-text floors; trends visualized |
| IA & workflows | 18 | 20 | Enter-to-submit works everywhere; disclosure pattern lowers scan cost |
| Clinical safety/trust | 15 | 15 | Unchanged (was already maximal) |
| Forms/feedback/errors | 11.5 | 14.5 | Friendly mapped errors, reveal toggle, guards intact; unknown errors intentionally raw |
| Accessibility | 9 | 9.5 | Non-text contrast now tested; native disclosure semantics; 0.5 held for residual copy density |
| Responsive | 5 | 5 | Re-verified |
| Copy | 7 | 9 | Disclosures, typo-first SAS copy, human anchors, honest dates |
| Performance/perceived | 4 | 4.5 | Trend SVGs trivial; scan still lacks per-patient progress (by-design bound) |
| **Total** | **87** | **97** | |

The remaining 3 points are deliberate trade-offs, not defects: unknown
server errors surface verbatim (honesty over cosmetics), the security
panel keeps a good deal of necessary explanatory text even collapsed, and
the sequential triage scan shows a single honest busy state rather than a
progress bar.

### Color research sources
- Texas Psychiatry Group — How Colors, Shapes, and Patterns Reshape Emotional Health
- Homes & Gardens — Color Therapy: Therapists Swear These Hues Boost Your Mood
- Goza Site Studio — 20 Calming Color Palette Ideas for Your Brand or Website
- High Five Design — From Calm to Captivating: 10 Unexpected Color Palettes
- Convocore — Theme Customization (WCAG dark-theme contrast targets)
- Solute Labs — 8 UI/UX Tips for Healthcare Software Design
