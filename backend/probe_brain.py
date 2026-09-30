"""Empirical probe: what does the mini-brain ACTUALLY surface on a realistic
journal with planted ground truth?

Design: the mood STREAM (continuous, planted structure) is injected through
JournalEntry.sentiment — exactly how a client-supplied mood tag behaves —
while the TEXT carries only themes and phrases. This decouples mood from
vocabulary so false-positive checks are meaningful (v2 failed here: five
false mood correlations at p <= 1e-6, driven purely by a mood trend).

Uniform standard (2026-09-26 statistical review, item 13): EVERY check
asserts SURFACING — store membership is not a verdict, a candidate that
never earned a card must not pass ground truth. F and G run on their own
MIXED corpora (realistic filler text, several themes, no isolated
sentiment-only series): the main corpus's planted dips (A/E) and decline
(C) cap the measured carryover/spread there, so each dynamic gets a clean
but realistic journal of its own.

Ground truth:
  A. 'work' text on Sundays (temporal) + scattered weekday work days
     whose mood dips WITHIN their weekday -> temporal + mood_correlation
     (lower). The scattered dips are the honest mood tie: under the
     weekly-cycle deconfounding (item 1) a Sunday-only dip is a calendar
     fact, not a work association, and is correctly absorbed.
  B. "can't sleep, my mind won't stop" on 10 days   -> rumination
  C. stream decline in the final 3 weeks            -> mood_shift(lower)
  D. 'guitar' phrased differently, RISING late     -> topic (only discovery can catch it)
  E. family-visit days -> stream forced low next day -> link(family, lower)
  F. mixed corpus: stream carryover (AR coefficient) rises late -> inertia
  G. mixed corpus: stream swing amplitude rises late -> instability
  H. NO other theme-mood association exists         -> no other mood_correlation/link
"""

from __future__ import annotations

import random
from datetime import date, timedelta

from app.services.brain import load_state, update
from app.services.patterns import JournalEntry

rng = random.Random(42)

start = date(2026, 6, 15)
end = date(2026, 9, 4)

FILLERS = [
    "read a few pages of the novel before lights out",
    "rearranged the kitchen shelves and found old receipts",
    "listened to a podcast on the commute home",
    "watered all the plants on the balcony",
    "tried a new recipe with lentils and rice",
    "fixed the squeaky door hinge at last",
    "walked past the old bookshop after lunch",
    "wrote a letter to my cousin overseas",
    "sorted through the photo box from the move",
    "repaired the bike tire in the garage",
    "watched the rain from the window with tea",
    "organized the desk drawers and old cables",
    "cooked soup for tomorrow and froze half",
    "stretched out on the couch for a while",
    "sketched the view from the kitchen window",
    "practiced chords until my fingers hurt",
    "paid the utilities and filed the receipt",
    "cleaned the bathroom and changed the sheets",
    "backed up the laptop and cleared the desktop",
    "called the pharmacy about the prescription",
    "took the long way home through the park",
    "mended the seam on my winter coat",
    "bought oranges and bread from the corner shop",
    "renewed the library books online",
    "moved the compost and planted basil",
    "ironed shirts while the race was on",
    "tidied the hallway and the shoe rack",
    "brewed proper coffee instead of instant",
    "changed the burnt bulb in the hallway",
    "drafted the card for my neighbor's birthday",
    "sewed the loose button back on my jacket",
    "took the recycling down and swept the stairs",
    "looked up train times for the weekend trip",
    "replaced the filter in the kitchen extractor",
    "archived last year's paperwork into the box",
    "set the alarm and laid out clothes for tomorrow",
    "answered the group chat and caught up on messages",
    "trimmed the hedge before the rain came in",
    "measured the hallway for the new shelf",
]
# 2026-09-20 audit H-20: the bare "can't sleep, my mind won't stop" scored
# +0.222 — VADER's damped negation flips the negative "stop" ("won't stop")
# POSITIVE — so the cluster never classified as rumination and check B
# passed only via the WORK rumination. The perseveration phrasing now
# carries its own negative valence ("so tired"), which the classifier's
# negativity path (or its <=0 + negators path) honestly reads.
SLEEP_VARIANTS = [
    "i can't sleep, my mind won't stop, i am so tired of it",
    "i can't sleep, my mind just won't stop tonight, i am so tired of it",
    "can't sleep, my mind won't stop racing, i am so tired of it",
]
FAMILY_DAYS = {
    date(2026, 6, 21),
    date(2026, 6, 28),
    date(2026, 7, 2),
    date(2026, 7, 7),
    date(2026, 7, 14),
    date(2026, 7, 21),
    date(2026, 7, 26),
    date(2026, 8, 4),
    date(2026, 8, 10),
    date(2026, 8, 11),
    date(2026, 8, 16),
    date(2026, 8, 18),
    date(2026, 8, 25),
    date(2026, 9, 1),
}
# Recalibrated 2026-09 (10 → 14 visit days, all four additions Tuesdays):
# the honest engine — full-family Benjamini-Hochberg over PRE-gate
# p-values, Welch n deflated for residual autocorrelation — needs more
# exposed transitions than the anti-conservative pre-fix engine did.
# Tuesdays keep the dipped follower days (Wed is skipped; Thu) clear of
# the EWMA baseline quarter (June) and away from Sundays, so A's work
# mood tie and C's shift survive. Side effect accepted as honest: visits
# now genuinely cluster on Tuesdays, so a true temporal:family pattern
# may also store.
SLEEP_PHRASE_DAYS = {
    date(2026, 6, 20),
    date(2026, 6, 30),
    date(2026, 7, 8),
    date(2026, 7, 17),
    date(2026, 7, 27),
    date(2026, 8, 3),
    date(2026, 8, 12),
    date(2026, 8, 22),
    date(2026, 8, 29),
    date(2026, 9, 2),
}
# D: a non-lexicon topic, phrased differently every time (so phrase
# clustering can NOT catch it), with a small early base and a strong late
# rise — only topic discovery can surface it.
GUITAR_VARIANTS = [
    "spent the evening with the guitar, learning fingerpicking",
    "practiced guitar scales after dinner",
    "wrote a riff on the guitar tonight",
    "guitar practice again, chords getting cleaner",
    "jammed on the guitar for a while",
]
GUITAR_EARLY = {date(2026, 6, 26), date(2026, 7, 9)}
GUITAR_LATE_COUNT = 10

# --- the planted mood stream ------------------------------------------------------
mood: dict[date, float] = {}
day = start
carry = 0.0
while day <= end:
    if day >= date(2026, 8, 8):
        phi, amplitude = 0.60, 0.70  # F: carryover rises; G: marginal swings grow ~2.5x
    else:
        phi, amplitude = 0.05, 0.15
    carry = phi * carry + (1 - phi) * rng.uniform(-amplitude, amplitude)
    value = 0.05 + carry
    if day >= date(2026, 8, 15):  # C: sustained decline (deepened 2026-09-26 so the
        value -= 0.75  # excursion clears the recalibrated ±3.1-sigma limits cleanly)
    mood[day] = max(-1.0, min(1.0, value))
    day += timedelta(days=1)

for d in FAMILY_DAYS:  # E: day after a family visit reads low
    for k in (1, 2):
        if d + timedelta(days=k) in mood:
            mood[d + timedelta(days=k)] = min(mood[d + timedelta(days=k)], -0.55)
for d in mood:  # A: Sundays read low (work dread) — the calendar fact
    if d.weekday() == 6:
        mood[d] = min(mood[d], -0.45)

# A's honest mood tie (item 1): 'work' on 10 scattered NON-Sunday days
# (never Wednesday — the skip day — and never colliding with family or
# sleep-phrase plantings), each dipping hard WITHIN its weekday. The
# Sunday-only dip is absorbed by the weekly-cycle deconfounding (as it
# must be); these within-weekday dips are what a real work-mood tie
# looks like. Two of the scattered days postdate the first recompute
# (Aug 15) so the claim replicates on >= 2 new evidence days (item 5).
SCATTERED_WORK_DAYS: set[date] = {
    date(2026, 6, 22),
    date(2026, 6, 30),
    date(2026, 7, 9),
    date(2026, 7, 17),
    date(2026, 7, 25),
    date(2026, 7, 30),
    date(2026, 8, 4),
    date(2026, 8, 13),
    date(2026, 8, 22),
    date(2026, 8, 31),
}
for _d in SCATTERED_WORK_DAYS:
    mood[_d] = min(mood[_d], -0.7)

# --- entries ----------------------------------------------------------------------
guitar_late_days: set[date] = set()
day = start + timedelta(days=55)
while len(guitar_late_days) < GUITAR_LATE_COUNT and day <= end:
    if day.weekday() != 2:
        guitar_late_days.add(day)
    day += timedelta(days=2)
guitar_idx = 0

entries: list[JournalEntry] = []
filler_uses: dict[int, int] = {}
day = start
while day <= end:
    wd = day.weekday()
    if wd != 2 and rng.random() < 0.9:
        # Random filler (each capped at 2 uses) — deterministic cycling would
        # phase-lock with the skip-Wednesday pattern and plant accidental
        # weekday structure the binomial test would then rightly flag.
        available = [i for i in range(len(FILLERS)) if filler_uses.get(i, 0) < 2]
        choice = rng.choice(available)
        filler_uses[choice] = filler_uses.get(choice, 0) + 1
        text = FILLERS[choice]
        if wd == 6:
            text = "big deadline pressure at work again, boss emailed twice about monday"
        if day in SCATTERED_WORK_DAYS:
            text = "hard shift at work, another late meeting and a heavy workload"
        if day in FAMILY_DAYS:
            text += ". visited the family, mom and dad were there"
        if day in SLEEP_PHRASE_DAYS:
            text += ". " + rng.choice(SLEEP_VARIANTS)
        if day in GUITAR_EARLY:
            text += ". messed around on the guitar for a bit"
        if day in guitar_late_days:
            text += ". " + GUITAR_VARIANTS[guitar_idx % len(GUITAR_VARIANTS)]
            guitar_idx += 1
        entries.append(JournalEntry(text=text, entry_date=day, sentiment=round(mood[day], 3)))
    day += timedelta(days=1)

print(f"entries: {len(entries)}  active days: {len({e.entry_date for e in entries})}")

# --- realistic recompute cadence: daily for the last 3 weeks ------------------------
state = load_state(None)
result = None
for run_day in [end - timedelta(days=d) for d in range(20, -1, -1)]:
    known = [e for e in entries if e.entry_date <= run_day]
    result = update(state, known, run_day)
    state = result.new_state
# Window-stat kinds (mood_shift) replicate only when their qualification
# days span >= 2 calendar days; the planted decline first qualified on the
# final in-corpus run, so two same-corpus recomputes at later dates let
# the claim re-derive and complete replication honestly (the window
# slides — this is exactly a user recomputing two days later).
for extra_day in (end + timedelta(days=1), end + timedelta(days=2)):
    result = update(state, entries, extra_day)
    state = result.new_state
    if any(p.kind == "mood_shift" for p in result.surfaced):
        break
surfaced = result.surfaced if result is not None else []
pats = state["patterns"]

print(f"\n=== STORED PATTERNS (final run {end}) ===")
for p in sorted(pats.values(), key=lambda r: r.pid):
    surf = "SURFACED" if p.state != "candidate" else "hidden  "
    extra = ""
    if p.kind in ("mood_correlation", "link"):
        extra = f" {p.detail.get('direction')} delta={p.detail.get('mood_delta')} p={p.detail.get('p_value')}"
    print(f"  [{surf}] {p.state:9} {p.kind:18} {p.label[:46]!r:48} occ={p.occurrences}{extra}")

print("\n=== VERDICT vs ground truth (surfaced-only, item 13) ===")


PROBE_FAILURES: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        PROBE_FAILURES.append(name)


def surfaced_kinds(kind: str) -> list:
    return [p for p in surfaced if p.kind == kind]


check(
    "A temporal:work (Sundays, surfaced)",
    any(p.kind == "temporal" and p.label == "work" for p in surfaced),
)
check(
    "A mood_correlation:work lower (within-weekday, surfaced)",
    any(
        p.kind == "mood_correlation" and p.label == "work" and p.detail.get("direction") == "lower"
        for p in surfaced
    ),
)
# B pins the SLEEP cluster specifically (audit H-20): the old check
# accepted ANY rumination and passed via the work cluster while the sleep
# phrase never classified. Surfaced-only (L-39): the probe's ground truth
# is what the brain ACTUALLY surfaces.
check(
    "B rumination (THE sleep cluster, surfaced)",
    any(p.kind == "rumination" and "sleep" in p.label for p in surfaced),
)
check(
    "C mood_shift:lower (surfaced)",
    any(p.kind == "mood_shift" and p.detail.get("direction") == "lower" for p in surfaced),
)
check(
    "D topic:guitar (rising, varied phrasing, surfaced)",
    any(
        p.kind == "topic" and p.label == "guitar" and p.detail.get("trend") == "rising"
        for p in surfaced
    ),
)
check(
    "E link:family lower (surfaced)",
    any(
        p.kind == "link" and p.label == "family" and p.detail.get("direction") == "lower"
        for p in surfaced
    ),
)


# F and G run on their own MIXED corpora (item 13): realistic varied
# filler text — several themes, no isolated sentiment-only series — with
# ONE planted dynamic each, so the ground truth is measured under the
# same full-family Benjamini-Hochberg discipline the main corpus faces.
def _mixed_corpora() -> tuple[list[JournalEntry], list[JournalEntry]]:
    f_rng = random.Random(7)
    days = [end - timedelta(days=69 - i) for i in range(70)]
    f_entries: list[JournalEntry] = []
    g_entries: list[JournalEntry] = []
    f_carry = 0.0
    for i, d in enumerate(days):
        filler = FILLERS[(i * 3) % len(FILLERS)]
        # F: wide iid noise early, then AR(1) carryover from day 40 on with
        # the SAME marginal spread (the marginal sd is held flat so the
        # EWMA level chart stays quiet — this corpus plants CARRYOVER, not
        # a level shift).
        if i >= 40:
            f_carry = 0.75 * f_carry + 0.25 * f_rng.uniform(-0.55, 0.55)
            f_mood = f_carry
        else:
            f_mood = f_rng.uniform(-0.4, 0.4)
        f_entries.append(JournalEntry(text=filler, entry_date=d, sentiment=f_mood))
        # G: small alternation early, wide swings from day 45 on.
        if i >= 45:
            g_mood = 0.05 + (0.5 if i % 2 == 0 else -0.5) + (0.05 if i % 3 == 0 else -0.05)
        else:
            g_mood = 0.05 + (0.03 if i % 2 == 0 else -0.03) + (0.01 if i % 3 == 0 else -0.01)
        g_entries.append(JournalEntry(text=filler, entry_date=d, sentiment=g_mood))
    return f_entries, g_entries


_f_entries, _g_entries = _mixed_corpora()
# Surfaced-only (audit L-39 + item 13): store membership is not surfacing —
# a candidate that never earned a card must not pass the ground truth.
# Both kinds are WINDOW-STAT: their qualification days must span >= 2
# calendar days, so the retries run two days on (a next-day recompute
# re-scores the same sliding window).
_f_state = update(load_state(None), _f_entries, end)
_f_ok = any(p.kind == "inertia" for p in _f_state.surfaced)
if not _f_ok:  # a marginal day can miss the gates; the next recompute lands it
    # 2026-09-29: window-stat replication needs qualification days >= 7
    # apart (the EWMA-family memory makes a 2-day spread re-score the same
    # excursion).
    _f_state = update(_f_state.new_state, _f_entries, end + timedelta(days=7))
    _f_ok = any(p.kind == "inertia" for p in _f_state.surfaced)
check("F inertia (mixed corpus, surfaced)", _f_ok)
_g_state = update(load_state(None), _g_entries, end)
_g_ok = any(p.kind == "instability" for p in _g_state.surfaced)
if not _g_ok:  # candidate on first qualification; a later recompute surfaces it
    # (The retry must thread .new_state — update() takes the state dict,
    # not the BrainUpdate envelope. The pre-replication-gate probe never
    # noticed: STRONG_EVIDENCE surfaced it on first contact. The retry is
    # SEVEN days on, not one or two: window-stat kinds replicate only when
    # the qualification days span >= WINDOW_STAT_REPLICATION_MIN_SPREAD_
    # DAYS (7) — a shorter gap re-scores the same sliding excursion
    # (2026-09-29 deep audit).)
    _g_state = update(_g_state.new_state, _g_entries, end + timedelta(days=7))
    _g_ok = any(p.kind == "instability" for p in _g_state.surfaced)
check("G instability (mixed corpus, surfaced)", _g_ok)
false_pos = [
    p
    for p in pats.values()
    if p.kind in ("mood_correlation", "link") and p.label not in ("work", "family")
]
false_topics = [p for p in pats.values() if p.kind == "topic" and p.label != "guitar"]
# Independent audit 2026-09-27: the old first clause contained a dead
# disjunct (str(list) is never ""), so the condition silently reduced to
# `not false_pos` — which IS the intended check; stated plainly now.
check("H no confound/false associations", not false_pos and not false_topics)

# I and J (deep audit 2026-09-29): the TAG-LESS path — the probe always
# planted mood via client tags, so the default user's text-scored mood was
# never ground-truthed. I: a genuine tie (theme days also carry real
# non-theme negative content) MUST surface. J: pure lexical overlap (the
# theme words ARE the only mood content) must mint NOTHING — the audit
# measured this firing pre-fix at mood_delta=0.408, a "personalized
# discovery" that was a population-level lexical identity.
_TAGLESS_NEUTRALS = (
    "ordinary day notes, chores and paperwork",
    "errands and laundry day, ordinary notes",
    "paperwork day, ordinary chores and notes",
    "ordinary sunday notes and bills",
)
_TAGLESS_THEME = (
    "slept badly and woke up tired all morning",
    "restless night, drowsy and yawning by noon",
    "tossed and turned, sleepy and drained",
)
_TAGLESS_NEGATIVES = (
    "and felt awful and hopeless the whole day",
    "but grim and miserable anyway",
    "yet everything felt terrible and bleak",
)


def _tagless_corpus(genuine: bool) -> list[JournalEntry]:
    entries: list[JournalEntry] = []
    for i in range(104):
        d = end - timedelta(days=103 - i)
        if i % 3 == 1:
            extra = _TAGLESS_NEGATIVES[i % 3] if genuine else ""
            entries.append(JournalEntry(_TAGLESS_THEME[i % 3] + extra, d))
        else:
            entries.append(JournalEntry(_TAGLESS_NEUTRALS[i % 4], d))
    return entries


def _tagless_surface(corpus: list[JournalEntry]) -> list:
    state = update(load_state(None), corpus, end)
    grown = corpus + [
        JournalEntry("bad night, tired again", end + timedelta(days=1)),
        JournalEntry("restless and drowsy again", end + timedelta(days=2)),
    ]
    second = update(state.new_state, grown, end + timedelta(days=2))
    return list(second.surfaced)


_i_surfaced = _tagless_surface(_tagless_corpus(genuine=True))
check(
    "I tag-less genuine tie surfaces (text-scored mood path)",
    any(
        p.kind == "mood_correlation" and p.label == "sleep"
        and p.detail.get("direction") == "lower"
        for p in _i_surfaced
    ),
)
_j_surfaced = _tagless_surface(_tagless_corpus(genuine=False))
check(
    "J tag-less lexical overlap alone mints nothing (tautology broken)",
    not [p for p in _j_surfaced if p.kind == "mood_correlation"],
)

# A FAILing probe must fail CI: exit nonzero so the ground-truth check can
# gate builds instead of only printing.
if PROBE_FAILURES:
    raise SystemExit(f"probe_brain: {len(PROBE_FAILURES)} check(s) failed: {PROBE_FAILURES}")
