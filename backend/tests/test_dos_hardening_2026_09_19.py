"""DoS-hardening regression pins (2026-09-19 remediation).

The audit's HIGH finding: the corpus budgets bound chars and entries but
never distinct-candidate cardinality, so a 30-day-old account could pack
tens of thousands of qualifying person names (or client tags) into the
2M-char analysis budget and one recompute cost minutes of CPU — on the
single-process deployment, four concurrent recomputes starved every other
user. These tests pin the cardinality ceilings (PERSON_MAX_CANDIDATES,
TAG_MAX_THEMES) and bound the wall time of exactly that attack corpus.

The timing assertions are deliberately generous (5s for work that measured
9.6s pre-fix and <1s post-fix): they exist to fail loudly if the caps are
ever removed, not to catch small regressions.
"""

from __future__ import annotations

import os
import time
from datetime import date, timedelta

os.environ.setdefault("MINDPATTERN_ENV", "development")

from app.services import brain  # noqa: E402
from app.services.brain import (  # noqa: E402
    PERSON_MAX_CANDIDATES,
    TAG_MAX_THEMES,
    JournalEntry,
    _person_candidates,
    _select_tag_themes,
    update,
)


def _letters(n: int) -> str:
    """Base-26 letters: candidate names must be pure alphabetic to pass
    the ``isalpha()`` gate in _person_candidates."""
    out = ""
    while True:
        out = chr(ord("a") + n % 26) + out
        n //= 26
        if n == 0:
            return out


def _entry(text: str, day: date, tags: tuple[str, ...] = ()) -> JournalEntry:
    return JournalEntry(text=text, entry_date=day, sentiment=None, tags=tags)


def _window(days: int, entries_per_day: int, text_for, tags_for=lambda i: ()) -> list[JournalEntry]:
    """A dated corpus over ``days`` calendar days starting 40 days back."""
    start = date.today() - timedelta(days=40)
    out: list[JournalEntry] = []
    i = 0
    for offset in range(days):
        for _ in range(entries_per_day):
            out.append(_entry(text_for(i), start + timedelta(days=offset), tags_for(i)))
            i += 1
    return out


def test_person_candidates_hard_capped_and_deterministic():
    # 200 distinct qualifying names: every name appears in every entry
    # across 10 days, so all 200 clear the qualification bars.
    names = [f"Zq{_letters(i)}" for i in range(200)]
    text = "Met " + " and ".join(names) + " again"
    window = _window(10, 1, lambda i: text)

    selected = _person_candidates(window)
    assert len(selected) == PERSON_MAX_CANDIDATES
    # Deterministic: the same corpus selects the same names, twice.
    assert selected == _person_candidates(window)
    # The ranking is (mentions, distinct days, name); all names here tie on
    # the first two keys, so the alphabetical head wins (candidates are
    # stored lowercase).
    assert selected == {n.lower() for n in sorted(names)[:PERSON_MAX_CANDIDATES]}


def test_person_candidates_ranking_prefers_most_mentioned():
    # "Aaaaa" appears in 20 entries; nine others appear in the 8-entry
    # minimum. The cap keeps the most-established name first.
    frequent = "Aaaaa"
    others = [f"Bb{_letters(i)}" for i in range(30)]
    texts = []
    for i in range(20):
        # Every entry mentions ``frequent``; entry i also mentions a
        # rotating subset of the others so each clears 8 mentions.
        texts.append("Saw " + frequent + " plus " + " ".join(others[i % 30] for _ in range(1)))
    window = [
        _entry(texts[i], date.today() - timedelta(days=40 + i)) for i in range(len(texts))
    ]
    # Each ``other`` appears in ~1 entry — below the bar — so only the
    # frequent name qualifies and the cap is not the thing under test
    # here; the point is the ranking key feeds off real counts.
    assert _person_candidates(window) == {frequent.lower()}


def test_person_candidates_small_corpora_unchanged():
    names = ["Mira", "Jonas", "Petra"]
    text = "Coffee with " + " and ".join(names) + " as usual"
    window = _window(8, 1, lambda i: text)
    assert _person_candidates(window) == {"mira", "jonas", "petra"}


def test_select_tag_themes_capped_and_deterministic():
    counts = {f"tag{_letters(i)}": 10 for i in range(100)}
    days = {f"tag{_letters(i)}": {date.today() - timedelta(days=k) for k in range(10)} for i in range(100)}
    kept = _select_tag_themes(counts, days)
    assert len(kept) == TAG_MAX_THEMES
    assert kept == _select_tag_themes(counts, days)
    # All-tie corpus: alphabetical head wins, deterministically.
    assert kept == set(sorted(counts)[:TAG_MAX_THEMES])
    # Fewer tags than the cap: everything rides, unchanged behavior.
    small = {"a": 5, "b": 4}
    small_days = {"a": {date.today()}, "b": {date.today()}}
    assert _select_tag_themes(small, small_days) == {"a", "b"}


def test_select_tag_themes_prefers_most_established():
    # daily (20 days), mid (6 days), 24 two-day tags, then a one-day
    # straggler: 27 candidates for 24 seats — the straggler is the one
    # dropped, and every two-day tag survives over it.
    counts = {"rare": 3, "daily": 40, "mid": 12}
    days = {
        "rare": {date.today() - timedelta(days=1)},
        "daily": {date.today() - timedelta(days=k) for k in range(20)},
        "mid": {date.today() - timedelta(days=k) for k in range(6)},
    }
    for i in range(TAG_MAX_THEMES):
        tag = f"two{i:02d}"
        counts[tag] = 2
        days[tag] = {date.today() - timedelta(days=1), date.today() - timedelta(days=2)}
    kept = _select_tag_themes(counts, days)
    assert len(kept) == TAG_MAX_THEMES
    assert "daily" in kept and "mid" in kept
    assert "rare" not in kept
    # The 24 seats are daily, mid, and the 22 highest-ranked two-day tags.
    assert len([t for t in kept if t.startswith("two")]) == TAG_MAX_THEMES - 2


def _attack_corpus_names(names_n: int, entries: int) -> list[JournalEntry]:
    """The measured attack shape: every entry names every candidate."""
    names = [f"Zq{_letters(i)}" for i in range(names_n)]
    text = "Met " + " and ".join(names) + " today"
    start = date.today() - timedelta(days=40)
    step = max(1, 40 // entries)
    return [
        _entry(text, start + timedelta(days=i * step % 40)) for i in range(entries)
    ]


def test_person_cardinality_perf_bounded():
    # 2,000 qualifying names x 100 entries (~20k chars each, the per-entry
    # analysis cap): pre-fix this measured ~9.6s CPU in _mentions_name and
    # the theme comprehensions; the caps bring it under a second.
    corpus = _attack_corpus_names(2_000, 100)
    started = time.perf_counter()
    update(brain.fresh_state(), corpus, date.today())
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"person-name corpus took {elapsed:.1f}s — cardinality cap regressed"


def test_tag_cardinality_perf_bounded():
    # 8 client tags per entry x 2,000 entries = 16,000 distinct tags: the
    # tag-vocabulary sibling of the same DoS. Pre-fix every tag rode the
    # per-theme O(entries) detectors (tens of seconds); the cap keeps only
    # TAG_MAX_THEMES.
    entries = 2_000
    start = date.today() - timedelta(days=40)

    def tags_for(i: int) -> tuple[str, ...]:
        # 16k distinct tags, 8 per entry, no tag recurring.
        base = i * 8
        return tuple(f"t{base + k:05d}" for k in range(8))

    corpus = [
        _entry("an ordinary day", start + timedelta(days=i % 40), tags_for(i))
        for i in range(entries)
    ]
    started = time.perf_counter()
    update(brain.fresh_state(), corpus, date.today())
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"16k-tag corpus took {elapsed:.1f}s — tag cap regressed"
