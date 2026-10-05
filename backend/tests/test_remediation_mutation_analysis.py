"""Public analyzer behavior at effect, personal-baseline and lifecycle boundaries."""

from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

START = date(2026, 6, 1)


def test_statistically_significant_small_effect_is_not_a_mood_claim():
    # Two observations/day, balanced around zero. The mean difference is
    # 0.24 with approximately 0.5 within-group SD: significant at this n,
    # but below the published standardized-effect floor of 0.5.
    entries = []
    for index in range(124):
        sign = 1 if index % 2 == 0 else -1
        day = START + timedelta(days=index)
        entries.extend(
            [
                JournalEntry(
                    "I wrote a journal about today.",
                    day,
                    sentiment=0.12 + 0.5 * sign,
                    tags=["work"],
                ),
                JournalEntry("I wrote a journal about today.", day, sentiment=-0.12 - 0.5 * sign),
            ]
        )
    first = brain.update(brain.fresh_state(), entries[:240], START + timedelta(days=119))
    later = brain.update(first.new_state, entries, START + timedelta(days=123))
    assert not [
        card for card in later.surfaced if card.kind == "mood_correlation" and card.label == "work"
    ]


@pytest.mark.parametrize(("rough", "rested"), [(3, 5), (1, 2)])
def test_sleep_mood_links_follow_the_person_not_a_fixed_rating_norm(rough, rested):
    entries = []
    for index in range(90):
        previous_rough_night = (index - 1) % 3 == 0
        entries.append(
            JournalEntry(
                "I wrote a journal about today.",
                START + timedelta(days=index),
                sentiment=(-0.6 if previous_rough_night else 0.3)
                + (0.04 if index % 2 == 0 else -0.04),
                sleep_quality=rough if index % 3 == 0 else rested,
            )
        )
    first = brain.update(brain.fresh_state(), entries[:80], START + timedelta(days=79))
    later = brain.update(first.new_state, entries, START + timedelta(days=89))
    assert [
        card
        for card in later.surfaced
        if card.kind == "link" and card.detail.get("channel") == "sleep_quality"
    ]


def test_window_claim_waits_seven_days_before_replicated_display():
    entries = [
        JournalEntry(
            "I wrote in my journal today.",
            START + timedelta(days=index),
            sentiment=(0.4 if index < 70 else -0.6) + (0.035 if index % 2 == 0 else -0.035),
        )
        for index in range(95)
    ]
    first = brain.update(brain.fresh_state(), entries, START + timedelta(days=94))
    assert first.new_state["patterns"]["mood_shift:lower"].state == "candidate"
    early = brain.update(first.new_state, entries, START + timedelta(days=100))
    assert early.new_state["patterns"]["mood_shift:lower"].state == "candidate"
    assert not [card for card in early.surfaced if card.kind == "mood_shift"]
    later = brain.update(first.new_state, entries, START + timedelta(days=101))
    assert [card for card in later.surfaced if card.kind == "mood_shift"]


@pytest.mark.parametrize(
    ("elapsed", "expected"), [(7, "emerging"), (8, "fading"), (45, "fading"), (46, "archived")]
)
def test_pattern_lifecycle_exact_grace_and_archive_boundaries(elapsed, expected):
    entries = [
        JournalEntry(
            "quiet day with some work in the afternoon"
            if (START - timedelta(days=ago)).weekday() == 6
            else "I read a book and made some tea at home.",
            START - timedelta(days=ago),
        )
        for ago in range(70, 0, -1)
    ]
    first = brain.update(brain.fresh_state(), entries, START)
    grown = entries + [
        JournalEntry("quiet day with some work in the afternoon", START + timedelta(days=offset))
        for offset in (3, 4)
    ]
    last_qualified = START + timedelta(days=4)
    active = brain.update(first.new_state, grown, last_qualified)
    assert active.new_state["patterns"]["temporal:work"].state == "emerging"
    quiet = [
        JournalEntry("I read a book and made some tea at home.", row.entry_date) for row in grown
    ]
    later = brain.update(active.new_state, quiet, last_qualified + timedelta(days=elapsed))
    assert later.new_state["patterns"]["temporal:work"].state == expected
