"""Declared unclamped public-library calendar domain, independent of HTTP validation.

brain.update deliberately analyzes the entries it is given, including dates
later than its supplied today. These finite ordinary library inputs exercise
that documented domain. They do not claim current API or server-producer
origin, or a clinical interpretation of the returned measurements.
"""

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

T = date(2026, 10, 22)


def recompute(stages):
    state = brain.fresh_state()
    for entries, today in stages:
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    return result


def native_future_entropy():
    monday = date(2026, 10, 26)
    es = []
    for earlier in (True, False):
        for j in range(20 if earlier else 100):
            week = monday - timedelta(weeks=4 + j) if earlier else monday + timedelta(weeks=j - 3)
            for day in range(7):
                tags = ["alpha"]
                if day < (1 if earlier and j == 0 else (4 + j % 2) if earlier else (3 + j % 2)):
                    tags.append("beta")
                if not earlier and day == 0:
                    tags.append("gamma")
                es.append(
                    JournalEntry("I have notes", week + timedelta(days=day), tags=tuple(tags))
                )
    return [(es, monday - timedelta(days=7)), (es, monday)]


def native_avoidance():
    monday = date(2026, 10, 26)
    es = []
    themed = set(range(5, 21)) | set(range(21, 37))
    for week in range(70):
        for weekday in range(7):
            if weekday == 1 and week < 21:
                continue
            d = monday + timedelta(weeks=week - 14, days=weekday)
            es.append(
                JournalEntry(
                    "I have notes",
                    d,
                    tags=("work",) if weekday == 0 and week in themed else (),
                )
            )
    return [(es, monday), (es, monday + timedelta(days=2))]


def test_native_tag_entropy_retains_the_cutoff_week_and_effect_measurement():
    # Actual weekly tag membership produces the native Miller-Madow entropy:
    # 20 earlier weeks and 100 recent/future weeks, 840 actual entries.
    result = recompute(native_future_entropy())
    (card,) = [p for p in result.surfaced if p.kind == "activity_diversity"]
    assert card.occurrences == 100
    assert card.detail["entropy_recent"] == 1.39
    assert card.detail["entropy_earlier"] == 1.01
    assert card.detail["direction"] == "widened"
    assert card.detail["sample_entries"] == 840


def test_native_calendar_skip_lift_retains_the_exact_inclusive_boundary():
    # 70 actual Mondays, 21 followed by an absent Tuesday. The 32 tagged
    # Mondays include 16 silences; actual per-weekday null probability 0.3
    # and observed share 0.5 meet the declared additive 0.2 lift exactly.
    result = recompute(native_avoidance())
    (card,) = [p for p in result.surfaced if p.kind == "avoidance" and p.label == "work"]
    assert card.occurrences == 16
    assert card.detail["observed"] == 32
    assert card.detail["silences"] == 16
    assert card.detail["expected_silences"] == 9.6
    assert card.detail["share"] == 0.5
