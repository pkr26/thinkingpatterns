"""Public sleep-rating patterns across repeated real corpus recomputes."""

from datetime import date, timedelta

import pytest


@pytest.mark.parametrize("poor_weekday", [0, 3, None])
def test_structured_sleep_ratings_surface_their_actual_weekday(poor_weekday):
    from app.services import brain
    from app.services.patterns import JournalEntry

    state = brain.fresh_state()
    for week in range(3):
        today = date(2026, 10, 5) + timedelta(weeks=week)
        entries = []
        for offset in range(84):
            day = today - timedelta(days=offset)
            poor = poor_weekday is not None and day.weekday() == poor_weekday
            entries.append(
                JournalEntry(
                    "I wrote an ordinary journal about the quiet day.",
                    day,
                    sentiment=0.8 if poor else 0.1,
                    sleep_quality=1 if poor else 5,
                )
            )
        result = brain.update(state, entries, today)
        state = result.new_state

    cards = [
        card for card in result.surfaced if card.kind == "temporal" and card.label == "poor sleep"
    ]
    if poor_weekday is None:
        assert cards == [], "Good sleep ratings must not invent a poor-sleep pattern"
    else:
        assert len(cards) == 1, "Repeated poor sleep must surface its weekday pattern"
        assert cards[0].detail["day"] == ("Monday" if poor_weekday == 0 else "Thursday")
        assert cards[0].detail["channel"] == "sleep_quality"
