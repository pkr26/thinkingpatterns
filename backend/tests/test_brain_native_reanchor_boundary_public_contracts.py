"""An established native mood alarm stops renewing at the re-anchor day."""

import json
from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry


def test_native_mood_alarm_reanchors_at_twenty_one_days_of_observed_evidence():
    today = date(2026, 10, 5)
    start = today - timedelta(days=83)
    entries = []
    for index in range(84):
        day = start + timedelta(days=index)
        if day == today - timedelta(days=4):
            mood = -0.9
        elif day >= today - timedelta(days=13):
            mood = -0.2
        else:
            mood = 0.05 if index % 2 else -0.05
        entries.append(JournalEntry("ordinary day notes", day, sentiment=mood))

    first = brain.update(brain.fresh_state(), entries, today)
    state = first.new_state
    (record,) = [
        record
        for record in json.loads(brain.dump_state(state))["patterns"].values()
        if record["kind"] == "mood_shift"
    ]
    assert record["state"] == "candidate"
    boundary = date.fromisoformat(record["first_seen"]) + timedelta(days=21)
    assert boundary > today

    previous = None
    for offset in range(1, (boundary - today).days + 1):
        day = today + timedelta(days=offset)
        entries.append(JournalEntry("ordinary day notes", day, sentiment=-0.2))
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, day)
        state = result.new_state
        cards = [
            card
            for card in result.surfaced
            if card.kind == "mood_shift" and card.detail["direction"] == "lower"
        ]
        if day == boundary - timedelta(days=1):
            (previous,) = cards
            assert previous.detail["last_seen"] == day.isoformat()
        elif day == boundary:
            (current,) = cards
            assert previous is not None
            # The actual stored alarm has aged 21 days. The native chart
            # relearns the following stable observations as its new normal,
            # so another identical report must not renew that old alarm.
            assert current.detail["last_seen"] == previous.detail["last_seen"]
            assert current.detail["first_seen"] == previous.detail["first_seen"]
