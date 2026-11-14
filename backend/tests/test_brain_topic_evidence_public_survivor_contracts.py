"""Public topic evidence measurements after genuine text and state roundtrips."""

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

TODAY = date(2026, 10, 22)

CONTEXTS = (
    "I walked to the bakery and bought some bread",
    "I wrote a note about the weather today",
    "I listened to the radio while cooking lunch",
    "I fixed the loose hinge near the cupboard",
    "I looked through the pictures from last spring",
    "I folded all the clean towels before dinner",
    "I sat by the window and watched the clouds",
    "I found the missing receipt inside a book",
    "I watered the plants beside the kitchen sink",
    "I took the bus across the town this morning",
    "I moved the lamp onto the other table",
    "I picked a new recipe for the weekend",
    "I washed the dishes before leaving the house",
    "I wrote the shopping list on the fridge",
    "I checked the tire pressure after breakfast",
    "I noticed a bird outside the front window",
    "I paid the utilities and filed the receipt",
    "I took the long way home through the park",
    "I bought oranges and bread from the corner shop",
    "I brewed proper coffee instead of instant",
)


def test_growing_topic_card_reports_native_entry_and_day_evidence():
    entries = [
        JournalEntry(
            context + (" guitar" if i >= 10 else ""),
            TODAY - timedelta(days=19 - i),
        )
        for i, context in enumerate(CONTEXTS)
    ]
    first = brain.update(brain.fresh_state(), entries, TODAY)
    entries += [
        JournalEntry(
            "I practiced the guitar after dinner with new chord shapes",
            TODAY + timedelta(days=1),
        ),
        JournalEntry(
            "I played the guitar before breakfast doing warmups",
            TODAY + timedelta(days=2),
        ),
    ]
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)),
        entries,
        TODAY + timedelta(days=2),
    )
    topics = [p for p in result.surfaced if p.kind == "topic"]
    assert len(topics) == 1
    card = topics[0]
    assert card.label == "guitar"
    assert card.occurrences == 12
    # These are public evidence measurements for twelve actual guitar
    # entries/dates among twenty-two supplied entries/dates. The two halves
    # each contain eleven dates, one versus eleven mentioning guitar.
    assert {
        key: card.detail[key]
        for key in (
            "entries",
            "distinct_days",
            "share",
            "share_earlier",
            "share_recent",
            "day_share_earlier",
            "day_share_recent",
            "trend",
            "p_value",
            "pattern_pid",
            "sample_days",
            "sample_entries",
            "evidence_dates",
        )
    } == {
        "entries": 12,
        "distinct_days": 12,
        "share": 0.545,
        "share_earlier": 0.091,
        "share_recent": 1.0,
        "day_share_earlier": 0.091,
        "day_share_recent": 1.0,
        "trend": "rising",
        "p_value": 0.0,
        "pattern_pid": "topic:guitar",
        "sample_days": 22,
        "sample_entries": 22,
        "evidence_dates": [(TODAY - timedelta(days=9 - i)).isoformat() for i in range(12)],
    }
