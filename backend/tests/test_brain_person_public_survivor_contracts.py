"""Native public person anchors from actual journal text and explicit moods."""

from datetime import date, timedelta

import pytest

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


def recompute_with_new_name_evidence(entries, name):
    first = brain.update(brain.fresh_state(), entries, TODAY)
    grown = entries + [
        JournalEntry(
            "I met " + name + " near the market today",
            TODAY + timedelta(days=offset),
            sentiment=-0.6,
        )
        for offset in (1, 2)
    ]
    return brain.update(
        brain.load_state(brain.dump_state(first.new_state)),
        grown,
        TODAY + timedelta(days=2),
    )


def assert_person_mood_card(result, name):
    card = next(p for p in result.surfaced if p.kind == "mood_correlation" and p.label == name)
    assert card.detail["source"] == "person"
    assert card.detail["direction"] == "lower"
    assert card.occurrences == 26
    assert card.detail["sample_entries"] == 72


@pytest.mark.parametrize(
    "name",
    (
        "art",
        "bill",
        "dan",
        "frank",
        "jack",
        "jan",
        "mark",
        "miles",
        "pat",
        "ray",
        "reed",
        "rose",
        "sue",
        "vic",
    ),
)
def test_capitalized_person_is_distinct_from_the_lowercase_homograph(name):
    entries = []
    for i in range(70):
        mentions_person = i % 3 == 0
        spelling = name.title() if mentions_person else name
        entries.append(
            JournalEntry(
                "I saw " + spelling + " near the bakery today",
                TODAY - timedelta(days=69 - i),
                sentiment=(-0.6 if mentions_person else 0.3) + (i % 5 - 2) * 0.007,
            )
        )
    # Lowercase occurrences are actual contrasting input. Only the recurring
    # capitalized name supplies evidence for this person association.
    result = recompute_with_new_name_evidence(entries, name.title())
    assert_person_mood_card(result, name)


def test_known_capitalized_word_does_not_hide_a_later_recurring_person():
    entries = [
        JournalEntry(
            "i felt Happy then saw "
            + ("Alice" if i % 3 == 0 else "nobody")
            + " near the bakery today",
            TODAY - timedelta(days=69 - i),
            sentiment=(-0.6 if i % 3 == 0 else 0.3) + (i % 5 - 2) * 0.007,
        )
        for i in range(70)
    ]
    result = recompute_with_new_name_evidence(entries, "Alice")
    assert_person_mood_card(result, "alice")


def test_eight_proper_name_entries_admit_later_lowercase_mentions():
    entries = []
    for i in range(70):
        mentions_person = i % 3 == 0
        # Exactly eight actual capitalized mentions on eight dates qualify
        # the candidate. The other sixteen mention dates use lowercase.
        spelling = "Felicity" if mentions_person and i < 24 else "felicity"
        text = (
            "I met " + spelling + " near the bakery today"
            if mentions_person
            else CONTEXTS[i % len(CONTEXTS)]
        )
        entries.append(
            JournalEntry(
                text,
                TODAY - timedelta(days=69 - i),
                sentiment=(-0.6 if mentions_person else 0.3) + (i % 5 - 2) * 0.007,
            )
        )
    result = recompute_with_new_name_evidence(entries, "felicity")
    assert_person_mood_card(result, "felicity")
