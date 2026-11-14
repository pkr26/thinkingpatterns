"""Native person cards from second-token names and default candidate ranking."""

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

TODAY = date(2026, 10, 22)
NAMES = (
    "Bianca",
    "Caroline",
    "Delilah",
    "Eleanor",
    "Felicity",
    "Gabriella",
    "Helena",
    "Isabelle",
    "Juliette",
    "Katrina",
    "Lydia",
    "Martina",
    "Natalia",
    "Ophelia",
    "Penelope",
    "Quinn",
    "Rebecca",
    "Sabrina",
    "Talia",
    "Ursula",
    "Vanessa",
    "Whitney",
    "Yvette",
    "Zoe",
)
CONTEXTS = (
    "I walked to the bakery and bought some bread",
    "I wrote a note about the weather today",
    "I listened to the radio while cooking lunch",
    "I fixed the loose hinge near the cupboard",
    "I looked through the pictures from last spring",
    "I folded all the clean towels before dinner",
    "I sat by the window and watched the clouds",
    "I found the missing receipt inside a book",
)


def _entry(text, index, *, lower):
    return JournalEntry(
        text,
        TODAY - timedelta(days=69 - index),
        sentiment=(-0.6 if lower else 0.3) + (index % 5 - 2) * 0.007,
    )


def _confirmed_result(entries, extra_names=()):
    first = brain.update(brain.fresh_state(), entries, TODAY)
    continuation = entries + [
        JournalEntry(
            "I met Alice near the market today"
            + (" with " + " and ".join(extra_names) if extra_names else ""),
            TODAY + timedelta(days=offset),
            sentiment=-0.6,
        )
        for offset in (1, 2)
    ]
    return brain.update(
        brain.load_state(brain.dump_state(first.new_state)),
        continuation,
        TODAY + timedelta(days=2),
    )


def _assert_alice_card(result, occurrences):
    cards = [
        pattern
        for pattern in result.surfaced
        if pattern.kind == "mood_correlation" and pattern.label == "alice"
    ]
    assert len(cards) == 1
    card = cards[0]
    assert card.detail["source"] == "person"
    assert card.detail["direction"] == "lower"
    assert card.occurrences == occurrences


def test_a_second_token_name_is_a_native_person_anchor():
    entries = [
        _entry(
            "Saw Alice near the bakery today"
            if index % 3 == 0
            else CONTEXTS[index % len(CONTEXTS)],
            index,
            lower=index % 3 == 0,
        )
        for index in range(70)
    ]
    _assert_alice_card(_confirmed_result(entries), 26)


def test_default_person_candidates_prioritize_more_actual_mentions():
    # Twenty-four other recurring proper names have eight genuine mentions
    # each. Alice has twenty-four, on distinct dates, with a clear mood split.
    other_dates = {0, 1, 3, 4, 6, 7, 9, 10}
    entries = []
    for index in range(70):
        lower = index % 3 == 0
        text = "I saw Alice near the bakery today" if lower else CONTEXTS[index % len(CONTEXTS)]
        if index in other_dates:
            text += " with " + " and ".join(NAMES)
        entries.append(_entry(text, index, lower=lower))
    _assert_alice_card(_confirmed_result(entries), 26)


def test_equal_mention_counts_prioritize_more_distinct_dates():
    # All twenty-five names have eight entries initially. Alice's are on
    # eight dates; each other person's eight entries span six dates. The
    # two new days mention everyone, preserving equal totals for the
    # documented distinct-date tie break at the unchanged default cap.
    alice_dates = {0, 9, 18, 27, 36, 45, 54, 63}
    other_dates = {1, 4, 7, 10, 13, 16}
    entries = []
    for index in range(70):
        lower = index in alice_dates
        text = "I saw Alice near the bakery today" if lower else CONTEXTS[index % len(CONTEXTS)]
        if index in other_dates:
            text += " with " + " and ".join(NAMES)
        entries.append(_entry(text, index, lower=lower))
    for index in (1, 4):
        entries.append(
            _entry(
                "I met " + " and ".join(NAMES) + " near the market today",
                index,
                lower=False,
            )
        )
    _assert_alice_card(_confirmed_result(entries, NAMES), 10)
