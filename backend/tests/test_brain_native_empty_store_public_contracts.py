"""A public empty JSON store initializes the same native analysis as fresh_state."""

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry


def test_empty_public_store_initializes_the_native_corpus_without_losing_its_result():
    today = date(2026, 10, 22)
    entries = [
        JournalEntry(
            "I take a quiet walk through the park each evening.",
            today - timedelta(days=index),
        )
        for index in range(14)
    ]
    expected = brain.update(brain.fresh_state(), entries, today)
    # An empty JSON object is an admitted dict-shaped initialization input.
    # No claim is made about an actual historical on-disk producer.
    actual = brain.update({}, entries, today)
    assert brain.dump_state(actual.new_state) == brain.dump_state(expected.new_state)
    assert actual.stats == expected.stats
    assert actual.surfaced == expected.surfaced
