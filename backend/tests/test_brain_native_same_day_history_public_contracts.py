"""Native same-day recomputation replaces the stored day instead of duplicating it."""

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry


def test_public_native_same_day_recompute_preserves_the_serialized_history():
    today = date(2026, 10, 22)
    entries = [
        JournalEntry(
            "I take a quiet walk through the park each evening.",
            today - timedelta(days=index),
        )
        for index in range(14)
    ]
    first = brain.update(brain.fresh_state(), entries, today)
    persisted = brain.dump_state(first.new_state)
    repeated = brain.update(brain.load_state(persisted), entries, today)
    assert brain.dump_state(repeated.new_state) == persisted
