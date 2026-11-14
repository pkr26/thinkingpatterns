"""Native persisted patterns age and expire at the public store boundaries."""

import json
from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

TODAY = date(2026, 10, 22)


def native_phrase_store():
    entries = [
        JournalEntry(
            "I take a quiet walk through the park each evening.",
            TODAY - timedelta(days=13 - index),
        )
        for index in range(14)
    ]
    result = brain.update(brain.fresh_state(), entries, TODAY)
    raw = brain.dump_state(result.new_state)
    records = json.loads(raw)["patterns"]
    pid = next(pid for pid, record in records.items() if record["kind"] == "recurring_phrase")
    assert records[pid]["state"] == "emerging"
    return raw, pid


def test_public_native_pattern_fades_after_the_full_unqualified_grace():
    raw, pid = native_phrase_store()
    result = brain.update(brain.load_state(raw), [], TODAY + timedelta(days=8))
    aged = json.loads(brain.dump_state(result.new_state))["patterns"]
    assert aged[pid]["state"] == "fading"


@pytest.mark.parametrize("days", [90, 91])
def test_public_native_archived_pattern_expires_after_ninety_unqualified_days(days):
    raw, pid = native_phrase_store()
    result = brain.update(brain.load_state(raw), [], TODAY + timedelta(days=days))
    aged = json.loads(brain.dump_state(result.new_state))["patterns"]
    if days == 90:
        assert aged[pid]["state"] == "archived"
    else:
        assert pid not in aged


def test_public_corrupt_empty_qualification_keeps_the_exact_first_seen_retention_boundary():
    raw, pid = native_phrase_store()
    legacy = json.loads(raw)
    # Explicitly the documented corrupt-store empty timestamp domain.
    # Everything else, including the record's real first_seen, comes from
    # the native producer. No handwritten StoredPattern or mocked signal.
    legacy["patterns"][pid]["last_qualified"] = ""
    first_seen = date.fromisoformat(legacy["patterns"][pid]["first_seen"])
    loaded = brain.load_state(json.dumps(legacy).encode())
    result = brain.update(loaded, [], first_seen + timedelta(days=90))
    aged = json.loads(brain.dump_state(result.new_state))["patterns"]
    assert aged[pid]["state"] == "archived"
