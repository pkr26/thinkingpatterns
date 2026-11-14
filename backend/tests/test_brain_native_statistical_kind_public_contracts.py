"""Actual native statistical kinds wait for replication and preserve their store."""

import json
from datetime import timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry
from tests.test_brain_calendar_boundary_public_survivor_contracts import native_cadence
from tests.test_brain_future_calendar_public_survivor_contracts import native_future_entropy
from tests.test_brain_public_algorithm_survivor_contracts import (
    SENSE_TEXTS,
    TODAY,
    carryover_entries,
)


def native_steps(kind):
    if kind == "cadence":
        yield from native_cadence()
        return
    if kind == "activity_diversity":
        # Explicitly the already tested public library's unclamped calendar
        # domain, with real tag counts. No current HTTP date-writer claim.
        yield from native_future_entropy()
        return
    channel = {
        "energy_inertia": "energy",
        "pa_inertia": "positive_affect",
        "na_inertia": "negative_affect",
    }.get(kind)
    if channel is not None:
        entries = carryover_entries(channel)
        for offset in range(9):
            yield entries, TODAY + timedelta(days=offset)
        return
    if kind == "instability":
        entries = [
            JournalEntry(
                "ordinary day notes",
                TODAY - timedelta(days=69 - index),
                sentiment=0.05 + ((0.5 if index >= 45 else 0.03) * (1 if index % 2 == 0 else -1)),
            )
            for index in range(70)
        ]
        yield entries, TODAY
        entries = entries + [
            JournalEntry(
                "ordinary day notes",
                TODAY + timedelta(days=offset),
                sentiment=0.55 if offset % 2 else -0.45,
            )
            for offset in range(1, 8)
        ]
        yield entries, TODAY + timedelta(days=7)
        return
    if kind == "sense_making":
        entries = [
            JournalEntry(
                SENSE_TEXTS[index % 2]
                if index >= 42
                else "we went to the market and i saw a friend there and walked home",
                TODAY - timedelta(days=69 - index),
            )
            for index in range(70)
        ]
        for offset in range(6):
            entries.append(JournalEntry(SENSE_TEXTS[offset % 2], TODAY + timedelta(days=offset)))
            yield list(entries), TODAY + timedelta(days=offset)
        return
    assert kind == "energy_mood_coupling"
    entries = []
    for index in range(70):
        recent = index >= 42
        mood = (
            (0.4 if (index // 4) % 2 == 0 else -0.4)
            if recent
            else (0.3 if index % 2 == 0 else -0.3)
        )
        entries.append(
            JournalEntry(
                "ordinary day notes",
                TODAY - timedelta(days=69 - index),
                sentiment=mood,
                energy=mood if recent else 0.05,
            )
        )
    for offset in range(9):
        yield entries, TODAY + timedelta(days=offset)


@pytest.mark.parametrize(
    "kind",
    [
        "instability",
        "cadence",
        "energy_inertia",
        "pa_inertia",
        "na_inertia",
        "energy_mood_coupling",
        "sense_making",
        "activity_diversity",
    ],
)
def test_native_statistical_kind_waits_for_replication_and_roundtrips_its_store(kind):
    state = brain.fresh_state()
    for entries, today in native_steps(kind):
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
        raw = brain.dump_state(state)
        produced = [
            record
            for record in json.loads(raw)["patterns"].values()
            if record["kind"] == kind and record["state"] != "archived"
        ]
        if produced:
            # A statistical inference must wait for a separately qualified
            # observation. This is the first actual qualification of this
            # kind, so it must not already expose an emerging/confirmed card.
            assert all(record["state"] == "candidate" for record in produced)
            # Every record, including its kind, dates and detail, is from
            # the actual public native engine. The loader must preserve
            # its own native store instead of treating this kind as unknown.
            assert brain.dump_state(brain.load_state(raw)) == raw
            return
    pytest.fail(f"Native input corpus did not produce its {kind} store record")
