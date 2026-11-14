"""Native public corpora preserve the two replication policies."""

import json
from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry
from tests.test_brain_native_statistical_kind_public_contracts import native_steps
from tests.test_brain_public_algorithm_survivor_contracts import TODAY, carryover_entries
from tests.test_brain_topic_boundary_public_survivor_contracts import simple_rise


def flavor_steps(kind):
    if kind in {
        "instability",
        "cadence",
        "energy_inertia",
        "pa_inertia",
        "na_inertia",
        "energy_mood_coupling",
        "sense_making",
    }:
        yield from native_steps(kind)
        return
    if kind == "inertia":
        entries = carryover_entries("sentiment")
        for offset in range(9):
            yield entries, TODAY + timedelta(days=offset)
        return
    if kind == "topic":
        yield from simple_rise("guitar")
        return
    if kind == "temporal":
        entries = []
        for offset in range(84):
            day = TODAY - timedelta(days=offset)
            tagged = day.weekday() == 0 or offset == 1
            entries.append(
                JournalEntry(
                    "ordinary day notes",
                    day,
                    sentiment=0.8 if tagged else 0.1,
                    tags=("yoga",) if tagged else (),
                )
            )
        yield entries, TODAY
        return
    if kind == "activity_diversity":
        first_day = date(2026, 10, 2)
        start = first_day - timedelta(days=111)
        for offset in (0, 7, 14, 21):
            today = first_day + timedelta(days=offset)
            entries = []
            for index in range((today - start).days + 1):
                week = index // 7
                distinct = (7 if week % 2 == 0 else 4) if week < 12 else (2 if week % 2 == 0 else 3)
                tag = f"activity_{week:02}_{index % 7 % distinct}"
                entries.append(
                    JournalEntry("ordinary day notes", start + timedelta(days=index), tags=(tag,))
                )
            yield entries, today
        return
    assert kind == "mood_shift"
    start = TODAY - timedelta(days=83)
    entries = []
    for index in range(84):
        day = start + timedelta(days=index)
        if day == TODAY - timedelta(days=4):
            mood = -0.9
        elif day >= TODAY - timedelta(days=13):
            mood = -0.2
        else:
            mood = 0.05 if index % 2 else -0.05
        entries.append(JournalEntry("ordinary day notes", day, sentiment=mood))
    yield entries, TODAY


@pytest.mark.parametrize(
    "kind",
    [
        "temporal",
        "sense_making",
        "activity_diversity",
        "topic",
        "inertia",
        "instability",
        "mood_shift",
        "cadence",
        "energy_inertia",
        "pa_inertia",
        "na_inertia",
        "energy_mood_coupling",
    ],
)
def test_unchanged_native_corpus_does_not_supply_independent_replication(kind):
    state = brain.fresh_state()
    for entries, today in flavor_steps(kind):
        first = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = first.new_state
        before = json.loads(brain.dump_state(state))["patterns"]
        produced = {
            pid: record
            for pid, record in before.items()
            if record["kind"] == kind and record["state"] != "archived"
        }
        if not produced:
            continue
        assert all(record["state"] == "candidate" for record in produced.values())

        # Reuse the actual saved result and exactly the same observed data.
        # Two calendar days alone neither move a window beyond its memory
        # nor add new observations to an evidence-date comparison.
        again = brain.update(
            brain.load_state(brain.dump_state(state)), entries, today + timedelta(days=2)
        )
        after = json.loads(brain.dump_state(again.new_state))["patterns"]
        continued = [after[pid] for pid in produced]
        assert all(len(record["qualification_days"]) == 2 for record in continued)
        assert all(record["state"] == "candidate" for record in continued)
        return
    pytest.fail(f"Native corpus did not produce its {kind} qualification")
