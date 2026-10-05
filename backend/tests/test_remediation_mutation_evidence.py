"""Behavioral evidence-drilldown controls added after the D4 survivor.

Real entry corpora must reach the public card with the actual observed dates.
These checks exercise the engine and encrypted API payload, not source text.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry
from tests.helpers import ClientEmulator

PHRASE = "i keep checking the locks every single night"
OTHER = "felt calm and grateful today"


def _phrase_card(cards):
    matches = [
        card
        for card in cards
        if card["kind"] in {"recurring_phrase", "rumination"} and card["label"] == PHRASE
    ]
    assert len(matches) == 1, "the strong recurring observation must actually surface"
    return matches[0]


@pytest.mark.parametrize("days,interval", [(70, 7), (90, 1)])
def test_public_evidence_dates_bind_observed_days_and_survive_state_roundtrip(days, interval):
    today = date(2026, 9, 4)
    start = today - timedelta(days=days - 1)
    entries = [
        JournalEntry(PHRASE if i % interval == 0 else OTHER, start + timedelta(days=i))
        for i in range(days)
    ]
    # Repeating an entry on one day must not duplicate a drill-down date.
    entries.append(JournalEntry(PHRASE, start))
    observed = sorted({entry.entry_date.isoformat() for entry in entries if entry.text == PHRASE})
    # The public contract retains the newest 60 actual dates, excluding
    # unrelated entries and calendar days with no occurrence of this phrase.
    expected = observed[-60:]
    first = brain.update(brain.fresh_state(), entries, today)
    card = _phrase_card([pattern.to_dict() for pattern in first.surfaced])
    assert card["detail"]["evidence_dates"] == expected
    assert card["detail"]["sample_days"] == days

    # Persistence and muting must retain the evidence needed by the collapsed
    # card's drilldown; a fresh unrelated observation cannot join this set.
    later = today + timedelta(days=1)
    entries.append(JournalEntry("I cooked dinner with my family this evening.", later))
    second = brain.update(
        brain.load_state(brain.dump_state(first.new_state)),
        entries,
        later,
        muted=[card["detail"]["pattern_pid"]],
    )
    restored = _phrase_card([pattern.to_dict() for pattern in second.surfaced])
    assert restored["detail"]["muted"] is True
    assert restored["detail"]["evidence_dates"] == expected


async def test_encrypted_insight_api_preserves_exact_observed_evidence_dates(client):
    today = date.today()
    emu = ClientEmulator("evidence-date-reader", "synthetic-evidence-passphrase")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    observed = []
    for i in range(35):
        day = today - timedelta(days=34 - i)
        text = PHRASE if i % 3 == 0 else OTHER
        if text == PHRASE:
            observed.append(day.isoformat())
        await emu.create_entry(
            client, text, day, client_entry_id=f"evidence-{i}", content_version=1
        )

    outcome = await emu.recompute(client)
    assert outcome["phase"] == "insight"
    payload = await emu.decrypt_insights(client)
    card = _phrase_card(payload["stats"]["patterns"])
    assert len(observed) == 12  # prove this is a real, nonempty surfaced fixture
    assert card["detail"]["evidence_dates"] == observed
    assert card["detail"]["sample_days"] == 35
