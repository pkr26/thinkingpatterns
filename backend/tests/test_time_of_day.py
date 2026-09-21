"""Regression tests for Phase 3 (2026-09-21): the time-of-day channel.

The entry payload's optional coarse writing-window bucket ("tod" —
morning/afternoon/evening/night) powers the "Sunday evening" temporal
refinement. Pinned here: the dominant-bucket rule (>=3 tod-bearing
entries at >=70% one bucket narrows the card), the v1 no-tod silence,
parser validation, and the mobile payload contract.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 8, 2)  # a Sunday


def _sundays(count: int) -> list[date]:
    return [T0 + timedelta(weeks=i) for i in range(count)]


def _corpus(tods: list[str | None]) -> list[JournalEntry]:
    """Sunday 'work' entries carrying the given tod buckets, padded with
    neutral weekdays so the base rates are defined."""
    entries: list[JournalEntry] = []
    for day, tod in zip(_sundays(len(tods)), tods, strict=True):
        entries.append(JournalEntry("busy day at work again", day, tod=tod))
    filler = T0 + timedelta(days=2)
    for i in range(14):
        entries.append(JournalEntry("quiet day, some reading", filler + timedelta(days=i)))
    return entries


def _surfaced(tods: list[str | None]) -> list:
    """Two-phase update: temporal is a STATISTICAL kind, so the card only
    surfaces after independent replication (a fresh evidence Sunday on the
    second run) — the same discipline the D-1 tests use."""
    today = T0 + timedelta(weeks=len(tods))
    first = brain.update(brain.load_state(None), _corpus(tods), today)
    # The fresh Sunday is one week PAST run 1's today — a genuinely new
    # evidence day, which is what satisfies the replication gate (the
    # last corpus Sunday is a week before today; adding one more week
    # here keeps it from colliding with run 1's date).
    fresh_sunday = today + timedelta(weeks=1)
    grown = _corpus(tods) + [
        JournalEntry("another busy work day", fresh_sunday, tod=tods[-1] if tods else None)
    ]
    second = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), grown, fresh_sunday
    )
    return [p for p in second.surfaced if p.kind == "temporal" and p.label == "work"]


class TestTemporalTimeOfDay:
    def test_dominant_evening_narrows_the_temporal_card(self):
        cards = _surfaced(["evening"] * 9)
        assert cards, "the Sunday-work temporal pattern must surface"
        assert cards[0].detail["time_of_day"] == "evening"

    def test_mixed_windows_do_not_narrow_the_claim(self):
        cards = _surfaced(["evening", "morning", "evening", "night", "morning", "afternoon", "evening", "night", "morning"])
        assert cards
        assert "time_of_day" not in cards[0].detail

    def test_v1_corpora_carry_no_tod_anywhere(self):
        cards = _surfaced([None] * 9)
        assert cards
        assert "time_of_day" not in cards[0].detail

    def test_dominant_fraction_below_the_bar_does_not_narrow(self):
        # 5 evening vs 3 morning: 0.625 < 0.7 — the claim stays "Sunday".
        cards = _surfaced(["evening"] * 5 + ["morning"] * 4)
        assert cards
        assert "time_of_day" not in cards[0].detail


# --- API level: the tod channel parses and validates -------------------------------


async def _mature_account(client, emu, days=32):
    from tests.helpers import daterange

    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, date.today()):
        await emu.create_entry(client, "quiet day some reading", day, client_entry_id=f"t-{day.isoformat()}")


async def test_recompute_accepts_the_tod_channel(client):
    from tests.helpers import ClientEmulator

    emu = ClientEmulator("tod-ok", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    await emu.create_entry(
        client,
        "anxious about work",
        date.today(),
        client_entry_id="tod-e-1",
        content_version=1,
        tod="evening",
    )
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
    )
    assert response.status_code == 200, response.text


async def test_recompute_rejects_an_unknown_tod_bucket(client):
    from tests.helpers import ClientEmulator

    emu = ClientEmulator("tod-bad", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    await emu.create_entry(
        client,
        "anxious about work",
        date.today(),
        client_entry_id="tod-e-2",
        content_version=1,
        tod="brunch",
    )
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "entry_payload_malformed"
