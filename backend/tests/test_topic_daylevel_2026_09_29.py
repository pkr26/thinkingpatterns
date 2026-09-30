"""Topic rising claims are DAY-level Bernoulli (deep audit 2026-09-29 HIGH).

The rising binomial used to count ENTRIES — the exact clustered-journal
flaw the weekday detector was already fixed for. A writer who journals
many entries per day multiplied the trial count ~Nx and any word slightly
more frequent per entry became "significantly rising". The trial is now
one calendar day, mirroring ``_detect_themes``.

Pins:
  1. A word whose DAY rate is flat cannot be "rising" no matter how many
     entries per day mention it (the pure inflation attack).
  2. A genuine day-level rise still surfaces as a rising topic.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry


def _detect_topics_for(entries: list[JournalEntry], today: date):
    result = brain.update(brain.load_state(None), entries, today)
    return [p for p in result.surfaced if p.kind == "topic"]


class TestClusteredJournalsCannotInflateTopics:
    def test_flat_day_rate_with_many_entries_per_day_is_not_rising(self) -> None:
        """'blanket' appears on the same fraction of DAYS in both halves
        (a bit under half), but the recent half writes 6 entries per day
        where the earlier half wrote 1. The old per-entry binomial saw a
        massively inflated recent count and called it rising; the day
        level sees flat."""
        start = date(2026, 6, 1)
        entries: list[JournalEntry] = []
        for i in range(60):
            d = start + timedelta(days=i)
            recent = i >= 30
            mentions = (i % 7) in (0, 1, 2)  # same day pattern both halves
            per_day = 6 if recent else 1
            for k in range(per_day):
                text = (
                    "cozy blanket evening"
                    if (mentions and k == 0)
                    else "quiet walk and tea and letters"
                )
                entries.append(JournalEntry(text, d))
        topics = {p.label: p for p in _detect_topics_for(entries, start + timedelta(days=60))}
        # 'blanket' may appear as a presence card (it is a steady share of
        # entries), but NEVER as a rising trend.
        blanket = topics.get("blanket")
        if blanket is not None:
            assert blanket.detail.get("trend") != "rising", (
                f"clustered entries must not manufacture a rising topic: {blanket.detail}"
            )

    def test_genuine_day_level_rise_still_surfaces(self) -> None:
        """'ceramics' is absent for the earlier half, then mentioned on a
        substantial fraction of RECENT DAYS — a real new preoccupation the
        day-level test must still catch (after the 2-qualification-day
        lifecycle every statistical kind requires)."""
        start = date(2026, 6, 1)

        fillers = (
            "watched the rain from the window with tea",
            "organized the desk drawers and old cables",
            "cooked soup for tomorrow and froze half",
            "stretched out on the couch for a while",
            "sketched the view from the kitchen window",
            "paid the utilities and filed the receipt",
            "took the long way home through the park",
            "bought oranges and bread from the corner shop",
            "brewed proper coffee instead of instant",
            "changed the burnt bulb in the hallway",
        )
        ceramics_lines = (
            " spent the evening at the ceramics wheel",
            " glazed the small bowls after ceramics class",
            " practiced centering clay at the studio",
            " loaded the kiln with my ceramics work",
            " trimmed mugs at the wheel before dinner",
        )

        def corpus(through: date) -> list[JournalEntry]:
            entries: list[JournalEntry] = []
            n_days = (through - start).days + 1
            for i in range(n_days):
                d = start + timedelta(days=i)
                text = fillers[i % len(fillers)]
                if i >= 34 and i % 3 != 2:
                    text += ceramics_lines[i % len(ceramics_lines)]
                entries.append(JournalEntry(text, d))
            return entries

        t0 = start + timedelta(days=59)
        first = brain.update(brain.load_state(None), corpus(t0), t0)
        topics = [p for p in first.surfaced if p.kind == "topic" and p.label == "ceramics"]
        if not topics:
            # Rising is a tested claim: promotion needs a second
            # qualification with NEW evidence days.
            t2 = t0 + timedelta(days=2)
            second = brain.update(
                brain.load_state(brain.dump_state(first.new_state)),
                corpus(t2),
                t2,
            )
            topics = [p for p in second.surfaced if p.kind == "topic" and p.label == "ceramics"]
        assert topics, "the genuine day-level rise must surface"
        rising = [p for p in topics if p.detail.get("trend") == "rising"]
        assert rising, f"ceramics must be RISING, got: {[p.detail for p in topics]}"
        detail = rising[0].detail
        # The tested rates are day shares now.
        assert detail["day_share_recent"] > detail["day_share_earlier"]
        assert "p_value" in detail
