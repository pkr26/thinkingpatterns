"""The 30-day threshold: progressive revelation of detected patterns."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Iterable

DEFAULT_UNLOCK_DAYS = 30


def _utc_today() -> date:
    """Server-UTC calendar day (2026-09-20 audit fix L-1).

    The streak's "today" anchor must be the same UTC calendar the entry-date
    bounds use; ``date.today()`` answers in the host's local timezone and let
    the streak flip at local midnight on non-UTC hosts.
    """
    return datetime.now(timezone.utc).date()


class Phase(str, Enum):
    BASELINE = "baseline"
    INSIGHT = "insight"


@dataclass(frozen=True)
class ThresholdState:
    active_days: int
    streak: int
    phase: Phase
    days_remaining: int


def count_active_days(dates: Iterable[date]) -> int:
    """Number of distinct calendar days with at least one entry.

    Future-dated entries COUNT (deliberate, pinned by
    test_checklist_round2_threshold_sync): entries.py admits server-today
    + 1 for UTC+14 clients, and for them that entry IS today — the grace
    window must apply to the unlock the same way it applies to storage.
    The STREAK anchor below is where the future-date handling matters
    (2026-09-28 deep audit)."""
    return len({d for d in dates if d is not None})


def current_streak(dates: Iterable[date], today: date | None = None) -> int:
    """Consecutive-day writing streak ending today (or yesterday, with grace).

    The walk anchors at the latest date NOT in the future (2026-09-28 deep
    audit): a single forward-grace entry (server-today + 1, admitted for
    UTC+14 clients) used to become the anchor, and "tomorrow not in (today,
    yesterday)" zeroed the streak of a user who had written every day."""
    distinct = sorted({d for d in dates if d is not None})
    if not distinct:
        return 0
    today = today or _utc_today()
    anchor_candidates = [d for d in distinct if d <= today]
    if not anchor_candidates:
        return 0
    day = anchor_candidates[-1]
    if day not in (today, today - timedelta(days=1)):
        return 0
    streak = 0
    index = len(distinct) - 1
    # Skip any trailing future-dated entries so the walk starts at the anchor.
    while index >= 0 and distinct[index] > today:
        index -= 1
    while index >= 0 and distinct[index] == day:
        streak += 1
        day -= timedelta(days=1)
        index -= 1
    return streak


def evaluate(
    dates: Iterable[date],
    threshold: int = DEFAULT_UNLOCK_DAYS,
    today: date | None = None,
) -> ThresholdState:
    """Compute the revelation phase and progress toward unlocking insights."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1 day")
    active = count_active_days(dates)
    phase = Phase.INSIGHT if active >= threshold else Phase.BASELINE
    return ThresholdState(
        active_days=active,
        streak=current_streak(dates, today),
        phase=phase,
        days_remaining=max(0, threshold - active),
    )


def is_unlocked(dates: Iterable[date], threshold: int = DEFAULT_UNLOCK_DAYS) -> bool:
    return evaluate(dates, threshold).phase is Phase.INSIGHT
