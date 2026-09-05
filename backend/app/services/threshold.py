"""The 30-day threshold: progressive revelation of detected patterns."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum
from typing import Iterable

DEFAULT_UNLOCK_DAYS = 30


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
    """Number of distinct calendar days with at least one entry."""
    return len({d for d in dates if d is not None})


def current_streak(dates: Iterable[date], today: date | None = None) -> int:
    """Consecutive-day writing streak ending today (or yesterday, with grace)."""
    distinct = sorted({d for d in dates if d is not None})
    if not distinct:
        return 0
    today = today or date.today()
    day = distinct[-1]
    if day not in (today, today - timedelta(days=1)):
        return 0
    streak = 0
    index = len(distinct) - 1
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
