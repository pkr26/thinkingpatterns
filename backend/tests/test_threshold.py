"""The 30-day progressive-revelation threshold."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.services import threshold
from app.services.threshold import Phase, evaluate, is_unlocked

BASE = date(2026, 7, 1)


def test_empty_is_baseline():
    state = evaluate([])
    assert state.phase is Phase.BASELINE
    assert state.active_days == 0
    assert state.days_remaining == 30


@pytest.mark.parametrize(
    "days,expected_phase",
    [
        (1, Phase.BASELINE),
        (29, Phase.BASELINE),
        (30, Phase.INSIGHT),
        (31, Phase.INSIGHT),
        (100, Phase.INSIGHT),
    ],
)
def test_phase_boundary(days, expected_phase):
    dates = [BASE + timedelta(days=i) for i in range(days)]
    assert evaluate(dates).phase is expected_phase


def test_duplicate_dates_count_once():
    dates = [BASE] * 50
    assert evaluate(dates).active_days == 1
    assert evaluate(dates).phase is Phase.BASELINE


def test_gap_days_do_not_block_unlock():
    # "continuous writing" is implemented as distinct active days: life happens,
    # a missed day pauses progress but never resets it.
    dates = [BASE + timedelta(days=i * 2) for i in range(30)]  # every other day, 60-day span
    state = evaluate(dates)
    assert state.active_days == 30
    assert state.phase is Phase.INSIGHT


def test_days_remaining_counts_down_and_clamps():
    for active in (0, 10, 29):
        assert (
            evaluate([BASE + timedelta(days=i) for i in range(active)]).days_remaining
            == 30 - active
        )
    assert evaluate([BASE + timedelta(days=i) for i in range(45)]).days_remaining == 0


def test_streak_consecutive_ending_today():
    today = date(2026, 9, 3)
    dates = [today - timedelta(days=i) for i in (0, 1, 2, 3)]
    assert evaluate(dates, today=today).streak == 4


def test_streak_with_gap():
    today = date(2026, 9, 3)
    dates = [today - timedelta(days=i) for i in (0, 1, 5, 6)]
    assert evaluate(dates, today=today).streak == 2


def test_streak_yesterday_grace():
    today = date(2026, 9, 3)
    dates = [today - timedelta(days=1), today - timedelta(days=2)]
    assert evaluate(dates, today=today).streak == 2


def test_streak_broken_when_stale():
    today = date(2026, 9, 3)
    dates = [today - timedelta(days=5), today - timedelta(days=6)]
    assert evaluate(dates, today=today).streak == 0


def test_streak_empty():
    assert evaluate([], today=BASE).streak == 0


def test_is_unlocked_helper():
    dates = [BASE + timedelta(days=i) for i in range(30)]
    assert is_unlocked(dates) is True
    assert is_unlocked(dates[:29]) is False


def test_custom_threshold():
    dates = [BASE + timedelta(days=i) for i in range(10)]
    assert evaluate(dates, threshold=10).phase is Phase.INSIGHT
    assert evaluate(dates, threshold=11).phase is Phase.BASELINE


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        evaluate([], threshold=0)


def test_none_dates_ignored():
    assert threshold.count_active_days([None, BASE, None, BASE]) == 1
