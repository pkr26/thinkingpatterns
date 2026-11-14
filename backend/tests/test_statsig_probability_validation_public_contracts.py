"""Exported probability validation precedes degenerate count shortcuts."""

import pytest

from app.services.statsig import binomial_sf


def test_native_binomial_tail_refuses_an_invalid_probability_before_count_shortcuts():
    for threshold, trials in [(0, 0), (0, 4), (5, 4)]:
        with pytest.raises(ValueError):
            binomial_sf(threshold, trials, 1.5)
