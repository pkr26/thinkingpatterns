"""Independent finite probability checks and released numerical results."""

from __future__ import annotations

import importlib
import itertools
import json
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tools/tests/fixtures/statistical_results.json"


def _stats(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    return importlib.import_module("app.services.statsig")


def test_binomial_tail_matches_finite_counting_at_every_small_boundary(monkeypatch):
    stats = _stats(monkeypatch)
    for n in range(13):
        for p in (0, 0.125, 0.25, 0.5, 0.75, 0.875, 1):
            for k in range(-1, n + 2):
                expected = math.fsum(
                    math.comb(n, hits) * p**hits * (1 - p) ** (n - hits)
                    for hits in range(max(k, 0), n + 1)
                )
                assert stats.binomial_sf(k, n, p) == pytest.approx(expected, abs=2e-14)
    with pytest.raises(ValueError, match="^n must be >= 0$"):
        stats.binomial_sf(1, -1, 0.5)
    for probability in (-0.001, 1.001, math.nan):
        with pytest.raises(ValueError, match=r"^p must be in \[0, 1\]$"):
            stats.binomial_sf(1, 4, probability)


def test_heterogeneous_tail_matches_all_bernoulli_outcomes(monkeypatch):
    stats = _stats(monkeypatch)
    for probabilities in (
        [],
        [0],
        [1],
        [0.25],
        [0, 0.25, 0.5, 1],
        [0.05, 0.2, 0.6, 0.95],
        [0.5] * 8,
    ):
        for threshold in range(-1, len(probabilities) + 2):
            total = 0.0
            for outcome in itertools.product((0, 1), repeat=len(probabilities)):
                if sum(outcome) >= threshold:
                    total += math.prod(
                        p if hit else 1 - p
                        for p, hit in zip(probabilities, outcome, strict=True)
                    )
            assert stats.poisson_binomial_sf(threshold, probabilities) == pytest.approx(
                total, abs=2e-14
            )
    for probabilities in ([-0.001], [1.001], [0.5, math.nan]):
        with pytest.raises(ValueError, match=r"^every p must be in \[0, 1\]$"):
            stats.poisson_binomial_sf(1, probabilities)


def test_regularized_beta_matches_integer_binomial_identity_and_arcsine(monkeypatch):
    stats = _stats(monkeypatch)
    for a, b in itertools.product(range(1, 7), repeat=2):
        n = a + b - 1
        for x in (0, 0.001, 0.125, 0.5, 0.875, 0.999, 1):
            expected = math.fsum(
                math.comb(n, hits) * x**hits * (1 - x) ** (n - hits)
                for hits in range(a, n + 1)
            )
            assert stats._betainc(a, b, x) == pytest.approx(expected, abs=2e-12)
    for x in (0.001, 0.125, 0.5, 0.875, 0.999):
        expected = 2 * math.asin(math.sqrt(x)) / math.pi
        assert stats._betainc(0.5, 0.5, x) == pytest.approx(expected, abs=2e-12)


def test_fdr_exact_rank_boundaries_and_input_order(monkeypatch):
    stats = _stats(monkeypatch)
    assert stats.benjamini_hochberg([0.01, 0.02, 0.03], q=0.03) == [True, True, True]
    assert stats.benjamini_hochberg([0.01001, 0.02001, 0.03001], q=0.03) == [
        False,
        False,
        False,
    ]
    assert stats.benjamini_hochberg([0.9, 0.002, 0.03, 0.001], q=0.04) == [
        False,
        True,
        True,
        True,
    ]
    assert stats.benjamini_hochberg([1], q=1) == [True]
    assert stats.benjamini_hochberg([], q=0.04) == []
    for q in (0, -0.001, 1.001, math.nan):
        with pytest.raises(ValueError, match=r"^q must be in \(0, 1\]$"):
            stats.benjamini_hochberg([0.1], q=q)


def test_released_statistical_values_repeat_for_same_corpus(monkeypatch):
    stats = _stats(monkeypatch)
    for row in json.loads(FIXTURE.read_text()):
        operation = getattr(stats, row["function"])
        first = operation(*row["args"], **row["kwargs"])
        second = operation(*row["args"], **row["kwargs"])
        # JSON arrays stand in for the public Welch tuple; the actual floats
        # retain their IEEE-754 representation through JSON serialization.
        if isinstance(first, tuple):
            first, second = list(first), list(second)
        assert first == second == row["result"], row


def test_statistical_degenerate_inputs_cannot_create_evidence(monkeypatch):
    stats = _stats(monkeypatch)
    for values in ([], [1]):
        assert stats.sample_sd(values) == 0
        assert stats.brown_forsythe_upper_p(values, [1, 2]) == 1
        assert stats.welch_test(values, [1, 2]) == (0, 1)
        assert stats.cohens_d(values, []) == 0
    assert stats.sample_sd([1, 2, 3]) == 1
    assert stats.welch_test([1] * 4, [2, 3, 4, 5], variance_floor=5) == (0, 1)
    assert stats.welch_test([2, 3, 4, 5], [1] * 4, variance_floor=5) == (0, 1)
    for n in (-1, 0, 1, 2, 3, 10, 100):
        for lag in (None, -0.5, 0, 0.1, 0.5, 0.9, 1):
            expected = (
                0
                if n <= 0
                else (
                    float(n)
                    if lag is None or lag <= 0
                    else min(n, max(3, n * (1 - min(lag, 0.9)) / (1 + min(lag, 0.9))))
                )
            )
            assert stats.effective_sample_size(n, lag) == expected


def test_large_f_degrees_preserve_symmetry_reciprocity_and_probability_bounds(
    monkeypatch,
):
    stats = _stats(monkeypatch)
    for degrees in (1, 2, 10, 1000, 1_000_000, 1_000_000_000):
        assert stats.f_sf(1, degrees, degrees) == 0.5
        for value in (0.5, 0.99, 0.999999, 1.000001, 1.01, 2):
            tail = stats.f_sf(value, degrees, degrees)
            reverse = stats.f_sf(1 / value, degrees, degrees)
            assert math.isfinite(tail) and 0 <= tail <= 1
            assert tail + reverse == pytest.approx(1, abs=2e-8)
    for value in (0.01, 0.1, 0.5, 1, 2, 10, 100):
        assert stats.f_sf(value, 2, 2) == pytest.approx(1 / (1 + value), abs=2e-12)
        assert stats.f_sf(value, 1, 1) == pytest.approx(
            2 * math.atan(1 / math.sqrt(value)) / math.pi, abs=2e-12
        )


def test_statistical_exact_degenerate_boundaries_and_two_observation_samples(
    monkeypatch,
):
    stats = _stats(monkeypatch)
    for f in (0, 1, 2):
        for df1, df2 in ((0, 1), (1, 0), (0, 0), (-1, 4)):
            assert stats.f_sf(f, df1, df2) == 1
    assert stats.student_t_sf_two_sided(1, 0) == 1
    assert stats.student_t_sf_two_sided(0, 1) == 1
    for r in (-1, 1):
        assert stats.correlation_p(r, 10) == 1
    assert stats.sample_sd([0, 1]) == math.sqrt(0.5)
    assert stats.benjamini_hochberg([0.03, 0.08]) == [False, False]
    assert stats.benjamini_hochberg([0.01, 0.03]) == [True, True]
    for one, other in (([], [0, 1, 2]), ([0], [1])):
        assert stats.cohens_d(one, other) == 0
        assert stats.cohens_d(other, one) == 0
    assert stats.cohens_d([0], [0, 1, 2]) == 1
    assert stats.cohens_d([0, 1, 2], [0]) == -1
    assert stats.cohens_d([1], [2, 3]) == pytest.approx(2.1213203435596424)
    assert stats.cohens_d([2, 3], [1]) == pytest.approx(-2.1213203435596424)
    assert stats.cohens_d([0, 0.1], [0.2, 0.3]) == pytest.approx(2.82842712474619)


def test_beta_exhaustion_is_an_explicit_bounded_numerical_failure(monkeypatch):
    stats = _stats(monkeypatch)
    # This genuinely difficult shape consumes the native iteration budget;
    # no limit is lowered and no incomplete result is accepted as evidence.
    with pytest.raises(
        stats.BetaConvergenceError,
        match="^incomplete beta continued fraction did not converge$",
    ):
        stats._betacf(1e10, 1e10, 0.5)


def test_beta_native_iteration_budget_bounds_actual_numeric_work(monkeypatch):
    stats = _stats(monkeypatch)
    comparisons = []
    absolute = abs

    def observed_absolute(value):
        comparisons.append(True)
        return absolute(value)

    monkeypatch.setattr(stats, "abs", observed_absolute, raising=False)
    with pytest.raises(
        stats.BetaConvergenceError,
        match="^incomplete beta continued fraction did not converge$",
    ):
        stats._betacf(1e10, 1e10, 0.5)
    assert len(comparisons) <= 10_000


def test_continued_fraction_refuses_exactly_singular_native_limbs(monkeypatch):
    stats = _stats(monkeypatch)
    for a, b in ((2, 3), (3, 3), (1, 4), (4, 8), (5, 2)):
        x = (a + 1) / (a + b)
        with pytest.raises(
            stats.BetaConvergenceError,
            match="^incomplete beta continued fraction is singular$",
        ):
            stats._betacf(a, b, x)
        # The public probability uses the other symmetry branch and still
        # agrees with the independent exact finite binomial expansion.
        beta = math.fsum(
            math.comb(a + b - 1, hits) * x**hits * (1 - x) ** (a + b - 1 - hits)
            for hits in range(a, a + b)
        )
        assert stats._betainc(a, b, x) == pytest.approx(beta, rel=2e-12)
    for a, b, x in (
        (1, 2, 0.75),
        (2, 8, 0.9375),
        (1e14, 3.0, math.nextafter(1.0, 0.0)),
    ):
        with pytest.raises(
            stats.BetaConvergenceError,
            match="^incomplete beta continued fraction is singular$",
        ):
            stats._betacf(a, b, x)


def test_probability_saturation_zero_tail_and_small_effective_count(monkeypatch):
    stats = _stats(monkeypatch)
    assert stats.poisson_binomial_sf(0, [0.1, 0.2, 0.3]) == 1
    assert stats.poisson_binomial_sf(0, [0.01] * 3) == 1
    assert stats.f_sf(0, 1, 1) == 1
    assert stats.f_sf(-1, 1, 1) == 1
    # F=0 has survival probability one for every positive degree count;
    # that analytic boundary needs no lossy conversion of large integers.
    assert stats.f_sf(0.0, 10**400, 1) == 1
    assert stats.f_sf(0.0, 1, 10**400) == 1
    # Median deviations produce F = (49/30)/(26/9); for F(1, 2),
    # the survival function is exactly 1-sqrt(F/(F+2)).
    f_value = (49 / 30) / (26 / 9)
    expected = 1 - math.sqrt(f_value / (f_value + 2))
    assert stats.brown_forsythe_upper_p(
        [0, 1], [0, 1, 5], n_eff_x=2, n_eff_y=2
    ) == pytest.approx(expected)
    assert 0 <= stats.binomial_sf(1, 1000, 0.9999) <= 1
    assert 0 <= stats.poisson_binomial_sf(1, [0.9] * 30) <= 1
    assert stats.welch_test([0, 2e-6, 4e-6], [-1e-6, 0, 1e-6]) != (0, 1)


def test_valid_beta_shapes_reject_invalid_numeric_results_and_keep_tiny_tails(
    monkeypatch,
):
    stats = _stats(monkeypatch)
    # Both shapes are strictly positive. Floating-point cancellation can
    # leave an invalid converged fraction or a result just above one; the
    # primitive must report numerical failure instead of emitting either.
    with pytest.raises(
        stats.BetaConvergenceError,
        match="^incomplete beta continued fraction is invalid$",
    ):
        stats._betacf(1e-15, 1_000_000.0, 0.49)
    # A natural binary64 zero in the second denominator must retain the
    # explicit numerical-failure outcome, with all work limits unchanged.
    with pytest.raises(
        stats.BetaConvergenceError,
        match="^incomplete beta continued fraction is singular$",
    ):
        stats._betacf(4.0, 2.0, math.nextafter(1.0, 0.0))
    with pytest.raises(
        stats.BetaConvergenceError,
        match="^incomplete beta result is not a probability$",
    ):
        stats._betainc(1e-15, 0.5, 0.1)
    assert stats._betacf(1, 1, 1e-300) == 1
    assert stats._betainc(1, 1, 1e-300) == pytest.approx(1e-300, rel=2e-12, abs=0)


def test_beta_singular_direct_fraction_keeps_accurate_public_probability(monkeypatch):
    stats = _stats(monkeypatch)
    a, b, x = 5, 20, 0.5881301598247708
    beta = math.fsum(
        math.comb(a + b - 1, hits) * x**hits * (1 - x) ** (a + b - 1 - hits)
        for hits in range(a, a + b)
    )
    with pytest.raises(
        stats.BetaConvergenceError,
        match="^incomplete beta continued fraction is singular$",
    ):
        stats._betacf(a, b, x)
    assert stats._betainc(a, b, x) == pytest.approx(beta, rel=5e-11)


def test_beta_can_use_last_native_iteration_for_a_valid_symmetric_shape(monkeypatch):
    stats = _stats(monkeypatch)
    shape = 10_435_044_286.899162
    # I_x(a,a)=1/2 at x=1/2. The gamma duplication identity gives
    # h=a*sqrt(pi)*Gamma(a)/Gamma(a+1/2). Its Stirling expansion has a
    # remainder of order a^-2 here, well below binary64 precision.
    expected = math.sqrt(math.pi * shape) * (1 + 1 / (8 * shape))
    assert stats._betacf(shape, shape, 0.5) == pytest.approx(expected, rel=2e-11)
