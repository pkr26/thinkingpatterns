"""Statistical primitives for pattern claims — exactness and safe failure.

These numbers are load-bearing: they decide when the app is ALLOWED to
tell a user something about their mental state. Pins use exact known
values (hand-computable binomial sums, published t-table quantiles).
"""

from __future__ import annotations

import math

import pytest

from app.services import statsig


class TestBinomialSf:
    def test_exact_fair_coin_value(self):
        # P(X >= 5 | 10 flips, p=0.5) = 638/1024 — hand-summed binomial.
        assert statsig.binomial_sf(5, 10, 0.5) == pytest.approx(638 / 1024)

    def test_sunday_base_rate_not_significant(self):
        # 49 of 70 mentions on Sunday when 70% of entries are Sundays:
        # the theme just follows the writing schedule. P(X >= mean) for a
        # binomial sits just above one half (the point mass at the mean).
        assert statsig.binomial_sf(49, 70, 0.7) == pytest.approx(0.5586, abs=5e-3)

    def test_true_concentration_is_significant(self):
        # 10 of 10 mentions on Sunday when only 1/7 of entries are Sundays.
        assert statsig.binomial_sf(10, 10, 1 / 7) < 1e-8

    def test_edges(self):
        assert statsig.binomial_sf(0, 10, 0.3) == 1.0
        assert statsig.binomial_sf(-1, 10, 0.3) == 1.0
        assert statsig.binomial_sf(11, 10, 0.3) == 0.0
        assert statsig.binomial_sf(3, 10, 0.0) == 0.0
        assert statsig.binomial_sf(3, 10, 1.0) == 1.0

    def test_monotone_decreasing_in_k(self):
        previous = statsig.binomial_sf(0, 30, 0.4)
        for k in range(1, 31):
            current = statsig.binomial_sf(k, 30, 0.4)
            assert current <= previous + 1e-12
            previous = current

    @pytest.mark.parametrize("bad_p", [-0.1, 1.1])
    def test_invalid_p_raises(self, bad_p):
        with pytest.raises(ValueError):
            statsig.binomial_sf(1, 10, bad_p)

    def test_invalid_n_raises(self):
        with pytest.raises(ValueError):
            statsig.binomial_sf(1, -1, 0.5)


class TestBenjaminiHochberg:
    def test_all_rejected(self):
        rejected = statsig.benjamini_hochberg([0.01, 0.04, 0.03], q=0.05)
        assert rejected == [True, True, True]

    def test_none_rejected(self):
        assert statsig.benjamini_hochberg([0.06, 0.9], q=0.05) == [False, False]

    def test_partial_rejection_step_up(self):
        # Largest rank passing the threshold decides; everything smaller is
        # rejected with it.
        assert statsig.benjamini_hochberg([0.001, 0.05, 0.9], q=0.05) == [True, False, False]

    def test_empty(self):
        assert statsig.benjamini_hochberg([], q=0.05) == []

    def test_invalid_q_raises(self):
        with pytest.raises(ValueError):
            statsig.benjamini_hochberg([0.01], q=0.0)


class TestStudentT:
    def test_known_value_dof_10(self):
        # Two-sided p for t=2.0, 10 dof (published t-tables): 0.0734.
        assert statsig.student_t_sf_two_sided(2.0, 10.0) == pytest.approx(0.07339, abs=1e-4)

    def test_cauchy_critical_value_dof_1(self):
        # t_{0.025} for 1 dof is 12.706 → two-sided p = 0.05.
        assert statsig.student_t_sf_two_sided(12.706, 1.0) == pytest.approx(0.05, abs=5e-4)

    def test_zero_t_is_certain(self):
        assert statsig.student_t_sf_two_sided(0.0, 8.0) == 1.0

    def test_huge_t_is_negligible(self):
        assert statsig.student_t_sf_two_sided(100.0, 8.0) < 1e-12

    def test_invalid_dof(self):
        assert statsig.student_t_sf_two_sided(2.0, -1.0) == 1.0


class TestWelchTest:
    def test_identical_groups_are_null(self):
        t, p = statsig.welch_test([1.0, 2.0, 3.0, 4.0], [1.0, 2.0, 3.0, 4.0])
        assert t == 0.0
        assert p == 1.0

    def test_separated_groups_significant(self):
        t, p = statsig.welch_test([0.1, 0.2, 0.15, 0.05, 0.2, 0.1, 0.05, 0.15],
                                  [0.9, 0.8, 0.85, 0.95, 0.9, 0.85, 0.8, 0.9])
        assert t < -5
        assert p < 1e-3

    def test_small_samples_fail_closed(self):
        assert statsig.welch_test([1.0], [2.0, 3.0]) == (0.0, 1.0)
        assert statsig.welch_test([1.0, 2.0], []) == (0.0, 1.0)

    def test_constant_groups_without_floor_fail_closed(self):
        assert statsig.welch_test([1.0] * 8, [0.0] * 8) == (0.0, 1.0)

    def test_constant_groups_with_floor_are_perfect_separation(self):
        # Two CONSTANT groups fabricate a t-test on variance the data never
        # had (p ~ 1e-22 from the floor alone): forced to "no evidence" —
        # a crafted mood-tag journal must not manufacture p=1e-22 claims.
        t, p = statsig.welch_test([1.0] * 8, [0.0] * 8, variance_floor=0.05)
        assert t == 0.0 and p == 1.0
        # One-sided constant vs genuinely noisy still measures separation.
        t, p = statsig.welch_test([1.0] * 8, [-0.6, 0.8, -0.4, 0.9, -0.7, 0.8, -0.5, 0.7], variance_floor=0.05)
        assert abs(t) > 2 and p < 0.05


class TestCohensD:
    def test_known_value(self):
        # Pooled SD of [1,2,3] and [4,5,6] is 1; means differ by 3.
        assert statsig.cohens_d([1.0, 2.0, 3.0], [4.0, 5.0, 6.0]) == pytest.approx(3.0)

    def test_sign_convention_b_minus_a(self):
        assert statsig.cohens_d([4.0, 5.0, 6.0], [1.0, 2.0, 3.0]) == pytest.approx(-3.0)

    def test_too_small_fails_closed(self):
        assert statsig.cohens_d([1.0], [2.0]) == 0.0

    def test_constant_groups_without_floor(self):
        assert statsig.cohens_d([1.0] * 8, [0.0] * 8) == 0.0

    def test_constant_groups_with_floor(self):
        # mean(b) - mean(a) over the floored SD: -1 / 0.05.
        effect = statsig.cohens_d([1.0] * 8, [0.0] * 8, variance_floor=0.05)
        assert effect == pytest.approx(-20.0)

    def test_identical_groups_zero(self):
        assert statsig.cohens_d([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == 0.0


class TestEffectiveSampleSize:
    def test_no_autocorrelation_keeps_n(self):
        assert statsig.effective_sample_size(30, None) == 30.0
        assert statsig.effective_sample_size(30, 0.0) == 30.0
        # Negative autocorrelation never INFLATES the effective sample.
        assert statsig.effective_sample_size(30, -0.5) == 30.0

    def test_known_deflation(self):
        # Bartlett n(1-r)/(1+r): n=30, r=0.5 -> 10.
        assert statsig.effective_sample_size(30, 0.5) == pytest.approx(10.0)

    def test_floor_and_cap(self):
        assert statsig.effective_sample_size(100, 0.9) == pytest.approx(100 * 0.1 / 1.9)
        # The lag-1 estimate itself is capped at 0.9 (beyond that the
        # formula is explosive); the n floor binds for tiny samples.
        assert statsig.effective_sample_size(100, 0.999) == pytest.approx(100 * 0.1 / 1.9)
        assert statsig.effective_sample_size(4, 0.5) == 3.0      # floor above n


class TestFisherZDifference:
    def test_equal_correlations_are_no_evidence(self):
        # One-sided upper tail at z = 0 sits at 0.5 — "no rise detected".
        assert statsig.fisher_z_difference_p(0.4, 30, 0.4, 30) == pytest.approx(0.5)

    def test_strong_rise_is_significant(self):
        # atanh(0.8) = 1.0986, se = sqrt(2/27) = 0.2722, z = 4.04.
        p = statsig.fisher_z_difference_p(0.8, 30, 0.0, 30)
        assert p < 1e-4

    def test_reversed_direction_is_no_evidence(self):
        # One-sided in the direction of the claim ("more than usual").
        assert statsig.fisher_z_difference_p(0.0, 30, 0.8, 30) > 0.999

    def test_degenerate_inputs_fail_closed(self):
        assert statsig.fisher_z_difference_p(0.9, 3, 0.0, 30) == 1.0
        # |r| = 1 would blow up atanh; clamped, never a crash.
        assert 0.0 <= statsig.fisher_z_difference_p(1.0, 30, 0.0, 30) <= 1.0


class TestWelchAutocorrelation:
    def test_lag1_deflation_weakens_significance(self):
        a = [-0.5, -0.4, -0.6, -0.45, -0.55, -0.5, -0.42, -0.58] * 3
        b = [0.4, 0.5, 0.35, 0.45, 0.55, 0.42, 0.5, 0.38] * 3
        _, p_plain = statsig.welch_test(a, b)
        _, p_deflated = statsig.welch_test(a, b, lag1=0.6)
        assert p_deflated > p_plain  # less independent evidence, weaker claim

    def test_lag1_none_matches_plain(self):
        a, b = [0.1, 0.2, 0.15, 0.05], [0.9, 0.8, 0.85, 0.95]
        assert statsig.welch_test(a, b, lag1=None) == statsig.welch_test(a, b)


class TestSampleSd:
    def test_matches_variance(self):
        values = [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0]
        assert statsig.sample_sd(values) == pytest.approx(math.sqrt(statsig._variance(values)))

    def test_degenerate(self):
        assert statsig.sample_sd([]) == 0.0
        assert statsig.sample_sd([1.5]) == 0.0


def test_determinism_trivially_stable():
    a = list(range(20))
    b = list(range(30, 50))
    assert statsig.welch_test(a, b) == statsig.welch_test(a, b)
    assert statsig.binomial_sf(7, 20, 0.3) == statsig.binomial_sf(7, 20, 0.3)
