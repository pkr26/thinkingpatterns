"""The exported F-tail interface matches independent small-shape identities."""

import itertools
import math
import sys

import pytest

from app.services.statsig import f_sf


def test_native_public_f_tail_matches_integer_beta_binomial_identity():
    # I_x(a,b)=P(Binomial(a+b-1,x)>=a), with positive integer
    # a=df2/2 and b=df1/2. Actual f_sf performs its native beta mapping.
    for a, b in itertools.product(range(1, 7), repeat=2):
        n = a + b - 1
        for x in (0, 0.001, 0.125, 0.5, 0.875, 0.999, 1):
            if x == 0:
                # A finite enormous F naturally rounds beta x to0.
                f = sys.float_info.max
            elif x == 1:
                # A finite positive subnormal F naturally rounds x to1.
                f = math.ulp(0.0)
            else:
                f = a * (1 - x) / (b * x)
            expected = math.fsum(
                math.comb(n, hits) * x**hits * (1 - x) ** (n - hits) for hits in range(a, n + 1)
            )
            assert f_sf(f, 2 * b, 2 * a) == pytest.approx(expected, rel=0, abs=2e-12)


def test_native_public_f_tail_matches_the_arcsine_reference():
    for x in (0.001, 0.125, 0.5, 0.875, 0.999):
        expected = 2 * math.asin(math.sqrt(x)) / math.pi
        assert f_sf((1 - x) / x, 1, 1) == pytest.approx(expected, rel=0, abs=2e-12)
