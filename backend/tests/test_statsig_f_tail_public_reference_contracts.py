"""Native exported F tail at a large, nearly symmetric reference input."""

import pytest

from app.services.statsig import f_sf


def test_native_public_f_tail_preserves_a_finite_near_median_probability():
    # Equal integer degrees give median1 by exchangeability of the two
    # independent chi-square variables. This adjacent binary64 input is
    # within4e-16 of1; the true tail is extremely close to1/2. A loose1e-5
    # tolerance accommodates the implementation's large-lgamma cancellation.
    # This is an exported numerical reference domain, not a current brain
    # sample-size producer or a clinical inference.
    probability = f_sf(0.9999999999999997, 20_870_088_510, 20_870_088_510)
    assert probability == pytest.approx(0.5, abs=1e-5)
