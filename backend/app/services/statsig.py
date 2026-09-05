"""Deterministic significance statistics for pattern claims.

Every function here is a pure function of its inputs — no RNG, no wall
clock, no platform-dependent iteration order. The brain must reach the
same verdict for the same corpus on every run and platform, forever:
that is what keeps the engine unit-testable, mutation-testable, and
honest with users (a pattern claim that appears and disappears between
runs is noise, not insight).

Numerical routines follow the standard recipes (log-space binomial
sums; the Lentz continued fraction for the regularized incomplete beta
function, as in Numerical Recipes / A&S 26.5.8) with fixed iteration
caps so they cannot spin or diverge silently.
"""

from __future__ import annotations

import math

_BETACF_MAX_ITER = 200
_BETACF_EPS = 3e-12
_BETACF_FPMIN = 1e-300


def binomial_sf(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p), exact via log-space summation.

    This is the engine behind base-rate-corrected weekday claims: "the
    theme appeared k of n times on Sundays — would that be surprising if
    it just followed the user's own Sunday-writing rate p?"
    """
    if n < 0:
        raise ValueError("n must be >= 0")
    if not 0.0 <= p <= 1.0:
        raise ValueError("p must be in [0, 1]")
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    if p == 0.0:
        return 0.0  # impossible to observe any hit
    if p == 1.0:
        return 1.0  # every trial hits, k <= n is certain
    log_p = math.log(p)
    log_q = math.log1p(-p)
    total = 0.0
    for i in range(k, n + 1):
        log_coef = math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
        total += math.exp(log_coef + i * log_p + (n - i) * log_q)
    return min(1.0, total)


def benjamini_hochberg(pvalues: list[float], q: float = 0.05) -> list[bool]:
    """Step-up FDR control: which hypotheses survive correction.

    The brain tests many hypotheses at once (each theme × each detector).
    Without correction, a 5% false-positive rate per test becomes a
    near-certain false pattern somewhere — the exact failure mode that
    makes self-tracking apps manufacture fake "insights".
    """
    if not 0.0 < q <= 1.0:
        raise ValueError("q must be in (0, 1]")
    if not pvalues:
        return []
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    cutoff_rank = 0
    for rank, idx in enumerate(order, start=1):
        if pvalues[idx] <= q * rank / m:
            cutoff_rank = rank
    rejected = [False] * m
    for idx in order[:cutoff_rank]:
        rejected[idx] = True
    return rejected


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (Lentz's method)."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _BETACF_FPMIN:
        d = _BETACF_FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, _BETACF_MAX_ITER + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETACF_FPMIN:
            d = _BETACF_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETACF_FPMIN:
            c = _BETACF_FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETACF_FPMIN:
            d = _BETACF_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETACF_FPMIN:
            c = _BETACF_FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _BETACF_EPS:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_bt = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    bt = math.exp(log_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def student_t_sf_two_sided(t: float, dof: float) -> float:
    """Two-sided P(|T| >= t) under Student's t with *dof* degrees of freedom."""
    if dof <= 0.0:
        return 1.0
    if t <= 0.0:
        return 1.0
    x = dof / (dof + t * t)
    return min(1.0, _betainc(dof / 2.0, 0.5, x))


def normal_two_sided_sf(z: float) -> float:
    """Two-sided standard-normal tail P(|Z| >= z) — exact via erfc."""
    return min(1.0, math.erfc(abs(z) / math.sqrt(2.0)))


def f_sf(f: float, df1: int, df2: int) -> float:
    """Upper tail P(F >= f) for F ~ F(df1, df2), via the incomplete beta."""
    if df1 < 1 or df2 < 1:
        return 1.0
    if f <= 0.0:
        return 1.0
    x = df2 / (df2 + df1 * f)
    return _betainc(df2 / 2.0, df1 / 2.0, x)


def correlation_p(r: float, n: int) -> float:
    """Two-sided p-value for a Pearson correlation over n pairs.

    t = r*sqrt((n-2)/(1-r^2)) under H0: rho = 0; degenerate inputs (n < 4
    or |r| >= 1 with no residual df) are "no evidence".
    """
    if n < 4 or not -1.0 < r < 1.0:
        return 1.0
    t = abs(r) * math.sqrt((n - 2) / (1.0 - r * r))
    return student_t_sf_two_sided(t, n - 2)


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _variance(values: list[float]) -> float:
    m = _mean(values)
    return sum((v - m) ** 2 for v in values) / (len(values) - 1)


def welch_test(a: list[float], b: list[float], variance_floor: float = 0.0) -> tuple[float, float]:
    """Welch's unequal-variance t-test: (t statistic, two-sided p-value).

    Degenerate inputs (n < 2 per side, or zero pooled standard error
    after any ``variance_floor``) return (0.0, 1.0) — "no evidence" —
    rather than dividing by zero. For a product that makes claims to
    vulnerable people, failing silent-and-negative is the only safe
    direction. Callers measuring noisy proxies (lexicon mood) pass a
    floor so single-sided constant groups still measure as separation —
    but TWO constant groups fabricate a t-test on variance the data never
    had (p ~ 1e-22 from pure floor), so that case is forced to "no
    evidence" regardless of the floor.
    """
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0
    m1, m2 = _mean(a), _mean(b)
    v1_actual, v2_actual = _variance(a), _variance(b)
    # Float-safe "constant group" test (a mean of 12 x -0.6 is off by ~1e-16).
    if v1_actual < 1e-12 and v2_actual < 1e-12:
        return 0.0, 1.0
    v1 = max(v1_actual, variance_floor**2)
    v2 = max(v2_actual, variance_floor**2)
    se2 = v1 / n1 + v2 / n2
    if se2 <= 0.0:
        return 0.0, 1.0
    t = (m1 - m2) / math.sqrt(se2)
    dof = se2**2 / ((v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1))
    return t, student_t_sf_two_sided(abs(t), dof)


def cohens_d(a: list[float], b: list[float], variance_floor: float = 0.0) -> float:
    """Standardized mean difference, signed: mean(b) - mean(a) over pooled SD.

    The caller passes (with-theme, without-theme) moods, so a positive d
    reads "mood is lower when the theme is present". ``variance_floor``
    treats constant groups as having at least that measurement noise —
    identical-but-different groups are perfect separation, not zero
    effect. A zero floor with zero spread still returns 0.0 (no
    measurable difference, no claim).
    """
    n1, n2 = len(a), len(b)
    if n1 + n2 < 3:
        return 0.0
    m1, m2 = _mean(a), _mean(b)
    v1 = _variance(a) if n1 > 1 else 0.0
    v2 = _variance(b) if n2 > 1 else 0.0
    pooled_sq = ((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2)
    pooled = max(math.sqrt(max(pooled_sq, 0.0)), variance_floor)
    if pooled <= 0.0:
        return 0.0
    return (m2 - m1) / pooled
