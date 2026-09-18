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
from collections.abc import Sequence

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


def poisson_binomial_sf(k: int, probs: Sequence[float]) -> float:
    """P(X >= k) for independent Bernoulli trials with PER-TRIAL p.

    The exact tail when the null itself is heterogeneous — the avoidance
    detector's trials carry the skip rate of the theme-day's own WEEKDAY,
    so a Mon-Fri writer's Friday->Saturday silence (p = 1 under their own
    calendar) contributes no surprise. Float DP over the exact
    distribution; monotone in k by construction (the SF sums the same
    computed dist). Matches binomial_sf on the constant-p case.
    """
    n = len(probs)
    if n == 0:
        return 1.0 if k <= 0 else 0.0
    for p in probs:
        if not 0.0 <= p <= 1.0:
            raise ValueError("every p must be in [0, 1]")
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    dist = [0.0] * (n + 1)
    dist[0] = 1.0
    for p in probs:
        q = 1.0 - p
        for j in range(n, 0, -1):
            dist[j] = dist[j] * q + dist[j - 1] * p
        dist[0] *= q
    return min(1.0, math.fsum(dist[k:]))


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
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log1p(-x)
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
    or |r| >= 1 with no residual df) are "no evidence". NOTE: the engine
    no longer tests this null for comparative claims ("more than usual"
    is a DIFFERENCE of correlations — see fisher_z_difference_p); this
    remains the right primitive for a standalone r ≠ 0 question.
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


def sample_sd(values: list[float]) -> float:
    """Sample standard deviation (n-1); 0.0 when unmeasurable (n < 2)."""
    if len(values) < 2:
        return 0.0
    return math.sqrt(_variance(values))


def effective_sample_size(n: int, lag1: float | None) -> float:
    """Effective independent-observation count under lag-1 autocorrelation.

    Bartlett-style deflation n_eff = n * (1 - r) / (1 + r): an AR(1) series
    with r = 0.5 carries the information of about n/3 independent points.
    Day-level mood residuals are exactly such a series (that is what the
    inertia detector measures), so tests over them must not count the raw
    n. Clamped to [3, n]: the floor keeps Welch's degrees of freedom
    defined, the cap means a zero/negative/unknown autocorrelation never
    INFLATES the effective sample beyond the observed one.
    """
    if n <= 0:
        return 0.0
    if lag1 is None or lag1 <= 0.0:
        return float(n)
    r = min(lag1, 0.9)  # cap: r -> 1 would nuke n_eff to the floor anyway
    return max(3.0, min(float(n), n * (1.0 - r) / (1.0 + r)))


def brown_forsythe_two_sided_p(
    xs: list[float], ys: list[float], n_eff_x: float | None = None, n_eff_y: float | None = None
) -> float:
    """Two-sided Brown-Forsythe (median-centered Levene) p for H0: equal spread.

    The instability detector replaced its variance-ratio F-test with this
    (2026-09-17): the F-test assumes iid normal observations and is
    notoriously kurtosis-sensitive — the input is bounded, platykurtic
    residual sentiment, often literally discrete 5-point mood tags.
    Brown-Forsythe tests spread via an ANOVA of median-absolute deviations,
    which is robust to exactly that. ``n_eff_x``/``n_eff_y`` are the
    Bartlett-deflated effective sample sizes (the residual series carries
    the day-to-day mood autocorrelation the inertia detector measures);
    they shrink df2 so autocorrelated evidence cannot buy significance —
    the same honesty Welch already applies. Degenerate inputs (a side
    shorter than 2, or zero within-group deviation spread) fail closed to
    p = 1: "no evidence", never a crash or a fake claim.
    """
    if len(xs) < 2 or len(ys) < 2:
        return 1.0

    def abs_devs(vals: list[float]) -> list[float]:
        ordered = sorted(vals)
        n = len(ordered)
        mid = n // 2
        med = ordered[mid] if n % 2 == 1 else (ordered[mid - 1] + ordered[mid]) / 2.0
        return [abs(v - med) for v in vals]

    dx, dy = abs_devs(xs), abs_devs(ys)
    nx, ny = float(len(xs)), float(len(ys))
    mean_dx, mean_dy = _mean(dx), _mean(dy)
    grand = (nx * mean_dx + ny * mean_dy) / (nx + ny)
    within = sum((v - mean_dx) ** 2 for v in dx) + sum((v - mean_dy) ** 2 for v in dy)
    if within <= 0.0:
        return 1.0
    between = nx * (mean_dx - grand) ** 2 + ny * (mean_dy - grand) ** 2
    bf = between / (within / (nx + ny - 2.0))
    if bf <= 0.0:
        return 1.0
    eff_x = n_eff_x if n_eff_x is not None else nx
    eff_y = n_eff_y if n_eff_y is not None else ny
    df2 = max(2, int(min(eff_x, nx) + min(eff_y, ny) - 2))
    upper = f_sf(bf, 1, df2)
    return min(1.0, 2.0 * min(upper, 1.0 - upper))


def fisher_z_difference_p(
    r_recent: float, n_recent: int, r_earlier: float, n_earlier: int
) -> float:
    """One-sided p for H0: rho_recent <= rho_earlier, Fisher z transform.

    The inertia claim is comparative — "mood is carrying over MORE than
    usual for you" — so its p-value must test the difference of two
    correlations, not the (much easier) null r = 0. One-sided because the
    effect gates already commit the direction before the test runs;
    degenerate inputs (tiny windows) fail closed to "no evidence".
    """
    if n_recent < 4 or n_earlier < 4:
        return 1.0
    z_recent = math.atanh(max(-0.9999, min(0.9999, r_recent)))
    z_earlier = math.atanh(max(-0.9999, min(0.9999, r_earlier)))
    se = math.sqrt(1.0 / (n_recent - 3) + 1.0 / (n_earlier - 3))
    if se <= 0.0:
        return 1.0
    z = (z_recent - z_earlier) / se
    return min(1.0, 0.5 * math.erfc(z / math.sqrt(2.0)))  # upper tail only


def welch_test(
    a: list[float], b: list[float], variance_floor: float = 0.0, lag1: float | None = None
) -> tuple[float, float]:
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

    ``lag1``: when the observations come from an autocorrelated series
    (day-overlapping mood residuals), the raw n overstates the evidence;
    pass the series' lag-1 autocorrelation and each side's n is deflated
    to its effective size (see effective_sample_size) before the standard
    error and degrees of freedom are computed.
    """
    n1, n2 = float(len(a)), float(len(b))
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0
    m1, m2 = _mean(a), _mean(b)
    v1_actual, v2_actual = _variance(a), _variance(b)
    # Float-safe "constant group" test (a mean of 12 x -0.6 is off by ~1e-16).
    if v1_actual < 1e-12 and v2_actual < 1e-12:
        return 0.0, 1.0
    v1 = max(v1_actual, variance_floor**2)
    v2 = max(v2_actual, variance_floor**2)
    if lag1 is not None:
        n1 = effective_sample_size(len(a), lag1)
        n2 = effective_sample_size(len(b), lag1)
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
