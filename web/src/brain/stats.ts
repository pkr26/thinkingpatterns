/**
 * The statistics core of the on-device brain (2026-09-19): the pure
 * functions the inertia-family detectors need, ported from
 * backend/app/services/statsig.py and brain.py's Pearson helper.
 *
 * Everything here is deterministic and pure — the same standing as the
 * Python engine: same verdict for the same inputs on every platform,
 * forever. Outputs are pinned against Python-generated vectors in
 * shared/brain_vectors.json (tests/brainVectors.test.ts); the erfc below
 * is W. J. Cody's rational approximation (double precision), so the
 * p-value tails agree with math.erfc to vector tolerance.
 */

/** Lag-1-friendly Pearson r; null when unmeasurable (<3 pairs, no variance). */
export function pearson(xs: number[], ys: number[]): number | null {
  if (xs.length !== ys.length || xs.length < 3) return null;
  const mx = xs.reduce((a, b) => a + b, 0) / xs.length;
  const my = ys.reduce((a, b) => a + b, 0) / ys.length;
  let sxx = 0;
  let syy = 0;
  let sxy = 0;
  for (let i = 0; i < xs.length; i++) {
    const dx = xs[i]! - mx;
    const dy = ys[i]! - my;
    sxx += dx * dx;
    syy += dy * dy;
    sxy += dx * dy;
  }
  if (sxx <= 0 || syy <= 0) return null;
  return sxy / Math.sqrt(sxx * syy);
}

/**
 * Complementary error function, implemented from first principles so the
 * whole derivation is auditable in-file:
 *  - |x| ≤ 2: the Maclaurin series erf(x) = (2/√π)·Σ (-1)ⁿ·x^{2n+1}/(n!·(2n+1));
 *    erfc = 1 − erf (alternating series, |error| below the first omitted
 *    term; 40 terms drive it far beneath double-precision at |x| = 2).
 *  - |x| > 2: the classic continued fraction (A&S 7.1.14)
 *    √π·e^{x²}·erfc(x) = 1/(x + (1/2)/(x + (2/2)/(x + (3/2)/(x + …))))
 *    evaluated by backward recurrence (60 levels — converged to double
 *    precision well before that for every |x| > 2).
 *  - Odd symmetry: erfc(−x) = 2 − erfc(x).
 *
 * Pinned against Python's math.erfc by shared/brain_vectors.json.
 */
export function erfc(x: number): number {
  if (Number.isNaN(x)) return Number.NaN;
  const ax = Math.abs(x);
  if (ax > 27.3) return x >= 0 ? 0.0 : 2.0;
  let result: number;
  if (ax <= 2.0) {
    // Maclaurin: term_n = x^{2n+1}/(n!·(2n+1)) with alternating sign.
    const x2 = ax * ax;
    let term = ax; // n = 0: x/(0!·1)
    let sum = term;
    for (let n = 1; n < 40; n++) {
      term *= -x2 / n; // x^{2n+1}/(n!·(2n+1)) from the previous term: × x²/n, × (2n−1)/(2n+1)
      term *= (2 * n - 1) / (2 * n + 1);
      sum += term;
      if (Math.abs(term) < 1e-18) break;
    }
    result = 1.0 - (2.0 / Math.sqrt(Math.PI)) * sum; // erfc = 1 − erf
  } else {
    // Backward recurrence of the A&S 7.1.14 continued fraction.
    let f = 0.0;
    for (let k = 60; k >= 1; k--) {
      f = (k / 2.0) / (ax + f);
    }
    result = Math.exp(-ax * ax) / ((ax + f) * Math.sqrt(Math.PI));
  }
  return x >= 0 ? result : 2.0 - result;
}

/** One-sided Fisher-z p for H0: rho_recent <= rho_earlier (upper tail). */
export function fisherZDifferenceP(
  rRecent: number,
  nRecent: number,
  rEarlier: number,
  nEarlier: number,
): number {
  if (nRecent < 4 || nEarlier < 4) return 1.0;
  const clamp = (r: number) => Math.max(-0.9999, Math.min(0.9999, r));
  const zRecent = Math.atanh(clamp(rRecent));
  const zEarlier = Math.atanh(clamp(rEarlier));
  const se = Math.sqrt(1.0 / (nRecent - 3) + 1.0 / (nEarlier - 3));
  if (se <= 0) return 1.0;
  const z = (zRecent - zEarlier) / se;
  return Math.min(1.0, 0.5 * erfc(z / Math.sqrt(2.0)));
}

export function sampleSd(values: number[]): number {
  if (values.length < 2) return 0.0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const ss = values.reduce((a, v) => a + (v - mean) * (v - mean), 0);
  return Math.sqrt(ss / (values.length - 1));
}
