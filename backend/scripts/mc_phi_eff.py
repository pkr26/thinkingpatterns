"""Scratch MC harness (re-audit item 2): measure the realized P(p <= 0.05)
of the REAL _detect_mood_shift under AR(1) nulls across candidate phi_eff
constants (monkeypatched onto the real module — the harness always drives
the production code path).

Run: ../.venv/bin/python scripts/mc_phi_eff.py [scan|final] [reps]
"""

from __future__ import annotations

import math
import random
import sys
from datetime import date, timedelta

sys.path.insert(0, ".")
from app.services import brain  # noqa: E402

T0 = date(2026, 1, 1)
SEED = 20260927
CELLS = [(21, 0.5), (21, 0.8), (40, 0.5), (40, 0.8)]


def ar1(rng: random.Random, phi: float, n: int) -> list[float]:
    out = [rng.gauss(0, 1)]
    innov = math.sqrt(1 - phi * phi)
    for _ in range(n - 1):
        out.append(phi * out[-1] + innov * rng.gauss(0, 1))
    return out


def run_cell(n: int, phi: float, reps: int) -> tuple[float, float]:
    rng = random.Random(SEED + n * 1000 + int(phi * 100))
    alarms = 0
    small_p = 0
    for _ in range(reps):
        days = [T0 + timedelta(days=i) for i in range(n)]
        sig = brain._detect_mood_shift(list(zip(days, ar1(rng, phi, n))))
        if sig:
            alarms += 1
            small_p += sig[0].pvalue <= 0.05
    return alarms / reps, small_p / reps


def scan(reps: int) -> None:
    # K=1.0 included (independent audit 2026-09-27): it is the
    # contrast the 'K=2.0 is the measured frontier' claim rests on — the
    # phi=0.8 short-n nulls sit at 15-23% there vs 3-7% at K=2.0.
    for k in (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0):
        for cap in (0.99, 2.2):
            brain._MOOD_SHIFT_PHI_EFF_K = k
            brain._MOOD_SHIFT_PHI_EFF_MAX = cap
            rates = [run_cell(n, phi, reps)[1] for n, phi in CELLS]
            flag = "" if all(r <= 0.06 for r in rates) else "  <-- over"
            print(f"k={k:4.1f} cap={cap:4.2f} " + " ".join(f"{r:.3f}" for r in rates) + flag)
    brain._MOOD_SHIFT_PHI_EFF_K = 2.0
    brain._MOOD_SHIFT_PHI_EFF_MAX = 0.99


def final(reps: int) -> None:
    for n, phi in [
        (21, 0.0),
        (21, 0.5),
        (21, 0.8),
        (40, 0.0),
        (40, 0.5),
        (40, 0.8),
        (90, 0.0),
        (90, 0.5),
        (90, 0.8),
    ]:
        alarm, small_p = run_cell(n, phi, reps)
        print(f"n={n:3d} phi={phi:.1f} reps={reps} alarm={alarm:.3f} P(p<=.05)={small_p:.3f}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "final"
    reps = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    {"scan": scan, "final": final}[mode](reps)
