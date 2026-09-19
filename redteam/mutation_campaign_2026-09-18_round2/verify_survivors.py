#!/usr/bin/env python3
"""Re-verify round-2 survivors against the FULL fast suite (round-1 protocol).

A mutant that survived its targeted suite may still be killed elsewhere in
the suite; only a survivor of the FULL suite is genuine and needs a pin.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

SURVIVORS = [
    "G2", "G4", "G5", "G14", "G15",          # brain round 2
    "I4",                                     # pairing expiry burn
    "J1", "J2",                               # crisis deeper
    "K1", "K4", "K5",                         # ops fail-closed
    "L2", "L4",                               # idiographic
]


def main() -> None:
    spec = importlib.util.spec_from_file_location("h", HERE / "harness.py")
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    full = {
        "cwd": "backend",
        # The repo-root venv is the canonical interpreter (README); the
        # backend/.venv copy is not kept suite-healthy.
        "cmd": [str(ROOT / ".venv" / "bin" / "python"), "-m", "pytest", "-q",
                "--no-header", "-p", "no:cacheprovider", "-m", "not slow"],
        "timeout": 1200,
        "kind": "pytest",
    }
    mobile_full = {
        "cwd": "mobile",
        "cmd": ["npx", "vitest", "run", "--no-coverage"],
        "timeout": 600,
        "kind": "vitest",
    }
    results = []
    todo = [m for m in h.MUTANTS if m["id"] in SURVIVORS]
    print(f"{len(todo)} survivors queued against the full suite\n", flush=True)
    for m in todo:
        spec_tests = mobile_full if m["file"].startswith("mobile/") else full
        print(f"[{m['id']}] {m['name']} ...", flush=True)
        t0 = time.monotonic()
        r = h.run_mutant({**m, "tests": spec_tests})
        elapsed = round(time.monotonic() - t0, 1)
        results.append({**r, "seconds": elapsed})
        print(f"    -> {r['status']} ({elapsed}s)"
              + (f"  first: {r['commands'][0]['failures'][0]}"
                 if r.get("commands") and r["commands"][0]["failures"] else ""), flush=True)
    genuine = [r for r in results if r["killed"] is False]
    print(f"\n{len(results) - len(genuine)}/{len(results)} killed by the full suite; "
          f"{len(genuine)} GENUINE survivors need pins", flush=True)
    for r in genuine:
        print(f"  {r['id']}: {r['name']}")
    out = HERE / "results" / "survivor_full_suite_verification.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"results: {out}")


if __name__ == "__main__":
    sys.exit(main())
