#!/usr/bin/env python3
"""Re-verify round-3 survivors against the FULL fast suite (round-1 protocol).

A mutant that survived its targeted suite may still be killed elsewhere in
the suite; only a survivor of the FULL suite is genuine and needs a pin (or
a documented-residual entry).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main() -> None:
    spec = importlib.util.spec_from_file_location("h", HERE / "harness.py")
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)

    # Collect every SURVIVED mutant id from this campaign's result JSONs.
    survivor_ids: list[str] = []
    for path in sorted((HERE / "results").glob("mutation_results_*.json")):
        for record in json.loads(path.read_text()):
            if record.get("status") == "SURVIVED" and record["id"] not in survivor_ids:
                survivor_ids.append(record["id"])
    if len(sys.argv) > 1:  # explicit override for pin re-verification runs
        survivor_ids = [a for a in sys.argv[1:]]

    full = {
        "cwd": "backend",
        # -x: a kill anywhere in the suite decides the verdict; stopping at the
        # first failure only shortens the runs that are kills anyway.
        "cmd": [str(ROOT / ".venv" / "bin" / "python"), "-m", "pytest", "-q", "-x",
                "--no-header", "-p", "no:cacheprovider", "-m", "not slow"],
        "timeout": 1200,
        "kind": "pytest",
    }
    results = []
    todo = [m for m in h.MUTANTS if m["id"] in survivor_ids]
    print(f"{len(todo)} survivors queued against the full suite\n", flush=True)
    for m in todo:
        print(f"[{m['id']}] {m['name']} ...", flush=True)
        t0 = time.monotonic()
        r = h.run_mutant({**m, "tests": full})
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
