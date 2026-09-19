#!/usr/bin/env python3
"""Survivor verification: re-run every SURVIVED mutant against the FULL suite.

A mutant that survived its targeted subset may still be killed by the rest
of the suite; only a full-suite survivor is a genuine coverage gap.
"""

from __future__ import annotations

import json
import pathlib
import sys

import importlib.util

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("h", HERE / "harness.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

FULL = {
    "backend": h.backend_full(),
    "mobile": h.vitest("mobile"),
    "portal": h.vitest("portal"),
}

results_file = sorted((HERE / "results").glob("mutation_results_*.json"))[-1]
results = json.loads(results_file.read_text())
survivors = [r for r in results if r["status"] == "SURVIVED"]
print(f"{len(survivors)} survivors from {results_file.name}: "
      + ", ".join(r["id"] for r in survivors) + "\n")

by_id = {m["id"]: m for m in h.MUTANTS}
out = []
for r in survivors:
    m = by_id[r["id"]]
    suite = FULL[m["tests"]["cwd"]]
    mutant = dict(m, tests=suite)
    print(f"[{m['id']}] {m['name']} -> FULL {m['tests']['cwd']} suite ...", flush=True)
    verdict = h.run_mutant(mutant)
    out.append(verdict)
    print(f"    -> {verdict['status']} ({verdict.get('seconds', '?')}s)"
          + (f"  first fail: {verdict['failing_tests'][0]}"
             if verdict.get("failing_tests") else ""), flush=True)

path = HERE / "results" / "survivor_full_suite_verification.json"
path.write_text(json.dumps(out, indent=2))
print(f"\nverification results: {path}")
