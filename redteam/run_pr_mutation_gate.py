#!/usr/bin/env python3
"""Per-PR incremental mutation gate (driver).

The scheduled deep campaigns (mutmut weekly, Stryker per platform, the
hand-written behavioral campaigns) are far too slow to re-run whole on
every pull request. This gate re-runs exactly the BEHAVIORAL mutants whose
target file appears in the PR diff — the 36/36 + round-2 standards cannot
silently regress on the files a PR actually touches.

A mutant whose find-string no longer matches its file (SETUP-ERROR) also
fails the gate: a pin that rotted is a pin that stopped guarding.

Usage (from the repo root, against a merge-base ref):
  python3 redteam/run_pr_mutation_gate.py origin/main...HEAD   # or a file list on stdin
  git diff --name-only origin/main... | python3 redteam/run_pr_mutation_gate.py -
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

HARNESS_GLOBS = (
    "mutation_campaign_2026-09-18/harness.py",
    "mutation_campaign_2026-09-18_round2/harness.py",
)


def load_harnesses() -> tuple[list[dict], object]:
    """All behavioral campaign mutants + one harness module (their
    run_mutant implementations are identical; one serves both)."""
    mutants: list[dict] = []
    module = None
    for rel in HARNESS_GLOBS:
        path = ROOT / "redteam" / rel
        if not path.exists():
            continue
        spec = importlib.util.spec_from_file_location(rel.replace("/", "_"), path)
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)  # type: ignore[union-attr]
        mutants.extend(loaded.MUTANTS)
        module = module or loaded
    return mutants, module


def changed_files(arg: str) -> set[str]:
    if arg == "-":
        raw = sys.stdin.read()
        return {line.strip() for line in raw.splitlines() if line.strip()}
    diff = subprocess.run(
        ["git", "diff", "--name-only", arg], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return {line.strip() for line in diff.splitlines() if line.strip()}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    diff = changed_files(sys.argv[1])
    if not diff:
        print("no changed files — nothing to gate")
        return 0
    mutants, harness = load_harnesses()
    mutants = [m for m in mutants if m["file"] in diff]
    if not mutants:
        print(f"{len(diff)} changed file(s); none carry behavioral mutants — gate passes trivially")
        return 0

    print(f"{len(diff)} changed file(s); {len(mutants)} behavioral mutants re-run:\n")
    failures: list[str] = []
    for m in mutants:
        print(f"[{m['id']}] {m['name']} ...", flush=True)
        result = harness.run_mutant(m)  # type: ignore[attr-defined]
        status = result["status"]
        print(f"    -> {status}"
              + (f"  ({result.get('detail', '')})" if status == "SETUP-ERROR" else ""), flush=True)
        if status in ("SURVIVED", "MISSED", "SETUP-ERROR"):
            failures.append(f"{m['id']} {status}: {m['name']}")
    if failures:
        print("\nPR MUTATION GATE FAILED — surviving/rotted mutants:")
        for f in failures:
            print(f"  {f}")
        print(
            "\nEvery behavioral mutant targeting a changed file must be killed by the "
            "current suite. Fix the regression, or (if the behavior intentionally "
            "changed) update the campaign mutant AND its pinning test together."
        )
        return 1
    print(f"\nPR MUTATION GATE PASSED — {len(mutants)}/{len(mutants)} killed/caught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
