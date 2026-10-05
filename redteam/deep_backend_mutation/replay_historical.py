#!/usr/bin/env python3
"""Replay all historical definitions using observed discriminating test cases.

Exploratory failures select existing pytest cases; they provide no kill credit.
Every selected case must pass and then kill its mutation on a new frozen snapshot.
Controls without a concrete pytest failure retain their complete original oracle.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import runner
from run_pr_mutation_gate import load_harnesses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exploratory-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("workers must be positive")
    historical, _ = load_harnesses()
    mutants = copy.deepcopy(historical)
    rows = [
        json.loads(line)
        for line in (args.exploratory_run / "results.jsonl").read_text().splitlines()
    ]
    observed = {row["id"]: row for row in rows}
    original = {
        mutant["id"]: mutant
        for mutant in json.loads((args.exploratory_run / "manifest.json").read_text())[
            "mutants"
        ]
    }
    if len(observed) != len(rows) or set(observed) != {m["id"] for m in mutants}:
        parser.error("exploratory evidence must cover each historical ID exactly once")
    if set(original) != set(observed):
        parser.error("exploratory manifest and result IDs must match")
    selections = []
    for mutant in mutants:
        specs = mutant["tests"]
        specs = specs if isinstance(specs, list) else [specs]
        row = observed[mutant["id"]]
        # A changed definition needs its current maintained oracle. An old
        # failure for another source replacement cannot select its test.
        observed_identity = row.get("mutation_sha256") or runner.mutation_identity(
            original[mutant["id"]]
        )
        if observed_identity != runner.mutation_identity(mutant):
            continue
        for index, command in enumerate(row.get("commands", [])):
            if (
                row["status"] != "KILLED"
                or command.get("setup_error")
                or command.get("timed_out")
                or command.get("returncode") != 1
                or not command.get("failures")
                or index >= len(specs)
                or specs[index]["kind"] != "pytest"
            ):
                continue
            case = command["failures"][0].removeprefix("FAILED ").split(" - ", 1)[0]
            if ".py::" not in case:
                continue
            selected = copy.deepcopy(specs[index])
            selected["cmd"] = [
                arg
                for arg in selected["cmd"]
                if not (".py" in arg and not arg.startswith("-"))
            ] + [case]
            mutant["tests"] = selected
            selections.append({"id": mutant["id"], "case": case})
            break
    preflight = runner.inventory(runner.ROOT, mutants)
    if any(row["status"] != "APPLICABLE" for row in preflight):
        print(json.dumps(preflight, indent=2))
        return 1
    groups = sorted({m["campaign"] for m in mutants})
    campaigns = [{"id": group, "name": f"Historical group {group}"} for group in groups]
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "oracle-selection.json").write_text(
        json.dumps(
            {
                "exploratory_run": str(args.exploratory_run),
                "selected_pytest_cases": selections,
                "kill_credit_reused": False,
            },
            indent=2,
        )
        + "\n"
    )
    return runner.run_program(campaigns, mutants, args.output, args.workers)


if __name__ == "__main__":
    raise SystemExit(main())
