#!/usr/bin/env python3
"""Behavioral mutation gate with a read-only applicability preflight.

  python redteam/run_pr_mutation_gate.py --preflight
  python redteam/run_pr_mutation_gate.py --preflight --json
  git diff --name-only origin/main... | python redteam/run_pr_mutation_gate.py -
  python redteam/run_pr_mutation_gate.py --all

Execution mutates and restores target files; run it only in an isolated checkout.
Every selected oracle must pass on unmodified source before mutants run. Stale
anchors, broken oracles, unknown statuses and surviving mutants fail the gate.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Support import-by-path tests as well as executing the script directly.
if str(ROOT / "redteam") not in sys.path:
    sys.path.insert(0, str(ROOT / "redteam"))
sys.dont_write_bytecode = True
from mutation_preflight import inventory
from mutation_oracles import redteam_baseline_error

HARNESS_GLOBS = (
    "mutation_campaign_2026-09-18/harness.py",
    "mutation_campaign_2026-09-18_round2/harness.py",
    "mutation_campaign_2026-09-19/harness.py",
    "mutation_campaign_2026-09-22/harness.py",
)

BACKEND_PYTEST_CONFIG = {
    "backend/conftest.py",
    "backend/pyproject.toml",
    "backend/pytest.ini",
    "backend/setup.cfg",
    "backend/tox.ini",
}


def load_harnesses() -> tuple[list[dict], object]:
    mutants, runner = [], None
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        for rel in HARNESS_GLOBS:
            path = ROOT / "redteam" / rel
            if not path.is_file():
                raise ValueError(f"required campaign is missing: {rel}")
            spec = importlib.util.spec_from_file_location(rel.replace("/", "_"), path)
            loaded = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(loaded)
            mutants.extend(loaded.MUTANTS)
            if rel.startswith("mutation_campaign_2026-09-18_round2"):
                runner = loaded
    finally:
        sys.dont_write_bytecode = previous
    if runner is None:
        raise ValueError("required mutation runner is missing")
    return mutants, runner


def changed_files(arg: str) -> set[str]:
    raw = (
        sys.stdin.read()
        if arg == "-"
        else subprocess.run(
            ["git", "diff", "--name-only", arg],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    return {line.strip() for line in raw.splitlines() if line.strip()}


def affected(mutant: dict, changed: set[str]) -> bool:
    # Changes to the gate or campaign catalog can affect every control.
    if any(
        path.startswith("redteam/mutation_campaign_")
        or path
        in {
            "redteam/run_pr_mutation_gate.py",
            "redteam/mutation_preflight.py",
            "redteam/mutation_oracles.py",
            ".github/workflows/mutation-pr.yml",
            ".nvmrc",
        }
        for path in changed
    ):
        return True
    if mutant["file"] in changed:
        return True
    specs = mutant["tests"] if isinstance(mutant["tests"], list) else [mutant["tests"]]
    for spec in specs:
        if spec["kind"] in {"pytest", "probe", "redteam"} and any(
            path == "backend/uv.lock"
            or path.startswith("backend/requirements") and path.endswith((".in", ".txt"))
            for path in changed
        ):
            return True
        if spec["kind"] == "redteam" and "redteam/common.py" in changed:
            return True
        if spec["kind"] == "vitest":
            # Aliases, setup files and imported test helpers define the real
            # oracle too. They are absent from Vitest's command-line selectors.
            # Include all client test/support and runner/dependency changes;
            # indirect imports cannot safely be inferred from filenames.
            client = pathlib.PurePosixPath(spec["cwd"])
            for path in map(pathlib.PurePosixPath, changed):
                if not path.is_relative_to(client):
                    continue
                relative = path.relative_to(client)
                if relative.parts and (
                    relative.parts[0] in {"tests", "redteam", "tools"}
                    or len(relative.parts) == 1 and (
                        relative.name in {"package.json", "package-lock.json", ".npmrc"}
                        or relative.name.startswith(("vite.config.", "vitest.config.", "tsconfig"))
                        or ".vitest.config." in relative.name
                    )
                ):
                    return True
        # Pytest loads conftest implicitly, and suites import shared emulator
        # helpers without naming them on the command line. Conservatively
        # rerun backend pytest controls for changes to test-support modules;
        # an import graph would otherwise miss indirect fixture dependencies.
        if spec["kind"] == "pytest" and spec["cwd"] == "backend" and (
            changed.intersection(BACKEND_PYTEST_CONFIG)
            or any(
                path.startswith("backend/tests/")
                and pathlib.PurePosixPath(path).suffix == ".py"
                and not pathlib.PurePosixPath(path).name.startswith("test_")
                for path in changed
            )
        ):
            return True
        for argument in spec["cmd"]:
            filename = argument.split("::", 1)[0]
            if str(pathlib.Path(spec["cwd"]) / filename) in changed:
                return True
    return False


def baseline_errors(mutants: list[dict], harness: object) -> list[str]:
    """No mutation receives credit for a failure already present in its oracle."""
    unique = {}
    for mutant in mutants:
        specs = mutant["tests"] if isinstance(mutant["tests"], list) else [mutant["tests"]]
        for spec in specs:
            unique.setdefault((spec["cwd"], tuple(spec["cmd"]), spec["kind"]), []).append(spec)
    errors = []
    for index, specs in enumerate(unique.values(), 1):
        spec = specs[0]
        print(
            f"[baseline {index}/{len(unique)}] {spec['cwd']}: {' '.join(spec['cmd'])}", flush=True
        )
        failed, setup, _, output, _ = harness.run_command(spec, "baseline")
        if spec["kind"] == "redteam":
            # Each mutation names its own negative control. Unrelated
            # architectural findings elsewhere in the campaign are not
            # that control's baseline; errors still invalidate the runner.
            for oracle in specs:
                if redteam_baseline_error(oracle, output):
                    failed = True
        if failed or setup:
            errors.append(setup or f"baseline failed: {' '.join(spec['cmd'])}")
    return errors


def verdict_passes(result: dict) -> bool:
    # No residual allowlist: history is evidence, never an exemption.
    return result.get("status") in {"KILLED", "CAUGHT"} and result.get("killed") is True


def prepare_direct_campaign(selected: list[dict]) -> object:
    """Legacy campaign launchers use the same gate before any source write."""
    mutants, harness = load_harnesses()
    stale = [row for row in inventory(ROOT, mutants) if row["status"] != "APPLICABLE"]
    if stale:
        raise SystemExit(f"MUTATION PREFLIGHT FAILED: {stale}")
    if not selected:
        raise SystemExit("No controls selected; no mutation audit was performed")
    errors = baseline_errors(selected, harness)
    if errors:
        raise SystemExit(f"MUTATION BASELINE FAILED: {errors}; no mutants executed")
    return harness


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diff", nargs="?")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument(
        "--json", action="store_true", help="print the complete applicability inventory"
    )
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    if not args.preflight and not args.all and args.diff is None:
        parser.error("provide a diff, --all, or --preflight")
    try:
        mutants, harness = load_harnesses()
        rows = inventory(ROOT, mutants)
    except (ValueError, OSError) as error:
        print(f"MUTATION PREFLIGHT FAILED: {error}", file=sys.stderr)
        return 1
    stale = [row for row in rows if row["status"] != "APPLICABLE"]
    if args.json:
        print(
            json.dumps(
                {
                    "total": len(rows),
                    "applicable": len(rows) - len(stale),
                    "errors": len(stale),
                    "mutants": rows,
                },
                indent=2,
            )
        )
    else:
        print(f"Mutation preflight: {len(rows) - len(stale)}/{len(rows)} applicable")
        for row in stale:
            print(f"[{row['id']}] SETUP-ERROR: {row['detail']}")
    if stale:
        return 1
    if args.preflight:
        return 0
    changed = set() if args.all else changed_files(args.diff)
    selected = mutants if args.all else [mutant for mutant in mutants if affected(mutant, changed)]
    if not selected:
        print("No behavioral controls affected; applicability preflight passed.")
        return 0
    errors = baseline_errors(selected, harness)
    if errors:
        print("MUTATION GATE FAILED: unmodified oracle failures; no mutants executed")
        for error in errors:
            print(f"  {error}")
        return 1
    results = []
    for mutant in selected:
        print(f"[{mutant['id']}] {mutant['name']} ...", flush=True)
        result = harness.run_mutant(mutant)
        results.append(result)
        print(f"    -> {result['status']} ({result.get('detail', '')})", flush=True)
    counts = Counter(result["status"] for result in results)
    failures = [result for result in results if not verdict_passes(result)]
    print(
        "Mutation results: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    )
    print(
        f"PR MUTATION GATE {'FAILED' if failures else 'PASSED'}: {sum(verdict_passes(r) for r in results)}/{len(results)} genuinely killed/caught"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
