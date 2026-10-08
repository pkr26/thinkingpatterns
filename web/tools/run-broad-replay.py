#!/usr/bin/env python3
"""Replay unresolved current-source operators against the full consumer suite.

The original complete-file reports remain the inventory evidence. This replay
adds cross-suite observations, in one immutable isolated copy, without changing
the normal dependency graph or introducing Stryker mutation exclusions.
"""
import argparse
import hashlib
import importlib.util
import json
import shutil
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("shards", Path(__file__).with_name("run-mutation-shards.py"))
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)

def key(file, mutant):
    start, end = mutant["location"]["start"], mutant["location"]["end"]
    fields = [file, start["line"], start["column"], end["line"], end["column"], mutant["mutatorName"], mutant["replacement"]]
    return hashlib.sha256(json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("reports", type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--coverage-analysis", choices=["perTest", "off"], default="perTest", help="Replay all selected consumer tests when coverage-selected activation needs an independent check")
    parser.add_argument("--runner-node-modules", type=Path)
    parser.add_argument("--review", type=Path, action="append", default=[])
    parser.add_argument("--exclude-source", action="append", default=[])
    parser.add_argument("--source", action="append")
    parser.add_argument("--runtime-only", action="store_true")
    parser.add_argument("--timeout-ms", type=int, default=6000)
    parser.add_argument("--test", action="append")
    args = parser.parse_args()
    reports = args.reports.resolve(); reports.mkdir(parents=True, exist_ok=True)
    payload = json.loads(args.input.read_text())
    reviewed = {row["key"] for path in args.review for row in json.loads(path.read_text())}
    excluded = set(args.exclude_source)
    selected, ranges, source_hashes = [], set(), {}
    for file, data in payload["files"].items():
        if file in excluded or args.source and file not in args.source:
            continue
        source = shards.ROOT / file
        if not source.exists() or source.read_text() != data["source"]:
            raise RuntimeError(f"{file}: input source is stale")
        for mutant in data["mutants"]:
            watchdog = mutant["status"] == "Killed" and any(fragment in mutant.get("statusReason", "").lower() for fragment in ["timed out", "beforeall", "afterall", "beforeeach", "aftereach"])
            if mutant["status"] == "Killed" and not watchdog and mutant.get("testsCompleted") != 0 or key(file, mutant) in reviewed or args.runtime_only and mutant.get("static"):
                continue
            start, end = mutant["location"]["start"], mutant["location"]["end"]
            ranges.add(f'{file}:{start["line"]}:{start["column"]-1}-{end["line"]}:{end["column"]-1}')
            selected.append({"file": file, "key": key(file, mutant), "input_id": mutant["id"], "status": mutant["status"]})
            source_hashes[file] = hashlib.sha256(data["source"].encode()).hexdigest()
    if not ranges:
        raise RuntimeError("No unresolved operators selected")
    scratch = Path(tempfile.mkdtemp(prefix="fathom-web-broad-replay-")); snapshot = scratch / "snapshot"
    manifest = shards.freeze(snapshot)
    for file, expected in source_hashes.items():
        if shards.digest(snapshot / "web" / file) != expected:
            raise RuntimeError(f"{file}: source changed before snapshot")
    shards.write_json(reports / "inputs.json", {"files": manifest, "snapshot_directory": str(snapshot), "launcher_sha256": shards.digest(Path(__file__))})
    modules = shards.bootstrap(snapshot, scratch, args.runner_node_modules, reports)
    witness = scratch / "witness"; shutil.copytree(snapshot, witness)
    (witness / "web/node_modules").symlink_to(modules, target_is_directory=True)
    shards.canary(witness / "web", reports, args.timeout_ms)
    lane = scratch / "campaign"; shutil.copytree(snapshot, lane); package = lane / "web"
    (package / "node_modules").symlink_to(modules, target_is_directory=True)
    tests = args.test or ["tests/**/*.test.ts", "tests/**/*.test.tsx"]
    wrapper = shards.wrapper(package, tests)
    # The shared wrapper gives Stryker's mutant budget priority over test watchdogs.
    baseline = reports / "baseline.json"
    code = shards.command([str(package / "node_modules/.bin/vitest"), "run", "--config", "vitest.shard.config.ts", "--coverage.enabled=false", "--maxWorkers=1", "--reporter=json", "--outputFile", str(baseline)], package, reports / "baseline.log")
    if code or not json.loads(baseline.read_text()).get("numPassedTests"):
        raise RuntimeError("Pristine full consumer baseline failed")
    report = reports / "combined.json"; report.unlink(missing_ok=True)
    config = shards.config_for(next(iter(source_hashes)), report, args.timeout_ms, args.workers)
    config["mutate"] = sorted(ranges)
    config["coverageAnalysis"] = args.coverage_analysis
    shards.write_json(package / "stryker.shard.json", config)
    shards.write_json(reports / "selected.json", {"input": str(args.input.resolve()), "input_sha256": shards.digest(args.input), "selected": selected, "ranges": sorted(ranges), "source_sha256": source_hashes})
    code = shards.command([str(package / "node_modules/.bin/stryker"), "run", "stryker.shard.json"], package, reports / "combined.log")
    if not report.exists():
        raise RuntimeError(f"Mutation runner returned {code} without a fresh report")
    for file, expected in source_hashes.items():
        if shards.digest(package / file) != expected:
            raise RuntimeError(f"{file}: source was not restored")
    shards.write_json(reports / "combined-metadata.json", {"source_sha256": source_hashes, "source_restored": True, "config": config, "selectors": tests,
        "snapshot": "inputs.json", "baseline": "baseline.json", "baseline_sha256": shards.digest(baseline), "runner": "runner-dependencies.json", "runner_witness": "runner-witness.json",
        "vitest_wrapper_sha256": shards.digest(wrapper), "report_sha256": shards.digest(report), "selected": "selected.json", "exit_code": code, "scratch_directory": str(package),
        "oracle_execution": shards.oracle_execution(json.loads(report.read_text()))})
    print(json.dumps({"report": str(report), "selected_operators": len(selected), "files": len(source_hashes)}), flush=True)

if __name__ == "__main__":
    main()
