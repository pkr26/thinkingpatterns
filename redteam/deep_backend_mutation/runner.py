#!/usr/bin/env python3
"""Execute semantic mutants in frozen, isolated copies of the working tree.

Each oracle must pass on the same snapshot before any mutation receives credit.
Results include exact source/test provenance, command logs and restoration checks.
Collection errors, skipped-only runs and timeouts never count as behavioral kills.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from contextlib import contextmanager

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "redteam"))
from mutation_oracles import oracle_setup_error, redteam_baseline_error
from mutation_preflight import inventory

CATALOGS = ("analysis", "security", "api", "operations")
SHARED_RUNTIME_PATHS = (
    ".venv",
    "backend/.venv",
    "web/node_modules",
    "mobile/node_modules",
    "portal/node_modules",
    ".tools/node",
)


def load_campaigns(selected=CATALOGS):
    campaigns = []
    for name in selected:
        path = ROOT / "redteam" / "deep_backend_mutation" / f"{name}_catalog.py"
        spec = importlib.util.spec_from_file_location(f"deep_{name}_catalog", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        campaigns.extend(module.CAMPAIGNS)
    identifiers = [campaign["id"] for campaign in campaigns]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("duplicate campaign IDs")
    mutants = []
    for campaign in campaigns:
        if not campaign["mutants"]:
            raise ValueError(f"empty campaign: {campaign['id']}")
        for mutant in campaign["mutants"]:
            mutants.append({**mutant, "campaign": campaign["id"]})
    return campaigns, mutants


def snapshot_files(root=ROOT):
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    files = {}
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = os.fsdecode(raw)
        path = root / relative
        if path.is_file():
            files[relative] = path.read_bytes()
    return files


def fingerprint(files):
    digest = hashlib.sha256()
    for name, content in sorted(files.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def make_copy(destination, files):
    destination.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        original = ROOT / relative
        if original.exists():
            path.chmod(original.stat().st_mode & 0o777)
    # A local repository boundary prevents git-based oracles from resolving
    # through the scratch directory into the user's real checkout.
    subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
    subprocess.run(
        ["git", "add", "."], cwd=destination, check=True, capture_output=True
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Mutation Snapshot",
            "-c",
            "user.email=mutation@localhost",
            "commit",
            "--quiet",
            "-m",
            "Frozen mutation snapshot",
        ],
        cwd=destination,
        check=True,
        capture_output=True,
    )
    for relative in SHARED_RUNTIME_PATHS:
        source = ROOT / relative
        link = destination / relative
        if source.exists() and not link.exists():
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(source, target_is_directory=True)


def restore_snapshot(root, files):
    """Remove oracle artifacts and restore every frozen file in a worker.

    Source, tests and auxiliary fixtures are immutable between controls.
    The private Git boundary and linked dependency installations are retained;
    no traversal enters them. Dependencies are shared, not a hermetic snapshot.
    """
    protected = {
        pathlib.PurePosixPath(name) for name in (".git", *SHARED_RUNTIME_PATHS)
    }

    def is_protected(path):
        relative = pathlib.PurePosixPath(path.relative_to(root).as_posix())
        return any(
            relative == prefix or prefix in relative.parents for prefix in protected
        )

    directories = []
    for directory, children, names in os.walk(root, followlinks=False):
        parent = pathlib.Path(directory)
        retained = []
        for name in children:
            path = parent / name
            if is_protected(path):
                continue
            if path.is_symlink():
                path.unlink()
            else:
                retained.append(name)
        children[:] = retained
        directories.append(parent)
        for name in names:
            path = parent / name
            if (
                not is_protected(path)
                and path.relative_to(root).as_posix() not in files
            ):
                path.unlink()
    for directory in reversed(directories):
        if directory != root:
            try:
                directory.rmdir()
            except OSError:
                pass  # A nonempty directory contains snapshot files.
    for relative, content in files.items():
        path = root / relative
        # An oracle-created symlink must never redirect restoration outside
        # the private worker. Known source parents must be real directories.
        for parent in reversed(path.parents):
            if parent == root or root not in parent.parents:
                continue
            if parent.is_symlink():
                parent.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        if not path.is_file() or path.read_bytes() != content:
            path.write_bytes(content)
    return all((root / name).read_bytes() == content for name, content in files.items())


def command_key(spec):
    return json.dumps(spec, sort_keys=True)


def mutation_identity(mutant):
    definition = {
        name: mutant.get(name, 1 if name == "count" else None)
        for name in ("file", "find", "replace", "count")
    }
    return hashlib.sha256(json.dumps(definition, sort_keys=True).encode()).hexdigest()


@contextmanager
def command_resource_lock(env):
    """Serialize schema-mutating probes against the same PostgreSQL database.

    A file lock covers both workers and independently launched runner processes.
    Only an opaque URL digest appears in the path; the URL is never printed.
    """
    database = env.get("DEEP_MUTATION_POSTGRES_URL")
    if not database:
        yield
        return
    directory = ROOT / ".tools/deep-mutation/resource-locks"
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(database.encode()).hexdigest()
    with (directory / f"postgres-{digest}.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def run_command(root, spec, log):
    env = dict(
        os.environ,
        CI="true",
        PYTHONDONTWRITEBYTECODE="1",
        MINDPATTERN_ENV="development",
    )
    env.pop("MINDPATTERN_TEST_DB_URL", None)
    env.pop("MINDPATTERN_DB_URL", None)
    env["PATH"] = str(ROOT / ".tools/node/bin") + os.pathsep + env.get("PATH", "")
    env["MINDPATTERN_LOCK_DIR"] = str(root / ".runtime-locks")
    env.update(spec.get("env", {}))
    command = list(spec["cmd"])
    # Historical red-team catalogs contain absolute interpreter paths.
    if command[0].endswith("/python") and ".venv" in command[0]:
        command[0] = str(ROOT / "backend/.venv/bin/python")
    started = time.monotonic()
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        with command_resource_lock(env), log.open("w") as stream:
            process = subprocess.Popen(
                command,
                cwd=root / spec["cwd"],
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=spec["timeout"])
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
            # A completed leader can leave children writing source or logs.
            # Drain its group on every exit, including timeout races where the
            # leader finished just before SIGKILL. Detached sessions remain
            # outside the process-group contract.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if timed_out:
                process.wait()
                returncode = process.returncode
        raw_output = log.read_bytes()
        output = raw_output.decode(errors="replace")
        error = (
            "oracle timed out"
            if timed_out
            else oracle_setup_error(spec["kind"], returncode, output)
        )
        return {
            "cmd": command,
            "cwd": spec["cwd"],
            "returncode": returncode,
            "seconds": round(time.monotonic() - started, 3),
            "setup_error": error,
            "timed_out": timed_out,
            "log": str(log),
            "failures": [
                line for line in output.splitlines() if line.startswith("FAILED ")
            ],
            "output_sha256": hashlib.sha256(raw_output).hexdigest(),
        }, output
    except OSError as error:
        return {
            "cmd": command,
            "cwd": spec["cwd"],
            "returncode": None,
            "setup_error": str(error),
            "timed_out": False,
            "log": str(log),
        }, ""


def specs_for(mutant):
    return mutant["tests"] if isinstance(mutant["tests"], list) else [mutant["tests"]]


def run_program(campaigns, mutants, output, workers=3):
    identifiers = [mutant["id"] for mutant in mutants]
    if not identifiers or len(identifiers) != len(set(identifiers)):
        raise ValueError("mutation execution requires nonempty unique control IDs")
    files = snapshot_files()
    output.mkdir(parents=True, exist_ok=True)
    provenance = fingerprint(files)
    manifest = {
        "schema": 1,
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "snapshot_sha256": provenance,
        "python": sys.version,
        "campaigns": [
            {
                "id": c["id"],
                "name": c["name"],
                "mutants": sum(m["campaign"] == c["id"] for m in mutants),
            }
            for c in campaigns
        ],
        "files": {
            name: hashlib.sha256(content).hexdigest() for name, content in files.items()
        },
        "mutants": mutants,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    selected_specs = {}
    for mutant in mutants:
        for spec in specs_for(mutant):
            selected_specs.setdefault(command_key(spec), spec)
    baselines = {}
    results = []
    result_lock = threading.Lock()
    worker_state = threading.local()
    worker_count = 0
    work_parent = output / "copies"

    def worker_copy():
        nonlocal worker_count
        if not hasattr(worker_state, "root"):
            with result_lock:
                worker_count += 1
                index = worker_count
            worker_state.root = work_parent / f"worker-{index}"
            make_copy(worker_state.root, files)
        return worker_state.root

    def baseline(item):
        key, spec = item
        root = worker_copy()
        if not restore_snapshot(root, files):
            raise RuntimeError("baseline snapshot restoration failed")
        name = hashlib.sha256(key.encode()).hexdigest()[:16]
        row, text = run_command(root, spec, output / "logs" / f"baseline-{name}.log")
        row["restored"] = restore_snapshot(root, files)
        row["passed"] = row["setup_error"] is None and row["returncode"] == 0
        if spec["kind"] == "redteam":
            row["passed"] = (
                row["setup_error"] is None
                and redteam_baseline_error(spec, text) is None
            )
        row["passed"] = row["passed"] and row["restored"]
        return key, row

    def mutate(mutant):
        root = worker_copy()
        if not restore_snapshot(root, files):
            raise RuntimeError("mutation snapshot restoration failed")
        target = root / mutant["file"]
        original = files[mutant["file"]]
        source = original.decode("utf-8")
        count = mutant.get("count", 1)
        if source.count(mutant["find"]) != count:
            return {
                "id": mutant["id"],
                "campaign": mutant["campaign"],
                "status": "SETUP-ERROR",
                "detail": "snapshot anchor changed",
            }
        row = {
            "id": mutant["id"],
            "campaign": mutant["campaign"],
            "name": mutant["name"],
            "file": mutant["file"],
            "status": "SURVIVED",
            "mutation_sha256": mutation_identity(mutant),
            "commands": [],
        }
        target.write_text(source.replace(mutant["find"], mutant["replace"], count))
        try:
            for index, spec in enumerate(specs_for(mutant)):
                command, text = run_command(
                    root, spec, output / "logs" / f"{mutant['id']}-{index}.log"
                )
                command["baseline_key"] = command_key(spec)
                row["commands"].append(command)
                if command["setup_error"]:
                    row["status"] = "TIMEOUT" if command["timed_out"] else "SETUP-ERROR"
                    break
                if spec["kind"] == "redteam":
                    wanted = spec.get("oracle", [])
                    caught = any(
                        line.startswith("AUDIT|")
                        and "|FINDING|" in line
                        and any(w in line for w in wanted)
                        for line in text.splitlines()
                    )
                    if caught:
                        row["status"] = "CAUGHT"
                        break
                elif command["returncode"] == 1:
                    row["status"] = "KILLED"
                    break
        finally:
            row["restored"] = restore_snapshot(root, files)
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(baseline, item) for item in selected_specs.items()]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            key, row = future.result()
            baselines[key] = row
            print(
                f"baseline {index}/{len(futures)} {'PASS' if row['passed'] else 'FAIL'} {row['log']}",
                flush=True,
            )
        (output / "baselines.json").write_text(json.dumps(baselines, indent=2) + "\n")
        if any(not row["passed"] for row in baselines.values()):
            print("Unmodified baselines failed; no mutants executed.", flush=True)
            return 1
        futures = [pool.submit(mutate, mutant) for mutant in mutants]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            row = future.result()
            results.append(row)
            with (output / "results.jsonl").open("a") as stream:
                stream.write(json.dumps(row) + "\n")
            print(
                f"mutant {index}/{len(futures)} {row['id']} {row['status']}", flush=True
            )
    counts = dict(Counter(row["status"] for row in results))
    per_campaign = {
        campaign["id"]: dict(
            Counter(
                row["status"] for row in results if row["campaign"] == campaign["id"]
            )
        )
        for campaign in campaigns
    }
    summary = {
        "snapshot_sha256": provenance,
        "campaigns": len(campaigns),
        "mutants": len(mutants),
        "completed": len(results),
        "counts": counts,
        "per_campaign": per_campaign,
        "passed": len(results) == len(mutants)
        and all(
            row["status"] in {"KILLED", "CAUGHT"} and row.get("restored")
            for row in results
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if summary["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog", nargs="+", choices=CATALOGS, default=list(CATALOGS)
    )
    parser.add_argument("--campaign", nargs="+")
    parser.add_argument("--mutant", nargs="+")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument(
        "--historical",
        action="store_true",
        help="replay all 220 maintained historical controls instead of new catalogs",
    )
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("workers must be positive")
    if args.historical:
        from run_pr_mutation_gate import load_harnesses

        mutants, _ = load_harnesses()
        groups = sorted({m["campaign"] for m in mutants})
        campaigns = [
            {
                "id": group,
                "name": f"Historical group {group}",
                "mutants": [m for m in mutants if m["campaign"] == group],
            }
            for group in groups
        ]
    else:
        campaigns, mutants = load_campaigns(args.catalog)
    if args.campaign:
        campaigns = [c for c in campaigns if c["id"] in args.campaign]
        mutants = [m for m in mutants if m["campaign"] in args.campaign]
    if args.mutant:
        mutants = [m for m in mutants if m["id"] in args.mutant]
        campaigns = [
            c for c in campaigns if any(m["campaign"] == c["id"] for m in mutants)
        ]
    rows = inventory(ROOT, mutants)
    errors = [row for row in rows if row["status"] != "APPLICABLE"]
    print(
        f"{len(campaigns)} campaigns; {len(rows) - len(errors)}/{len(rows)} applicable mutants",
        flush=True,
    )
    if errors:
        print(json.dumps(errors, indent=2))
        return 1
    if args.preflight:
        return 0
    output = args.output or ROOT / ".tools/deep-mutation" / time.strftime(
        "run-%Y%m%d-%H%M%S", time.gmtime()
    )
    output = output.resolve()
    if (output / "manifest.json").exists():
        parser.error("output already contains a run; choose a fresh directory")
    return run_program(campaigns, mutants, output, args.workers)


if __name__ == "__main__":
    raise SystemExit(main())
