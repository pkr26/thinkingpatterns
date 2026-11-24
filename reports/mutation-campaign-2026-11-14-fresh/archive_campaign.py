#!/usr/bin/env python3
"""Export safe public outcomes and a private byte-exact campaign backup.

This script never changes the source campaign.  Raw objects go only to the
ignored private-output directory; public exports deliberately omit test output,
response bodies, contracts, tracebacks, replacement strings and status reasons.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile

COMPONENTS = (
    "control-evidence", "backend-results", "backend-logs", "frontend-results",
    "frontend-logs", "frozen-inputs", "oracle-plans",
)
SKIP_DIRECTORIES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".hypothesis", ".ruff_cache", ".mypy_cache", "copies", "DerivedData",
    "Pods", "build", "dist", ".artifacts", "locks", "scheduling-schema",
}
SKIP_ROOT_DIRECTORIES = {"backend-tmp", "backend-baseline-tmp"}
DEPENDENCY_LOCKS = {"yarn.lock", "uv.lock", "poetry.lock", "Cargo.lock", "Pipfile.lock", "Gemfile.lock", "Podfile.lock"}
SECRET_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.test",
    ".netrc", ".pypirc", "id_rsa", "id_ed25519", "credentials", "credentials.json",
}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db"}
BACKEND_OUTCOMES = {
    "KILLED": "Killed", "SURVIVED": "Survived", "ORACLE_ERROR": "OracleError",
    "TIMEOUT": "Timeout", "INVALID_SYNTAX": "InvalidSyntax",
    "NON_BEHAVIORAL_FAILURE": "NonBehavioralFailure",
}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def gzip_lines(path, rows):
    with Path(path).open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
        for row in rows:
            compressed.write(encoded(row) + b"\n")


def relative_reference(value, root):
    if not value:
        return None
    text = str(value)
    try:
        return Path(text).relative_to(root).as_posix()
    except ValueError:
        return None


def backend_rows(root):
    backend = root / "backend"
    seen = set()
    canonical = {row["id"] for row in json.loads((backend / "mutants.json").read_text())}
    for path in sorted(backend.rglob("results-*.jsonl")):
        if {"copies", "logs"} & set(path.relative_to(backend).parts):
            continue
        for ordinal, line in enumerate(path.read_bytes().splitlines(), 1):
            row = json.loads(line)
            identity = row["id"]
            if identity not in canonical or identity in seen:
                raise ValueError(f"Duplicate/unknown backend control: {identity}")
            seen.add(identity)
            outcome = BACKEND_OUTCOMES[row["status"]]
            if outcome != "InvalidSyntax" and (row.get("restored") is not True or row.get("temporary_restored") is not True):
                raise ValueError(f"Unrestored backend control: {identity}")
            if outcome == "Killed" and row.get("timed_out"):
                raise ValueError("Timeout cannot earn kill credit")
            yield {
                "package": "backend", "source": "backend/" + row["file"], "id": identity,
                "rawOutcome": row["status"], "effectiveOutcome": outcome,
                "killCredit": outcome == "Killed", "seconds": row.get("seconds"),
                "timeoutSeconds": row.get("timeout_seconds"), "selectorCount": len(row.get("selectors", [])),
                "baselineId": row.get("baseline_id"), "sourceRestored": row.get("restored"),
                "temporaryRestored": row.get("temporary_restored"),
                "artifact": path.relative_to(root).as_posix(), "recordOrdinal": ordinal,
                "rawRecordCanonicalSha256": hashlib.sha256(encoded(row)).hexdigest(),
                "log": relative_reference(row.get("log"), root),
            }
    if seen != canonical or len(seen) != 44104:
        raise ValueError("Backend canonical inventory is incomplete")


def frontend_rows(package, root, status, policy):
    inventory = next(row for row in json.loads((root / "frontend-enumeration.json").read_text())["packages"] if row["package"] == package)
    targets = {row["file"]: row["mutations"] for row in inventory["targets"]}
    state = status["packages"][package]
    output = Path(state["output"])
    overlays = {}
    if package == "web":
        for row in json.loads((output / "kill-qualification.json").read_text())["controls"]:
            overlays[(row["file"], str(row["id"]))] = row
    seen = set()
    counts = Counter()

    def compact(source, row, path, ordinal=None, flagged=False):
        source = policy["canonical_source"](source, targets)
        identity = str(row["id"])
        key = (source, identity)
        if source is None or key in seen:
            raise ValueError(f"Duplicate/unknown {package} control: {key}")
        seen.add(key)
        counts[source] += 1
        effective = policy["qualified_frontend_outcome"]({**row, "oracleFlag": flagged}, overlays.get(key))
        if effective not in policy["FRONTEND_TERMINAL"]:
            raise ValueError(f"Unresolved frontend outcome: {key}")
        return {
            "package": package, "source": package + "/" + source, "id": identity,
            "rawOutcome": row["status"], "effectiveOutcome": effective,
            "killCredit": effective == "Killed", "testsCompleted": row.get("testsCompleted") if type(row.get("testsCompleted")) in (int, float) else None,
            "artifact": path.relative_to(root).as_posix(), "recordOrdinal": ordinal,
            "rawRecordCanonicalSha256": hashlib.sha256(encoded(row)).hexdigest(),
            "qualificationOverlay": key in overlays, "oracleFlag": flagged,
        }

    if package == "mobile":
        path = output / "mutants.jsonl"
        with path.open() as handle:
            for ordinal, line in enumerate(handle, 1):
                row = json.loads(line)
                yield compact(row["fileName"], row, path, ordinal)
    else:
        reports = output / "fresh-files" if package == "portal" else output
        for path in sorted(reports.glob("*.json")):
            if "baseline" in path.stem.lower() or path.stem.startswith("runner-"):
                continue
            payload = json.loads(path.read_text())
            if not isinstance(payload, dict) or not isinstance(payload.get("files"), dict):
                continue
            metadata_path = path.with_name(path.stem + "-metadata.json")
            metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
            flags = {(policy["canonical_source"](source, targets), identity)
                     for source, identity in policy["ORACLE_FLAGS"](metadata.get("oracle_execution", {}))}
            for source, data in payload["files"].items():
                if not isinstance(data, dict) or not isinstance(data.get("mutants"), list):
                    continue
                for row in data["mutants"]:
                    key = (policy["canonical_source"](source, targets), str(row["id"]))
                    yield compact(source, row, path, flagged=key in flags)
    if len(seen) != inventory["mutations"] or any(counts[source] != count for source, count in targets.items()):
        raise ValueError(f"Incomplete {package} inventory")


def export_public(root, public, captured):
    policy = runpy.run_path(str(root / "status.py"))
    status = json.loads((root / "frontend-status.json").read_text())
    status["packages"].update(json.loads((root / "frontend-recovery-status.json").read_text())["packages"])
    packages = {}
    for name in ("backend", "web", "mobile", "portal"):
        counts, raw, identities = Counter(), Counter(), set()
        source_rows = backend_rows(root) if name == "backend" else frontend_rows(name, root, status, policy)

        def checked():
            for row in source_rows:
                key = (row["source"], row["id"])
                if key in identities:
                    raise ValueError("Duplicate compact identity")
                identities.add(key)
                counts[row["effectiveOutcome"]] += 1
                raw[row["rawOutcome"]] += 1
                yield row

        destination = public / f"{name}-outcomes.jsonl.gz"
        gzip_lines(destination, checked())
        expected = captured["backend_outcomes"] if name == "backend" else captured["frontend_effective_outcomes"][name]
        expected = {BACKEND_OUTCOMES[key]: value for key, value in expected.items()} if name == "backend" else expected
        if dict(counts) != expected:
            raise ValueError(f"Compact outcomes disagree with current verified status: {name}: {counts} / {expected}")
        packages[name] = {"controls": len(identities), "effectiveOutcomes": dict(counts), "rawOutcomes": dict(raw),
                          "ledger": destination.name, "ledgerSha256": digest(destination)}
        print(json.dumps({"exported": name, "controls": len(identities), "gzipBytes": destination.stat().st_size}), flush=True)
    source = json.loads((root / "snapshot-manifest.json").read_text())
    summary = {
        "schemaVersion": 1, "campaign": "mutation-campaigns-2026-11-14/fresh",
        "sourceCommit": source["commit"], "plannedControls": 125982,
        "verifiedControls": sum(value["controls"] for value in packages.values()),
        "completedAt": json.loads((root / "backend-worker02-parallel-status.json").read_text())["completed_at"],
        "complete": True, "packages": packages,
        "countingPolicy": "Timeouts, oracle/runtime errors, invalid syntax and no coverage receive no kill credit. Qualification overlays replace outcomes without adding canonical controls.",
        "rawRecordHashPolicy": "SHA-256 of UTF-8 json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True). Raw artifact byte hashes are in the private file manifest.",
        "privacy": "Public ledgers omit free-form test output, status reasons, contracts, response bodies, tracebacks, test names and replacement strings. Byte-exact originals are private-backup assets.",
        "scope": "Execution completion is verified; surviving controls and unresolved execution outcomes remain findings, not release-readiness approval.",
    }
    if summary["verifiedControls"] != 125982:
        raise ValueError("Wrong overall canonical count")
    write_json(public / "summary.json", summary)
    return summary


def is_input(parts):
    first = parts[0]
    return (first in {"snapshot", "backend-source", "backend-worker01-retry-source", "backend-worker02-clock-source",
                      "backend-inventory-source", "backend-tooling", "backend-tooling-plugin-fix"}
            or first.startswith("backend-bootstrap-")
            or "counterfactual-source" in parts or "pristine-source" in parts
            or (first == "frontend-attempts" and any(part.endswith("-source") for part in parts)))


def component_for(relative):
    parts = relative.parts
    first = parts[0]
    if is_input(parts):
        return "frozen-inputs"
    if (first.startswith("backend-plan") or relative.name == "selected-plan.json"):
        return "oracle-plans"
    if first == "backend":
        return "backend-logs" if "logs" in parts else "backend-results"
    if first in {"frontend", "frontend-logs"}:
        return "frontend-logs" if first == "frontend-logs" or relative.suffix == ".log" else "frontend-results"
    return "control-evidence"


def inventory(root, extras=None):
    records, objects, excluded = [], {}, []
    for current, directories, files in os.walk(root, followlinks=False):
        relative_dir = Path(current).relative_to(root)
        keep = []
        for name in sorted(directories):
            candidate = Path(current) / name
            if (name in SKIP_DIRECTORIES or name.endswith("-locks") or candidate.is_symlink()
                    or (not relative_dir.parts and name in SKIP_ROOT_DIRECTORIES)):
                excluded.append({"path": candidate.relative_to(root).as_posix(), "reason": "runtime dependency/copy/cache/lock directory or symlink", "directory": True})
            else:
                keep.append(name)
        directories[:] = keep
        for name in sorted(files):
            path = Path(current) / name
            relative = path.relative_to(root)
            reason = None
            if path.is_symlink():
                reason = "machine-specific symlink"
            elif (relative.parts[0].startswith("progress-") and name != "progress-updates.stop"):
                reason = "local notification/session orchestration"
            elif (name.endswith(".pid") or (name.endswith(".lock") and name not in DEPENDENCY_LOCKS)
                  or name.endswith(".coverage") or name.startswith(".coverage")):
                reason = "runtime PID/lock/coverage database"
            elif name in SECRET_NAMES or path.suffix.lower() in SECRET_SUFFIXES:
                reason = "environment/credential/private-key/database file"
            elif name in {".npmrc", "pip.conf"} and any(token in path.read_text(errors="replace") for token in ("_authToken", "_password", "password=", "password =")):
                reason = "credential-bearing package-manager configuration"
            if reason:
                excluded.append({"path": relative.as_posix(), "reason": reason, "directory": False})
                continue
            before = path.stat()
            checksum = digest(path)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RuntimeError(f"Source changed while archiving: {relative}")
            record = {"path": relative.as_posix(), "sha256": checksum, "bytes": before.st_size,
                      "mode": before.st_mode & 0o777}
            if checksum not in objects:
                objects[checksum] = {"source": path, "bytes": before.st_size, "component": component_for(relative)}
            record["component"] = objects[checksum]["component"]
            records.append(record)
    for relative, path in sorted((extras or {}).items()):
        before = path.stat()
        checksum = digest(path)
        if (before.st_size, before.st_mtime_ns) != (path.stat().st_size, path.stat().st_mtime_ns):
            raise RuntimeError("Migration provenance changed while archiving")
        if checksum not in objects:
            objects[checksum] = {"source": path, "bytes": before.st_size, "component": "control-evidence"}
        records.append({"path": relative, "sha256": checksum, "bytes": before.st_size,
                        "mode": before.st_mode & 0o777, "component": objects[checksum]["component"]})
    return sorted(records, key=lambda row: row["path"]), objects, excluded


class CheckedReader:
    def __init__(self, handle):
        self.handle, self.checksum = handle, hashlib.sha256()

    def read(self, count=-1):
        result = self.handle.read(count)
        self.checksum.update(result)
        return result


def archive_component(private, name, objects):
    selected = sorted((checksum, row) for checksum, row in objects.items() if row["component"] == name)
    if not selected:
        return None
    target = private / f"fresh-{name}.tar.gz"
    with target.open("wb") as raw, gzip.GzipFile(fileobj=raw, filename="", mode="wb", compresslevel=6, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for checksum, record in selected:
                info = tarfile.TarInfo("objects/" + checksum)
                info.size, info.mode, info.mtime = record["bytes"], 0o600, 0
                with record["source"].open("rb") as handle:
                    checked = CheckedReader(handle)
                    archive.addfile(info, checked)
                    if checked.checksum.hexdigest() != checksum:
                        raise RuntimeError("Original evidence changed during backup")
    result = {"file": target.name, "sha256": digest(target), "bytes": target.stat().st_size,
              "objects": len(selected), "uncompressedObjectBytes": sum(row["bytes"] for _, row in selected)}
    print(json.dumps({"privateComponent": result}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-root", type=Path, default=Path(".tools/mutation-campaigns-2026-11-14/fresh"))
    parser.add_argument("--private-output", type=Path, default=Path(".tools/migration-backup-2026-11-24"))
    parser.add_argument("--public-output", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root, private, public = args.campaign_root.resolve(), args.private_output.resolve(), args.public_output.resolve()
    if private.is_relative_to(public) or root.is_relative_to(private) or private.is_relative_to(root):
        parser.error("Source, public exports and private raw backup must be separate")
    if private.exists() and any(path.name != "validation" for path in private.iterdir()):
        parser.error("Private output may contain only pre-existing validation logs; refusing to overwrite a prior backup")
    private.mkdir(parents=True, exist_ok=True)
    os.chmod(private, 0o700)
    public.mkdir(parents=True, exist_ok=True)
    captured = json.loads(subprocess.check_output([sys.executable, "-B", str(root / "status.py")], text=True))
    if captured["lanes"]["backend"]["status"] != "completed" or captured["backend_completed"] != 44104:
        raise RuntimeError("Backend completion proof is not valid")
    if any(captured[key] for key in ("backend_duplicate_results", "backend_unknown_results", "backend_invalid_results", "backend_restoration_failures")):
        raise RuntimeError("Backend integrity check failed")
    summary = export_public(root, public, captured)
    validation = private / "validation"
    validation.mkdir(exist_ok=True)
    repository = Path.cwd().resolve()
    patch = validation / "working-tree.patch"
    patch.write_bytes(subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=repository))
    revisions = {
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip(),
        "originMain": subprocess.check_output(["git", "rev-parse", "origin/main"], cwd=repository, text=True).strip(),
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=repository, text=True).strip(),
        "patchSha256": digest(patch),
        "scope": "Tracked working-tree changes at backup time; original mutation snapshot is separately preserved.",
    }
    write_json(validation / "git-provenance.json", revisions)
    extras = {"_migration-validation/" + path.relative_to(validation).as_posix(): path
              for path in validation.rglob("*") if path.is_file() and not path.is_symlink()}
    for path in public.iterdir():
        if path.is_file() and path.name not in {"backup-catalog.json", "SHA256SUMS"}:
            extras["_migration-public-export/" + path.name] = path
    print("Inventorying private raw evidence; source remains untouched", flush=True)
    records, objects, excluded = inventory(root, extras)
    gzip_lines(private / "fresh-file-manifest.jsonl.gz", records)
    write_json(private / "excluded-paths.json", excluded)
    with ThreadPoolExecutor(max_workers=4) as pool:
        components = [value for value in pool.map(lambda name: archive_component(private, name, objects), COMPONENTS) if value]
    support = []
    for name in ("fresh-file-manifest.jsonl.gz", "excluded-paths.json"):
        path = private / name
        support.append({"file": name, "sha256": digest(path), "bytes": path.stat().st_size})
    manifest = {
        "schemaVersion": 1, "createdAt": datetime.now(timezone.utc).isoformat(),
        "campaign": summary["campaign"], "originalCampaignRoot": str(root),
        "sourceCommit": summary["sourceCommit"], "controls": 125982,
        "files": len(records), "uncompressedRestoredBytes": sum(row["bytes"] for row in records),
        "uniqueObjects": len(objects), "components": components, "supportFiles": support,
        "fileManifest": "fresh-file-manifest.jsonl.gz", "publicSummarySha256": digest(public / "summary.json"),
        "restorePolicy": "Original artifact bytes and historical absolute path strings are preserved. Resolve historical campaign-root paths in memory against the chosen extraction root.",
        "excludedPolicy": "Redundant runtime copies, dependencies, caches, PID/lock files, coverage databases, notification orchestration, symlinks, environment files, private keys and databases are excluded; exact exclusions are private excluded-paths.json.",
        "privacy": "PRIVATE backup: unmodified synthetic test logs may contain generated tokens, keys and journal text. Never publish these assets in a public repository or release.",
    }
    write_json(private / "fresh-backup-manifest.json", manifest)
    catalog = {key: value for key, value in manifest.items() if key not in {"originalCampaignRoot", "privacy"}}
    catalog["privateBackupRequired"] = True
    catalog["privateManifestSha256"] = digest(private / "fresh-backup-manifest.json")
    write_json(public / "backup-catalog.json", catalog)
    for name in ("verify_restore.py", "RESTORE.md"):
        if (public / name).exists():
            shutil.copyfile(public / name, private / name)
    shutil.copyfile(public / "summary.json", private / "summary.json")
    checksummed = sorted(path for path in private.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (private / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.name}\n" for path in checksummed))
    print(json.dumps({"privateBackup": str(private), "publicExports": str(public), "files": len(records),
                      "objects": len(objects), "restoredBytes": manifest["uncompressedRestoredBytes"],
                      "compressedBytes": sum(row["bytes"] for row in components)}), flush=True)


if __name__ == "__main__":
    main()
