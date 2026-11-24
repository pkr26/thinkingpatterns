#!/usr/bin/env python3
"""Verify or restore private mutation evidence with Python's standard library.

Examples:
  python3 verify_restore.py --assets /path/to/downloaded-assets
  python3 verify_restore.py --assets /path/to/assets --restore /new/path/fresh
  python3 verify_restore.py --assets /path/to/assets --check-restored /new/path/fresh
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def safe_relative(name):
    if not isinstance(name, str) or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError(f"Unsafe archive path: {name!r}")
    value = PurePosixPath(name)
    if value.is_absolute() or not value.parts or any(part in {"..", "."} for part in value.parts):
        raise ValueError(f"Unsafe archive path: {name}")
    return Path(*value.parts)


def regular_file(root, name):
    relative = safe_relative(name)
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"Symlink is not permitted in evidence paths: {name}")
    if not path.is_file():
        raise ValueError(f"Evidence file missing: {name}")
    return path


def read_records(assets, manifest):
    name = manifest["fileManifest"]
    if name not in {row["file"] for row in manifest["supportFiles"]}:
        raise ValueError("File manifest is not checksum-bound to a support asset")
    with gzip.open(regular_file(assets, name), "rt") as handle:
        rows = [json.loads(line) for line in handle]
    paths = [row["path"] for row in rows]
    if len(rows) != manifest["files"] or len(set(paths)) != len(paths):
        raise ValueError("Duplicate or incomplete original file manifest")
    for row in rows:
        safe_relative(row["path"])
        if len(row["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in row["sha256"]):
            raise ValueError("Invalid object identity")
        if type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o777 or type(row["bytes"]) is not int or row["bytes"] < 0:
            raise ValueError("Invalid original file metadata")
    return rows


def verify_assets(assets, catalog=None):
    checksums = assets / "SHA256SUMS"
    if not checksums.is_file():
        raise ValueError("SHA256SUMS is required")
    verified = {}
    for line in checksums.read_text().splitlines():
        expected, name = line.split("  ", 1)
        if name in verified:
            raise ValueError("Duplicate checksummed asset name")
        path = regular_file(assets, name)
        actual = digest(path)
        if actual != expected:
            raise ValueError(f"Asset checksum mismatch: {name}")
        verified[name] = actual
    if "fresh-backup-manifest.json" not in verified:
        raise ValueError("The backup manifest itself must be checksummed")
    if catalog is not None:
        trusted = json.loads(catalog.read_text())
        if trusted.get("privateManifestSha256") != verified["fresh-backup-manifest.json"]:
            raise ValueError("Private backup differs from the trusted public catalog")
    manifest = json.loads(regular_file(assets, "fresh-backup-manifest.json").read_text())
    for record in manifest["components"] + manifest["supportFiles"]:
        path = regular_file(assets, record["file"])
        if verified.get(record["file"]) != record["sha256"] or path.stat().st_size != record["bytes"]:
            raise ValueError(f"Manifest/catalog mismatch: {record['file']}")
    rows = read_records(assets, manifest)
    return manifest, rows, verified


def walk_objects(assets, manifest, rows, destination=None):
    expected = {}
    for row in rows:
        existing = expected.setdefault(row["sha256"], (row["component"], row["bytes"]))
        if existing != (row["component"], row["bytes"]):
            raise ValueError("Inconsistent deduplicated object mapping")
    seen = set()
    for component in manifest["components"]:
        component_name = component["file"][len("fresh-"):-len(".tar.gz")]
        count = 0
        with tarfile.open(assets / component["file"], "r|gz") as archive:
            for entry in archive:
                if not entry.isfile() or entry.name.count("/") != 1 or not entry.name.startswith("objects/"):
                    raise ValueError("Unexpected archive member or link")
                identity = entry.name.split("/", 1)[1]
                if identity in seen or expected.get(identity) != (component_name, entry.size):
                    raise ValueError("Duplicate, unreferenced or misplaced raw object")
                seen.add(identity)
                count += 1
                checksum = hashlib.sha256()
                stream = archive.extractfile(entry)
                output = (destination / identity).open("xb") if destination else None
                try:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        checksum.update(block)
                        if output:
                            output.write(block)
                finally:
                    stream.close()
                    if output:
                        output.close()
                if checksum.hexdigest() != identity:
                    raise ValueError("Original raw object checksum mismatch")
        if count != component["objects"]:
            raise ValueError("Component object count mismatch")
    if seen != set(expected) or len(seen) != manifest["uniqueObjects"]:
        raise ValueError("Backup is missing original content objects")
    return len(seen)


def restore(assets, manifest, rows, target):
    if target.exists() or target.is_symlink():
        raise ValueError("Restore destination must be new; existing data is never overwritten")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mutation-objects-", dir=target.parent) as directory:
        objects = Path(directory)
        walk_objects(assets, manifest, rows, objects)
        target.mkdir(mode=0o700)
        for row in rows:
            path = target / safe_relative(row["path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(objects / row["sha256"], path)
            os.chmod(path, row["mode"])
    return check_restored(manifest, rows, target)


def check_restored(manifest, rows, target):
    for row in rows:
        path = regular_file(target, row["path"])
        if path.stat().st_size != row["bytes"] or digest(path) != row["sha256"]:
            raise ValueError(f"Restored original bytes differ: {row['path']}")
    backend = target / "backend"
    proof = json.loads((target / "backend-worker02-parallel-status.json").read_text())
    if proof["status"] != "completed":
        raise ValueError("Backend completed receipt absent")
    final = proof["completion_verification"]
    for mapping in (final["result_files_sha256"], final["receipt_files_sha256"]):
        for name, expected in mapping.items():
            if digest(backend / safe_relative(name)) != expected:
                raise ValueError("Hash-bound final backend evidence differs")
    canonical = {row["id"] for row in json.loads((backend / "mutants.json").read_text())}
    seen, outcomes = set(), Counter()
    for name in final["result_files_sha256"]:
        with (backend / safe_relative(name)).open() as handle:
            for line in handle:
                row = json.loads(line)
                if row["id"] in seen or row["id"] not in canonical:
                    raise ValueError("Duplicate or unknown canonical backend result")
                seen.add(row["id"])
                outcomes[row["status"]] += 1
                if row["status"] != "INVALID_SYNTAX" and (row.get("restored") is not True or row.get("temporary_restored") is not True):
                    raise ValueError("Backend source/temp restoration failure")
    if len(seen) != 44104 or seen != canonical or dict(outcomes) != final["counts"]:
        raise ValueError("Canonical backend inventory differs")
    # Absolute paths inside immutable historical JSON remain unchanged.  Translate
    # them only when opening a reference on this machine.
    original = PurePosixPath(manifest["originalCampaignRoot"])
    def relocated(value):
        return target / safe_relative(PurePosixPath(value).relative_to(original).as_posix())
    state = json.loads((target / "frontend-status.json").read_text())
    state["packages"].update(json.loads((target / "frontend-recovery-status.json").read_text())["packages"])
    inventory = json.loads((target / "frontend-enumeration.json").read_text())["packages"]
    frontend = {}
    for package in inventory:
        name = package["package"]
        output = relocated(state["packages"][name]["output"])
        files = {}
        if name == "mobile":
            reports = [json.loads((output / "mutation.json").read_text())]
        elif name == "portal":
            reports = [json.loads((output / "fresh-mutation.json").read_text())]
        else:
            reports = []
            for path in sorted(output.glob("*.json")):
                if "baseline" in path.stem.lower() or path.stem.startswith("runner-"):
                    continue
                data = json.loads(path.read_text())
                if isinstance(data, dict) and isinstance(data.get("files"), dict):
                    reports.append(data)
        for report in reports:
            for source, data in report["files"].items():
                if source in files:
                    raise ValueError("Duplicate frontend source")
                files[source] = data
        total = 0
        for expected in package["targets"]:
            data = files.get(expected["file"])
            if data is None and name == "mobile" and expected["mutations"] == 0:
                continue
            if data is None or len(data["mutants"]) != expected["mutations"]:
                raise ValueError("Incomplete restored frontend inventory")
            ids = [str(row["id"]) for row in data["mutants"]]
            if len(set(ids)) != len(ids):
                raise ValueError("Duplicate frontend canonical ID")
            source = target / "snapshot" / name / expected["file"]
            if hashlib.sha256(data["source"].encode()).hexdigest() != digest(source):
                raise ValueError("Frontend source bytes differ from frozen inputs")
            total += len(ids)
        if total != package["mutations"]:
            raise ValueError("Wrong frontend inventory total")
        frontend[name] = total
    if len(seen) + sum(frontend.values()) != 125982:
        raise ValueError("Whole canonical inventory incomplete")
    original_inputs = json.loads((target / "snapshot-manifest.json").read_text())["files"]
    original_source = json.loads((backend / "provenance.json").read_text())["source_and_test_sha256"]
    first_source = json.loads((target / "backend-worker01-retry-status.json").read_text())["source_and_test_sha256"]
    expected_sources = {"snapshot": original_source, "backend-source": original_source,
                        "backend-worker01-retry-source": first_source,
                        "backend-worker02-clock-source": proof["source_and_test_sha256"]}
    fingerprints = {}
    for name, expected in expected_sources.items():
        inputs = {row["path"][len(name) + 1:]: row["sha256"]
                  for row in rows if row["path"].startswith(name + "/")}
        if set(inputs) != set(original_inputs):
            raise ValueError("Frozen source input file set differs from original scope")
        checksum = hashlib.sha256()
        for path, value in sorted(inputs.items()):
            checksum.update(path.encode() + b"\0" + bytes.fromhex(value))
        fingerprints[name] = checksum.hexdigest()
        if fingerprints[name] != expected:
            raise ValueError("Frozen source/test fingerprint differs from execution provenance")
    return {"restoredFilesVerified": len(rows), "backendControls": len(seen), "backendOutcomes": dict(outcomes),
            "frontendControls": frontend, "totalControls": 125982, "historicalPathsRewritten": False,
            "frozenSourceFingerprints": fingerprints}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, help="Trusted backup-catalog.json from the public Git checkout; auto-detected beside this script")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--restore", type=Path)
    group.add_argument("--check-restored", type=Path)
    args = parser.parse_args()
    assets = args.assets.resolve()
    catalog = args.catalog
    if catalog is None:
        candidate = Path(__file__).resolve().with_name("backup-catalog.json")
        catalog = candidate if candidate.is_file() else None
    if args.restore and args.restore.is_symlink():
        raise ValueError("Restore destination cannot be a symlink")
    manifest, rows, verified = verify_assets(assets, catalog)
    if args.restore:
        result = restore(assets, manifest, rows, args.restore.resolve())
    elif args.check_restored:
        result = check_restored(manifest, rows, args.check_restored.resolve())
    else:
        result = {"rawObjectsVerified": walk_objects(assets, manifest, rows), "originalFiles": len(rows)}
    print(json.dumps({"verified": True, "assetChecksumsVerified": len(verified), **result}, sort_keys=True))


if __name__ == "__main__":
    main()
