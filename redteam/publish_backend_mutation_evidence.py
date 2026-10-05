"""Export selected mutation evidence without depending on ignored workspace paths.

The published records retain original locators and hashes. Runtime traceback text
is redacted; the optional local archive retains the originals and deduplicated
source/oracle inputs. This is an evidence export, not a historical replay claim.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from collections import Counter, defaultdict
from pathlib import Path

HISTORY = {"execution_history", "attempt_history", "attempts", "history"}
CACHE = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".hypothesis",
    ".mypy_cache",
    ".ruff_cache",
    "copies",
    "locks",
    "logs",
}
JWT = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
PAT = re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9]{20,}")
PATCH = ("file", "line", "index", "position", "before", "after", "source_line")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode()


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def credential_jwt(token: str) -> bool:
    for segment in token.split(".")[:2]:
        try:
            value = json.loads(
                base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            )
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict) and {"exp", "iat"} <= value.keys():
            return True
    return False


def sanitized(value, redactions: list, location="", *, verdict=False):
    """Keep schemas while marking omitted histories and potentially sensitive text."""
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            where = f"{location}/{key}"
            if key in HISTORY:
                redactions.append(
                    {
                        "field": where,
                        "reason": "unaccepted attempt history omitted",
                        "sha256": digest(encoded(child)),
                    }
                )
                continue
            if verdict and key == "detail" and isinstance(child, str):
                sha = digest(child.encode())
                result[key] = f"[REDACTED_RUNTIME_TRACEBACK sha256={sha}]"
                redactions.append(
                    {
                        "field": where,
                        "reason": "runtime traceback can contain synthetic credentials, keys or journal data",
                        "sha256": sha,
                        "bytes": len(child.encode()),
                    }
                )
            elif verdict and key == "contracts" and child:
                sha = digest(encoded(child))
                result[key] = {"redacted": True, "original_sha256": sha}
                redactions.append(
                    {
                        "field": where,
                        "reason": "captured runtime response payload omitted",
                        "sha256": sha,
                    }
                )
            else:
                result[key] = sanitized(child, redactions, where, verdict=verdict)
        return result
    if isinstance(value, list):
        return [
            sanitized(child, redactions, f"{location}/{index}", verdict=verdict)
            for index, child in enumerate(value)
        ]
    if isinstance(value, str):

        def replace(match):
            token = match.group()
            if match.re is JWT and not credential_jwt(token):
                return token
            sha = digest(token.encode())
            redactions.append(
                {
                    "field": location,
                    "reason": "credential-shaped synthetic output",
                    "sha256": sha,
                    "bytes": len(token),
                }
            )
            return f"[REDACTED_CREDENTIAL sha256={sha}]"

        return PAT.sub(replace, JWT.sub(replace, value))
    return value


class Export:
    def __init__(self, base: Path, output: Path):
        self.base, self.output = base.resolve(), output.resolve()
        if self.output.exists() and any(self.output.iterdir()):
            raise ValueError(f"output must be empty: {self.output}")
        self.output.mkdir(parents=True, exist_ok=True)
        self.references = {}
        self.files = {}
        self.archive_files = set()
        self.snapshots = set()

    def causal_files(self, value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key not in HISTORY:
                    self.causal_files(child)
        elif isinstance(value, list):
            for child in value:
                self.causal_files(child)
        elif (
            isinstance(value, str)
            and len(value) < 4096
            and "\n" not in value
            and value.endswith((".json", ".jsonl", ".py", ".log", ".txt"))
        ):
            path = Path(value)
            path = (path if path.is_absolute() else self.base / path).resolve()
            if path.is_relative_to(self.base) and path.is_file():
                self.archive_files.add(path)

    def path(self, value) -> Path:
        path = Path(value)
        path = (path if path.is_absolute() else self.base / path).resolve()
        if not path.is_relative_to(self.base):
            raise ValueError(f"evidence outside campaign: {path}")
        return path

    def register(self, path: Path, locator: str):
        path = self.path(path)
        if path not in self.references:
            self.references[path] = {
                "recorded_path": str(path),
                "original_sha256": file_hash(path),
                "original_bytes": path.stat().st_size,
                "portable_locators": [],
            }
        self.references[path]["portable_locators"].append(locator)
        self.archive_files.add(path)

    def write(self, name: str, data: bytes, *, original: Path | None = None):
        path = self.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        exported = gzip.compress(data, mtime=0) if name.endswith(".gz") else data
        path.write_bytes(exported)
        self.files[name] = {
            "sha256": digest(exported),
            "bytes": len(exported),
            "decompressed_sha256": digest(data),
            "decompressed_bytes": len(data),
        }
        if original:
            self.register(original, name)
            self.files[name]["original_sha256"] = self.references[original.resolve()][
                "original_sha256"
            ]

    def document(self, original: Path, name: str):
        raw = original.read_bytes()
        redactions = []
        clean = sanitized(json.loads(raw), redactions)
        self.write(name, encoded(clean) if redactions else raw, original=original)
        self.files[name]["redactions"] = redactions

    def archive(self, target: Path):
        """Preserve a content-addressed, inspection-only local closure."""
        target = target.resolve()
        if target.exists():
            raise ValueError(f"local archive already exists: {target}")
        trees, objects, omissions = [], {}, Counter()

        def add(path, original, relative=None):
            sha = file_hash(path)
            objects.setdefault(sha, path)
            entry = {
                "recorded_path": original,
                "sha256": sha,
                "bytes": path.stat().st_size,
                "mode": path.stat().st_mode & 0o777,
            }
            if relative is not None:
                entry["snapshot_relative_path"] = relative
            trees.append(entry)

        print(
            json.dumps(
                {
                    "local_archive_phase": "collecting immutable inputs",
                    "selected_files": len(self.archive_files),
                    "snapshot_trees": len(self.snapshots),
                }
            ),
            flush=True,
        )
        for path in sorted(self.archive_files):
            add(path, str(path))
        for snapshot in sorted(self.snapshots):
            for directory, dirs, files in os.walk(snapshot):
                dirs[:] = sorted(d for d in dirs if d not in CACHE and d != "results")
                for name in sorted(files):
                    path = Path(directory) / name
                    relative = path.relative_to(snapshot)
                    if path.is_symlink():
                        omissions["symlinks"] += 1
                        continue
                    if name in {
                        ".env",
                        ".coverage",
                        "coverage.json",
                        "coverage.xml",
                    } or name.endswith(
                        (".db", ".db-wal", ".db-shm", ".pyc", ".log", ".enc")
                    ):
                        omissions[
                            "runtime database, ciphertext, environment or generated file"
                        ] += 1
                        continue
                    add(path, str(path), str(relative))
        index = {
            "schema": 1,
            "purpose": "local inspection and reconstruction inputs; historical replay is not certified",
            "files": trees,
            "snapshots": [str(p) for p in sorted(self.snapshots)],
            "omissions": dict(omissions),
            "excluded_directory_names": sorted(CACHE | {"results"}),
            "external_dependencies_bundled": False,
        }
        print(
            json.dumps(
                {
                    "local_archive_phase": "compressing deduplicated objects",
                    "file_entries": len(trees),
                    "unique_objects": len(objects),
                    "uncompressed_object_bytes": sum(
                        path.stat().st_size for path in objects.values()
                    ),
                }
            ),
            flush=True,
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        with (
            target.open("wb") as raw,
            gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
            tarfile.open(fileobj=zipped, mode="w|") as archive,
        ):

            def member(name, data, mode=0o644):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, 0
                archive.addfile(info, io.BytesIO(data))

            member("index.json", encoded(index))
            for sha, path in sorted(objects.items()):
                member(f"objects/{sha}", path.read_bytes())
        # Verify all archived objects before any workspace cleanup is considered.
        verified = set()
        with tarfile.open(target, "r:gz") as archive:
            for item in archive:
                if item.name.startswith("objects/"):
                    stream = archive.extractfile(item)
                    assert stream is not None
                    sha = hashlib.file_digest(stream, "sha256").hexdigest()
                    assert item.name == f"objects/{sha}"
                    verified.add(sha)
        assert verified == objects.keys()
        return {
            "path": str(target),
            "sha256": file_hash(target),
            "bytes": target.stat().st_size,
            "file_entries": len(trees),
            "unique_objects": len(objects),
            "unique_uncompressed_bytes": sum(
                path.stat().st_size for path in objects.values()
            ),
            "all_object_hashes_verified": True,
            "boundary": index["purpose"],
            "excluded_directory_names": index["excluded_directory_names"],
            "omissions": index["omissions"],
        }


def publish(base: Path, output: Path, expected: str, local_archive: Path | None):
    export = Export(base, output)
    ledger_path = export.base / "backend-current-ledger.json"
    raw_ledger = ledger_path.read_bytes()
    assert digest(raw_ledger) == expected, "announced ledger hash changed"
    ledger = json.loads(raw_ledger)
    rows = {row["id"]: row for row in ledger["rows"]}
    assert (
        len(rows) == ledger["total"]
        and Counter(row["status"] for row in rows.values()) == ledger["counts"]
    )
    audit = json.loads(
        (export.base / "independent-final-backend-audit.json").read_text()
    )
    reviewed_audit = json.loads(
        (export.base / "independent-final-reviewed-disposition-audit.json").read_text()
    )
    validation = json.loads(
        (export.base / "final-campaign-validation.json").read_text()
    )
    assert (
        audit["ledger_sha256"]
        == reviewed_audit["ledger_sha256"]
        == validation["canonical_ledger_sha256"]
        == expected
    )
    assert audit["counts"] == validation["counts"] == ledger["counts"]
    assert audit["status"].endswith("PASS") and validation["status"].endswith("PASS")
    assert not reviewed_audit["missing_evidence"]
    selected = defaultdict(dict)
    accepted_nonruntime = {row["id"]: row for row in reviewed_audit["rows"]}
    proof_rows, owners = [], {}
    for identifier, row in rows.items():
        status = row["status"]
        if status == "INVALID_SYNTAX":
            continue
        locator = (
            row["verification"]
            if status == "KILLED"
            else accepted_nonruntime[identifier]["evidence"]
        )
        result = export.path(locator.get("result_file") or locator["runtime_result"])
        selected[result][identifier] = {
            "global_status": status,
            "expected_line": locator["result_line"],
            "baseline": export.path(locator["baseline_file"]),
        }
        snapshot = export.path(locator["source_snapshot"])
        export.snapshots.add(snapshot)
        export.register(
            export.path(locator["mutation_manifest"]), f"ledger.json.gz#id={identifier}"
        )
        for filename in ("provenance.json", "runner.py", "plan.json"):
            path = result.parent / filename
            if path.exists():
                export.archive_files.add(path)
        if status != "KILLED":
            reference = row["disposition_evidence"]
            owner = export.path(reference["ledger"])
            if owner not in owners:
                raw = owner.read_bytes()
                document = json.loads(raw)
                owners[owner] = (
                    digest(raw),
                    document["rows"] if isinstance(document, dict) else document,
                )
            sha, owner_rows = owners[owner]
            assert sha == reference["ledger_sha256"]
            proof = owner_rows[reference["row_index"]]
            assert proof["id"] == identifier
            export.causal_files(proof)
            redactions = []
            proof_rows.append(
                {
                    "id": identifier,
                    "status": status,
                    "owner_ledger": str(owner),
                    "original_owner_ledger_sha256": sha,
                    "owner_row_index": reference["row_index"],
                    "original_owner_row_sha256": digest(encoded(proof)),
                    "record": sanitized(proof, redactions, verdict=True),
                    "redactions": redactions,
                    "accepted_evidence": locator,
                }
            )
            export.register(owner, f"reviewed-dispositions.json.gz#id={identifier}")
    evidence_path = export.output / "accepted-evidence.jsonl.gz"
    pristine, accepted = {}, Counter()
    with (
        evidence_path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
    ):

        def emit(record):
            zipped.write(encoded(record))

        for result, requested in sorted(selected.items()):
            source_sha = file_hash(result)
            found = set()
            with result.open("rb") as stream:
                for line_number, raw_line in enumerate(stream, 1):
                    attempt = json.loads(raw_line)
                    identifier = attempt["id"]
                    if identifier not in requested:
                        continue
                    assert identifier not in found
                    found.add(identifier)
                    wanted = requested[identifier]
                    assert line_number == wanted["expected_line"]
                    assert all(attempt[key] == rows[identifier][key] for key in PATCH)
                    assert attempt.get("restored") and attempt.get(
                        "temporary_restored", True
                    )
                    assert not attempt.get("errors") and not attempt.get("timed_out")
                    if wanted["global_status"] == "REVIEWED_EQUIVALENT":
                        assert (
                            attempt["status"] == "SURVIVED"
                            and attempt["returncode"] == 0
                            and attempt["passed"] > 0
                            and not attempt["failures"]
                        )
                    else:
                        assert (
                            attempt["status"] == "KILLED" and attempt["returncode"] != 0
                        )
                        assert any(
                            failure["phase"] == "call"
                            for failure in attempt["failures"]
                        )
                    baseline_file = wanted["baseline"]
                    group = (baseline_file, attempt["baseline_id"])
                    if group not in pristine:
                        baselines = json.loads(baseline_file.read_bytes())
                        matches = [
                            value
                            for value in baselines.values()
                            if value["baseline_id"] == attempt["baseline_id"]
                        ]
                        assert len(matches) == 1
                        baseline = matches[0]
                        assert baseline["returncode"] == 0 and baseline["passed"] > 0
                        assert (
                            not baseline["failures"]
                            and not baseline["errors"]
                            and not baseline["timed_out"]
                        )
                        assert baseline["restored"] and baseline.get(
                            "temporary_restored", True
                        )
                        assert baseline["selectors"] == attempt["selectors"]
                        pristine[group] = baseline
                        redactions = []
                        emit(
                            {
                                "kind": "pristine",
                                "recorded_file": str(baseline_file),
                                "original_file_sha256": file_hash(baseline_file),
                                "baseline_id": baseline["baseline_id"],
                                "original_record_sha256": digest(encoded(baseline)),
                                "record": sanitized(baseline, redactions, verdict=True),
                                "redactions": redactions,
                            }
                        )
                        export.register(
                            baseline_file,
                            f"accepted-evidence.jsonl.gz#baseline={baseline_file.parent.name}/{baseline['baseline_id']}",
                        )
                        if baseline.get("log"):
                            export.archive_files.add(export.path(baseline["log"]))
                    else:
                        assert pristine[group]["selectors"] == attempt["selectors"]
                    redactions = []
                    emit(
                        {
                            "kind": "accepted",
                            "id": identifier,
                            "global_status": wanted["global_status"],
                            "recorded_file": str(result),
                            "original_file_sha256": source_sha,
                            "original_line": line_number,
                            "original_line_sha256": digest(raw_line),
                            "record": sanitized(attempt, redactions, verdict=True),
                            "redactions": redactions,
                        }
                    )
                    export.register(
                        result, f"accepted-evidence.jsonl.gz#id={identifier}"
                    )
                    if attempt.get("log"):
                        export.archive_files.add(export.path(attempt["log"]))
                    accepted[wanted["global_status"]] += 1
            assert found == requested.keys(), (result, requested.keys() - found)
    assert (
        sum(accepted.values()) == ledger["total"] - ledger["counts"]["INVALID_SYNTAX"]
    )
    export.files[evidence_path.name] = {
        "sha256": file_hash(evidence_path),
        "bytes": evidence_path.stat().st_size,
        "accepted_controls": sum(accepted.values()),
        "accepted_counts": dict(accepted),
        "pristine_groups": len(pristine),
        "redaction_boundary": "free-form runtime traceback and captured response payloads omitted; original file/line/field hashes retained",
    }
    export.write(
        "reviewed-dispositions.json.gz",
        encoded({"ledger_sha256": expected, "rows": proof_rows}),
    )
    for original, name in (
        (ledger_path, "ledger.json.gz"),
        (export.base / "backend-current-summary.json", "summary.json"),
        (
            export.base / "independent-final-backend-audit.json",
            "independent-audit.json",
        ),
        (export.base / "final-campaign-validation.json", "validation.json"),
        (
            export.base
            / "independent-pre-token-pin-correction-b18/independent-final-backend-audit.json",
            "historical-audit-before-token-pin-correction.json",
        ),
    ):
        export.document(original, name)
    for reference in audit.get("artifacts", []):
        original = export.path(reference["artifact"])
        assert file_hash(original) == reference["sha256"]
        export.document(original, "audits/" + original.name + ".gz")
    for name in (
        "static-disposition-independent-audit.json",
        "runner-archival-candidates.json",
    ):
        original = export.base / name
        if original.exists():
            export.document(original, "audits/" + name + ".gz")
    for name in (
        "opaque-capability-entropy-current-certificate.json",
        "totp-entropy-current-certificate.json",
        "current-locks-reviewed-equivalents.json",
        "current-account-sqlite342-certificate.json",
        "independent-final-runtime-pin-review.json",
        "independent-current-lock-equivalence-audit.json",
        "current-lock-scheduling-review/causal-review.json",
        "historical-nested-sharing-lock-proof/provenance.json",
        "historical-nested-sharing-lock-proof/native_nested_sharing_pool_probe.json",
    ):
        original = export.base / name
        if original.exists():
            export.document(original, "certificates/" + name.replace("/", "-"))
    # Retain the exact earlier claim and audit scripts in the local archive.
    for directory in (
        export.base / "independent-pre-token-pin-correction-b18",
        export.base / "independent-audit-scripts",
    ):
        export.archive_files.update(
            path for path in directory.rglob("*") if path.is_file()
        )
    for path in (
        export.base / "current-source-scope.json",
        export.base / "augmented-mutants.json",
    ):
        export.archive_files.add(path)
    for path in (export.base / "historical-nested-sharing-lock-proof").glob("*"):
        if path.is_file():
            export.archive_files.add(path)
    original_snapshot = export.base / "snapshot-ready"
    if original_snapshot.is_dir():
        export.snapshots.add(original_snapshot)
    repository = Path(__file__).resolve().parents[1]
    cleanup_sources = [
        "attach_backend_reviewed_evidence.py",
        "close_backend_account_campaign.py",
        "close_backend_auxiliary_campaign.py",
        "close_backend_insights_campaign.py",
        "close_backend_locks_campaign.py",
        "close_backend_provider_campaign.py",
        "close_backend_statistics_campaign.py",
        "close_current_backend_account_export.py",
        "close_current_backend_account_root.py",
        "consolidate_backend_mutation.py",
        "review_backend_language_equivalents.py",
        "review_backend_lock_pool.py",
        "review_backend_totp_entropy.py",
        "upgrade_backend_audit_reviewed_typing.py",
        "automatic_backend_data_oracles.py",
    ]
    retained_cleanup_sources = []
    for name in cleanup_sources:
        path = repository / "redteam" / name
        if path.is_file():
            export.archive_files.add(path)
            retained_cleanup_sources.append(
                {
                    "recorded_path": str(path),
                    "sha256": file_hash(path),
                    "bytes": path.stat().st_size,
                }
            )
    fresh_gate = repository / ".tools/backend-publish-2026-10-05"
    if fresh_gate.is_dir():
        export.archive_files.update(
            path
            for path in fresh_gate.iterdir()
            if path.is_file() and path.suffix in {".xml", ".json", ".log", ".txt"}
        )
    archive = export.archive(local_archive) if local_archive else None
    export.write(
        "portable-reference-index.json.gz",
        encoded(
            {
                "schema": 1,
                "ledger_sha256": expected,
                "recorded_paths_are_historical_provenance": True,
                "references": [value for _, value in sorted(export.references.items())],
                "source_snapshots": [str(path) for path in sorted(export.snapshots)],
                "local_archive": archive,
            }
        ),
    )
    manifest = {
        "schema": 1,
        "ledger_sha256": expected,
        "total": ledger["total"],
        "counts": ledger["counts"],
        "files": export.files,
        "local_archive": archive,
        "retained_cleanup_source_files": retained_cleanup_sources,
        "original_paths_rewritten": False,
        "historical_replay_certified": False,
        "published_traceback_text_redacted": True,
        "missing_historical_runner_versions": audit["runner_artifacts"][
            "stages_without_standalone_retained_runner_file"
        ],
        "all_current_production_sha256": ledger["current_production_sha256"],
        "evidence_scope": audit["evidence_scope"],
    }
    (export.output / "README.md").write_text(
        "# Backend mutation evidence, 2026-10-05\n\n"
        f"The final current-source inventory contains **{ledger['total']:,} controls** across 95 production Python files (92 with operators and three empty initializers). "
        f"It records {ledger['counts']['KILLED']:,} runtime kills, {ledger['counts']['STATIC_TYPECHECK_CAUGHT']:,} static type-check detections, {ledger['counts']['REVIEWED_EQUIVALENT']:,} reviewed equivalents and {ledger['counts']['INVALID_SYNTAX']:,} syntax-invalid controls. "
        "There are no unresolved survivors, timeouts or oracle errors. Reviewed equivalents and syntax-invalid controls are separate from runtime kills.\n\n"
        f"The authoritative ledger SHA-256 is `{expected}`. [Manifest](manifest.json) records export hashes, original hashes, source fingerprints and redactions. "
        "[Summary](summary.json), [independent audit](independent-audit.json) and [validation](validation.json) describe the scope and checks. "
        "[Ledger](ledger.json.gz), [reviewed dispositions](reviewed-dispositions.json.gz), [accepted verdicts and pristine groups](accepted-evidence.jsonl.gz) and [reference index](portable-reference-index.json.gz) are gzip-compressed JSON or JSONL.\n\n"
        "The accepted evidence records preserve actual call nodes, phases, return codes, selector baselines, restoration flags and original record hashes. "
        "Free-form runtime tracebacks and captured response payloads are explicitly redacted because synthetic tests can print credentials, keys or journal data. "
        "Redacted exports do not reproduce those original bytes; their hashes identify the retained local originals.\n\n"
        "Recorded absolute snapshot and log paths are historical provenance, not links that are expected to exist in a fresh checkout. "
        "The reference index maps selected records to portable files. Immutable historical source/oracle inputs and detailed logs are retained in a deduplicated local archive when noted in the manifest; the archive is not committed. "
        "Dependencies, runtime databases and external services are not bundled. Seventeen early stages lack a recorded execution-runner version. "
        "This publication supports evidence inspection and current regression execution; it does not certify byte-for-byte historical replay. Earlier snapshots of unchanged targets can have different dependency bytes, supplemented by final dependency witnesses.\n\n"
        "The [original independent audit](historical-audit-before-token-pin-correction.json) is preserved verbatim. "
        "The final audit explicitly withdraws the M010117/M010648 private token-size pin kills after both genuine native/HTTP/type replays passed. "
        "The earlier M008096 pool-size equivalence was also withdrawn after a native sharing-producer deadlock witness; the complete corrected locks module was re-enumerated and replayed. "
        "Certificates retain these boundaries, including observable entropy, wire-length and scheduling differences.\n"
    )
    readme = export.output / "README.md"
    export.files["README.md"] = {
        "sha256": file_hash(readme),
        "bytes": readme.stat().st_size,
    }
    (export.output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    )
    assert ledger_path.read_bytes() == raw_ledger, "ledger changed during export"
    print(
        json.dumps(
            {
                "output": str(export.output),
                "total": ledger["total"],
                "counts": ledger["counts"],
                "published_bytes": sum(
                    path.stat().st_size
                    for path in export.output.rglob("*")
                    if path.is_file()
                ),
                "local_archive": archive,
            },
            indent=2,
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ledger-sha256", required=True)
    parser.add_argument("--local-archive", type=Path)
    args = parser.parse_args()
    publish(args.campaign, args.output, args.ledger_sha256, args.local_archive)


if __name__ == "__main__":
    main()
