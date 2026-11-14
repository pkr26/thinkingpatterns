#!/usr/bin/env python3
"""Prepare current behavioral oracles for every canonical backend mutation.

Historical IDs and verdicts never identify current controls or earn kill credit.
An archived oracle is reusable only when both the full target-source hash and
the canonical (file, position, before, after) patch match. Static type checks
and source pins are excluded. Fresh runner baselines remain mandatory.
"""

from __future__ import annotations

import argparse
import ast
import functools
import gzip
import hashlib
import json
import os
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
NON_BEHAVIORAL = (
    "test_mutation_pins_2026_09_30.py",
    "test_contract_registry_2026_09_30.py",
    "test_encrypt_with_nonce_absent_from_production_paths",
    "test_production_code_never_calls_the_v1_patterns_analyzer",
    "test_es_function_words_carry_no_duplicate_literals",
    "static_typecheck",
    "test_crisis.py::TestParity::",
    "test_crisis_consumed_catalog_matches_the_released_cross_platform_contract",
    "test_concat_patterns_are_the_marked_twins",
    "test_crisis_unicode_token_and_regex_transform_boundaries",
    "test_crisis_normalized_variants_and_released_verdicts",
    "test_crisis_each_confusable_invisible_leet_and_concat_boundary",
    "test_crisis_lowercases_ascii_capitals_introduced_by_nfkc",
    "test_folded_channel_only_adds_catches",
    "test_crisis_leet_normalization_reaches_its_fixed_point",
    "test_user_locks_default_cap_is_ten_thousand",
)
CRISIS_ORACLES = [
    "../tools/tests/test_crisis_public_contracts.py::test_public_crisis_normalizer_preserves_plain_journal_text",
    "../tools/tests/test_crisis_public_contracts.py::test_finite_crisis_public_decisions_make_progress",
    "../tools/tests/test_crisis_public_contracts.py::test_mixed_script_crisis_boundaries_follow_punctuation_folding",
    "../tools/tests/test_crisis_public_contracts.py::test_contextual_crisis_obfuscation_and_benign_continuations",
    "../tools/tests/test_crisis_public_contracts.py::test_released_crisis_decisions_through_both_public_tiers",
    "tests/test_crisis.py::TestFixtures",
    "tests/test_crisis.py::TestRedteamCorpus",
    "tests/test_crisis.py::TestDualVariantAndMasking",
    "tests/test_crisis.py::TestLetterDoublingFold::test_doubled_letters_fire_both_tiers",
    "tests/test_crisis.py::TestLetterDoublingFold::test_fold_never_fires_on_ordinary_prose",
    "tests/test_crisis.py::TestLetterDoublingFold::test_benign_compounds_remask_after_folding",
    "tests/test_crisis.py::TestAuditRemediation2026_09_17::test_mask_gap_ideation_adjacent_to_compound_word_fires",
    "tests/test_crisis.py::TestAuditRemediation2026_09_17::test_residual_splits_and_concat_fire",
    "tests/test_crisis.py::TestAuditRemediation2026_09_17::test_invisible_and_homoglyph_families_fire",
    "tests/test_crisis.py::TestAuditRemediation2026_09_17::test_cross_engine_divergence_inputs",
    "tests/test_crisis.py::TestAuditRemediation2026_09_17::test_concat_variant_anchored_endings_stay_benign",
    "tests/test_crisis.py::TestEngineInterlock",
    "tests/test_crisis.py::TestProbeCorpusRegression",
    "tests/test_crisis.py::test_carried_forward_label_alone_marks_the_public_card_sensitive",
    "tests/test_crisis.py::test_bare_crisis_beside_benign_compounds_reaches_both_public_tiers",
    "tests/test_checklist_round4_crisis.py",
    "tests/test_deep_campaign_analysis.py::test_dialog_language_is_always_suppressed_by_actual_matcher",
    "tests/test_deep_campaign_analysis.py::test_partial_crisis_split_still_suppresses_reflective_question",
    "tests/test_deep_campaign_analysis.py::test_split_is_keeps_its_original_crisis_interpretation",
    "tests/test_deep_campaign_analysis.py::test_partial_benign_words_remain_outside_both_crisis_tiers",
    "tests/test_deep_campaign_analysis.py::test_marked_concat_does_not_invent_crisis_from_word_junctions",
]
LOCK_IDLE_EVICTION_ORACLE = (
    "tests/test_security_fixes.py::test_user_locks_still_recycle_idle_entries"
)
LOCK_IDLE_EVICTION_SOURCE_SHA256 = (
    "607c30b36276522a3f6ee0db031a4dd7a21d9faab63950f738ae34636c594230"
)
LOCK_IDLE_EVICTION_TEST_SHA256 = (
    "156df37968f4bae74ad7c349aac0cd8b9dd56532c644289369439c2acb976214"
)
LOCK_IDLE_EVICTION_PATCHES = frozenset(
    {
        ("app/locks.py", 4675, "-", "+"),
        ("app/locks.py", 4694, "1", "2"),
    }
)
LOCK_DEFAULT_CAP_ORACLE = (
    "tests/test_locks_default_cap_behavior.py::"
    "test_default_user_locks_recycle_the_first_idle_key_at_the_ten_thousand_cap"
)
LOCK_DEFAULT_CAP_TEST_SHA256 = (
    "a6722778f4fa5af23b93bf416d487b42fca4e008c8e3a31b5d7372def9c38cbe"
)
LOCK_DEFAULT_CAP_PATCH = ("app/locks.py", 2050, "_000", "001")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_key(row):
    return (row["file"], row["position"], row["before"], row["after"])


def behavioral(selector):
    return not any(value in selector for value in NON_BEHAVIORAL)


def selector_path(snapshot, selector):
    filename = selector.split("::", 1)[0]
    if not filename or Path(filename).is_absolute():
        raise ValueError(f"oracle must have a relative test path: {selector}")
    path = (snapshot / "backend" / filename).resolve()
    if not path.is_relative_to(snapshot.resolve()):
        raise ValueError(f"oracle escapes frozen snapshot: {selector}")
    return path


@functools.lru_cache(maxsize=512)
def oracle_tree(path, modified, size):
    return ast.parse(path.read_text(), filename=str(path))


def validate_selector(snapshot, selector):
    if not behavioral(selector):
        raise ValueError(f"nonbehavioral oracle: {selector}")
    path = selector_path(snapshot, selector)
    if not path.is_file() or path.suffix != ".py":
        raise ValueError(f"oracle file does not exist: {selector}")
    stat = path.stat()
    tree = oracle_tree(path, stat.st_mtime_ns, stat.st_size)
    names = selector.split("::")[1:]
    body = tree.body
    selected = None
    for name in names:
        symbol = name.split("[", 1)[0]
        selected = next(
            (
                node
                for node in body
                if isinstance(
                    node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                )
                and node.name == symbol
            ),
            None,
        )
        if selected is None:
            raise ValueError(f"oracle symbol does not exist: {selector}")
        body = selected.body
    scope = selected if selected is not None else tree
    tests = [
        node
        for node in ast.walk(scope)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test")
    ]
    if not tests:
        raise ValueError(f"oracle contains no test functions: {selector}")


def node_selector(snapshot, nodeid, original_selectors=()):
    """Normalize pytest's root-relative or occasionally fileless node IDs."""
    if nodeid.startswith("::"):
        candidates = [value.split("::", 1)[0] + nodeid for value in original_selectors]
    elif nodeid.startswith(("tools/", "redteam/")):
        candidates = ["../" + nodeid]
    elif nodeid.startswith("backend/"):
        candidates = [nodeid.removeprefix("backend/")]
    else:
        candidates = [nodeid]
    valid = []
    for candidate in dict.fromkeys(candidates):
        try:
            validate_selector(snapshot, candidate)
        except (ValueError, OSError, SyntaxError):
            continue
        valid.append(candidate)
    return valid[0] if len(valid) == 1 else None


def archive_index(archive):
    ledger = json.loads(gzip.decompress((archive / "ledger.json.gz").read_bytes()))
    rows = {patch_key(row): row for row in ledger["rows"]}
    if len(rows) != len(ledger["rows"]):
        raise ValueError("historical ledger has ambiguous canonical patches")
    accepted = {}
    with gzip.open(archive / "accepted-evidence.jsonl.gz", "rt") as stream:
        for line in stream:
            item = json.loads(line)
            if item["kind"] != "accepted":
                continue
            row = item["record"]
            key = patch_key(row)
            if key not in rows:
                raise ValueError("accepted evidence is not in the canonical ledger")
            if key in accepted:
                raise ValueError("ambiguous archived accepted patch")
            accepted[key] = {"record": row, "status": item["global_status"]}
    return ledger["current_production_sha256"], rows, accepted


def prior_behavioral_selectors(snapshot, item):
    row = item["record"]
    # A type-check assertion is a static disposition, even if pytest ran it.
    if item["status"] == "STATIC_TYPECHECK_CAUGHT":
        return []
    if item["status"] == "KILLED":
        for failure in row.get("failures", []):
            if failure.get("phase") == "call":
                selector = node_selector(snapshot, failure["nodeid"], row["selectors"])
                if selector:
                    return [selector]
    available = []
    for value in dict.fromkeys(row["selectors"]):
        if not behavioral(value):
            continue
        try:
            validate_selector(snapshot, value)
        except (ValueError, OSError, SyntaxError):
            continue
        available.append(value)
    return available


def verified_lock_idle_eviction_oracle(snapshot, row, source_sha256):
    """Add the existing eviction behavior test for the two exact lock patches.

    Archived selectors cover overflow contention but omit the idle eviction
    path. The source, patch, and test bytes must all still match the reviewed
    current-source observations before this selector may be used.
    """
    if (
        source_sha256 != LOCK_IDLE_EVICTION_SOURCE_SHA256
        or patch_key(row) not in LOCK_IDLE_EVICTION_PATCHES
    ):
        return None
    path = selector_path(snapshot, LOCK_IDLE_EVICTION_ORACLE)
    if not path.is_file() or sha256(path) != LOCK_IDLE_EVICTION_TEST_SHA256:
        raise ValueError("lock idle eviction oracle bytes require fresh review")
    validate_selector(snapshot, LOCK_IDLE_EVICTION_ORACLE)
    return LOCK_IDLE_EVICTION_ORACLE


def verified_lock_default_cap_oracle(snapshot, row, source_sha256):
    """Use the exercised default-cap eviction test for the exact default patch."""
    if (
        source_sha256 != LOCK_IDLE_EVICTION_SOURCE_SHA256
        or patch_key(row) != LOCK_DEFAULT_CAP_PATCH
    ):
        return None
    path = selector_path(snapshot, LOCK_DEFAULT_CAP_ORACLE)
    if not path.is_file() or sha256(path) != LOCK_DEFAULT_CAP_TEST_SHA256:
        raise ValueError("lock default-cap behavioral oracle bytes require fresh review")
    validate_selector(snapshot, LOCK_DEFAULT_CAP_ORACLE)
    return LOCK_DEFAULT_CAP_ORACLE


def function_span(tree, line):
    spans = [
        (node.lineno, node.end_lineno)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.lineno <= line <= node.end_lineno
    ]
    return min(spans, key=lambda span: span[1] - span[0]) if spans else None


def coverage_index(path, snapshot, production_files):
    """Only call contexts whose measured production source is still identical."""
    if path is None:
        return {}, {}
    from coverage import CoverageData

    data = CoverageData(basename=str(path))
    data.read()
    result, excluded = {}, {}
    for name in data.measured_files():
        measured = Path(name)
        try:
            parts = measured.parts
            offset = max(
                index for index, value in enumerate(parts) if value == "backend"
            )
        except ValueError:
            continue
        relative = Path(*parts[offset + 1 :]).as_posix()
        if relative not in production_files:
            continue
        target = snapshot / "backend" / relative
        if (
            not target.is_file()
            or not measured.is_file()
            or sha256(target) != sha256(measured)
        ):
            excluded[relative] = (
                "measured and frozen production bytes differ or are unavailable"
            )
            continue
        contexts = {}
        for line, values in data.contexts_by_lineno(name).items():
            nodes = []
            for context in values:
                nodeid, separator, phase = context.rpartition("|")
                if separator and phase == "run":
                    selector = node_selector(snapshot, nodeid)
                    if selector:
                        nodes.append(selector)
            if nodes:
                contexts[line] = sorted(set(nodes))
        result[relative] = contexts
    return result, excluded


def prepare(snapshot, manifest, archive, coverage=None):
    hashes, historical, accepted = archive_index(archive)
    unavailable_archived = []
    for value in sorted(
        {
            selector
            for item in accepted.values()
            for selector in item["record"]["selectors"]
            if behavioral(selector)
        }
    ):
        try:
            validate_selector(snapshot, value)
        except (ValueError, OSError, SyntaxError) as error:
            unavailable_archived.append({"selector": value, "reason": str(error)})
    current_hashes, sources = {}, {}
    trees = {}
    seen_ids = set()
    for row in manifest:
        identifier = row["id"]
        if not isinstance(identifier, str) or not identifier or identifier in seen_ids:
            raise ValueError("mutation IDs must be unique nonempty strings")
        seen_ids.add(identifier)
        if (
            isinstance(row.get("position"), bool)
            or not isinstance(row.get("position"), int)
            or row["position"] < 0
            or isinstance(row.get("line"), bool)
            or not isinstance(row.get("line"), int)
            or row["line"] < 1
            or not isinstance(row.get("before"), str)
            or not isinstance(row.get("after"), str)
            or row["before"] == row["after"]
        ):
            raise ValueError(f"invalid canonical patch fields: {identifier}")
        target = (snapshot / "backend" / row["file"]).resolve()
        if not target.is_relative_to((snapshot / "backend").resolve()):
            raise ValueError("mutation target escapes the frozen backend")
        if row["file"] not in sources:
            sources[row["file"]] = target.read_text()
            current_hashes[row["file"]] = sha256(target)
        source = sources[row["file"]]
        if row["position"] > len(source):
            raise ValueError(f"canonical patch lies beyond frozen source: {identifier}")
        if (
            source[row["position"] : row["position"] + len(row["before"])]
            != row["before"]
        ):
            raise ValueError(
                f"manifest patch does not match frozen source: {identifier}"
            )
        if row["file"] not in trees:
            trees[row["file"]] = ast.parse(source)
    contexts, excluded_coverage = coverage_index(
        coverage, snapshot, set(current_hashes)
    )
    reusable = defaultdict(list)
    for key, item in accepted.items():
        filename = key[0]
        if current_hashes.get(filename) != hashes.get(filename):
            continue
        selectors = prior_behavioral_selectors(snapshot, item)
        if selectors:
            reusable[filename].append((item["record"], selectors))
    plan, details, gaps = {}, [], []
    for row in manifest:
        filename, key = row["file"], patch_key(row)
        aligned = current_hashes[filename] == hashes.get(filename)
        selectors, method = [], None
        item = accepted.get(key) if aligned else None
        if filename == "app/services/crisis.py":
            selectors, method = CRISIS_ORACLES[:], "current_crisis_behavioral_suite"
        elif item:
            selectors = prior_behavioral_selectors(snapshot, item)
            if selectors:
                method = (
                    "archived_runtime_failure"
                    if item["status"] == "KILLED"
                    else "archived_behavioral_oracles"
                )
        if not selectors:
            observed = contexts.get(filename, {})
            selectors = observed.get(row["line"], [])
            if selectors:
                method = "current_runtime_line_contexts"
            else:
                span = function_span(trees[filename], row["line"])
                if span:
                    selectors = sorted(
                        {
                            value
                            for line, values in observed.items()
                            if span[0] <= line <= span[1]
                            for value in values
                        }
                    )
                    if selectors:
                        method = "current_runtime_function_contexts"
        if not selectors and aligned:
            span = function_span(trees[filename], row["line"])
            candidates = [
                (other, values)
                for other, values in reusable[filename]
                if span is None or span[0] <= other["line"] <= span[1]
            ]
            candidates.sort(key=lambda pair: abs(pair[0]["position"] - row["position"]))
            for _, values in candidates:
                for value in values:
                    if value not in selectors:
                        selectors.append(value)
                    if len(selectors) == 3:
                        break
                if len(selectors) == 3:
                    break
            if selectors:
                method = (
                    "neighboring_function_behavior"
                    if span
                    else "neighboring_module_behavior"
                )
        lock_oracle = verified_lock_idle_eviction_oracle(
            snapshot, row, current_hashes[filename]
        )
        if lock_oracle and lock_oracle not in selectors:
            selectors.append(lock_oracle)
            method = (
                f"{method}+verified_lock_idle_eviction"
                if method
                else "verified_lock_idle_eviction"
            )
        default_oracle = verified_lock_default_cap_oracle(
            snapshot, row, current_hashes[filename]
        )
        if default_oracle and default_oracle not in selectors:
            selectors.append(default_oracle)
            method = (
                f"{method}+verified_lock_default_cap"
                if method
                else "verified_lock_default_cap"
            )
        if not selectors:
            gaps.append(
                {
                    "id": row["id"],
                    "file": filename,
                    "line": row["line"],
                    "reason": "no source-aligned behavioral oracle or current call context",
                }
            )
            continue
        plan[row["id"]] = list(dict.fromkeys(selectors))
        details.append(
            {
                "id": row["id"],
                "file": filename,
                "method": method,
                "source_sha256": current_hashes[filename],
                "archive_source_aligned": aligned,
                "patch_identity_sha256": hashlib.sha256(
                    json.dumps(key).encode()
                ).hexdigest(),
                "previous_disposition": historical.get(key, {}).get("status")
                if aligned
                else None,
                "archived_http_contract_capture": bool(
                    item and item["record"].get("contracts")
                ),
                "archived_public_response_values": bool(
                    item and item["record"].get("public_response_values")
                ),
                "selectors": plan[row["id"]],
            }
        )
    unique = sorted({value for values in plan.values() for value in values})
    for selector in unique:
        validate_selector(snapshot, selector)
    summary = {
        "total_manifest": len(manifest),
        "mapped": len(plan),
        "gaps": gaps,
        "methods": dict(Counter(row["method"] for row in details)),
        "unique_selectors": len(unique),
        "unique_selector_groups": len({tuple(v) for v in plan.values()}),
        "current_production_sha256": current_hashes,
        "excluded_coverage_sources": excluded_coverage,
        "unavailable_archived_oracles": unavailable_archived,
        "archived_http_contract_capture_controls": sum(
            row["archived_http_contract_capture"] for row in details
        ),
        "archived_public_response_value_controls": sum(
            row["archived_public_response_values"] for row in details
        ),
        "serial_postgres_ownership_ids": [
            identifier
            for identifier, values in plan.items()
            if any(
                "test_full_backend_postgres_ownership_contracts.py" in value
                for value in values
            )
        ],
        "fresh_pristine_baselines_required": True,
        "mutation_execution": False,
    }
    return plan, details, summary


def verify_collection(snapshot, plan, log, python):
    """Collect each named test file once, then verify every planned selector."""
    selectors = sorted({value for values in plan.values() for value in values})
    files = sorted({value.split("::", 1)[0] for value in selectors})
    command = [
        str(python),
        "-m",
        "pytest",
        "--collect-only",
        "-q",
        "--no-header",
        "--rootdir",
        str(snapshot),
        "-o",
        "addopts=",
        "-p",
        "no:cacheprovider",
        *files,
    ]
    result = subprocess.run(
        command,
        check=False,
        cwd=snapshot / "backend",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "MINDPATTERN_ENV": "development",
        },
    )
    log.write_text(result.stdout)
    if result.returncode:
        raise ValueError(
            f"oracle collection failed with exit {result.returncode}; see {log}"
        )
    nodes = set()
    for line in result.stdout.splitlines():
        filename, separator, _names = line.partition("::")
        if separator and filename.endswith(".py"):
            normalized = node_selector(snapshot, line)
            if normalized:
                nodes.add(normalized)

    def collected(selector):
        return any(
            node == selector or node.startswith((selector + "::", selector + "["))
            for node in nodes
        )

    # Parameter labels can change while the same behavioral oracle remains.
    # Select its current complete parameter family rather than guess a new ID.
    refreshed = {}
    for selector in selectors:
        if not collected(selector) and "[" in selector:
            base = selector.split("[", 1)[0]
            if collected(base):
                refreshed[selector] = base
    for values in plan.values():
        values[:] = list(dict.fromkeys(refreshed.get(value, value) for value in values))
    selectors = sorted({value for values in plan.values() for value in values})
    missing = [selector for selector in selectors if not collected(selector)]
    if missing:
        missing_path = log.with_suffix(".missing.json")
        missing_path.write_text(json.dumps(missing, indent=2) + "\n")
        raise ValueError(
            f"{len(missing)} planned selectors collected zero tests; see {missing_path}"
        )
    return {
        "returncode": result.returncode,
        "collected": len(nodes),
        "verified_selectors": len(selectors),
        "command": command,
        "log": str(log),
        "refreshed_parameter_selectors": refreshed,
        "log_sha256": sha256(log),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--archive", type=Path, default=ROOT / "reports/mutation-2026-10-05"
    )
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-collection", action="store_true")
    parser.add_argument(
        "--python", type=Path, default=ROOT / "backend/.venv/bin/python"
    )
    args = parser.parse_args()
    snapshot, output = args.snapshot.resolve(), args.output.resolve()
    if any((output / name).exists() for name in ("plan.json", "plan-evidence.json")):
        parser.error("output already contains a plan; choose a fresh directory")
    manifest = json.loads(args.manifest.read_text())
    if not isinstance(manifest, list) or not manifest:
        parser.error("manifest must be a nonempty canonical mutation list")
    plan, details, summary = prepare(
        snapshot, manifest, args.archive.resolve(), args.coverage
    )
    output.mkdir(parents=True, exist_ok=True)
    summary.update(
        {
            "snapshot": str(snapshot),
            "manifest": str(args.manifest.resolve()),
            "manifest_sha256": sha256(args.manifest),
            "generator_sha256": GENERATOR_SHA256,
            "ledger_sha256": sha256(args.archive / "ledger.json.gz"),
            "accepted_evidence_sha256": sha256(
                args.archive / "accepted-evidence.jsonl.gz"
            ),
        }
    )
    if summary["gaps"]:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        raise SystemExit(
            f"refusing incomplete plan: {len(summary['gaps'])} unmapped controls"
        )
    if args.verify_collection:
        summary["collection"] = verify_collection(
            snapshot, plan, output / "collection.log", args.python
        )
        summary["unique_selectors"] = len(
            {value for values in plan.values() for value in values}
        )
        summary["unique_selector_groups"] = len(
            {tuple(values) for values in plan.values()}
        )
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    (output / "plan-evidence.json").write_text(json.dumps(details, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: value
                for key, value in summary.items()
                if key not in {"current_production_sha256", "collection"}
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
