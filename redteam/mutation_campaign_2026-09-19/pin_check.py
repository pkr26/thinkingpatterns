#!/usr/bin/env python3
"""Hand-verification: every round-3 pin must FAIL under its own mutant.

For each (mutant, pin) pair: apply the exact campaign mutation, run the pin
file, require a failure, restore byte-wise. A pin that passes under its
mutant guards nothing.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent

PIN_FILE = "tests/test_mutation_pins.py"

# mutant id -> the pin test node that must fail under it
PINS: dict[str, str] = {
    "O2": "test_suspended_account_is_refused_on_insights_reads",
    "O10": "test_therapist_registration_requires_the_enrollment_token",
    "P5": "test_entry_page_ordering_carries_the_id_tiebreak",
    "P6": "test_same_day_recompute_rewrites_the_question_blob",
    "Q1": "test_legacy_entry_page_budget_is_two_mebibytes",
    "Q9": "test_grant_rejects_when_the_therapist_caseload_is_full",
    "R8": "test_concurrent_pair_grant_answers_conflict_not_500",
    "R10": "test_pairing_code_creation_only_retries_unique_violations",
    "S3": "test_keystore_per_owner_session_cap",
    "S5": "test_ahead_of_server_snapshot_marker_also_conflicts",
    "S6": "test_insights_blob_not_served_after_threshold_regression",
    "S7": "test_therapist_insights_read_phase_gates_the_blob",
    "T6": "test_forwarded_identity_requires_the_trusted_peer_decision",
    "T8": "test_absent_keys_stay_on_the_overflow_lock_until_it_drains",
}


def main() -> None:
    spec = importlib.util.spec_from_file_location("h", HERE / "harness.py")
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    oracle = h.backend_pytest(PIN_FILE)

    results = []
    todo = [m for m in h.MUTANTS if m["id"] in PINS]
    print(f"{len(todo)} pin/mutant pairs queued\n", flush=True)
    ok = 0
    for m in todo:
        pin_node = f"{PIN_FILE}::{PINS[m['id']]}"
        print(f"[{m['id']}] pin {PINS[m['id']]} under mutant ...", flush=True)
        t0 = time.monotonic()
        r = h.run_mutant({**m, "tests": {**oracle, "cmd": oracle["cmd"] + [pin_node]}})
        elapsed = round(time.monotonic() - t0, 1)
        killed = bool(r["killed"])
        ok += killed
        results.append(r)
        print(f"    -> {'PIN-KILLS-MUTANT' if killed else 'PIN-FAILED-TO-KILL'} ({elapsed}s)"
              + (f"  first: {r['commands'][0]['failures'][0][1].split('::')[-1]}"
                 if r.get("commands") and r["commands"][0]["failures"] else ""), flush=True)
    print(f"\n{ok}/{len(todo)} pins kill their mutant", flush=True)
    out = HERE / "results" / "pin_kill_verification.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"results: {out}")
    sys.exit(0 if ok == len(todo) else 1)


if __name__ == "__main__":
    main()
