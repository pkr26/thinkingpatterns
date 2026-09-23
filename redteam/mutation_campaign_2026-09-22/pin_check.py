#!/usr/bin/env python3
"""Hand-verification: every round-4 pin must FAIL under its own mutant.

For each (mutant, pin) pair: apply the exact campaign mutation, run the pin
node, require a failure, restore byte-wise. A pin that passes under its
mutant guards nothing.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent

PIN_FILE = "tests/test_mutation_round4_pins.py"

# mutant id -> the pin test node that must fail under it
PINS: dict[str, str] = {
    "U7": "test_totp_enable_consumes_its_timestep",
    "U8": "test_totp_disable_refuses_the_code_that_just_logged_in",
    "V1": "test_measure_quota_is_enforced_at_the_boundary",
    "V8": "test_measure_create_fails_closed_when_revision_cannot_advance",
    "V9": "test_measure_page_fails_closed_when_the_collection_moves_mid_read",
    "V11": "test_therapist_measure_mirror_fails_closed_when_the_collection_moves",
    "V12": "test_therapist_measure_mirror_enforces_the_byte_budget_post_fetch",
    "W7": "test_note_revisions_read_is_therapist_scoped",
    "W8": "test_note_revisions_arrive_newest_first",
    "W9": "test_note_revisions_page_ceiling_is_two_hundred",
    "X4": "test_entry_aad_v2_binds_the_content_version",
    "X5": "test_rekey_re_encrypts_under_the_v2_aad",
    "Y2": "test_temporal_narrowing_needs_three_tod_entries",
    "Y4": "test_temporal_narrowing_includes_the_exact_dominance_bar",
    "Y8": "test_short_corpora_keep_the_english_default",
    "Z3": "test_access_log_cursor_tiebreaks_on_id_within_one_timestamp",
    "Z4": "test_therapist_access_log_is_actor_scoped",
    "Z6": "test_wrap_key_rotation_refuses_deactivated_accounts",
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
