#!/usr/bin/env python3
"""Reject missing, empty, malformed or errored attack-campaign evidence.

FINDING/residual policy remains in the workflow; this shared runner check
ensures that every named campaign completed and emitted usable evidence.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

EXPECTED = frozenset({
    "a_crypto", "b_auth", "c_api", "e_crisis", "e2_brain", "g_infra",
    "g_voice", "h_privacy", "d_llm", "c1_multiworker", "f_mobile",
})
STATUSES = frozenset({"BLOCKED", "FINDING", "PARTIAL", "INFO", "NOT-RUN", "ERROR"})
INVENTORY = json.loads((Path(__file__).parent / "verdict_inventory.json").read_text(encoding="utf-8"))
# Only these environmental inspections may be unavailable. A unavailable
# dependency audit is still visible here; its separate CI supply-chain gate
# must pass. Attack scenarios themselves must execute.
ALLOWED_NOT_RUN = frozenset({"G1.dump-contents", "G2.npm-audit", "G2.pip-audit"})


def validate(directory: Path) -> list[dict]:
    seen = {path.stem for path in directory.glob("*.json")}
    if seen != EXPECTED:
        raise ValueError(f"campaign inventory mismatch: missing={sorted(EXPECTED-seen)}, unexpected={sorted(seen-EXPECTED)}")
    rows = []
    ids = set()
    for name in sorted(EXPECTED):
        campaign = json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
        if not isinstance(campaign, list) or not campaign:
            raise ValueError(f"empty/invalid campaign: {name}")
        campaign_ids = set()
        for row in campaign:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"] or row.get("status") not in STATUSES or not isinstance(row.get("summary"), str):
                raise ValueError(f"malformed verdict in {name}")
            if row["id"] in ids:
                raise ValueError(f"duplicate verdict id: {row['id']}")
            ids.add(row["id"])
            campaign_ids.add(row["id"])
            if row["status"] == "NOT-RUN" and row["id"] not in ALLOWED_NOT_RUN:
                raise ValueError(f"attack scenario did not run: {row['id']}")
            rows.append(row)
        expected_ids = set(INVENTORY[name])
        if campaign_ids != expected_ids:
            raise ValueError(f"verdict inventory mismatch in {name}: missing={sorted(expected_ids-campaign_ids)}, unexpected={sorted(campaign_ids-expected_ids)}")
    errors = [row["id"] for row in rows if row["status"] == "ERROR"]
    if errors:
        raise ValueError(f"campaign errors: {errors}")
    return rows


def main() -> int:
    try:
        rows = validate(Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parent / "results")
    except (OSError, ValueError, TypeError) as exc:
        print(f"invalid red-team evidence: {exc}", file=sys.stderr)
        return 1
    counts = Counter(row["status"] for row in rows)
    print(f"{len(rows)} verdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for row in rows:
        if row["status"] == "FINDING":
            print(f"  FINDING {row['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
