"""Former documented mutation survivors must now fail the effective PR gate.

Campaign history is preserved as evidence. It no longer waives a surviving
security control, and an oracle error must never be reported as a kill.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "behavioral_mutation_gate", REPO_ROOT / "redteam/run_pr_mutation_gate.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def test_former_residuals_remain_in_inventory_but_have_no_gate_exemption():
    mutants, _ = gate.load_harnesses()
    ids = {mutant["id"] for mutant in mutants}
    for identifier in {"I4", "J1", "N4", "N9", "O6", "S10"}:
        assert identifier in ids
        assert not gate.verdict_passes({"id": identifier, "status": "SURVIVED", "killed": False})
        assert not gate.verdict_passes({"id": identifier, "status": "MISSED", "killed": False})
        assert gate.verdict_passes({"id": identifier, "status": "KILLED", "killed": True})


def test_only_genuine_terminal_kills_pass_the_gate():
    for status in {"SETUP-ERROR", "RuntimeError", "CompileError", "UNKNOWN", "SURVIVED", "MISSED"}:
        assert not gate.verdict_passes({"status": status, "killed": True})
    assert not gate.verdict_passes({"status": "KILLED", "killed": None})
    assert not gate.verdict_passes({"status": "CAUGHT", "killed": False})
