"""Check actual red-team verdicts against good and deliberately bad controls."""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "redteam"))
spec = importlib.util.spec_from_file_location("audit_infra_oracle", ROOT / "redteam/g_infra.py")
infra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(infra)


def test_backup_oracle_executes_helper_independent_of_formatting(tmp_path):
    original = (ROOT / "backup/backup_mac.py").read_text()
    reformatted = tmp_path / "reformatted.py"
    reformatted.write_text(ast.unparse(ast.parse(original)))
    assert infra._backup_helper_contract(reformatted)
    weakened = tmp_path / "weakened.py"
    assert original.count('"600000"') == 1
    weakened.write_text(original.replace('"600000"', '"1"'))
    assert not infra._backup_helper_contract(weakened)


def test_complete_staging_boot_and_single_fault_refusals(monkeypatch):
    rows = []
    monkeypatch.setattr(infra, "verdict", lambda *row: rows.append(row))
    infra.g3_config_and_hygiene()
    config_rows = [
        row
        for row in rows
        if row[0].startswith("G3.")
        and "secret" in row[0]
        or row[0]
        in {
            "G3.prod-sqlite",
            "G3.prod-http-llm-url",
            "G3.typo-env-fails-closed",
            "G3.staging-valid-boots-under-prod-gates",
        }
    ]
    assert len(config_rows) == 7  # six boot controls plus tracked-secret hygiene
    assert all(row[1] == "BLOCKED" for row in config_rows), config_rows
    positive = next(row for row in rows if row[0] == "G3.staging-valid-boots-under-prod-gates")
    assert "booted" in positive[2]


def test_unrelated_config_failure_cannot_satisfy_expected_refusal(monkeypatch):
    rows = []
    monkeypatch.setattr(infra, "verdict", lambda *row: rows.append(row))
    infra._boot_check(
        "wrong-fault",
        {"MINDPATTERN_ENV": "production", "MINDPATTERN_TOKEN_SECRET": "short"},
        True,
        "MINDPATTERN_LLM_URL",
    )
    assert rows[0][1] == "FINDING"
