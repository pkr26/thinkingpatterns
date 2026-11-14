"""Oracle plans require exact source identity and real collected test targets."""

import gzip
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "backend_plan", ROOT / "redteam/prepare_automatic_backend_plan.py"
)
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


class BackendPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "snapshot"
        (self.snapshot / "backend/app").mkdir(parents=True)
        (self.snapshot / "backend/tests").mkdir()
        self.source = "def allowed():\n    return 10 + 20\n"
        self.target = self.snapshot / "backend/app/logic.py"
        self.target.write_text(self.source)
        self.oracle = self.snapshot / "backend/tests/test_logic.py"
        self.oracle.write_text(
            "def test_allowed():\n    assert True\n"
            "def test_other():\n    assert True\n"
            "def test_models_pass_the_existing_backend_static_typecheck_gate():\n    assert True\n"
        )
        self.row = {
            "id": "CURRENT-1",
            "file": "app/logic.py",
            "line": 2,
            "index": 0,
            "position": self.source.index("10"),
            "before": "10",
            "after": "11",
        }
        self.archive = self.root / "archive"
        self.archive.mkdir()

    def write_archive(self, entries):
        rows, accepted = [], []
        for index, (row, status, selectors) in enumerate(entries):
            archived = {**row, "id": f"OLD-{index}", "status": status}
            rows.append(archived)
            if status == "INVALID_SYNTAX":
                continue
            accepted.append(
                {
                    "kind": "accepted",
                    "id": archived["id"],
                    "global_status": status,
                    "record": {
                        **archived,
                        "selectors": selectors,
                        "failures": [{"phase": "call", "nodeid": selectors[0]}]
                        if status != "REVIEWED_EQUIVALENT"
                        else [],
                    },
                }
            )
        ledger = {
            "rows": rows,
            "current_production_sha256": {
                "app/logic.py": hashlib.sha256(self.source.encode()).hexdigest()
            },
        }
        (self.archive / "ledger.json.gz").write_bytes(gzip.compress(json.dumps(ledger).encode()))
        (self.archive / "accepted-evidence.jsonl.gz").write_bytes(
            gzip.compress("".join(json.dumps(row) + "\n" for row in accepted).encode())
        )

    def prepare(self, rows=None):
        return planner.prepare(self.snapshot, rows or [self.row], self.archive)

    def test_current_numeric_id_is_irrelevant_when_source_and_patch_match(self):
        self.write_archive([(self.row, "KILLED", ["tests/test_logic.py::test_allowed"])])
        plan, details, summary = self.prepare()
        self.assertEqual(plan, {"CURRENT-1": ["tests/test_logic.py::test_allowed"]})
        self.assertEqual(summary["gaps"], [])
        self.assertEqual(details[0]["method"], "archived_runtime_failure")
        self.assertTrue(summary["fresh_pristine_baselines_required"])
        self.assertFalse(summary["mutation_execution"])

    def test_source_hash_mismatch_refuses_archived_oracle_even_for_identical_patch(self):
        self.write_archive([(self.row, "KILLED", ["tests/test_logic.py::test_allowed"])])
        self.target.write_text(self.source + "# current implementation changed\n")
        plan, _, summary = self.prepare()
        self.assertEqual(plan, {})
        self.assertEqual(len(summary["gaps"]), 1)

    def test_changed_source_can_use_current_measured_runtime_contexts(self):
        self.write_archive([(self.row, "KILLED", ["tests/test_logic.py::test_allowed"])])
        self.target.write_text(self.source + "# current implementation changed\n")
        with mock.patch.object(
            planner,
            "coverage_index",
            return_value=({"app/logic.py": {2: ["tests/test_logic.py::test_other"]}}, {}),
        ):
            plan, details, summary = self.prepare()
        self.assertEqual(plan["CURRENT-1"], ["tests/test_logic.py::test_other"])
        self.assertEqual(details[0]["method"], "current_runtime_line_contexts")
        self.assertFalse(details[0]["archive_source_aligned"])

    def test_static_only_and_invalid_controls_receive_neighboring_real_behavior(self):
        static = {
            **self.row,
            "id": "CURRENT-2",
            "position": self.source.index("20"),
            "before": "20",
            "after": "None",
        }
        invalid = {
            **self.row,
            "id": "CURRENT-3",
            "position": self.source.index("+"),
            "before": "+",
            "after": "",
        }
        self.write_archive(
            [
                (self.row, "KILLED", ["tests/test_logic.py::test_allowed"]),
                (
                    static,
                    "STATIC_TYPECHECK_CAUGHT",
                    [
                        "tests/test_logic.py::test_models_pass_the_existing_backend_static_typecheck_gate"
                    ],
                ),
                (invalid, "INVALID_SYNTAX", []),
            ]
        )
        plan, details, summary = self.prepare([self.row, static, invalid])
        self.assertEqual(len(plan), 3)
        self.assertEqual(summary["gaps"], [])
        for row in details[1:]:
            self.assertEqual(row["method"], "neighboring_function_behavior")
            self.assertEqual(row["selectors"], ["tests/test_logic.py::test_allowed"])

    def test_duplicate_ids_and_stale_patches_are_rejected(self):
        self.write_archive([(self.row, "KILLED", ["tests/test_logic.py::test_allowed"])])
        with self.assertRaisesRegex(ValueError, "unique"):
            self.prepare([self.row, self.row])
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.prepare([{**self.row, "before": "obsolete"}])

    def test_missing_symbol_empty_file_static_and_escape_are_rejected(self):
        (self.snapshot / "backend/tests/empty.py").write_text("value = 1\n")
        for value in [
            "tests/test_logic.py::test_deleted",
            "tests/empty.py",
            "tests/test_logic.py::test_models_pass_the_existing_backend_static_typecheck_gate",
            "../../outside.py",
        ]:
            with self.subTest(selector=value), self.assertRaises(ValueError):
                planner.validate_selector(self.snapshot, value)

    def test_retired_archived_selector_is_reported_and_never_included_in_plan(self):
        self.write_archive(
            [
                (
                    self.row,
                    "REVIEWED_EQUIVALENT",
                    ["tests/test_logic.py::test_retired", "tests/test_logic.py::test_allowed"],
                )
            ]
        )
        plan, _, summary = self.prepare()
        self.assertEqual(plan["CURRENT-1"], ["tests/test_logic.py::test_allowed"])
        self.assertEqual(len(summary["unavailable_archived_oracles"]), 1)

    def test_fileless_failure_is_resolved_only_to_an_existing_selected_oracle(self):
        self.assertEqual(
            planner.node_selector(
                self.snapshot, "::test_allowed", ["tests/test_logic.py", "tests/absent.py"]
            ),
            "tests/test_logic.py::test_allowed",
        )
        self.assertIsNone(
            planner.node_selector(self.snapshot, "::test_missing", ["tests/test_logic.py"])
        )

    def test_collection_verifies_every_planned_selector_and_refuses_zero_tests(self):
        plan = {"A": ["tests/test_logic.py::test_allowed"], "B": ["tests/test_logic.py"]}
        result = mock.Mock(returncode=0, stdout="tests/test_logic.py::test_allowed\n")
        with mock.patch.object(planner.subprocess, "run", return_value=result):
            report = planner.verify_collection(
                self.snapshot, plan, self.root / "collect.log", Path("python")
            )
        self.assertEqual(report["verified_selectors"], 2)
        result.stdout = "no tests collected\n"
        with (
            mock.patch.object(planner.subprocess, "run", return_value=result),
            self.assertRaisesRegex(ValueError, "zero tests"),
        ):
            planner.verify_collection(self.snapshot, plan, self.root / "empty.log", Path("python"))

    def test_collection_errors_never_validate_a_plan(self):
        result = mock.Mock(returncode=2, stdout="collection error\n")
        with (
            mock.patch.object(planner.subprocess, "run", return_value=result),
            self.assertRaisesRegex(ValueError, "collection failed"),
        ):
            planner.verify_collection(
                self.snapshot,
                {"A": ["tests/test_logic.py"]},
                self.root / "error.log",
                Path("python"),
            )

    def test_collection_refreshes_changed_parameter_labels_to_current_behavioral_family(self):
        plan = {"A": ["tests/test_logic.py::test_allowed[old]"]}
        result = mock.Mock(returncode=0, stdout="tests/test_logic.py::test_allowed[current]\n")
        with mock.patch.object(planner.subprocess, "run", return_value=result):
            report = planner.verify_collection(
                self.snapshot, plan, self.root / "parameters.log", Path("python")
            )
        self.assertEqual(plan["A"], ["tests/test_logic.py::test_allowed"])
        self.assertEqual(
            report["refreshed_parameter_selectors"],
            {"tests/test_logic.py::test_allowed[old]": "tests/test_logic.py::test_allowed"},
        )

    def test_coverage_uses_only_executed_call_contexts_from_matching_source(self):
        data = mock.Mock()
        data.measured_files.return_value = [str(self.target)]
        data.contexts_by_lineno.return_value = {
            2: [
                "tests/test_logic.py::test_allowed|run",
                "tests/test_logic.py::test_other|setup",
                "tests/test_logic.py::test_other|teardown",
            ]
        }
        with mock.patch("coverage.CoverageData", return_value=data):
            index, excluded = planner.coverage_index(
                self.root / ".coverage", self.snapshot, {"app/logic.py"}
            )
        self.assertEqual(index, {"app/logic.py": {2: ["tests/test_logic.py::test_allowed"]}})
        self.assertEqual(excluded, {})
        measured = self.root / "other/backend/app/logic.py"
        measured.parent.mkdir(parents=True)
        measured.write_text(self.source + "# different measured source\n")
        data.measured_files.return_value = [str(measured)]
        with mock.patch("coverage.CoverageData", return_value=data):
            index, excluded = planner.coverage_index(
                self.root / ".coverage", self.snapshot, {"app/logic.py"}
            )
        self.assertEqual(index, {})
        self.assertIn("app/logic.py", excluded)


if __name__ == "__main__":
    unittest.main()
