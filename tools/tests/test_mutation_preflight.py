"""OPS-02: applicability is read-only, and broken oracles never count as kills."""

import contextlib
import fnmatch
import importlib.util
import io
import json
import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "redteam"))
from mutation_preflight import ApplicabilityError, inventory, validate_mutant
from mutation_oracles import oracle_setup_error, redteam_baseline_error
import run_pr_mutation_gate as gate


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        (self.root / "backend/tests").mkdir(parents=True)
        (self.root / "backend/target.py").write_text("def allowed():\n    return True\n")
        (self.root / "backend/tests/test_target.py").write_text(
            "class TestGate:\n    def test_allowed(self):\n        assert True\n"
        )
        self.mutant = {
            "id": "Q1",
            "campaign": "Q",
            "name": "disable gate",
            "file": "backend/target.py",
            "find": "    return True",
            "replace": "    return False",
            "tests": {
                "cwd": "backend",
                "kind": "pytest",
                "cmd": [
                    sys.executable,
                    "-m",
                    "pytest",
                    "tests/test_target.py::TestGate::test_allowed",
                ],
                "timeout": 10,
            },
        }

    def snapshot(self):
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }

    def test_current_selector_and_anchor_pass_without_any_file_change(self):
        before = self.snapshot()
        self.assertEqual(validate_mutant(self.root, self.mutant)["status"], "APPLICABLE")
        self.assertEqual(before, self.snapshot())

    def test_stale_ambiguous_noop_and_invalid_python_mutations_fail_without_writing(self):
        before = self.snapshot()
        for changes in (
            {"find": "obsolete anchor"},
            {"replace": "    return True"},
            {"replace": "    return ("},
            {"count": 2},
            {"count": True},
        ):
            with self.subTest(changes=changes), self.assertRaises(ApplicabilityError):
                validate_mutant(self.root, {**self.mutant, **changes})
        path = self.root / "backend/target.py"
        path.write_text(path.read_text() + "\ndef second():\n    return True\n")
        with self.assertRaisesRegex(ApplicabilityError, "matched 2"):
            validate_mutant(self.root, self.mutant)
        path.write_bytes(before["backend/target.py"])
        self.assertEqual(before, self.snapshot())

    def test_deleted_or_renamed_test_selectors_fail(self):
        for selector in [
            "tests/gone.py",
            "tests/test_target.py::Renamed",
            "tests/test_target.py::TestGate::test_gone",
        ]:
            changed = {
                **self.mutant,
                "tests": {
                    **self.mutant["tests"],
                    "cmd": [sys.executable, "-m", "pytest", selector],
                },
            }
            with self.subTest(selector=selector), self.assertRaises(ApplicabilityError):
                validate_mutant(self.root, changed)

    def test_malformed_json_and_wildcard_redteam_selector_are_setup_errors(self):
        (self.root / "backend/fixture.json").write_text('{"floor": 100}')
        invalid_json = {
            **self.mutant,
            "file": "backend/fixture.json",
            "find": "100",
            "replace": "undefined",
        }
        with self.assertRaisesRegex(ApplicabilityError, "invalid JSON"):
            validate_mutant(self.root, invalid_json)
        wildcard = {
            **self.mutant,
            "tests": {
                **self.mutant["tests"],
                "kind": "redteam",
                "cmd": [sys.executable, "tests/test_target.py"],
                "oracle": [""],
            },
        }
        with self.assertRaisesRegex(ApplicabilityError, "audit selectors"):
            validate_mutant(self.root, wildcard)

    def test_inventory_rejects_duplicates_empty_lists_and_path_escape(self):
        self.assertEqual(
            inventory(self.root, [self.mutant, self.mutant])[1]["status"], "SETUP-ERROR"
        )
        with self.assertRaises(ApplicabilityError):
            inventory(self.root, [])
        for changes in (
            {"id": []},
            {"id": ""},
            {"file": "../outside.py"},
            {"tests": []},
            {"tests": {**self.mutant["tests"], "kind": "unknown"}},
        ):
            self.assertEqual(
                inventory(self.root, [{**self.mutant, **changes}])[0]["status"], "SETUP-ERROR"
            )

    def test_diff_of_a_test_or_harness_selects_its_controls(self):
        self.assertTrue(gate.affected(self.mutant, {"backend/tests/test_target.py"}))
        self.assertTrue(gate.affected(self.mutant, {"redteam/mutation_preflight.py"}))
        self.assertFalse(gate.affected(self.mutant, {"README.md"}))

    def test_shared_backend_helpers_and_fixtures_select_backend_oracles(self):
        client = {
            **self.mutant,
            "file": "mobile/src/target.ts",
            "tests": {
                "cwd": "mobile",
                "kind": "vitest",
                "cmd": ["npx", "vitest", "run", "tests/target.test.ts"],
            },
        }
        for shared in [
            "backend/tests/helpers.py",
            "backend/tests/conftest.py",
            "backend/tests/fixtures/conftest.py",
            "backend/tests/support/auth.py",
            "backend/tests/__init__.py",
        ]:
            with self.subTest(shared=shared):
                self.assertTrue(gate.affected(self.mutant, {shared}))
                self.assertFalse(gate.affected(client, {shared}))
        for unrelated in ["backend/tests/README.md", "backend/tests/test_unrelated.py"]:
            with self.subTest(unrelated=unrelated):
                self.assertFalse(gate.affected(self.mutant, {unrelated}))

        # Exercise the diff entrypoint too: helper-only changes must run the
        # selected baseline and mutant instead of reporting zero controls.
        runner = mock.Mock()
        runner.run_command.return_value = (False, None, [], "1 passed", 0.0)
        runner.run_mutant.return_value = {"status": "KILLED", "killed": True}
        with (
            mock.patch.object(gate, "ROOT", self.root),
            mock.patch.object(gate, "load_harnesses", return_value=([self.mutant], runner)),
            mock.patch.object(sys, "stdin", io.StringIO("backend/tests/helpers.py\n")),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.main(["-"]), 0)
        runner.run_command.assert_called_once_with(self.mutant["tests"], "baseline")
        runner.run_mutant.assert_called_once_with(self.mutant)

    def test_shared_runner_config_and_redteam_common_select_only_their_oracles(self):
        redteam = {
            **self.mutant,
            "tests": {
                "cwd": ".",
                "kind": "redteam",
                "cmd": [sys.executable, "redteam/b_auth.py"],
            },
        }
        self.assertTrue(gate.affected(redteam, {"redteam/common.py"}))
        self.assertFalse(gate.affected(self.mutant, {"redteam/common.py"}))
        for config in gate.BACKEND_PYTEST_CONFIG:
            with self.subTest(config=config):
                self.assertTrue(gate.affected(self.mutant, {config}))
                self.assertFalse(gate.affected(redteam, {config}))
        mixed = {**self.mutant, "tests": [redteam["tests"], self.mutant["tests"]]}
        self.assertTrue(gate.affected(mixed, {"redteam/common.py"}))
        self.assertTrue(gate.affected(mixed, {"backend/pyproject.toml"}))
        self.assertFalse(gate.affected(mixed, {"backend/README.md"}))

    def test_client_helpers_configuration_and_dependencies_select_client_oracles(self):
        for client in ("mobile", "portal"):
            control = {
                **self.mutant,
                "file": f"{client}/src/target.ts",
                "tests": {
                    "cwd": client,
                    "kind": "vitest",
                    "cmd": ["npx", "vitest", "run", "tests/target.test.ts"],
                },
            }
            for support in (
                "tests/helpers/setup.ts", "tests/helpers/nodeEngine.ts",
                "vitest.config.ts", "vite.config.ts", "tsconfig.json",
                "package.json", "package-lock.json", ".npmrc",
            ):
                with self.subTest(client=client, support=support):
                    self.assertTrue(gate.affected(control, {f"{client}/{support}"}))
                    self.assertFalse(gate.affected(self.mutant, {f"{client}/{support}"}))
            self.assertFalse(gate.affected(control, {f"{client}/README.md"}))

    def test_gate_workflow_and_runtime_changes_select_all_controls(self):
        for path in (".github/workflows/mutation-pr.yml", ".nvmrc"):
            with self.subTest(path=path):
                self.assertTrue(gate.affected(self.mutant, {path}))

    def test_workflow_triggers_cover_client_oracle_support(self):
        workflow = (ROOT / ".github/workflows/mutation-pr.yml").read_text()
        paths = re.findall(r'^\s+- "([^"]+)"\s*$', workflow, re.M)
        for changed in (
            "mobile/tests/helpers/nodeEngine.ts", "portal/tests/helpers/setup.ts",
            "mobile/vitest.config.ts", "mobile/redteam.vitest.config.ts",
            "portal/vite.config.ts", "mobile/tsconfig.json", "portal/tsconfig.json",
            "mobile/package-lock.json", "portal/package.json", "mobile/.npmrc",
            ".nvmrc", ".github/workflows/mutation-pr.yml",
            "backend/requirements.dev.lock.txt", "backend/requirements.lock.txt",
            "backend/requirements.in", "backend/uv.lock",
        ):
            with self.subTest(changed=changed):
                self.assertTrue(any(fnmatch.fnmatchcase(changed, pattern) for pattern in paths))

    def test_python_dependency_changes_select_all_python_oracle_kinds(self):
        for kind in ("pytest", "probe", "redteam"):
            control = {**self.mutant, "tests": {**self.mutant["tests"], "kind": kind}}
            for path in ("backend/requirements.dev.lock.txt", "backend/requirements.lock.txt",
                         "backend/requirements.in", "backend/uv.lock"):
                with self.subTest(kind=kind, path=path):
                    self.assertTrue(gate.affected(control, {path}))

    def test_baseline_failure_prevents_mutation_and_old_residual_ids_get_no_exemption(self):
        runner = mock.Mock()
        runner.run_command.return_value = (True, None, [], "FAILED tests/test_target.py", 0.1)
        with (
            mock.patch.object(gate, "ROOT", self.root),
            mock.patch.object(gate, "load_harnesses", return_value=([self.mutant], runner)),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.main(["--all"]), 1)
        runner.run_mutant.assert_not_called()
        for identifier in ["I4", "J1", "N4", "N9", "O6", "S10"]:
            self.assertFalse(
                gate.verdict_passes({"id": identifier, "status": "SURVIVED", "killed": False})
            )
        for status in ["SETUP-ERROR", "RuntimeError", "CompileError", "UNKNOWN", "MISSED"]:
            self.assertFalse(gate.verdict_passes({"status": status, "killed": True}))

    def test_real_baseline_and_mutant_probe_run_then_restore_exact_bytes(self):
        _, runner = gate.load_harnesses()
        probe = self.root / "backend/probe.py"
        probe.write_text(
            "from target import allowed\nvalue = allowed()\nprint('  PASS gate' if value else '  FAIL gate')\nraise SystemExit(0 if value else 1)\n"
        )
        control = {
            **self.mutant,
            "tests": {
                "cwd": "backend",
                "cmd": [sys.executable, "probe.py"],
                "kind": "probe",
                "timeout": 10,
            },
        }
        before = (self.root / control["file"]).read_bytes()
        with mock.patch.object(runner, "ROOT", self.root):
            self.assertFalse(runner.run_command(control["tests"], "baseline")[0])
            result = runner.run_mutant(control)
            self.assertEqual(result["status"], "KILLED", result)
            self.assertTrue(result["killed"])
            self.assertEqual((self.root / control["file"]).read_bytes(), before)
            probe.write_text("this is invalid python !\n")
            self.assertEqual(runner.run_mutant(control)["status"], "SETUP-ERROR")
            self.assertEqual((self.root / control["file"]).read_bytes(), before)

    def test_all_direct_campaign_entrypoints_reject_bad_baselines_and_survivors(self):
        for relative in gate.HARNESS_GLOBS:
            specification = importlib.util.spec_from_file_location(
                "direct_campaign_control", ROOT / "redteam" / relative
            )
            module = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(module)
            for failed_baseline in [True, False]:
                runner = mock.Mock()
                runner.run_command.return_value = (
                    failed_baseline,
                    None,
                    [],
                    "FAILED test_target.py" if failed_baseline else "1 passed",
                    0.0,
                )
                runner.run_mutant.return_value = {
                    "id": self.mutant["id"],
                    "campaign": "Q",
                    "status": "SURVIVED",
                    "killed": False,
                    "commands": [],
                }
                with (
                    self.subTest(campaign=relative, failed_baseline=failed_baseline),
                    mock.patch.object(gate, "ROOT", self.root),
                    mock.patch.object(gate, "load_harnesses", return_value=([self.mutant], runner)),
                    mock.patch.object(module, "MUTANTS", [self.mutant]),
                    mock.patch.object(module, "OUT_DIR", self.root / "results"),
                    mock.patch.object(sys, "argv", ["harness.py"]),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    module.main()
                self.assertNotEqual(raised.exception.code, 0)
                if failed_baseline:
                    runner.run_mutant.assert_not_called()
                else:
                    runner.run_mutant.assert_called_once_with(self.mutant)

    def test_artifact_cleanup_error_cannot_strand_mutated_application_source(self):
        _, runner = gate.load_harnesses()
        result_path = self.root / "redteam/results/control.json"
        result_path.parent.mkdir(parents=True)
        result_path.write_text('{"baseline": true}')
        target = self.root / self.mutant["file"]
        original = target.read_bytes()
        write_bytes = pathlib.Path.write_bytes

        def fail_artifact_write(path, data):
            if path == result_path:
                raise OSError("controlled artifact restore failure")
            return write_bytes(path, data)

        with (
            mock.patch.object(runner, "ROOT", self.root),
            mock.patch.object(
                runner,
                "run_command",
                return_value=(True, None, ["test assertion"], "FAILED test_target.py", 0.0),
            ),
            mock.patch.object(pathlib.Path, "write_bytes", fail_artifact_write),
        ):
            with self.assertRaisesRegex(OSError, "artifact restore"):
                runner.run_mutant(self.mutant)
        self.assertEqual(target.read_bytes(), original)


class OracleClassificationTests(unittest.TestCase):
    def test_success_without_executed_passing_controls_is_not_a_baseline(self):
        for kind, output in (
            ("pytest", ""), ("pytest", "3 skipped in 0.01s"),
            ("vitest", ""), ("vitest", "Tests  3 skipped (3)"),
            ("probe", ""), ("probe", "diagnostic started"),
        ):
            with self.subTest(kind=kind, output=output):
                self.assertIsNotNone(oracle_setup_error(kind, 0, output))

    def test_executed_passing_controls_are_valid_baselines(self):
        for kind, output in (
            ("pytest", "3 passed in 0.01s"),
            ("pytest", "...s [100%]\n"),
            ("vitest", "Tests  3 passed | 1 skipped (4)"),
            ("probe", "  PASS planted association"),
            ("pytest", "\x1b[32m3 passed\x1b[0m in 0.1s"),
            ("vitest", "\x1b[2m Tests \x1b[22m \x1b[32m3 passed\x1b[39m (3)"),
        ):
            with self.subTest(kind=kind, output=output):
                self.assertIsNone(oracle_setup_error(kind, 0, output))

    def test_missing_malformed_or_error_verdicts_never_kill(self):
        for kind, code, output in [
            ("pytest", 5, "no tests ran"),
            ("pytest", 2, "collection failed"),
            ("pytest", 1, "FAILED test_a.py::test_one\nERROR test_a.py::test_two"),
            ("vitest", 1, "No test files found"),
            ("vitest", 1, "Transform failed"),
            ("vitest", 1, "Tests  1 failed | 2 passed (3)\nUnhandled Rejection"),
            ("redteam", 0, "AUDIT|example|ERROR|runner broken"),
            ("redteam", 1, "Traceback"),
            ("probe", 1, "SyntaxError"),
        ]:
            with self.subTest(kind=kind, output=output):
                self.assertIsNotNone(oracle_setup_error(kind, code, output))

    def test_actual_test_and_finding_failures_are_recognized(self):
        for kind, code, output in [
            ("pytest", 1, "FAILED tests/test_gate.py::test_gate - AssertionError"),
            (
                "pytest",
                1,
                "ERROR    mindpattern:middleware.py:714 unhandled request failure\nFAILED tests/test_gate.py::test_gate - assert 500 == 410",
            ),
            ("vitest", 1, "Tests  1 failed | 2 passed (3)"),
            ("probe", 1, "  FAIL planted association"),
            ("redteam", 0, "AUDIT|example|FINDING|control bypassed"),
        ]:
            with self.subTest(kind=kind):
                self.assertIsNone(oracle_setup_error(kind, code, output))

    def test_redteam_baseline_requires_the_selected_control_to_be_observed_blocked(self):
        spec = {"oracle": ["B1.wrong-verifier-rejected"]}
        unrelated = "AUDIT|B1.verifier-replay|FINDING|reusable password equivalent"
        blocked = "AUDIT|B1.wrong-verifier-rejected|BLOCKED|wrong proof rejected"
        self.assertIsNone(redteam_baseline_error(spec, unrelated + "\n" + blocked))
        for output in [
            unrelated,
            blocked.replace("BLOCKED", "FINDING"),
            blocked.replace("BLOCKED", "PARTIAL"),
            blocked.replace("BLOCKED", "ERROR"),
            blocked.replace("BLOCKED", "INFO"),
        ]:
            with self.subTest(output=output):
                self.assertIsNotNone(redteam_baseline_error(spec, output))
