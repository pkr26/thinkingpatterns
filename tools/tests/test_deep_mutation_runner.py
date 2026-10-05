"""Execution-level checks for honest isolated mutation evidence."""

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "deep_runner", ROOT / "redteam/deep_backend_mutation/runner.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@unittest.skipUnless(
    importlib.util.find_spec("pytest") is not None,
    "execution tests require locked pytest; backend CI runs this module explicitly",
)
class DeepMutationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def command(self, body):
        test = self.root / "test_oracle.py"
        test.write_text(body)
        return runner.run_command(
            self.root,
            {
                "cwd": ".",
                "kind": "pytest",
                "cmd": [sys.executable, "-m", "pytest", "-q", "test_oracle.py"],
                "timeout": 20,
            },
            self.root / "command.log",
        )[0]

    def test_passing_and_failing_assertions_have_distinct_real_verdicts(self):
        passed = self.command("def test_ok():\n    assert 2 + 2 == 4\n")
        self.assertIsNone(passed["setup_error"])
        self.assertEqual(passed["returncode"], 0)
        failed = self.command("def test_bad():\n    assert 2 + 2 == 5\n")
        self.assertIsNone(failed["setup_error"])
        self.assertEqual(failed["returncode"], 1)
        self.assertTrue(failed["failures"])

    def test_collection_failure_and_skipped_only_oracles_are_not_kills(self):
        for body in [
            "import unavailable_mutation_oracle\n",
            "import pytest\ndef test_skipped():\n    pytest.skip('unavailable')\n",
        ]:
            with self.subTest(body=body):
                self.assertIsNotNone(self.command(body)["setup_error"])

    def test_timeout_is_explicit_and_never_behavioral_credit(self):
        row, _ = runner.run_command(
            self.root,
            {
                "cwd": ".",
                "kind": "pytest",
                "cmd": [sys.executable, "-c", "import time; time.sleep(10)"],
                "timeout": 0.1,
            },
            self.root / "timeout.log",
        )
        self.assertTrue(row["timed_out"])
        self.assertEqual(row["setup_error"], "oracle timed out")

    def test_mutation_identity_changes_with_replacement_and_target(self):
        mutant = {"file": "a.py", "find": "True", "replace": "False"}
        self.assertEqual(
            runner.mutation_identity(mutant),
            runner.mutation_identity({**mutant, "count": 1}),
        )
        self.assertNotEqual(
            runner.mutation_identity(mutant),
            runner.mutation_identity({**mutant, "replace": "None"}),
        )
        self.assertNotEqual(
            runner.mutation_identity(mutant),
            runner.mutation_identity({**mutant, "file": "b.py"}),
        )

    def test_failed_baseline_prevents_all_mutation_writes(self):
        mutant = {
            "id": "TEST-1",
            "name": "test",
            "campaign": "TEST",
            "file": "logic.py",
            "find": "True",
            "replace": "False",
            "tests": {
                "cwd": ".",
                "kind": "pytest",
                "cmd": ["python", "-m", "pytest", "tests/test_logic.py"],
                "timeout": 10,
            },
        }
        files = {
            "logic.py": b"allowed = True\n",
            "tests/test_logic.py": b"def test_logic():\n    assert False\n",
        }
        failure = {"setup_error": None, "returncode": 1, "log": "failed-baseline.log"}
        with (
            mock.patch.object(runner, "snapshot_files", return_value=files),
            mock.patch.object(runner, "make_copy"),
            mock.patch.object(
                runner,
                "run_command",
                return_value=(failure, "FAILED tests/test_logic.py::test_logic"),
            ),
        ):
            self.assertEqual(
                runner.run_program(
                    [{"id": "TEST", "name": "test", "mutants": [mutant]}],
                    [mutant],
                    self.root / "evidence",
                    workers=1,
                ),
                1,
            )
        self.assertFalse((self.root / "evidence/results.jsonl").exists())

    def test_timeout_kills_child_before_it_can_write_late_artifact(self):
        marker = self.root / "late-child"
        started = self.root / "child-started"
        child = (
            "import time,pathlib; pathlib.Path("
            + repr(str(started))
            + ").write_text('started'); time.sleep(1); pathlib.Path("
            + repr(str(marker))
            + ").write_text('late')"
        )
        parent = (
            "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
            + repr(child)
            + "]); time.sleep(10)"
        )
        result, _ = runner.run_command(
            self.root,
            {
                "cwd": ".",
                "kind": "probe",
                "cmd": [str(pathlib.Path(sys.executable).resolve()), "-c", parent],
                "timeout": 0.5,
            },
            self.root / "child-timeout.log",
        )
        self.assertTrue(result["timed_out"])
        self.assertTrue(
            started.exists(), "the child must actually start before cleanup is credited"
        )
        time.sleep(1.1)
        self.assertFalse(marker.exists())

    def test_completed_leader_does_not_leave_child_writing_after_oracle(self):
        marker = self.root / "orphan-artifact"
        started = self.root / "orphan-started"
        child = (
            "import time,pathlib; pathlib.Path("
            + repr(str(started))
            + ").write_text('started'); time.sleep(1); pathlib.Path("
            + repr(str(marker))
            + ").write_text('late')"
        )
        parent = (
            "import subprocess,sys,pathlib,time; subprocess.Popen([sys.executable,'-c',"
            + repr(child)
            + "]);\nwhile not pathlib.Path("
            + repr(str(started))
            + ").exists(): time.sleep(0.01)\nprint('PASS behavior')"
        )
        result, _ = runner.run_command(
            self.root,
            {
                "cwd": ".",
                "kind": "probe",
                "cmd": [str(pathlib.Path(sys.executable).resolve()), "-c", parent],
                "timeout": 10,
            },
            self.root / "orphan.log",
        )
        self.assertIsNone(result["setup_error"])
        self.assertTrue(started.exists())
        time.sleep(1.1)
        self.assertFalse(marker.exists())

    def test_output_hash_is_exact_log_bytes_even_for_invalid_utf8(self):
        log = self.root / "binary.log"
        result, _ = runner.run_command(
            self.root,
            {
                "cwd": ".",
                "kind": "probe",
                "cmd": [
                    str(pathlib.Path(sys.executable).resolve()),
                    "-c",
                    "import os; os.write(1,b'PASS behavior\\n\\xff')",
                ],
                "timeout": 10,
            },
            log,
        )
        self.assertIsNone(result["setup_error"])
        self.assertEqual(
            result["output_sha256"], hashlib.sha256(log.read_bytes()).hexdigest()
        )

    def test_restore_preserves_dependencies_and_never_follows_generated_symlinks(self):
        worker = self.root / "worker"
        worker.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "logic.py").write_text("outside must stay unchanged")
        (worker / "app").symlink_to(outside, target_is_directory=True)
        (worker / ".venv").symlink_to(outside, target_is_directory=True)
        (worker / ".git").mkdir()
        (worker / ".git/config").write_text("keep git boundary")
        (worker / "generated.py").write_text("poisoned generated import")
        self.assertTrue(
            runner.restore_snapshot(worker, {"app/logic.py": b"frozen logic\n"})
        )
        self.assertEqual((worker / "app/logic.py").read_bytes(), b"frozen logic\n")
        self.assertFalse((worker / "generated.py").exists())
        self.assertTrue((worker / ".venv").is_symlink())
        self.assertEqual(
            (outside / "logic.py").read_text(), "outside must stay unchanged"
        )
        self.assertEqual((worker / ".git/config").read_text(), "keep git boundary")

    def test_workers_execute_every_control_from_frozen_source_and_restore_auxiliary_files(
        self,
    ):
        files = {
            "logic.py": b"allowed = True\n",
            "auxiliary.txt": b"frozen fixture\n",
            "oracle.py": b"import pathlib,sys\nallowed = 'True' in pathlib.Path('logic.py').read_text()\nprint('PASS behavior' if allowed else 'FAIL behavior')\nsys.exit(0 if allowed else 1)\n",
        }
        command = {
            "cwd": ".",
            "kind": "probe",
            "cmd": [str(pathlib.Path(sys.executable).resolve()), "oracle.py"],
            "timeout": 10,
        }
        mutants = [
            {
                "id": "FROZEN-1",
                "name": "first",
                "campaign": "FROZEN",
                "file": "logic.py",
                "find": "True",
                "replace": "False",
                "tests": command,
            },
            {
                "id": "FROZEN-2",
                "name": "second",
                "campaign": "FROZEN",
                "file": "logic.py",
                "find": "True",
                "replace": "None",
                "tests": command,
            },
        ]
        seen = []
        real_command = runner.run_command

        def observed_command(worker, spec, log):
            self.assertEqual(
                (worker / "auxiliary.txt").read_bytes(), files["auxiliary.txt"]
            )
            self.assertFalse((worker / "generated.py").exists())
            result = real_command(worker, spec, log)
            seen.append((worker / "logic.py").read_bytes())
            (worker / "auxiliary.txt").write_text("oracle poisoned fixture")
            (worker / "generated.py").write_text("oracle poisoned import")
            # The live checkout changing after freeze cannot affect workers.
            (self.root / "logic.py").write_text("live checkout changed")
            return result

        output = self.root / "evidence"
        runner.make_copy(self.root, files)
        with (
            mock.patch.object(runner, "ROOT", self.root),
            mock.patch.object(
                runner,
                "snapshot_files",
                side_effect=lambda: {
                    name: (self.root / name).read_bytes() for name in files
                },
            ),
            mock.patch.object(runner, "run_command", side_effect=observed_command),
        ):
            self.assertEqual(
                runner.run_program(
                    [{"id": "FROZEN", "name": "frozen", "mutants": mutants}],
                    mutants,
                    output,
                    workers=1,
                ),
                0,
            )
        self.assertEqual(
            seen, [b"allowed = True\n", b"allowed = False\n", b"allowed = None\n"]
        )
        rows = [
            json.loads(line)
            for line in (output / "results.jsonl").read_text().splitlines()
        ]
        self.assertEqual({row["id"] for row in rows}, {"FROZEN-1", "FROZEN-2"})
        self.assertTrue(
            all(row["restored"] and row["status"] == "KILLED" for row in rows)
        )
        copy = output / "copies/worker-1"
        self.assertEqual((copy / "logic.py").read_bytes(), files["logic.py"])
        self.assertEqual((copy / "auxiliary.txt").read_bytes(), files["auxiliary.txt"])
        self.assertFalse((copy / "generated.py").exists())

    def test_failed_auxiliary_restoration_prevents_mutation_credit(self):
        mutant = {
            "id": "RESTORE-1",
            "name": "restore",
            "campaign": "RESTORE",
            "file": "logic.py",
            "find": "True",
            "replace": "False",
            "tests": {
                "cwd": ".",
                "kind": "probe",
                "cmd": ["python", "oracle.py"],
                "timeout": 10,
            },
        }
        with (
            mock.patch.object(
                runner, "snapshot_files", return_value={"logic.py": b"allowed=True\n"}
            ),
            mock.patch.object(runner, "make_copy"),
            mock.patch.object(runner, "restore_snapshot", side_effect=[True, False]),
            mock.patch.object(
                runner,
                "run_command",
                return_value=(
                    {"returncode": 0, "setup_error": None, "log": "pass.log"},
                    "PASS behavior",
                ),
            ),
        ):
            output = self.root / "failed-restoration"
            result = runner.run_program(
                [{"id": "RESTORE", "name": "restore", "mutants": [mutant]}],
                [mutant],
                output,
                workers=1,
            )
        self.assertEqual(result, 1)
        self.assertFalse((output / "results.jsonl").exists())
        baselines = json.loads((output / "baselines.json").read_text())
        self.assertTrue(
            all(not row["passed"] and not row["restored"] for row in baselines.values())
        )

    def test_partial_selection_metadata_counts_only_executed_controls(self):
        spec = {
            "cwd": ".",
            "kind": "probe",
            "cmd": [str(pathlib.Path(sys.executable).resolve()), "oracle.py"],
            "timeout": 10,
        }
        mutant = {
            "id": "PART-1",
            "campaign": "PART",
            "name": "selected",
            "file": "logic.py",
            "find": "True",
            "replace": "False",
            "tests": spec,
        }
        files = {
            "logic.py": b"True\n",
            "oracle.py": b"import pathlib,sys\nallowed = 'True' in pathlib.Path('logic.py').read_text()\nprint('PASS behavior' if allowed else 'FAIL behavior')\nsys.exit(0 if allowed else 1)\n",
        }
        output = self.root / "partial"
        with mock.patch.object(runner, "snapshot_files", return_value=files):
            result = runner.run_program(
                [
                    {
                        "id": "PART",
                        "name": "subset",
                        "mutants": [mutant, {**mutant, "id": "PART-2"}],
                    }
                ],
                [mutant],
                output,
                workers=1,
            )
        self.assertEqual(result, 0)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["campaigns"][0]["mutants"], 1)
        self.assertEqual(len(manifest["mutants"]), 1)

    def test_empty_and_duplicate_control_ids_cannot_pass_vacuously(self):
        for mutants in ([], [{"id": "same"}, {"id": "same"}]):
            with self.subTest(mutants=mutants), self.assertRaises(ValueError):
                runner.run_program([], mutants, self.root / "invalid", workers=1)

    def test_postgres_resource_lock_serializes_same_database_including_baselines(self):
        active = 0
        peak = 0
        counter_lock = threading.Lock()
        ready = threading.Barrier(2)

        def operation():
            nonlocal active, peak
            ready.wait()
            with runner.command_resource_lock(
                {"DEEP_MUTATION_POSTGRES_URL": "postgresql://same-test-db"}
            ):
                with counter_lock:
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.1)
                with counter_lock:
                    active -= 1

        with mock.patch.object(runner, "ROOT", self.root):
            threads = [threading.Thread(target=operation) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
        self.assertEqual(peak, 1)


if __name__ == "__main__":
    unittest.main()
