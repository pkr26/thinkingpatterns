import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("web_mutation_runner", Path(__file__).resolve().parents[1] / "run-mutation-shards.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class MutationEvidenceTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory) / "web"
        files = ["src/example.ts", "tests/__snapshots__/example.snap", "package.json", "package-lock.json",
                 "vite.config.ts", "tsconfig.json", "index.html", "stryker.config.json"]
        for name in files + ["../shared/vector.json", "../deploy/nginx/mindpattern.conf.example"]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("frozen input\n")
        return root

    def test_source_snapshots_and_shared_fixtures_are_independent_inputs(self):
        for name in ["src/example.ts", "tests/__snapshots__/example.snap", "../shared/vector.json"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                expected = RUNNER.input_manifest(root)
                RUNNER.verify_inputs(root, expected, "pristine")
                (root / name).write_text("changed by a test or mutant\n")
                with self.assertRaisesRegex(RuntimeError, "frozen source/oracle inputs changed"):
                    RUNNER.verify_inputs(root, expected, "after mutation")

    def test_a_new_oracle_or_shared_fixture_is_detected(self):
        for name in ["tests/unexpected.test.ts", "../shared/unexpected.json"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                expected = RUNNER.input_manifest(root)
                (root / name).write_text("new input\n")
                with self.assertRaises(RuntimeError):
                    RUNNER.verify_inputs(root, expected, "after baseline")

    def test_score_exit_is_separate_from_an_abnormal_or_partial_run(self):
        source = "export const value = 1;"
        source_hash = hashlib.sha256(source.encode()).hexdigest()
        report = {"files": {"src/example.ts": {"source": source, "mutants": [{"status": "Survived"}]}}}
        self.assertEqual(RUNNER.validate_report(report, "src/example.ts", source_hash, 1, 55), {"Survived": 1})
        report["files"]["src/example.ts"]["mutants"][0]["status"] = "Killed"
        with self.assertRaisesRegex(RuntimeError, "runner exit"):
            RUNNER.validate_report(report, "src/example.ts", source_hash, 1, 55)
        report["files"]["src/example.ts"]["mutants"][0]["status"] = "Pending"
        with self.assertRaisesRegex(RuntimeError, "unfinished"):
            RUNNER.validate_report(report, "src/example.ts", source_hash, 0, 55)
        with self.assertRaisesRegex(RuntimeError, "frozen input"):
            RUNNER.validate_report(report, "src/example.ts", "0" * 64, 0, 55)


if __name__ == "__main__":
    unittest.main()
