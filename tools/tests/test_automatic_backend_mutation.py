"""Check canonical operators and honest isolation in the automatic campaign."""

import ast
import importlib.util
import os
import pathlib
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "automatic_runner", ROOT / "redteam/run_automatic_backend_mutation.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@unittest.skipUnless(importlib.util.find_spec("mutmut"), "requires locked mutmut")
class AutomaticOperatorTests(unittest.TestCase):
    def test_every_operator_patch_matches_canonical_mutmut_bytes(self):
        import mutmut

        fixtures = [
            """from __future__ import annotations
import x
from x import y
@decorator("value")
def check(x: int=2, y: str="hello") -> bool:
    mapping = {"name": 4, "another": [1, 2, 3]}
    result = 2 + 4 * 3 - 1
    result /= 2
    match = x > 1 and y is not None or not x
    match = not not x
    if result:
        for number in range(3):
            if number <= 2:
                break
        while match:
            continue
    else:
        raise ValueError("bad")
    return True
""",
            "answer = 123",
            'answer = f(x=1, y=False, z="hello")\n',
            '@wrap("x")\n@functools.cache\ndef x():\n    return True\n',
            "number: int = 2\nmissing: int\nclass Thing:\n    value: str | None = None\n",
            '__all__ = ["hello"]\n__version__ = "1.0"\n__private__ = True\n',
            "answer = True # pragma: no mutate\nother = False\n",
            "answer = dict(hello=True, count=3)\n",
        ]
        for source in fixtures:
            with self.subTest(source=source):
                canonical = mutmut.list_mutations(
                    mutmut.Context(source=source, filename="fixture.py")
                )
                rows = runner.canonical_mutants(source, "fixture.py")
                self.assertEqual(len(rows), len(canonical))
                for row, identity in zip(rows, canonical, strict=True):
                    expected, count = mutmut.mutate(
                        mutmut.Context(
                            source=source, filename="fixture.py", mutation_id=identity
                        )
                    )
                    self.assertEqual(count, 1)
                    self.assertEqual(
                        (row["line"], row["index"]),
                        (identity.line_number + 1, identity.index),
                    )
                    position, before = row["position"], row["before"]
                    self.assertEqual(source[position : position + len(before)], before)
                    actual = (
                        source[:position]
                        + row["after"]
                        + source[position + len(before) :]
                    )
                    self.assertEqual(actual.replace(" not not ", " "), expected)

    def test_grouped_with_variants_preserve_ast_and_every_original_mutation(self):
        import mutmut

        fixtures = [
            'with (\n    opened("x") as f,\n    opened("y") as g,\n):\n    value = True\n',
            'with (\n    opened("x") as f,\n    opened("y") as g\n):\n    value = True\n',
            'with (opened("x") as f, opened("y") as g):\n    value = True\n',
            'with (opened("x") as f,\n      opened("y") as g):\n    value = True\n',
            'with (  # grouped resources\n    opened("x") as f,\n    opened("y") as g,\n):\n    value = True\n',
            'with (\n    opened("x") as f,  # first resource\n    opened("y") as g,\n):\n    value = True\n',
            'with (\n    opened("x") as f,\n\n    opened("y") as g,\n):\n    value = True\n',
            'async def call():\n    async with (\n        opened("x") as f,\n        opened("y") as g,\n    ):\n        value = True\n',
            'with (\n    opened(("x", "y")) as f,\n    opened("z") as g,\n):\n    value = True\n',
        ]
        for source in fixtures:
            with self.subTest(source=source):
                compatible, mapping = runner.parser_compatible_source(source)
                self.assertEqual(len(mapping), len(compatible))
                self.assertEqual(source.count("\n"), compatible.count("\n"))
                self.assertEqual(
                    ast.dump(ast.parse(source)), ast.dump(ast.parse(compatible))
                )
                canonical = mutmut.list_mutations(
                    mutmut.Context(source=compatible, filename="fixture.py")
                )
                rows = runner.canonical_mutants(source, "fixture.py")
                self.assertEqual(len(rows), len(canonical))
                for row, identity in zip(rows, canonical, strict=True):
                    expected, count = mutmut.mutate(
                        mutmut.Context(
                            source=compatible,
                            filename="fixture.py",
                            mutation_id=identity,
                        )
                    )
                    self.assertEqual(count, 1)
                    self.assertEqual(
                        (row["line"], row["index"]),
                        (identity.line_number + 1, identity.index),
                    )
                    position, before = row["position"], row["before"]
                    self.assertEqual(source[position : position + len(before)], before)
                    actual = (
                        source[:position]
                        + row["after"]
                        + source[position + len(before) :]
                    )
                    self.assertEqual(
                        ast.dump(ast.parse(actual)), ast.dump(ast.parse(expected))
                    )
                    for comment in ("# grouped resources", "# first resource"):
                        if comment in source:
                            self.assertIn(comment, actual)


class AutomaticRestorationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name) / "worker"
        self.root.mkdir()
        self.files = {
            "app/logic.py": b"allowed = True\n",
            "tests/test_logic.py": b"def test_ok():\n    assert True\n",
            "fixtures/value.json": b'{"limit": 12}\n',
        }
        for name, content in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.frozen = runner.FrozenFiles(self.root, self.files)

    def test_source_oracle_and_auxiliary_changes_restore_before_next_control(self):
        for name in self.files:
            (self.root / name).write_text("changed\n")
        (self.root / "poison.py").write_text("raise RuntimeError('generated import')\n")
        self.assertTrue(self.frozen.restore())
        for name, content in self.files.items():
            self.assertEqual((self.root / name).read_bytes(), content)
        self.assertFalse((self.root / "poison.py").exists())

    def test_auxiliary_same_size_same_timestamp_changes_cannot_poison_next_control(
        self,
    ):
        path = self.root / "fixtures/value.json"
        original_stat = path.stat()
        path.write_bytes(b'{"limit": 99}\n')
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        self.assertTrue(self.frozen.restore())
        self.assertEqual(path.read_bytes(), self.files["fixtures/value.json"])

    def test_generated_bytecode_is_removed_without_entering_shared_dependencies(self):
        cache = self.root / "app/__pycache__"
        cache.mkdir()
        (cache / "logic.cpython-314.pyc").write_bytes(b"poisoned compiled source")
        dependency_cache = self.root / ".venv/lib/__pycache__"
        dependency_cache.mkdir(parents=True)
        dependency = dependency_cache / "dependency.pyc"
        dependency.write_bytes(b"shared dependency")
        self.assertTrue(self.frozen.restore())
        self.assertFalse(cache.exists())
        self.assertEqual(dependency.read_bytes(), b"shared dependency")

    def test_generated_symlinks_are_removed_and_parents_cannot_redirect_restoration(
        self,
    ):
        outside = pathlib.Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "logic.py").write_text("outside must remain untouched\n")
        (self.root / "app/logic.py").unlink()
        (self.root / "app").rmdir()
        (self.root / "app").symlink_to(outside, target_is_directory=True)
        (self.root / "poison.py").symlink_to(outside / "logic.py")
        (self.root / ".venv").symlink_to(outside, target_is_directory=True)
        self.assertTrue(self.frozen.restore())
        self.assertEqual(
            (outside / "logic.py").read_text(), "outside must remain untouched\n"
        )
        self.assertFalse((self.root / "app").is_symlink())
        self.assertEqual(
            (self.root / "app/logic.py").read_bytes(), self.files["app/logic.py"]
        )
        self.assertFalse((self.root / "poison.py").is_symlink())
        self.assertTrue((self.root / ".venv").is_symlink())


@unittest.skipUnless(
    hasattr(os, "fork")
    and importlib.util.find_spec("pytest")
    and importlib.util.find_spec("pytest_asyncio"),
    "execution tests require fork and locked pytest plugins",
)
class AutomaticOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        environment = mock.patch.dict(
            os.environ,
            {
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "MINDPATTERN_ENV": "development",
            },
        )
        environment.start()
        self.addCleanup(environment.stop)
        # Match the production fork parent: pytest may be preloaded, app may not.
        original_bytecode_setting = sys.dont_write_bytecode
        self.addCleanup(setattr, sys, "dont_write_bytecode", original_bytecode_setting)
        runner.preload()

    def command(self, body, name="oracle", timeout=20):
        test = self.root / "test_oracle.py"
        test.write_text(body)
        return runner.pytest_child(
            self.root, [test.name], self.root / f"{name}.log", timeout
        )

    def test_reporter_separates_call_failures_from_collection_setup_and_teardown(self):
        reporter = runner.Reporter()
        reporter.pytest_collectreport(
            SimpleNamespace(
                failed=True, nodeid="test_bad.py", longrepr="missing module"
            )
        )
        for phase in ("setup", "call", "teardown"):
            reporter.pytest_runtest_logreport(
                SimpleNamespace(
                    failed=True,
                    when=phase,
                    nodeid="test_bad.py::test_bad",
                    longrepr="failure",
                    skipped=False,
                    passed=False,
                )
            )
        self.assertEqual([row["phase"] for row in reporter.failures], ["call"])
        self.assertEqual(
            [row["phase"] for row in reporter.errors],
            ["collection", "setup", "teardown"],
        )

    def test_only_actual_call_failures_are_kills(self):
        cases = [
            ("def test_ok():\n    assert True\n", "SURVIVED"),
            ("def test_bad():\n    assert False\n", "KILLED"),
            ("import unavailable_mutation_oracle\n", "ORACLE_ERROR"),
            (
                "import pytest\n@pytest.fixture\ndef fixture():\n    raise RuntimeError('setup')\ndef test_ok(fixture):\n    assert True\n",
                "ORACLE_ERROR",
            ),
            (
                "import pytest\ndef test_skipped():\n    pytest.skip('unavailable')\n",
                "ORACLE_ERROR",
            ),
            ("value = 1\n", "ORACLE_ERROR"),
        ]
        for index, (body, status) in enumerate(cases):
            with self.subTest(status=status, body=body):
                row = self.command(body, f"oracle-{index}")
                self.assertEqual(row["status"], status)
                self.assertFalse(row["timed_out"])
                if status == "KILLED":
                    self.assertTrue(row["failures"])
                    self.assertFalse(row["errors"])

    def test_source_inventory_failures_cannot_earn_runtime_credit(self):
        for name in runner.NON_BEHAVIORAL_TESTS:
            record = {"phase": "call", "nodeid": f"tests/{name}::test_inventory"}
            self.assertFalse(runner.is_behavior_failure(record))
        self.assertTrue(
            runner.is_behavior_failure(
                {"phase": "call", "nodeid": "tests/test_wire.py::test_response"}
            )
        )
        row = self.command(
            "def test_es_function_words_carry_no_duplicate_literals():\n    assert False\n",
            "source-inventory",
        )
        self.assertEqual(row["status"], "NON_BEHAVIORAL_FAILURE")
        self.assertEqual(row["behavior_failures"], [])
        mixed = self.command(
            "def test_actual_response():\n    assert False\n"
            "def test_es_function_words_carry_no_duplicate_literals():\n    assert False\n",
            "mixed-evidence",
        )
        self.assertEqual(mixed["status"], "KILLED")
        self.assertEqual(len(mixed["behavior_failures"]), 1)

    def test_each_control_imports_application_from_its_fresh_child(self):
        package = self.root / "app"
        package.mkdir()
        (package / "__init__.py").write_text("")
        source = package / "logic.py"
        oracle = "def test_allowed():\n    from app.logic import allowed\n    assert allowed\n"
        for index, (allowed, status) in enumerate(
            [(True, "SURVIVED"), (False, "KILLED"), (True, "SURVIVED")]
        ):
            source.write_text(f"allowed = {allowed}\n")
            self.assertEqual(self.command(oracle, f"fresh-{index}")["status"], status)
        self.assertNotIn("app.logic", sys.modules)

    def test_preload_disables_bytecode_in_the_already_running_interpreter(self):
        with (
            mock.patch.object(sys, "dont_write_bytecode", False),
            mock.patch.dict(os.environ, {"PYTHONDONTWRITEBYTECODE": "0"}),
        ):
            runner.preload()
            self.assertTrue(sys.dont_write_bytecode)
            self.assertEqual(os.environ["PYTHONDONTWRITEBYTECODE"], "1")

    def test_same_second_same_length_variants_import_their_actual_current_value(self):
        package = self.root / "app"
        package.mkdir()
        (package / "__init__.py").write_text("")
        source = package / "logic.py"
        source.write_text("value = 0\n")
        original_stat = source.stat()
        frozen = runner.FrozenFiles(
            self.root,
            {"app/__init__.py": b"", "app/logic.py": source.read_bytes()},
        )
        for value in (0, 1, 2):
            source.write_text(f"value = {value}\n")
            os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            body = f"def test_value():\n    from app.logic import value\n    assert value == {value}\n"
            row = self.command(body, f"same-size-{value}")
            self.assertEqual(row["status"], "SURVIVED", row)
            self.assertFalse((package / "__pycache__").exists())
            self.assertTrue(frozen.restore())
            self.assertEqual(source.read_text(), "value = 0\n")
        self.assertNotIn("app.logic", sys.modules)

    def test_timeout_kills_descendants_without_assigning_failure_credit(self):
        started, marker = self.root / "started", self.root / "late-artifact"
        child = (
            f"import pathlib,time;pathlib.Path({str(started)!r}).write_text('ready');"
            f"time.sleep(2);pathlib.Path({str(marker)!r}).write_text('late')"
        )
        body = (
            "import pathlib,subprocess,sys,time\n"
            "def test_waiting():\n"
            f"    subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            f"    while not pathlib.Path({str(started)!r}).exists(): time.sleep(0.01)\n"
            "    time.sleep(10)\n"
        )
        row = self.command(body, "timeout", timeout=1.5)
        self.assertTrue(
            started.exists(), "descendant must start before cleanup receives credit"
        )
        self.assertEqual(row["status"], "TIMEOUT")
        self.assertTrue(row["timed_out"])
        self.assertFalse(row["failures"])
        time.sleep(1.1)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
