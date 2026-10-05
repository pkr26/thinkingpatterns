"""Verify actual customer response differences fail inside pytest calls."""

import ast
import importlib.util
import json
import pathlib
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "http_contract_runner", ROOT / "redteam/run_automatic_backend_mutation.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class HttpContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / "test_customer.py").write_text("""
import asyncio
import json
from pathlib import Path
import httpx

async def endpoint(scope, receive, send):
    detail = Path('detail.txt').read_text()
    body = json.dumps({'code': 'validation_error', 'detail': detail}).encode()
    await send({'type': 'http.response.start', 'status': 422,
                'headers': [(b'content-type', b'application/json')]})
    await send({'type': 'http.response.body', 'body': body})

def test_customer_rejection():
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=endpoint),
                                     base_url='http://testserver') as client:
            route = Path('route.txt').read_text() if Path('route.txt').exists() else '/api/v1/customer'
            response = await client.get(route)
            assert response.status_code == 422
    asyncio.run(request())
""")
        (self.root / "detail.txt").write_text("malformed cursor")
        runner.preload()

    def run_child(self, label, capture=True, expected=None, public_values=False):
        return runner.pytest_child(
            self.root,
            ["test_customer.py"],
            self.root / f"{label}.log",
            10,
            capture,
            expected,
            public_values,
        )

    def test_customer_error_detail_change_is_a_real_call_failure(self):
        baseline = self.run_child("baseline")
        repeat = self.run_child("repeat")
        self.assertEqual(baseline["status"], "SURVIVED")
        self.assertEqual(repeat["contracts"], baseline["contracts"])
        self.assertEqual(
            baseline["contracts"]["test_customer.py::test_customer_rejection"],
            [
                {
                    "method": "GET",
                    "path": "/api/v1/customer",
                    "status": 422,
                    "error": {"code": "validation_error", "detail": "malformed cursor"},
                }
            ],
        )
        (self.root / "detail.txt").write_text("different customer message")
        plain = self.run_child("plain", capture=False)
        self.assertEqual(plain["status"], "SURVIVED")
        mutated = self.run_child("mutated", expected=baseline["contracts"])
        self.assertEqual(mutated["status"], "KILLED")
        self.assertEqual(mutated["returncode"], 1)
        self.assertFalse(mutated["errors"])
        self.assertEqual(mutated["failures"][0]["phase"], "call")
        self.assertIn(
            "customer HTTP status/error contract changed",
            mutated["failures"][0]["detail"],
        )

    def test_pipe_parameter_ids_survive_runtime_coverage_mapping(self):
        nodeid = "tests/test_cursor.py::test_invalid[stamp|identifier]"
        self.assertEqual(runner.runtime_context_nodeid(nodeid + "|run"), nodeid)
        for context in (nodeid + "|setup", nodeid + "|teardown", "", nodeid):
            self.assertIsNone(runner.runtime_context_nodeid(context))

    def test_random_fixture_identity_shape_does_not_make_baseline_flaky(self):
        (self.root / "detail.txt").write_text("account " + "a" * 32 + " on 2026-10-05")
        (self.root / "route.txt").write_text("/api/entries/e-2026-10-05-abcd1234")
        first = self.run_child("first")
        self.assertEqual(
            first["contracts"]["test_customer.py::test_customer_rejection"][0]["path"],
            "/api/entries/e-<calendar>-<nonce>",
        )
        (self.root / "detail.txt").write_text("account " + "b" * 32 + " on 2026-10-06")
        (self.root / "route.txt").write_text("/api/entries/e-2026-10-06-abcd5678")
        second = self.run_child("second", expected=first["contracts"])
        self.assertEqual(second["status"], "SURVIVED")

    def test_success_fields_types_permissions_and_lengths_fail_inside_the_call(self):
        (self.root / "test_customer.py").write_text("""
import asyncio,json
from pathlib import Path
import httpx
async def endpoint(scope, receive, send):
    body = Path('payload.json').read_bytes()
    await send({'type': 'http.response.start', 'status': 200,
                'headers': [(b'content-type', b'application/json')]})
    await send({'type': 'http.response.body', 'body': body})
def test_customer_rejection():
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=endpoint),
                                     base_url='http://test') as client:
            assert (await client.get('/api/v1/customer')).status_code == 200
    asyncio.run(request())
""")
        payload = {
            "user_id": "a" * 32,
            "blob": "random ciphertext",
            "entry_count": 2,
            "permitted": True,
            "rows": [
                {"id": "b" * 32, "text": "narrative one", "expires": None},
                {"id": "e" * 32, "text": "narrative two", "expires": "2026-10-05"},
            ],
        }
        path = self.root / "payload.json"
        path.write_text(json.dumps(payload))
        baseline = self.run_child("success-baseline")
        self.assertEqual(baseline["status"], "SURVIVED")
        repeat = self.run_child("success-repeat")
        self.assertEqual(baseline["contracts"], repeat["contracts"])
        dynamic = {
            **payload,
            "user_id": "c" * 32,
            "blob": "fresh ciphertext",
            "rows": [
                {"id": "d" * 32, "text": "changed second", "expires": "2026-10-06"},
                {"id": "f" * 32, "text": "changed first", "expires": None},
            ],
        }
        path.write_text(json.dumps(dynamic))
        self.assertEqual(
            self.run_child("success-dynamic", expected=baseline["contracts"])["status"],
            "SURVIVED",
        )
        missing = {key: value for key, value in payload.items() if key != "entry_count"}
        for label, changed in [
            ("missing-field", missing),
            ("wrong-type", {**payload, "entry_count": "2"}),
            ("wrong-permission", {**payload, "permitted": False}),
            ("wrong-length", {**payload, "rows": payload["rows"] * 2}),
        ]:
            with self.subTest(label=label):
                path.write_text(json.dumps(changed))
                actual = self.run_child(label, expected=baseline["contracts"])
                self.assertEqual(actual["status"], "KILLED", actual)
                self.assertFalse(actual["errors"])
                self.assertEqual(actual["failures"][0]["phase"], "call")

    def test_published_enum_and_generation_changes_are_real_call_failures(self):
        source = (self.root / "test_customer.py").read_text()
        source = source.replace(
            "detail = Path('detail.txt').read_text()\n    body = json.dumps({'code': 'validation_error', 'detail': detail}).encode()",
            "body = Path('payload.json').read_bytes()",
        )
        source = source.replace("'status': 422", "'status': 200").replace(
            "response.status_code == 422", "response.status_code == 200"
        )
        (self.root / "test_customer.py").write_text(source)
        payload = {
            "role": "patient",
            "phase": "insight",
            "key_scheme": "v2",
            "state_seq": 1,
            "blob": "opaque ciphertext",
            "text": "private narrative",
        }
        path = self.root / "payload.json"
        path.write_text(json.dumps(payload))
        baseline = self.run_child("values-baseline", public_values=True)
        self.assertEqual(baseline["status"], "SURVIVED")
        self.assertEqual(
            self.run_child("values-repeat", public_values=True)["contracts"],
            baseline["contracts"],
        )
        path.write_text(
            json.dumps({**payload, "blob": "new ciphertext", "text": "new narrative"})
        )
        self.assertEqual(
            self.run_child(
                "values-private", expected=baseline["contracts"], public_values=True
            )["status"],
            "SURVIVED",
        )
        for field, value in [
            ("role", "therapist"),
            ("phase", "baseline"),
            ("key_scheme", "v1"),
            ("state_seq", 2),
        ]:
            with self.subTest(field=field):
                path.write_text(json.dumps({**payload, field: value}))
                result = self.run_child(
                    "values-" + field,
                    expected=baseline["contracts"],
                    public_values=True,
                )
                self.assertEqual(result["status"], "KILLED", result)
                self.assertEqual(result["failures"][0]["phase"], "call")
                self.assertFalse(result["errors"])


class CoverageSelectionTests(unittest.TestCase):
    def test_missing_line_uses_all_enclosing_function_calls(self):
        tree = ast.parse("""
constant = 3
def first(value):
    if value:
        return "branch"
    return "tail"
def other():
    return "other"
""")
        contexts = {
            "2": [],
            "4": ["tests/a.py::positive", "tests/a.py::negative"],
            "6": ["tests/a.py::negative"],
            "8": ["tests/b.py::other"],
        }
        nodes, kind = runner.full_runtime_covering_nodes(tree, 5, contexts)
        self.assertEqual(nodes, {"tests/a.py::positive", "tests/a.py::negative"})
        self.assertEqual(kind, "enclosing_function")
        self.assertEqual(
            runner.full_runtime_covering_nodes(tree, 6, contexts),
            ({"tests/a.py::negative"}, "line"),
        )
        nodes, kind = runner.full_runtime_covering_nodes(tree, 2, contexts)
        self.assertEqual(
            nodes, {"tests/a.py::positive", "tests/a.py::negative", "tests/b.py::other"}
        )
        self.assertEqual(kind, "module")

    def test_sharding_preserves_scope_and_reuses_small_oracle_groups(self):
        rows = [
            {"id": f"{group}-{index}", "selectors": [group]}
            for group, count in [("large", 12), ("small-a", 3), ("small-b", 3)]
            for index in range(count)
        ]
        shards = runner.grouped_shards(rows, 3, [])
        self.assertEqual(
            sorted(row["id"] for shard in shards for row in shard),
            sorted(row["id"] for row in rows),
        )
        self.assertEqual([len(shard) for shard in shards], [6, 6, 6])
        for group in ("small-a", "small-b"):
            self.assertEqual(
                sum(
                    any(row["selectors"] == [group] for row in shard)
                    for shard in shards
                ),
                1,
            )


class ChildTemporaryOwnershipTests(unittest.TestCase):
    def test_unclosed_tempfiles_and_descendants_are_removed_after_all_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            runner.preload()
            for label, ending, expected in [
                ("pass", "", "SURVIVED"),
                ("fail", "assert False", "KILLED"),
                ("timeout", "time.sleep(10)", "TIMEOUT"),
            ]:
                with self.subTest(label=label):
                    oracle = root / "test_temporary.py"
                    record = root / f"{label}-paths"
                    late = root / f"{label}-late"
                    oracle.write_text(f"""
import os,pathlib,subprocess,sys,tempfile,time
def test_owned_temporary(tmp_path):
    descriptor, leaked = tempfile.mkstemp()
    os.write(descriptor, b'unclosed application tempfile')
    os.close(descriptor)
    pathlib.Path({str(record)!r}).write_text(tempfile.gettempdir() + '\\n' + str(tmp_path))
    ready = pathlib.Path(tempfile.gettempdir()) / 'descendant-ready'
    code = "import pathlib,time;pathlib.Path(" + repr(str(ready)) + ").write_text('ready');time.sleep(2);pathlib.Path(" + repr({str(late)!r}) + ").write_text('escaped')"
    subprocess.Popen([sys.executable, '-c', code])
    while not ready.exists(): time.sleep(0.01)
    {ending or "pass"}
""")
                    row = runner.pytest_child(
                        root,
                        [oracle.name],
                        root / f"{label}.log",
                        1.5 if label == "timeout" else 10,
                    )
                    self.assertEqual(row["status"], expected, row)
                    self.assertTrue(row["temporary_restored"])
                    owned = pathlib.Path(row["temporary_directory"])
                    self.assertEqual(owned.parent, root)
                    actual_temp, pytest_temp = map(
                        pathlib.Path, record.read_text().splitlines()
                    )
                    self.assertEqual(actual_temp, owned)
                    self.assertTrue(pytest_temp.is_relative_to(owned))
                    self.assertFalse(owned.exists())
                    time.sleep(1.1 if label == "timeout" else 2.1)
                    self.assertFalse(
                        late.exists(), "descendant escaped the owned process group"
                    )


if __name__ == "__main__":
    unittest.main()
