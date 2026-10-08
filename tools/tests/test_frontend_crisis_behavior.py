"""Check reproducibility and public behavior of the independent crisis corpus."""
from __future__ import annotations

import gzip
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("frontend_crisis_behavior", ROOT / "tools/generate-frontend-crisis-behavior.py")
assert SPEC and SPEC.loader
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class CrisisBehaviorCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = GENERATOR.build_payload()

    def test_expected_results_reproduce_from_the_backend_public_apis(self) -> None:
        self.assertEqual(json.loads(gzip.decompress(GENERATOR.OUTPUT.read_bytes())), self.payload)

    def test_every_pattern_family_has_all_generated_alternatives_in_the_corpus(self) -> None:
        rows = {text for text, *_ in self.payload["rows"]}
        self.assertEqual(len(self.payload["witnesses"]), 146)
        for witness in self.payload["witnesses"]:
            self.assertEqual(witness["alternatives"], len(witness["texts"]))
            self.assertTrue(witness["texts"])
            self.assertTrue(set(witness["texts"]) <= rows)

    def test_benign_compounds_stay_quiet_without_masking_neighboring_ideation(self) -> None:
        rows = {text: (dialog, suppress) for text, dialog, suppress in self.payload["rows"]}
        self.assertEqual(rows["suicide squad"], (False, False))
        self.assertEqual(rows["suicide squad but I want to die"], (True, True))
        self.assertEqual(rows["A calm ordinary afternoon"], (False, False))


if __name__ == "__main__":
    unittest.main()
