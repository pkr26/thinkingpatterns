"""The frontend corpus must be reproducible from the independent Python APIs."""

from __future__ import annotations

import gzip
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "frontend_brain_behavior", ROOT / "tools/generate-frontend-brain-behavior.py"
)
assert SPEC and SPEC.loader
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class FrontendBrainBehaviorCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = GENERATOR.build_payload()

    def test_checked_in_cases_reproduce_from_the_backend_component_apis(self) -> None:
        artifact = json.loads(gzip.decompress(GENERATOR.OUTPUT.read_bytes()))
        self.assertEqual(artifact, self.payload)

    def test_cases_cover_language_scoping_and_unsupported_script_eligibility(self) -> None:
        languages = dict(self.payload["language"])
        self.assertEqual(languages["happy"], "en")
        self.assertEqual(languages["feliz"], "es")
        self.assertEqual(languages["北京非常难过 happy"], "other")
        scored = {(text, locale): (score, positive, negative) for text, locale, score, positive, negative in self.payload["sentiment"]}
        self.assertLess(scored["not happy", "en"][0], 0)
        self.assertGreater(scored["happy", "en"][0], 0)
        self.assertLess(scored["sad", "es"][0], 0)
        self.assertEqual(scored["constructor", None], (0, 0, 0))

    def test_tokenization_cases_keep_accent_and_emoji_interoperability(self) -> None:
        tokenized = dict(self.payload["tokenize"])
        self.assertEqual(tokenized["❤ ☀ ☹"], ["❤️", "☀️", "☹️"])
        self.assertEqual(tokenized["depresio\u0301n"], ["depresion"])
        self.assertEqual(tokenized["don’t feel good"], ["don't", "feel", "good"])

    def test_unicode_fold_cases_include_compatibility_bases_and_prefixed_context(self) -> None:
        folded = dict(self.payload["fold"])
        self.assertEqual(folded["Ǆ"], "DZ")
        self.assertEqual(folded["abǄ"], "abDZ")
        self.assertEqual(folded["happy Ǆ sad"], "happy DZ sad")
        self.assertGreater(len(folded), 3000)


if __name__ == "__main__":
    unittest.main()
