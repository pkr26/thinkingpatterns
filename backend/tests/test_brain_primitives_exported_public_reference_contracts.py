"""Exported pure brain functions preserve released return references."""

import json
from pathlib import Path

from app.services import brain

REFERENCE = Path(__file__).with_name("fixtures") / "brain_primitives_public_reference.json"


def test_exported_text_and_token_functions_preserve_released_return_references():
    cases = json.loads(REFERENCE.read_text())["textCases"]
    for case in cases:
        tokens = case["tokens"]
        assert brain.sentences_of(case["text"]) == case["sentences"]
        assert brain.absolutist_density(tokens) == case["density"]
        for language, expected in case["languages"].items():
            language = None if language == "None" else language
            assert brain.sentiment_score(tokens, language) == expected["score"]
            assert list(brain.sentiment_components(tokens, language)) == expected["components"]
            assert sorted(brain.extract_themes(tokens, language or "en")) == expected["themes"]


def test_exported_word_forms_preserve_released_return_references():
    for case in json.loads(REFERENCE.read_text())["forms"]:
        assert list(brain.word_forms(case["token"])) == case["forms"]
