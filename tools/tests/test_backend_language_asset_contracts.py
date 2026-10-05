"""Actual on-device asset export and public sentiment interoperability."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_supported_generator_preserves_released_mobile_and_web_assets(
    monkeypatch, tmp_path
):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    generator = importlib.import_module("scripts.dump_brain_lexicon")
    output = tmp_path / "language.json"
    modules = (tmp_path / "mobile.ts", tmp_path / "web.ts")
    monkeypatch.setattr(generator, "OUT", output)
    monkeypatch.setattr(generator, "TS_OUTS", modules)
    generator.main()
    expected = json.loads((ROOT / "shared/brain_lexicon.json").read_text())
    assert json.loads(output.read_text()) == expected
    for module in modules:
        content = module.read_text()
        assert json.loads(content[len(generator.TS_PRELUDE) : -2]) == expected


def test_exported_words_score_identically_through_public_sentiment_operations(
    monkeypatch,
):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    brain = importlib.import_module("app.services.brain")
    asset = json.loads((ROOT / "shared/brain_lexicon.json").read_text())
    scale = asset["scalars"]["sentiment_scale"]
    contrast = set(asset["word_sets"]["but_words"])
    emoji = asset["emoji_valences"]
    for language, field in (
        ("en", "sentiment_lexicon"),
        ("es", "sentiment_lexicon_es"),
    ):
        for word, value in {**asset[field], **emoji}.items():
            # A single contrast conjunction divides an empty phrase. Every
            # other singleton has no booster or preceding negation window.
            valence = 0 if word in contrast else max(-4.0, min(4.0, value))
            expected_score = max(-1.0, min(1.0, valence / scale))
            positive = min(1.0, max(0.0, valence / scale))
            negative = min(1.0, max(0.0, -valence / scale))
            assert brain.sentiment_score([word], language) == expected_score, (
                language,
                word,
            )
            assert brain.sentiment_components([word], language) == (
                positive,
                negative,
            ), (language, word)
