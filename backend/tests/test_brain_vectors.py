"""Cross-platform brain-vector parity guard (server side).

shared/brain_vectors.json is the contract between the Python engine and
the mobile on-device port (mobile/src/brain/). The mobile suite runs the
TS modules against these vectors; THIS test regenerates them from the
live Python engine and compares, so a server-side engine change that
would silently break on-device parity fails here first — the same
standing the crypto vectors enjoy on both sides.

If this test fails after an intentional engine change, regenerate:
    cd backend && ../.venv/bin/python scripts/gen_brain_vectors.py
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

from app.services import brain, statsig

VECTORS = Path(__file__).resolve().parents[2] / "shared" / "brain_vectors.json"


def _tokens(text: str) -> list[str]:
    tokens = re.findall(r"[a-z']+", text.lower())
    tokens.extend(e for e in brain.EMOJI_VALENCES for _ in range(text.count(e)))
    return tokens


def test_sentiment_vectors_match_the_live_engine():
    payload = json.loads(VECTORS.read_text())
    for case in payload["sentiment"]:
        tokens = _tokens(case["text"])
        assert brain.sentiment_score(tokens) == case["score"], case["text"]
        pa, na = brain.sentiment_components(tokens)
        assert round(pa, 6) == case["pa"], case["text"]
        assert round(na, 6) == case["na"], case["text"]


def test_stats_vectors_match_the_live_engine():
    payload = json.loads(VECTORS.read_text())
    for z, expected in payload["stats"]["erfc"]:
        assert math.erfc(z) == expected
    for xs, ys, expected in payload["stats"]["pearson"]:
        assert brain._pearson(xs, ys) == expected
    for r1, n1, r2, n2, expected in payload["stats"]["fisher_z"]:
        assert statsig.fisher_z_difference_p(r1, n1, r2, n2) == expected


def test_lexicon_artifact_matches_the_live_engine():
    """The dumped lexicon (shared + the mobile TS copy) must equal what the
    Python engine actually consults — a drifted artifact is a silent
    on-device scoring change."""
    lex_path = Path(__file__).resolve().parents[2] / "shared" / "brain_lexicon.json"
    ts_path = Path(__file__).resolve().parents[2] / "mobile" / "src" / "brain" / "lexicon.ts"
    shared = json.loads(lex_path.read_text())
    assert shared["sentiment_lexicon"] == brain.SENTIMENT_LEXICON
    assert shared["intensifiers"] == brain.INTENSIFIERS
    assert shared["irregular_forms"] == brain.IRREGULAR_FORMS
    assert shared["emoji_valences"] == brain.EMOJI_VALENCES
    assert shared["emoji_order"] == list(brain.EMOJI_VALENCES)
    assert shared["word_sets"]["negators"] == sorted(brain.NEGATORS)
    assert shared["word_sets"]["but_words"] == sorted(brain.BUT_WORDS)
    assert shared["word_sets"]["sense_words"] == sorted(brain.SENSE_WORDS)
    # The mobile TS module is the runtime consumer: same object, one file.
    ts_body = ts_path.read_text()
    start = ts_body.index("export const LEXICON = ")
    embedded = json.loads(ts_body[start + len("export const LEXICON = ") :].rstrip().rstrip(";"))
    assert embedded == shared
