"""Replay released cross-platform decisions through the two consumer APIs.

The shared corpus also contains intermediate normalization representations.
These tests use only its explicit dialog/suppression decisions. Changing a
regex spelling or an internal variant cannot fail this contract by itself.
"""

from __future__ import annotations

import gzip
import json
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ROWS_PER_SHARD = 256


@lru_cache(maxsize=1)
def released_rows():
    with gzip.open(ROOT / "shared/frontend_crisis_behavior.json.gz", "rt") as stream:
        return json.load(stream)["rows"]


@pytest.mark.parametrize(
    "shard", range((len(released_rows()) + ROWS_PER_SHARD - 1) // ROWS_PER_SHARD)
)
def test_released_crisis_decisions_through_both_public_tiers(monkeypatch, shard):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    # Import inside the call: an unavailable consumer module is an observed
    # runtime failure rather than a collection failure credited as a kill.
    from app.services import crisis

    class BoundedSubstitution:
        def __init__(self, expression):
            self.expression = expression
            self.calls = 0

        def sub(self, *args, **kwargs):
            self.calls += 1
            assert self.calls <= 256, (
                "finite journal text did not finish its normalizer passes"
            )
            return self.expression.sub(*args, **kwargs)

    substitutions = []
    for name in ("_LEET_RE", "_LEET_EDGE_RE", "_LEET_TRAIL_RE"):
        expression = BoundedSubstitution(getattr(crisis, name))
        substitutions.append(expression)
        monkeypatch.setattr(crisis, name, expression)

    start = shard * ROWS_PER_SHARD
    rows = released_rows()[start : start + ROWS_PER_SHARD]
    for text, dialog, suppress in rows:
        for expression in substitutions:
            expression.calls = 0
        observed = (crisis.matches_dialog(text), crisis.matches_suppress(text))
        assert observed == (dialog, suppress), (text, observed, (dialog, suppress))


@pytest.mark.parametrize(
    "text,dialog,suppress",
    [
        ("म:suicide", True, True),
        ("म_suicide", True, True),
        ("म!suicide", True, True),
        ("म:want to die", True, True),
        ("म:quitarme la vida", True, True),
        ("म:suicid3", True, True),
        ("suicideम", True, True),
        ("मsuicide", True, True),
        ("quitarme la vidaम", True, True),
        ("मacabar con todo", False, True),
        ("suicid3म", True, True),
        ("estaría mejor muert0म", True, True),
        ("म0ff myself", True, True),
        ("म:my mom wants to diet", False, False),
        ("म:suicide prevention", False, False),
        ("म:suicide squad", False, False),
        ("म9suicide", False, False),
    ],
)
def test_mixed_script_crisis_boundaries_follow_punctuation_folding(
    monkeypatch, text, dialog, suppress
):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    from app.services import crisis

    assert (crisis.matches_dialog(text), crisis.matches_suppress(text)) == (
        dialog,
        suppress,
    )


# Whole phrase examples exercise homoglyphs and the second punctuation gap.
# Mundane grooming and social-media intentions stay outside both tiers.
@pytest.mark.parametrize(
    "text,dialog,suppress",
    [
        ("suicidаl", True, True),
        ("suicidе", True, True),
        ("want tо die", True, True),
        ("dont want to wake uр", True, True),
        ("kill mуself", True, True),
        ("want to јump off", True, True),
        ("wisһ was dead", True, True),
        ("suiciԁe", True, True),
        ("killinɡ myself", True, True),
        ("ԛuiero morir", True, True),
        ("ԝant to die", True, True),
        ("no reason to liѵe", True, True),
        ("suicidз", True, True),
        ("want tο die", True, True),
        ("suicidαl", True, True),
        ("suicidε", True, True),
        ("suιcide", True, True),
        ("κill myself", True, True),
        ("dont want to wake uρ", True, True),
        ("wanτ to die", True, True),
        ("sυicide", True, True),
        ("no reason to liνe", True, True),
        ("kill μyself", True, True),
        ("killiηg myself", True, True),
        ("ωant to die", True, True),
        ("suiϲide", True, True),
        ("sᴜicide", True, True),
        ("me quiero cortar la barba", False, False),
        ("me quiero cortar las unas", False, False),
        ("me quiero desaparecer de las redes", False, False),
        ("म:suicide", True, True),
        ("su😊ic😊de", True, True),
        ("su😊ic😊dal", True, True),
        ("s\ufe00icide", False, False),
        ("s\ufe10icide", True, True),
        ("hàrm myself", True, True),
        ("no hay salida de emergencia; salida bloqueada", False, False),
        ("no hay: salida de emergencia", False, False),
        ("I h aa ng myself", True, True),
        ("h a n g myself", True, True),
        ("e nd my l i f e tonight", True, True),
        ("s0me off😊ng myself", True, True),
        ("s4me off😊ng myself", True, True),
        ("s@me off😊ng myself", True, True),
        ("t!me off😊ng myself", True, True),
        ("a5k off😊ng myself", True, True),
        ("la7e off😊ng myself", True, True),
        ("a8ove off😊ng myself", True, True),
        ("a$k off😊ng myself", True, True),
        ("t1me off😊ng myself", True, True),
        ("h3re off😊ng myself", True, True),
        ("she1f off😊ng myself", True, True),
        ("today’s journal: off😊ng myself", True, True),
        ("suicide prevention off😊ng myself", True, True),
        ("entry13 entry13 off😊ng myself", True, True),
        ("自:杀", True, True),
        ("自_杀", True, True),
        ("aम k😊ll myself", True, True),
        ("I introduced z h a n g myself", False, False),
        ("voy a acabar con t o d o", True, True),
        ("me voy a acabar con esta v i d a", True, True),
        ("I p lanning to jump off", True, True),
        ("9𐐀ff myself", True, True),
        ("z𐐀ff myself", True, True),
        ("𐐀 su😊ic😊de", True, True),
        ("h𐐀ng myself", True, True),
        ("a c u t t i n gboard for vegetables", False, False),
        ("want to d i𐐀t", True, True),
    ],
)
def test_contextual_crisis_obfuscation_and_benign_continuations(
    monkeypatch, text, dialog, suppress
):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    from app.services import crisis

    assert (crisis.matches_dialog(text), crisis.matches_suppress(text)) == (
        dialog,
        suppress,
    )


def test_public_crisis_normalizer_preserves_plain_journal_text(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    from app.services.crisis import normalize_crisis_text

    assert normalize_crisis_text("hello") == "hello"
    assert normalize_crisis_text("") == ""
    assert normalize_crisis_text("х") == "x"


def test_finite_crisis_public_decisions_make_progress(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    from app.services import crisis

    class BoundedSubstitution:
        def __init__(self, expression):
            self.expression = expression
            self.calls = 0

        def sub(self, *args, **kwargs):
            self.calls += 1
            assert self.calls <= 256, (
                "finite public crisis decision stopped making progress"
            )
            return self.expression.sub(*args, **kwargs)

    substitutions = []
    for name in ("_LEET_RE", "_LEET_EDGE_RE", "_LEET_TRAIL_RE"):
        expression = BoundedSubstitution(getattr(crisis, name))
        substitutions.append(expression)
        monkeypatch.setattr(crisis, name, expression)
    for text, expected in (
        ("ordinary journal", (False, False)),
        ("su1c1de", (True, True)),
        ("k1ll myse1f", (True, True)),
        ("1 am tired", (False, False)),
        ("1am tired", (False, False)),
        ("suic1d3", (True, True)),
        ("I want to d13", (True, True)),
        ("h a n g myself", (True, True)),
    ):
        for expression in substitutions:
            expression.calls = 0
        observed = (crisis.matches_dialog(text), crisis.matches_suppress(text))
        assert observed == expected, (text, observed, expected)
