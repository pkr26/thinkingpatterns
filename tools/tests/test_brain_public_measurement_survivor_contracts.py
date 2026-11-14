"""Public surfaced-pattern and statistics contracts for released entry corpora.

These cases retain the released valid-entry corpus and expected public output.
Detector input/result traces and private standalone helper probes are excluded.
"""

import dataclasses
import gzip
import importlib.util
import json
import math
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TODAY = date(2026, 10, 5)
sys.path.insert(0, str(ROOT / "backend"))
_CASES_SPEC = importlib.util.spec_from_file_location(
    "released_measurement_corpus_producers",
    ROOT / "tools/tests/test_full_backend_analysis_mutation.py",
)
assert _CASES_SPEC is not None and _CASES_SPEC.loader is not None
_cases = importlib.util.module_from_spec(_CASES_SPEC)
_CASES_SPEC.loader.exec_module(_cases)
# This helper constructs valid persisted-state input only. It never replaces a
# detector or algorithm; every public update below calls the real implementation.
stored_record = _cases.stored_record
normalized = _cases.normalized


def public_result(result):
    return {
        "stats": result.stats,
        "surfaced": [dataclasses.asdict(p) for p in result.surfaced],
    }


def public_measurement_cases():
    """Same released valid-entry corpora, actual public BrainUpdate fields only; no detector mocks/traces/standalone private calls."""
    from app.services import brain
    from app.services.patterns import JournalEntry

    output = {}
    for size in (9, 10, 11, 12):
        entries = []
        for index in range(size):
            day = TODAY - timedelta(days=index)
            entries.append(
                JournalEntry(
                    "happy work because i understand my friends and the reason",
                    day,
                    (-1) ** index * 0.6,
                    (-1) ** index * 0.4,
                    1 + index % 5,
                    ("tag" + str(index % 4),),
                    "night",
                )
            )
            if index % 3 == 0:
                entries.append(
                    JournalEntry("sad family", day, None, 0.3, 5, ("tag0",), "morning")
                )
        result = brain.update(brain.fresh_state(), entries, TODAY)
        output[f"structured:{size}"] = public_result(result)
    for majority in ("en", "es", "other"):
        for explicit in (False, True):
            entries = []
            texts = {
                "en": "i met Alice and felt happy because i understood why my work was hard "
                * 8,
                "es": "mi madre dijo que estoy feliz porque entiendo cómo ocurrió el trabajo "
                * 8,
                "other": "日本語 Это дневник " * 40
                + "happy work family because i understand",
            }
            for i in range(20):
                text = (
                    texts[majority]
                    if i % 3
                    else texts["other" if majority != "other" else "en"]
                )
                if i in (1, 4):
                    text = ""
                entries.append(
                    JournalEntry(
                        text,
                        TODAY - timedelta(days=20 - i),
                        0.4 if explicit else None,
                        math.sin(i * 0.73) * 0.6,
                        tags=("guitar",),
                    )
                )
            result = brain.update(brain.fresh_state(), entries, TODAY)
            output[f"mixed_measurement:{majority}:{explicit}"] = public_result(result)
    for case in ("duplicates", "sleep_median", "punctuation_ratio", "reanchor"):
        entries = []
        for i in range(20):
            text = "i am happy and worried because i realized why my work matters"
            if case == "punctuation_ratio":
                text = "`^_[ ] " + text
            energy = (-1 if i % 2 else 1) * 0.4
            sleep = (
                ([1, 1, 1, 2, 2, 2, 3, 3, 3, 4] + [5] * 10)[i]
                if case == "sleep_median"
                else None
            )
            day = TODAY - timedelta(days=i // 2 if case == "duplicates" else i)
            entries.append(JournalEntry(text, day, energy=energy, sleep_quality=sleep))
        state = brain.fresh_state()
        if case == "reanchor":
            state["patterns"]["mood_shift:higher"] = stored_record(
                brain, "mood_shift:higher", "mood_shift", "confirmed", age=21
            )
            entries.extend(
                JournalEntry(
                    "happy work because i understand my friends",
                    TODAY - timedelta(days=i),
                    math.sin(i * 0.71) * 0.4,
                )
                for i in range(20, 60)
            )
        result = brain.update(state, entries, TODAY)
        output["specific_measurement:" + case] = public_result(result)
    entries = [
        JournalEntry("", TODAY - timedelta(days=i // 30), 0.2, 0.3) for i in range(4002)
    ]
    result = brain.update(brain.fresh_state(), entries, TODAY)
    output["window_entry_cap"] = public_result(result)
    entries = []
    common = "not never celadon amber ivory linen granite marble. "
    for i in range(8):
        day = TODAY - timedelta(days=i)
        entries.append(
            JournalEntry(
                "i felt happy because i understood why my friends came today. " * 4
                + common,
                day,
            )
        )
        entries.append(
            JournalEntry(
                "mi madre dijo que estoy feliz porque entiendo cómo ocurrió el trabajo. "
                * 4
                + common,
                day,
            )
        )
    result = brain.update(brain.fresh_state(), entries, TODAY)
    output["same_sentence_mixed_entry_languages"] = public_result(result)
    return normalized(output)


def test_released_public_measurement_results():
    actual = public_measurement_cases()
    with gzip.open(
        ROOT / "tools/tests/fixtures/analysis_runtime_contract.json.gz",
        "rt",
        encoding="utf8",
    ) as f:
        released = json.load(f)["brain_measurements"]
    expected = {
        k: {"stats": released[k][0]["stats"], "surfaced": released[k][0]["surfaced"]}
        for k in actual
    }
    assert len(actual) == 16
    assert actual == expected
