"""Data-table and tuning-constant pins from the 2026-09-30 deep mutation
campaign (fresh full-scope run: 34,924 mutants over the pyproject deep
scope plus locks/metrics/singleprocess).

The campaign's first wave of survivors was dominated by one class: the
engine's pure data surfaces, whose individual entries no behavioral test
can economically pin one-by-one —

  * ``sentiment_lexicon_es``: the ENTIRE module survived at 98.5% (1,738
    of 1,752 mutants). The ES tables were pinned structurally only
    (fold-invariance, a handful of word-for-word spot checks); any other
    entry's valence, key, or set membership could change silently. The
    ES engine's scoring contract was effectively unpinned.
  * ``sentiment_lexicon.VADER_BASE``: the artifact pin covers the MERGED
    lexicon (``{**VADER_BASE, **CURATED}``), so base entries shadowed by
    a curated override are invisible to it — those values are dead to
    every existing assertion.
  * ``brain``: the engine's tuning constants (windows, gates, budgets,
    half-lives) and word tables are the deterministic mini-brain's
    contract — the same values the mobile port replicates — but only the
    ones a behavior test happens to exercise were pinned.

These tests freeze those surfaces with content digests: any single-entry
change (the mutation operator's smallest edit) breaks the digest. A
deliberate tuning change regenerates the digest deliberately — run
``python tests/test_mutation_pins_2026_09_30.py`` (module main) to print
the new values. Behavioral gaps the campaign surfaced in logic (not
data) are pinned semantically in their own suites, not here.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from app.services import brain, sentiment_lexicon as lexicon_en
from app.services import sentiment_lexicon_es as lexicon_es

# -- canonical form + digest (mirror of the module-main regenerator) ------


def _canon(value: object) -> object:
    if isinstance(value, re.Pattern):
        return {"$regex": value.pattern, "flags": value.flags}
    if isinstance(value, type):
        return {"$type": f"{value.__module__}.{value.__qualname__}"}
    if isinstance(value, (set, frozenset)):
        return sorted((_canon(v) for v in value), key=repr)
    if isinstance(value, dict):
        return {str(k): _canon(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    if isinstance(value, (int, float, str, bool, bytes, type(None))):
        if isinstance(value, bytes):
            return {"$bytes": value.hex()}
        return value
    raise TypeError(f"unpinnable constant type {type(value).__name__}")


def _digest(value: object) -> str:
    payload = json.dumps(_canon(value), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _brain_tuning_contract() -> dict[str, object]:
    """Every public module-level constant on the engine: scalars, word
    tables, compiled regexes. Excludes modules/functions/callables (their
    behavior is what the semantic suites pin)."""
    out: dict[str, object] = {}
    for name in dir(brain):
        # public contract only: leading-underscore names can be runtime
        # state (brain._FOLD_CACHE fills as the engine runs)
        if not name.isupper() or name.startswith("_"):
            continue
        value = getattr(brain, name)
        if isinstance(
            value,
            (re.Pattern, int, float, str, bool, bytes, list, tuple, dict, set, frozenset),
        ):
            out[name] = value
    return out


# Digests frozen 2026-09-30 from the live engine at campaign start.
BRAIN_TUNING_DIGEST = "db54bd23fea9c4f9"

# Snapshots are captured at COLLECTION time (this module's import): some
# engine modules carry runtime memoization dicts among their module-level
# UPPERCASE names (brain._FOLD_CACHE fills as tests run) — the frozen
# contracts must see import-time state or the pin becomes order-dependent.
BRAIN_TUNING_SNAPSHOT = _brain_tuning_contract()

ES_TABLE_DIGESTS = {
    "VADER_BASE_ES": ("acb3d04fa6a3f680", 470),
    "INTENSIFIERS_ES": ("acff031ceb028789", 21),
    "NEGATORS_ES": ("8e40e5bc61e9447d", 14),
    "BUT_WORDS_ES": ("3cf18e86677cbd98", 4),
    "ABSOLUTIST_WORDS_ES": ("31cdae68f411feb2", 24),
    "SENSE_WORDS_ES": ("e554fcec98646157", 52),
    "LANGUAGE_FUNCTION_WORDS_ES": ("a78eb63caba9f65a", 179),
}

EN_BASE_DIGESTS = {
    # the base tables UNDER the curated merge: shadowed entries included
    "VADER_BASE": ("3dcb08a72e816adc", 7208),
    "EMOJI_VALENCES": ("4cd3a3a393dbf3f6", 35),
}


def test_brain_tuning_constants_are_frozen():
    contract = BRAIN_TUNING_SNAPSHOT
    assert len(contract) >= 135, (
        "the engine's module-level constant surface shrank — if constants "
        "were deliberately moved, regenerate BRAIN_TUNING_DIGEST"
    )
    got = _digest(contract)
    assert got == BRAIN_TUNING_DIGEST, (
        "the mini-brain's tuning contract changed. If this is a deliberate "
        "tuning change, regenerate with: "
        "PYTHONPATH=. python tests/test_mutation_pins_2026_09_30.py — and "
        "remember the mobile brain port must be re-pinned to match "
        "(cross-platform vector digests will fail next otherwise)"
    )


@pytest.mark.parametrize("table", sorted(ES_TABLE_DIGESTS))
def test_es_lexicon_tables_are_frozen(table: str):
    expected, size = ES_TABLE_DIGESTS[table]
    value = getattr(lexicon_es, table)
    assert len(value) == size
    assert _digest(value) == expected, (
        f"{table} changed — regenerate ES_TABLE_DIGESTS via "
        "python tests/test_mutation_pins_2026_09_30.py after a deliberate "
        "curation change"
    )


@pytest.mark.parametrize("table", sorted(EN_BASE_DIGESTS))
def test_en_base_lexicon_tables_are_frozen(table: str):
    expected, size = EN_BASE_DIGESTS[table]
    value = getattr(lexicon_en, table)
    assert len(value) == size
    assert _digest(value) == expected, (
        f"{table} changed — the merged-lexicon artifact pin hides shadowed "
        "entries, so the base table is pinned here directly; regenerate "
        "EN_BASE_DIGESTS via python tests/test_mutation_pins_2026_09_30.py"
    )


# Per-module public constant digests (the tuning/limit/contract
# constants every module freezes at import — same rationale as the brain
# digest above; see the module docstring).
MODULE_CONSTANTS_DIGESTS = {
    "app.api._audit": "3e07fb7ea7f005bc",
    "app.api._paging": "db67a3b84a562735",
    "app.api._sharing_state": "9f695ac5429dc595",
    "app.api.account": "c4c1df3e0da017f9",
    "app.api.audio": "a7d942ebdd3f6cfc",
    "app.api.auth": "e6806670574bf7b3",
    "app.api.consents": "6b6234fc0eb8e3d7",
    "app.api.entries": "f403b709ff5593f1",
    "app.api.insights": "9bc5fea0edc0aca5",
    "app.api.measures": "98bb90af47e23b76",
    "app.api.meta": "33685e531404d79b",
    "app.api.therapist": "a3b747d3c02e9468",
    "app.cache": "9cafcda6da25d7e1",
    "app.config": "48fce0698f78bffb",
    "app.db": "d375979383d7a6f1",
    "app.deps": "eef3badf33769d80",
    "app.locks": "37856db1c6d2e319",
    "app.main": "2b23248e6a2be2b3",
    "app.metrics": "10aefb028623642d",
    "app.middleware": "27babfd5745e9b0b",
    "app.schemas": "20fbb6883918e31c",
    "app.security.crypto": "4f9a5836e613d869",
    "app.security.deletion_tombstone": "78b15c35df955cc3",
    "app.security.enclave": "a430522a897ac462",
    "app.security.envelope": "d53ebc6d8ab2b46b",
    "app.security.kdf": "59fbabc75041d1f1",
    "app.security.sharing": "647c6968345282e5",
    "app.security.step_up": "527887e1a38f5fb8",
    "app.security.tokens": "9fd35793a68932a7",
    "app.security.totp": "764e7437fd20e644",
    "app.services.account_deletion": "9e04cc778615d2b2",
    "app.services.audio_store": "e9dbb67a7e4db1bf",
    "app.services.crisis": "214490ad774f26f4",
    "app.services.llm": "2b0310fe5bf2db75",
    "app.services.patterns": "5c1b74f0800b1a40",
    "app.services.phrases": "8e57f838b840229f",
    "app.services.questions": "860046a3cbfadb09",
    "app.services.stt": "0f960320b839c7c0",
    "app.services.threshold": "a320cefdf99c2cb0",
    "app.singleprocess": "18badaef13fb0023",
}


def _module_constants(module: object) -> dict[str, object]:
    out: dict[str, object] = {}
    for name in dir(module):
        if not name.isupper() or name.startswith("_"):
            continue
        value = getattr(module, name)
        if isinstance(
            value,
            (re.Pattern, int, float, str, bool, bytes, list, tuple, dict, set, frozenset),
        ):
            out[name] = value
    return out


# import-time DIGESTS for every module (see BRAIN_TUNING_SNAPSHOT's note;
# digests, not references — runtime-mutated tables would leak through)
import importlib as _importlib  # noqa: E402

MODULE_CONSTANTS_DIGESTS_AT_IMPORT = {
    name: _digest(_module_constants(_importlib.import_module(name)))
    for name in MODULE_CONSTANTS_DIGESTS
}


@pytest.mark.parametrize("module_name", sorted(MODULE_CONSTANTS_DIGESTS))
def test_module_constants_are_frozen(module_name):
    """The per-module contract constants (limits, budgets, header names,
    code maps) frozen 2026-09-30 — the campaign showed them individually
    unpinned (a limit could move ±1, a header name could drift, without
    any test failing). Deliberate changes regenerate via:
    PYTHONPATH=. python tests/test_mutation_pins_2026_09_30.py"""
    assert (
        MODULE_CONSTANTS_DIGESTS_AT_IMPORT[module_name] == MODULE_CONSTANTS_DIGESTS[module_name]
    ), (
        f"{module_name}'s module-level constants changed — if deliberate, "
        "regenerate MODULE_CONSTANTS_DIGESTS with "
        "PYTHONPATH=. python tests/test_mutation_pins_2026_09_30.py"
    )


if __name__ == "__main__":
    print(f'BRAIN_TUNING_DIGEST = "{_digest(_brain_tuning_contract())}"')
    for name, _ in sorted(ES_TABLE_DIGESTS.items()):
        print(
            f'    "{name}": ("{_digest(getattr(lexicon_es, name))}", {len(getattr(lexicon_es, name))}),'
        )
    for name in sorted(EN_BASE_DIGESTS):
        print(
            f'    "{name}": ("{_digest(getattr(lexicon_en, name))}", {len(getattr(lexicon_en, name))}),'
        )
    print("MODULE_CONSTANTS_DIGESTS = {")
    import importlib

    for mod in sorted(MODULE_CONSTANTS_DIGESTS):
        m = importlib.import_module(mod)
        print(f'    "{mod}": "{_digest(_module_constants(m))}",')
    print("}")


# llm.py's PRIVATE data contracts (leading-underscore tables the public
# digest deliberately skips — these are frozen prompts/bounds/allowlists,
# not runtime state): the refiner prompt, its numeric-bounds schema, the
# spelled-number map, and the grounding allowlist.
LLM_PRIVATE_CONTRACT_DIGEST = "cfeb0a391527cce1"


def test_llm_private_data_contract_is_frozen():
    import re as _re

    from app.services import llm as llm_mod

    contract = {
        _n: getattr(llm_mod, _n)
        for _n in dir(llm_mod)
        if _n.startswith("_")
        and _n.isupper()
        and isinstance(
            getattr(llm_mod, _n),
            (str, tuple, frozenset, set, list, dict, _re.Pattern, int, float, bool),
        )
    }
    assert len(contract) >= 14
    assert _digest(contract) == LLM_PRIVATE_CONTRACT_DIGEST, (
        "llm.py's private prompt/bounds/allowlist tables changed — the "
        "refiner's exact contract is part of the processing-policy "
        "surface (prompts, clinical/imperative/manipulation blocklists, "
        "contact/domain detectors, numeric bounds); regenerate "
        "LLM_PRIVATE_CONTRACT_DIGEST deliberately "
        "via PYTHONPATH=. python tests/test_mutation_pins_2026_09_30.py"
    )


# Private (leading-underscore) frozen data tables — prompts, bound maps,
# allowlists, template strings — snapshotted at collection time like the
# public constants above; llm.py's equivalent is named explicitly above.
PRIVATE_TABLE_DIGESTS = {
    "app.api._audit": "28952281c15838d4",
    "app.api._paging": "f77949057f7b789f",
    "app.api.entries": "b68d43d01acb489a",
    "app.api.insights": "0ab61ee8acc09c3b",
    "app.cache": "85e3c8868decda83",
    "app.schemas": "a11fc3560db59c8f",
    "app.services.crisis": "075fb9e3c7671d0f",
    "app.services.phrases": "5cad465e4f3299b5",
    "app.services.questions": "07fcf97d72adc879",
    "app.services.stt": "9da07b88205d933e",
}

import importlib as _il  # noqa: E402

# digests are computed AT IMPORT TIME (collection): some private tables
# are runtime caches that fill during the suite, so holding live object
# references would make the pin order-dependent
PRIVATE_TABLE_DIGESTS_AT_IMPORT = {}
for _m in PRIVATE_TABLE_DIGESTS:
    _mod = _il.import_module(_m)
    _tables = {
        _n: getattr(_mod, _n)
        for _n in dir(_mod)
        if _n.startswith("_")
        and _n.isupper()
        and isinstance(
            getattr(_mod, _n),
            (str, tuple, frozenset, set, list, dict, re.Pattern, int, float, bool),
        )
    }
    PRIVATE_TABLE_DIGESTS_AT_IMPORT[_m] = _digest(_tables)


@pytest.mark.parametrize("module_name", sorted(PRIVATE_TABLE_DIGESTS))
def test_private_data_tables_are_frozen(module_name):
    """The modules' private frozen tables (prompts, bound maps, template
    prose): same digest contract as the public constants, for the
    leading-underscore surface."""
    assert PRIVATE_TABLE_DIGESTS_AT_IMPORT[module_name] == PRIVATE_TABLE_DIGESTS[module_name], (
        f"{module_name}'s private data tables changed — if deliberate, "
        "regenerate PRIVATE_TABLE_DIGESTS via PYTHONPATH=. python tests/test_mutation_pins_2026_09_30.py"
    )
