"""Crisis interlock: the embedded phrase contract and its engine wiring.

The parity tests are the sync mechanism for services/crisis.py: the
backend cannot load shared/crisis_phrases.json at runtime (the Docker
image ships only backend/), so the lists are embedded as literals and
these tests hard-fail when either side drifts — the same idiom as
shared/vectors.json in test_encrypt_vectors.py.

The behavior tests pin what the tiers are FOR: suppress-tier content is
never quoted back — not as a question (questions.build_pool), and not on
a pattern card without a ``sensitive: true`` marker the client can
down-rank to a non-quoting variant.
"""

from __future__ import annotations

import json
import re
from datetime import date, timedelta
from pathlib import Path

from app.services import brain, crisis, questions
from app.services.patterns import JournalEntry, Pattern

CRISIS_JSON_PATH = Path(__file__).resolve().parents[2] / "shared" / "crisis_phrases.json"

T0 = date(2026, 9, 4)


def _contract() -> dict:
    # Hard failure, never a silent skip: the JSON is committed; a missing
    # file means a broken checkout (same posture as test_encrypt_vectors).
    assert CRISIS_JSON_PATH.exists(), (
        f"shared/crisis_phrases.json not found at {CRISIS_JSON_PATH} — "
        "it is committed; restore it"
    )
    return json.loads(CRISIS_JSON_PATH.read_text())


class TestParity:
    """Embedded tuples must equal the JSON arrays EXACTLY, in order."""

    def test_dialog_list_matches_json(self):
        assert list(crisis.DIALOG_PATTERNS) == _contract()["dialog"]

    def test_suppress_extra_list_matches_json(self):
        assert list(crisis.SUPPRESS_EXTRA_PATTERNS) == _contract()["suppress_extra"]

    def test_suppress_tier_is_dialog_plus_extra(self):
        data = _contract()
        assert list(crisis.SUPPRESS_PATTERNS) == data["dialog"] + data["suppress_extra"]

    def test_every_pattern_compiles_under_python_re(self):
        for pattern in crisis.SUPPRESS_PATTERNS:
            re.compile(pattern, re.IGNORECASE)


class TestFixtures:
    """The JSON's own fixtures, replayed against the embedded tiers."""

    def test_dialog_fixtures_fire(self):
        for text in _contract()["fixtures"]["dialog_fires"]:
            assert crisis.matches_dialog(text), f"dialog tier missed {text!r}"

    def test_dialog_silent_fixtures_do_not_fire(self):
        for text in _contract()["fixtures"]["dialog_silent"]:
            assert not crisis.matches_dialog(text), f"dialog tier fired on {text!r}"

    def test_suppress_only_fixtures(self):
        for text in _contract()["fixtures"]["suppress_only_fires"]:
            assert crisis.matches_suppress(text), f"suppress tier missed {text!r}"
            assert not crisis.matches_dialog(text), f"dialog tier fired on {text!r}"

    def test_dialog_fixtures_are_also_suppressed(self):
        # The suppress tier is dialog + extra: every dialog fire suppresses.
        for text in _contract()["fixtures"]["dialog_fires"]:
            assert crisis.matches_suppress(text), f"suppress tier missed {text!r}"


class TestEngineInterlock:
    """A crisis-adjacent cluster: flagged sensitive, never a question."""

    def _worry_corpus(self, label_line: str, dark_variant: str) -> list[JournalEntry]:
        """A recurring near-duplicate worry across 8 separated days; the
        dark variant recurs on 3 of them so the cluster reads negative
        enough to classify as rumination."""
        filler = "watered the plants and walked past the old bookshop slowly"
        entries = []
        start = T0 - timedelta(days=55)
        for i in range(56):
            day = start + timedelta(days=i)
            text = filler
            if i % 7 == 0:  # 8 occurrences across 49 days
                text = dark_variant if i % 21 == 0 else label_line
            entries.append(JournalEntry(text, day))
        return entries

    def test_crisis_cluster_is_sensitive_and_never_quotes(self):
        corpus = self._worry_corpus(
            "i can't go on anymore",
            "i can't go on anymore everything feels hopeless",
        )
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        state = brain.update(brain.load_state(brain.dump_state(state)), corpus,
                             T0 + timedelta(days=1)).new_state
        dumped = brain.dump_state(state)  # persistence must not drop the flag's inputs
        worries = [rec for rec in state["patterns"].values()
                   if "can't go on" in rec.label]
        assert worries, "the recurring worry must cluster and store"
        assert any(rec.kind == "rumination" for rec in worries)

        result = brain.update(brain.load_state(dumped), corpus, T0 + timedelta(days=2))
        cards = [p for p in result.surfaced if "can't go on" in p.label]
        assert cards, "the worry must surface after re-qualification"
        # (b) the card is marked sensitive so the client renders the
        # non-quoting variant instead of mirroring the wording back.
        assert all(p.detail.get("sensitive") is True for p in cards)
        # (a) it never enters the question pool — not via the pattern
        # filter, the variants scan, or the rendered-text filter.
        pool = questions.build_pool(result.surfaced)
        assert all("can't go on" not in q.lower() for q in pool)
        assert all("go on anymore" not in q.lower() for q in pool)

    def test_non_crisis_patterns_are_unaffected(self):
        corpus = self._worry_corpus(
            "i keep replaying that conversation",
            "i keep replaying that conversation again",
        )
        result = brain.update(brain.load_state(None), corpus, T0)
        result = brain.update(
            brain.load_state(brain.dump_state(result.new_state)), corpus,
            T0 + timedelta(days=1))
        cards = [p for p in result.surfaced
                 if p.kind in ("recurring_phrase", "rumination")]
        assert cards, "the non-crisis recurring thought must still surface"
        # (c) no sensitive flag, and its questions render normally.
        assert all("sensitive" not in p.detail for p in cards)
        assert any("replaying that conversation" in q
                   for q in questions.build_pool(result.surfaced))

    def test_questions_sensitive_detail_is_excluded_even_without_label_match(self):
        # Belt and braces: a pattern whose LABEL is clean but whose stored
        # variants are suppress-tier is still excluded from questions.
        pattern = Pattern(
            "recurring_phrase", "it keeps coming back", 6, 0.8,
            {"variants": ["it keeps coming back", "i want to disappear"]},
        )
        pool = questions.build_pool([pattern])
        assert all("keeps coming back" not in q for q in pool)
        assert pool, "generic questions remain"

    def test_questions_sensitive_flag_is_excluded(self):
        pattern = Pattern(
            "rumination", "the same heavy thought", 6, 0.8,
            {"sensitive": True},
        )
        pool = questions.build_pool([pattern])
        assert all("heavy thought" not in q for q in pool)


class TestProbeCorpusRegression:
    """The re-audit's headline repro: a 90-day corpus whose last 30 days
    read "thinking about cutting again tonight, the urge for cutting was
    loud after dinner" surfaced a QUOTED rising topic card ('cutting'), a
    quoted recurring-phrase card, and quoted engagement questions ("what is
    that about for you?") — the contract only anchored self-harm to
    first-person phrasing ("cutting myself"), so non-anchored ideation
    slipped every tripwire (sensitive=None). The suppress tier's bare topic
    words now mark those cards sensitive and strip the wording from the
    question pool."""

    def test_cutting_corpus_never_quotes_crisis_adjacent_patterns(self):
        filler = "watered the plants and walked past the old bookshop slowly"
        cutting_line = ("thinking about cutting again tonight, "
                        "the urge for cutting was loud after dinner")
        start = T0 - timedelta(days=89)
        entries = [
            JournalEntry(
                filler if i < 60 else f"{filler}. {cutting_line}",
                start + timedelta(days=i),
            )
            for i in range(90)
        ]
        result = brain.update(brain.load_state(None), entries, T0)

        # The patterns still SURFACE — suppression means non-quoting cards,
        # not hidden ones.
        cards = [p for p in result.surfaced if "cutting" in p.label]
        assert any(p.kind == "topic" for p in cards), \
            "the rising 'cutting' topic must still surface"
        assert any(p.kind in ("recurring_phrase", "rumination") for p in cards), \
            "the repeated sentence must still surface as a phrase card"
        # ...and every one carries sensitive: true (pre-fix: None), so the
        # client renders the gentle non-quoting variant.
        assert all(p.detail.get("sensitive") is True for p in cards)
        # Zero crisis-adjacent questions: not via the pattern filter, the
        # variants scan, or the rendered-text belt-and-braces filter.
        pool = questions.build_pool(result.surfaced)
        assert pool, "the generic questions remain"
        assert all("cutting" not in q.lower() for q in pool)
        assert all(not crisis.matches_suppress(q) for q in pool)
