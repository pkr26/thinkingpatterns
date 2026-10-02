"""2026-10-01 deep audit, stats M5: negated perseverative distress must
never score positive.

The valence walk's negation flip (VADER's x-0.74) used to turn "can't stop
crying" into +0.444: "crying" (-2.4) sits below the 2.5 strong-negation
guard, so the flip applied — a direction inversion of the module's own
stated invariant (brain.py's lexicon note: "'won't stop' phrasing lands at
<= 0"). A perseverative frame (stop/quit/dejar) in the negator window now
suppresses BOTH the flip and the strong-absence zero: the state is ongoing,
so the word keeps its own valence — in both directions ("can't stop
smiling" keeps its positive valence too; the old flip scored it negative).
"""

from __future__ import annotations

from app.services import brain


def _score(text: str) -> float:
    return brain.sentiment_score(text.split())


def test_perseverative_distress_scores_negative():
    assert _score("can't stop crying") < 0.0
    assert _score("won't stop crying") < 0.0
    assert _score("can't stop the tears") < 0.0
    assert _score("can't stop the pain") < 0.0


def test_perseverative_joy_scores_positive():
    # The same rule in the other direction: the old flip made this negative.
    assert _score("can't stop smiling") > 0.0
    assert _score("can't stop laughing about it") > 0.0


def test_strong_absence_guard_still_zeroes():
    # The perseverative suppression must not weaken the 2026-09-29 guard:
    # plain negation of a strong negative is still the ABSENCE of the state.
    assert _score("i am not suicidal") == 0.0
    assert _score("i am not depressed") == 0.0


def test_plain_negation_still_flips_with_damping():
    assert _score("i am not happy today") < 0.0
    assert _score("not bad not great just a day") < 0.0


def test_spanish_frame_keeps_negative_valence():
    # "no puedo dejar de llorar" — the ES frame ("dejar") suppresses the
    # flip the same way ("llorar" is negative; "no" is a negator).
    es = brain.sentiment_score("no puedo dejar de llorar".split(), "es")
    assert es < 0.0


def test_frames_are_pinned_in_the_shared_contract():
    # shared/brain_lexicon.json word_sets.perseverative_frames is what the
    # on-device engines consume — drift here is a cross-platform parity bug.
    import json
    from pathlib import Path

    payload = json.loads(
        (Path(__file__).resolve().parents[2] / "shared" / "brain_lexicon.json").read_text()
    )
    assert set(payload["word_sets"]["perseverative_frames"]) == set(brain.PERSEVERATIVE_FRAMES)
