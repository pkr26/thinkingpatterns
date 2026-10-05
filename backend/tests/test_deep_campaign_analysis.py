"""Behavioral oracles for the deep analysis campaigns.

Small controlled cohorts isolate longitudinal, language, user-preference and
untrusted-output invariants. They intentionally include positive controls so a
detector that silently returns nothing cannot satisfy every safety assertion.
"""

from __future__ import annotations

import itertools
import json
import math
from datetime import date, timedelta

import pytest

from app.services import brain, crisis, llm, phrases, questions, statsig, threshold
from app.services.patterns import JournalEntry, Pattern

START = date(2026, 1, 1)


def tokens(text):
    return brain.WORD_RE.findall(brain._fold_sentiment_text(text.lower()))


def record(
    pid="phrase:known", kind="recurring_phrase", label="a quiet recurring observation", **kwargs
):
    fields = dict(
        pid=pid,
        kind=kind,
        label=label,
        first_seen=START.isoformat(),
        last_seen=START.isoformat(),
        first_qualified=START.isoformat(),
        last_qualified=START.isoformat(),
        occurrences=12,
        state="emerging",
        qualification_days=[START.isoformat()],
        evidence_dates=[START.isoformat()],
        feedback={},
        detail={},
    )
    fields.update(kwargs)
    return brain.StoredPattern(**fields)


def signal(pid="temporal:work", kind="temporal", days=None, **kwargs):
    fields = dict(
        pid=pid,
        kind=kind,
        label="work",
        occurrences=12,
        pvalue=0.001,
        detail={"day": "Sunday"},
        evidence_days=days or [START],
    )
    fields.update(kwargs)
    return brain._Signal(**fields)


def test_future_grace_does_not_erase_current_streak():
    today = START + timedelta(days=10)
    dates = [today - timedelta(days=i) for i in range(4)] + [today + timedelta(days=1)]
    assert threshold.evaluate(dates, today=today).streak == 4
    assert threshold.evaluate(dates, today=today).active_days == 5


def test_grammatical_no_does_not_double_count_distress():
    assert brain.sentiment_score(tokens("no good"), "en") == pytest.approx(-0.3515)
    assert brain.sentiment_score(tokens("no"), "en") < 0
    assert brain.sentiment_score(tokens("no no"), "en") < 0


def test_last_contrast_controls_the_sentiment_reading():
    # The final clause is the reflective interpretation of the earlier ones.
    assert brain.sentiment_score(tokens("happy but sad but calm"), "en") > 0
    assert brain.sentiment_score(tokens("sad but happy but miserable"), "en") < 0


def test_weekday_cycle_is_not_a_personal_theme_mood_association():
    entries = [
        JournalEntry(
            "I wrote in my journal today.",
            START + timedelta(days=i),
            sentiment=(-0.55 if (START + timedelta(days=i)).weekday() == 0 else 0.35)
            + (0.035 if i % 2 else -0.035),
            tags=("work",) if (START + timedelta(days=i)).weekday() == 0 else (),
        )
        for i in range(140)
    ]
    first = brain.update(brain.fresh_state(), entries[:126], START + timedelta(days=125))
    later = brain.update(first.new_state, entries, START + timedelta(days=139))
    assert any(p.kind == "temporal" and p.label == "work" for p in later.surfaced)
    assert not any(p.kind == "mood_correlation" and p.label == "work" for p in later.surfaced)


@pytest.mark.parametrize(
    "theme_text",
    [
        "Hoy me siento feliz con el sueno cansado agotado insomnio y la cama",
        "I am happy with sleep insomnia exhausted tired bed and rest today.",
    ],
)
def test_spanish_minority_theme_tokens_cannot_manufacture_a_mood_association(theme_text):
    entries = [
        JournalEntry(
            theme_text if i % 4 == 0 else "I am happy today after writing in my journal.",
            START + timedelta(days=i),
        )
        for i in range(140)
    ]
    first = brain.update(brain.fresh_state(), entries[:112], START + timedelta(days=111))
    later = brain.update(first.new_state, entries, START + timedelta(days=139))
    assert later.stats["language"] == "en"
    assert later.stats["mood_summary"]["text_estimates"] == 140
    assert not any(p.kind == "mood_correlation" and p.label == "sleep" for p in later.surfaced)


def test_language_aware_theme_baselines_preserve_independent_mood_associations():
    entries = [
        JournalEntry(
            "Hoy me siento feliz con el sueno cansado agotado insomnio y la cama"
            if i % 4 == 0
            else "I am sad and miserable today while writing in my journal.",
            START + timedelta(days=i),
        )
        for i in range(140)
    ]
    first = brain.update(brain.fresh_state(), entries[:112], START + timedelta(days=111))
    later = brain.update(first.new_state, entries, START + timedelta(days=139))
    assert later.stats["language"] == "en"
    associated = [p for p in later.surfaced if p.kind == "mood_correlation" and p.label == "sleep"]
    assert len(associated) == 1
    assert associated[0].detail["direction"] == "higher"
    assert associated[0].detail["mood_delta"] < -1


@pytest.mark.parametrize(
    "rating", [float("nan"), float("inf"), -float("inf")], ids=["nan", "inf", "negative-inf"]
)
def test_nonfinite_rating_text_fallback_cannot_manufacture_theme_mood(rating):
    # Invalid ratings fall back to the text scorer. The same fallback must
    # retain text decontamination: the theme lexicon is not a mood report.
    entries = [
        JournalEntry(
            "I am happy with sleep insomnia exhausted tired bed and rest today."
            if i % 4 == 0
            else "I am happy today after writing in my journal.",
            START + timedelta(days=i),
            sentiment=rating if i % 4 == 0 else None,
        )
        for i in range(140)
    ]
    first = brain.update(brain.fresh_state(), entries[:112], START + timedelta(days=111))
    later = brain.update(first.new_state, entries, START + timedelta(days=139))
    assert later.stats["mood_summary"]["explicit_mood"] == 0
    assert later.stats["mood_summary"]["text_estimates"] == 140
    assert not any(p.kind == "mood_correlation" and p.label == "sleep" for p in later.surfaced)


def test_spanish_minority_grammar_and_theme_words_are_not_emergent_topics(monkeypatch):
    observed = []
    original = brain._detect_topics

    def capture(*args):
        claims = original(*args)
        observed.extend(claims)
        return claims

    monkeypatch.setattr(brain, "_detect_topics", capture)
    entries = [
        JournalEntry(
            "Hoy cuando porque tengo sueno veo guitarra "
            + ["marble", "planet", "telescope", "basket"][i % 4]
            if i % 3
            else "I am happy today after writing in my journal.",
            START + timedelta(days=i),
        )
        for i in range(60)
    ]
    # Make English the majority without removing the supported ES sources.
    entries.extend(
        JournalEntry(
            "I am happy and calm after walking with my family today.",
            START + timedelta(days=60 + i),
        )
        for i in range(70)
    )
    result = brain.update(brain.fresh_state(), entries, entries[-1].entry_date)
    assert result.stats["language"] == "en"
    assert observed, "recurring non-function content supplies eligible topic candidates"
    assert not any(set(s.label.split()) & {"cuando", "porque", "sueno"} for s in observed)


def test_spanish_window_excludes_code_switched_grammar_from_english_topic_cards():
    """A grammatical 'because' remains grammar inside bilingual English prose.

    The diary has 48 different English pottery observations and 72 Spanish
    entries. Real per-entry detection reads the minority observations as
    English, while the full window is Spanish. The recurring content must
    still surface, without turning their code-switched connector into a topic.
    """
    observations = [
        "bowl needed a wider rim",
        "mug had a blue glaze",
        "tray stayed on the shelf",
        "vase dried by the window",
        "plate used a red clay sample",
        "cup looked different in daylight",
        "box had a rough surface",
        "jar required a thinner handle",
        "lamp reflected the kiln light",
        "frame needed a smaller stencil",
        "beads showed the leaf pattern",
        "tile kept its uneven edge",
        "dish held some white paint",
        "pot needed more water",
        "sculpture took a shallow shape",
    ]
    reasons = [
        "the soup would need more space",
        "my sketch showed that color",
        "a fresh coat still needed time",
        "the weather had turned humid",
        "the local shop had that sample",
        "my desk lamp was warmer",
        "the grain looked interesting",
        "I wanted it to feel lighter",
        "the old mixture was lumpy",
        "my table is quite narrow",
        "the leaves had inspired me",
        "a smooth finish seemed dull",
        "I liked the extra contrast",
        "the material seemed too dry",
        "my drawing suggested this angle",
    ]
    spanish_observations = [
        "preparo una taza azul",
        "moldeo un plato ancho",
        "pinto una vasija pequena",
        "dibujo flores en el barro",
        "mezclo arcilla con agua",
        "ordeno los pinceles en la mesa",
        "pruebo un horno nuevo",
        "limpio los bordes de un cuenco",
        "guardo las piezas en la cocina",
        "miro los colores al sol",
        "busco formas en el jardin",
        "hago una caja para las herramientas",
        "corto una hoja de papel",
        "elijo un esmalte diferente",
        "espero que las piezas se sequen",
    ]
    entries = []
    detected_languages = []
    for i in range(120):
        group, position = divmod(i, 5)
        if position < 2:
            index = 2 * group + position
            text = (
                f"Today my pottery {observations[index % 15]} porque "
                f"{reasons[(index * 7 + index // 15) % 15]}."
            )
            expected_language = "en"
        else:
            index = 3 * group + position - 2
            text = (
                f"Hoy sigo con la ceramica y {spanish_observations[index % 15]} "
                "mientras pienso en lo que quiero hacer despues."
            )
            expected_language = "es"
        folded = brain._fold_sentiment_text(text.lower())
        detected = brain._analysis_language(
            brain.WORD_RE.findall(folded),
            sum("a" <= character <= "z" for character in folded),
            sum(character.isalpha() for character in folded),
            bool(text),
        )
        assert detected == expected_language
        detected_languages.append(detected)
        entries.append(JournalEntry(text, START + timedelta(days=i)))
    assert detected_languages.count("en") == 48
    assert len({e.text for e, lang in zip(entries, detected_languages) if lang == "en"}) == 48

    result = brain.update(brain.fresh_state(), entries, entries[-1].entry_date)
    assert result.stats["language"] == "es"
    topics = [card for card in result.surfaced if card.kind == "topic"]
    pottery = next(card for card in topics if card.label == "pottery")
    assert pottery.detail["entries"] == 48 and pottery.detail["share"] == 0.4
    assert pottery.detail["presence"] is True
    assert not any("porque" in card.label.split() for card in topics)


@pytest.mark.parametrize(
    ("text", "language", "direction"),
    [
        ("abandonment", "en", -1),
        ("feliz", "es", 1),
    ],
)
def test_direct_lexical_assets_retain_distress_and_joy(text, language, direction):
    assert direction * brain.sentiment_score(tokens(text), language) > 0.5


def test_sob_emoji_supplies_negative_affect_without_positive_affect():
    emitted = brain._emoji_tokens("😢")
    positive, negative = brain.sentiment_components(emitted)
    assert positive == 0 and negative > 0.5
    assert brain.sentiment_score(emitted) < -0.5


def test_sentence_initials_do_not_become_people():
    # Pliny is deliberately outside the lexicons; sentence-initial casing is
    # nevertheless not evidence that the author is describing a person.
    initials = [
        JournalEntry("Pliny wrote a quiet note today.", START + timedelta(days=i)) for i in range(9)
    ]
    names = [
        JournalEntry("I met Pliny after dinner today.", START + timedelta(days=i)) for i in range(9)
    ]
    assert "pliny" not in brain._person_candidates(initials)
    assert "pliny" in brain._person_candidates(names)


@pytest.mark.parametrize("detail", [{"source": "tag"}, {"channel": "sleep_quality"}, {}])
def test_structured_link_copy_respects_gap_two(detail):
    card = Pattern(
        "link",
        "poor sleep" if "channel" in detail else "walk",
        12,
        0.8,
        {"lag_days": 2, "direction": "lower", **detail},
    )
    assert "day after" not in card.describe().lower()
    assert "days after" in card.describe().lower()


def test_link_gap_census_counts_only_measured_outcomes():
    days = [START + timedelta(days=i) for i in range(50)]
    exposure_days = {days[i] for i in range(0, 45, 3)}
    theme_days = {d: {"work"} if d in exposure_days else set() for d in days}
    missing = {days[i + 1] for i in (0, 3, 6, 9)}
    residuals = {
        d: (-0.6 if d - timedelta(days=1) in exposure_days else 0.2) + (0.035 if i % 2 else -0.035)
        for i, d in enumerate(days)
        if d not in missing
    }
    claim = next(
        s for s in brain._detect_links(theme_days, residuals, days[-1]) if s.label == "work"
    )
    expected = {d + timedelta(days=1) for d in exposure_days} - missing
    assert claim.gate_ok and claim.pvalue < 0.05
    assert set(claim.evidence_days) == expected
    assert claim.detail["n_after"] == claim.detail["gap1_days"] == len(expected)
    assert claim.detail["gap2_days"] == 0


def test_inertia_requires_a_personal_rise_even_with_significant_test(monkeypatch):
    # The measured correlations can differ significantly at a high baseline
    # while their change remains smaller than the meaningful-effect gate.
    correlations = iter((0.95, 0.74))
    monkeypatch.setattr(brain, "_pearson", lambda _a, _b: next(correlations))
    series = [(START + timedelta(days=i), math.sin(i)) for i in range(170)]
    claim = brain._inertia_signal(series, "inertia:mood", "inertia", "mood", series[-1][0])
    assert claim is not None and claim.pvalue < 0.05
    assert claim.gate_ok is False


def test_avoidance_censors_the_last_observed_day():
    days = {START + timedelta(days=i * 2) for i in range(12)}
    # Additional consecutive writing supplies a nondegenerate personal rate.
    days |= {START + timedelta(days=40 + i) for i in range(12)}
    themed = {d: {"work"} for d in sorted(days)[:11]}
    themed[max(days)] = {"work"}
    claims = brain._detect_avoidance(themed, days, max(days))
    work = next(s for s in claims if s.label == "work")
    assert work.detail["observed"] == 11
    assert work.detail["silences"] == 11
    assert max(days) not in work.evidence_days


def test_weekend_silence_follows_own_writing_calendar():
    days = {
        START + timedelta(days=i) for i in range(140) if (START + timedelta(days=i)).weekday() < 5
    }
    themes = {d: {"work"} if d.weekday() == 4 else set() for d in days}
    claims = brain._detect_avoidance(themes, days, max(days))
    claim = next(s for s in claims if s.label == "work")
    assert claim.pvalue == 1.0
    assert claim.gate_ok is False


def test_short_text_cannot_supply_sense_making_density():
    assert brain._sense_density(tokens("because I understand why")) is None
    assert (
        brain._sense_density(
            tokens("I understand why because today I wrote about the reasons for this")
        )
        > 0
    )


def test_recovered_ewma_tail_is_not_a_current_shift(monkeypatch):
    monkeypatch.setattr(brain, "_lag1_autocorr", lambda _values: None)
    values = [0.01, -0.01] * 5 + [0.0] * 11
    series = [(START + timedelta(days=i), v) for i, v in enumerate(values)]
    assert brain._detect_mood_shift(series) == []
    decline = values[:10] + [-0.6] * 11
    assert brain._detect_mood_shift([(START + timedelta(days=i), v) for i, v in enumerate(decline)])


def test_ewma_tail_requires_same_direction_run(monkeypatch):
    monkeypatch.setattr(brain, "_lag1_autocorr", lambda _values: None)
    values = [0.01, -0.01] * 5 + [0.0] * 6 + [0.5, 0.5, 0.5, -1.0, -1.0]
    series = [(START + timedelta(days=i), v) for i, v in enumerate(values)]
    assert brain._detect_mood_shift(series) == []


def test_ewma_probability_and_limits_use_the_same_dependence(monkeypatch):
    captured = []
    original = brain._ewma_alarm_probability
    monkeypatch.setattr(brain, "_lag1_autocorr", lambda _values: 0.8)
    monkeypatch.setattr(
        brain,
        "_ewma_alarm_probability",
        lambda phi, n, z: captured.append(phi) or original(phi, n, z),
    )
    values = [0.01, -0.01] * 15 + [-0.9] * 90
    claims = brain._detect_mood_shift(
        [(START + timedelta(days=i), v) for i, v in enumerate(values)]
    )
    assert claims and captured == [pytest.approx(0.8)]


def test_phrase_recurrence_needs_three_distinct_days():
    refs = [phrases.SentenceRef("i keep checking the locks every evening", START)] * 5
    refs.append(
        phrases.SentenceRef("i keep checking the locks every evening", START + timedelta(days=9))
    )
    assert not phrases.near_duplicate_clusters(refs)
    refs.append(
        phrases.SentenceRef("i keep checking the locks every evening", START + timedelta(days=10))
    )
    assert len(phrases.near_duplicate_clusters(refs)) == 1


def topic_rows(texts):
    return [
        (JournalEntry(text, START + timedelta(days=i)), tokens(text), set(), 0.0)
        for i, text in enumerate(texts)
    ]


def test_fixed_theme_words_cannot_mint_emergent_topics():
    texts = [
        f"I wrote about work alongside {['marble', 'guitar', 'orchard', 'telescope'][i % 4]}"
        if i % 3
        else "I wrote a quiet journal about today"
        for i in range(60)
    ]
    claims = brain._detect_topics(topic_rows(texts), [], "en")
    assert not any("work" in s.label.split() for s in claims)
    assert claims, "non-theme recurring content is a positive control"


def test_topic_bigrams_cannot_bridge_function_words():
    texts = [
        f"guitar the orchard {['marble', 'planet', 'telescope', 'basket'][i % 4]}"
        if i % 3
        else "I wrote a quiet journal today"
        for i in range(60)
    ]
    claims = brain._detect_topics(topic_rows(texts), [], "en")
    assert any(s.label == "guitar" for s in claims)
    assert not any(s.label == "guitar orchard" for s in claims)


def test_rising_topic_significance_does_not_depend_on_entries_per_day():
    texts = [
        "I wrote about guitar " + ["marble", "planet", "telescope", "basket"][i % 4]
        if (i < 20 and i in (1, 8, 15)) or (i >= 20 and i % 2 == 0)
        else "I wrote a quiet journal today"
        for i in range(40)
    ]
    rows = topic_rows(texts)
    first = next(s for s in brain._detect_topics(rows, [], "en") if s.label == "guitar")
    clustered = [row for row in rows for _ in range(10)]
    second = next(s for s in brain._detect_topics(clustered, [], "en") if s.label == "guitar")
    assert first.gate_ok and second.gate_ok
    assert first.pvalue == second.pvalue
    assert first.detail["day_share_recent"] == second.detail["day_share_recent"]


def test_repeated_phrases_do_not_double_as_presence_topics():
    texts = [
        f"I keep the guitar {['marble', 'planet', 'telescope', 'basket'][i % 4]} nearby every evening"
        if i % 3
        else "I wrote a quiet journal today"
        for i in range(60)
    ]
    rows = topic_rows(texts)
    refs = [
        phrases.SentenceRef(" ".join(tokens(e.text)), e.entry_date)
        for e, *_ in rows
        if "guitar" in e.text
    ]
    cluster = phrases.PhraseCluster(refs, refs[0].text, 59, len(refs))
    unclustered = brain._detect_topics(rows, [], "en")
    assert any(
        s.label == "guitar" and (s.fallback or s.detail.get("presence")) for s in unclustered
    )
    clustered = brain._detect_topics(rows, [cluster], "en")
    assert not any(
        s.label == "guitar" and (s.fallback or s.detail.get("presence")) for s in clustered
    )


def test_measured_topic_presence_survives_rejected_rising_inference(monkeypatch):
    measured = signal(
        pid="topic:guitar",
        kind="topic",
        label="guitar",
        pvalue=None,
        detail={"trend": "steady", "presence": True},
        occurrences=30,
    )
    tested = signal(
        pid=measured.pid,
        kind="topic",
        label="guitar",
        pvalue=1.0,
        detail={"trend": "rising"},
        fallback=measured,
    )
    monkeypatch.setattr(brain, "_detect_topics", lambda *_args: [tested])
    entries = [
        JournalEntry("I wrote a calm journal today.", START + timedelta(days=i)) for i in range(25)
    ]
    result = brain.update(brain.fresh_state(), entries, entries[-1].entry_date)
    card = next(p for p in result.surfaced if p.kind == "topic" and p.label == "guitar")
    assert card.detail["trend"] == "steady" and card.detail["presence"] is True


def test_heterogeneous_skip_tail_matches_independent_enumeration():
    probabilities = (0.1, 0.4, 0.8, 1.0)
    for k in range(1, 5):
        expected = sum(
            math.prod(p if bit else 1 - p for p, bit in zip(probabilities, outcomes))
            for outcomes in itertools.product((0, 1), repeat=4)
            if sum(outcomes) >= k
        )
        assert statsig.poisson_binomial_sf(k, probabilities) == pytest.approx(expected)


def test_variance_floor_cannot_create_missing_group_variation():
    assert statsig.welch_test([0.8] * 12, [-0.8, -0.6] * 6, variance_floor=0.05) == (0.0, 1.0)
    _, p = statsig.welch_test([0.7, 0.9] * 6, [-0.8, -0.6] * 6, variance_floor=0.05)
    assert p < 0.001


def test_bh_step_up_rejects_later_rank_after_early_nonrejection():
    assert statsig.benjamini_hochberg([0.04, 0.045], q=0.05) == [True, True]
    assert statsig.benjamini_hochberg([0.045, 0.04], q=0.05) == [True, True]
    assert statsig.benjamini_hochberg([0.025, 0.2], q=0.05) == [True, False]


def test_inference_requires_two_fresh_evidence_days():
    memory = brain.fresh_state()
    brain._merge_lifecycle(memory, [signal()], START)
    brain._merge_lifecycle(
        memory, [signal(days=[START, START + timedelta(days=1)])], START + timedelta(days=1)
    )
    assert memory["patterns"]["temporal:work"].state == "candidate"
    brain._merge_lifecycle(
        memory,
        [signal(days=[START, START + timedelta(days=1), START + timedelta(days=2)])],
        START + timedelta(days=2),
    )
    assert memory["patterns"]["temporal:work"].state == "emerging"


def test_first_surface_starts_its_own_confirmation_clock():
    memory = brain.fresh_state()
    brain._merge_lifecycle(memory, [signal()], START)
    display_day = START + timedelta(days=30)
    grown = signal(days=[START, display_day - timedelta(days=1), display_day])
    brain._merge_lifecycle(memory, [grown], display_day)
    stored = memory["patterns"][grown.pid]
    assert stored.state == "emerging" and stored.first_qualified == display_day.isoformat()


def test_rotated_phrase_anchor_keeps_established_identity():
    memory = brain.fresh_state()
    old = record(
        detail={
            "phrase_anchor": "i keep checking the locks every single night",
            "variants": ["i keep checking the locks every single night"],
        }
    )
    memory["patterns"][old.pid] = old
    incoming = signal(
        pid="phrase:new",
        kind="recurring_phrase",
        label="i keep checking the locks every single evening",
        pvalue=None,
        detail={
            "phrase_anchor": "i keep checking the locks every single evening",
            "variants": ["i keep checking the locks every single evening"],
        },
        days=[START + timedelta(days=1)],
    )
    brain._merge_lifecycle(memory, [incoming], START + timedelta(days=1))
    assert set(memory["patterns"]) == {old.pid}
    assert memory["patterns"][old.pid].first_seen == START.isoformat()


def test_muted_pattern_never_reenters_question_pool():
    muted = Pattern("topic", "guitar", 20, 0.8, {"trend": "steady", "muted": True})
    assert questions.build_pool([muted]) == list(questions.GENERIC_QUESTIONS)
    assert any(
        "guitar" in q
        for q in questions.build_pool([Pattern("topic", "guitar", 20, 0.8, {"trend": "steady"})])
    )


def test_patient_rejection_moves_a_topic_below_unrejected_topics():
    rejected = Pattern("topic", "guitar", 20, 0.8, {"trend": "steady", "feedback": {"not_me": 3}})
    accepted = Pattern("topic", "orchard", 20, 0.8, {"trend": "steady", "feedback": {}})
    pool = questions.build_pool([rejected, accepted])
    assert "orchard" in pool[0]
    assert all("guitar" not in q for q in pool[:3])
    assert any("guitar" in q for q in pool[3:6])


def test_spanish_question_pool_is_entirely_localized():
    assert questions.build_pool([], "es") == list(questions.GENERIC_QUESTIONS_ES)


def test_day_pin_is_scoped_by_user_date_and_language(monkeypatch):
    monkeypatch.setattr(questions, "_DAY_PINNED_QUESTIONS", {})
    english = questions.question_for_today("reader", [], START, "en")
    spanish = questions.question_for_today("reader", [], START, "es")
    assert english in questions.GENERIC_QUESTIONS
    assert spanish in questions.GENERIC_QUESTIONS_ES
    assert english != spanish


@pytest.mark.parametrize("text", ["I want to die", "quiero morir", "I will hang myself", "我想死"])
def test_dialog_language_is_always_suppressed_by_actual_matcher(text):
    assert crisis.matches_dialog(text)
    assert crisis.matches_suppress(text)


@pytest.mark.parametrize(
    "text", ["I w a nt to die", "I w ant to die", "I k ill myself", "I h urt myself"]
)
def test_partial_crisis_split_still_suppresses_reflective_question(text):
    assert crisis.matches_dialog(text)
    assert crisis.matches_suppress(text)
    card = Pattern("rumination", text, 12, 0.8, {})
    assert questions.build_pool([card]) == list(questions.GENERIC_QUESTIONS)


@pytest.mark.parametrize(
    "text",
    [
        "life i s n't worth living",
        "life i s n't worth living anymore",
        "life i s not worth living",
    ],
)
def test_split_is_keeps_its_original_crisis_interpretation(text):
    assert crisis.matches_dialog(text)
    assert crisis.matches_suppress(text)


@pytest.mark.parametrize(
    "text", ["I w a nt to diet", "I w ant to dine", "I a m so sad", "I k now myself"]
)
def test_partial_benign_words_remain_outside_both_crisis_tiers(text):
    assert not crisis.matches_dialog(text)
    assert not crisis.matches_suppress(text)


@pytest.mark.parametrize(
    "text",
    ["a rocky sunset", "weekend it all comes together", "sending it all back", "a lucky star"],
)
def test_marked_concat_does_not_invent_crisis_from_word_junctions(text):
    assert not crisis.matches_dialog(text)
    assert not crisis.matches_suppress(text)


def test_sensitive_fourth_variant_survives_display_list_trimming():
    variants = [
        "a recurring quiet worry in the evening",
        "b recurring quiet worry in the evening",
        "c recurring quiet worry in the evening",
        "z recurring quiet worry I want to die",
    ]
    refs = [phrases.SentenceRef(v, START + timedelta(days=i * 3)) for i, v in enumerate(variants)]
    cluster = phrases.PhraseCluster(refs, variants[0], 9, 4)
    detected = brain._detect_phrases([cluster], language="en")[0]
    assert len(detected.detail["variants"]) == 3
    assert all(not crisis.matches_suppress(v) for v in detected.detail["variants"])
    stored = record(label=detected.label, kind=detected.kind, detail=detected.detail)
    state = brain.fresh_state()
    state["patterns"][stored.pid] = stored
    result = brain.update(state, [], START + timedelta(days=1))
    assert result.surfaced[0].detail["sensitive"] is True


def test_mild_label_cannot_hide_sensitive_question_variant():
    card = Pattern(
        "rumination", "a quiet recurring worry", 12, 0.8, {"variants": ["I want to die"]}
    )
    assert questions.pattern_is_sensitive(card)
    assert questions.build_pool([card]) == list(questions.GENERIC_QUESTIONS)


def test_enrichment_cannot_change_established_finding_numbers(monkeypatch):
    original = Pattern("temporal", "work", 14, 0.73, {"day": "Sunday", "p_value": 0.002})
    analyzer = llm.LLMAnalyzer("https://unused.invalid", "unused")
    item = {
        "kind": "temporal",
        "label": "work",
        "occurrences": 999,
        "confidence": 0.01,
        "detail": {"day": "Monday"},
        "narrative": "Work has a recurring place in your writing.",
    }
    monkeypatch.setattr(
        analyzer,
        "_post",
        lambda _payload: {"choices": [{"message": {"content": json.dumps({"patterns": [item]})}}]},
    )
    refined = analyzer.extract_patterns([JournalEntry("work", START)], [original])
    assert len(refined) == 1
    assert refined[0].occurrences == 14 and refined[0].confidence == 0.73
    assert refined[0].detail["day"] == "Sunday" and refined[0].detail["p_value"] == 0.002


def test_unknown_provider_finding_does_not_discard_valid_narration(monkeypatch):
    original = Pattern("temporal", "work", 14, 0.73, {"day": "Sunday"})
    analyzer = llm.LLMAnalyzer("https://unused.invalid", "unused")
    items = [
        {"kind": "temporal", "label": "guitar", "narrative": "Guitar recurs in your writing."},
        {"kind": "temporal", "label": "work", "narrative": "Work recurs in your writing."},
    ]
    monkeypatch.setattr(
        analyzer,
        "_post",
        lambda _payload: {"choices": [{"message": {"content": json.dumps({"patterns": items})}}]},
    )
    result = analyzer.extract_patterns([JournalEntry("work guitar", START)], [original])
    assert len(result) == 1 and result[0].label == "work"
    assert analyzer.last_error is None


@pytest.mark.parametrize(
    "prefix",
    [
        "You should abandon your friends. ",
        "Your medication needs changing. ",
        "I want to die. ",
        "Visit helpnow.example.com. ",
        "Your mood shifted by 87 percent. ",
    ],
)
def test_long_narrative_still_passes_all_hostile_output_guards(prefix):
    assert llm._clean_narrative(prefix + "A recurring observation about your days. " * 12) is None
