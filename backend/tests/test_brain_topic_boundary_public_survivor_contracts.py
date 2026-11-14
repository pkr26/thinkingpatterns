"""Native public topic boundaries, edited journals, language and phrase continuity."""

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

T = date(2026, 10, 22)
FOLLOWERS = ("plucking", "tuning", "strumming", "picking", "fretting", "learning")


def recompute(stages):
    state = brain.fresh_state()
    for entries, today in stages:
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    return result


def topics(result):
    return [p for p in result.surfaced if p.kind == "topic"]


def simple_rise(label):
    before = [
        JournalEntry("I have " + (label if i >= 10 else "notes"), T - timedelta(days=19 - i))
        for i in range(20)
    ]
    final = before + [JournalEntry("I have " + label, T + timedelta(days=k)) for k in (1, 2)]
    return [(before, T), (final, T + timedelta(days=2))]


def edited_six():
    before = [
        JournalEntry("I have " + ("guitar" if i >= 12 else "notes"), T - timedelta(days=19 - i))
        for i in range(20)
    ]
    final = [
        JournalEntry("I have " + ("guitar" if i >= 16 else "notes"), T - timedelta(days=19 - i))
        for i in range(20)
    ]
    final += [JournalEntry("I have guitar", T + timedelta(days=k)) for k in (1, 2)]
    return [(before, T), (final, T + timedelta(days=2))]


def rate_boundary(earlier_n, recent_n, earlier_hits, recent_hits):
    first = []
    final = []
    for i in range(100):
        di = i * earlier_n // 100
        day = T - timedelta(days=earlier_n + recent_n - 1 - di)
        entry = JournalEntry("I have " + ("guitar" if di < earlier_hits else "notes"), day)
        first.append(entry)
        final.append(entry)
    for i in range(recent_n):
        day = T - timedelta(days=recent_n - 1 - i)
        hit_final = i < recent_hits - 2 or i >= recent_n - 2
        hit_first = i < recent_hits + 2
        final.append(JournalEntry("I have " + ("guitar" if hit_final else "notes"), day))
        if i < recent_n - 2:
            first.append(JournalEntry("I have " + ("guitar" if hit_first else "notes"), day))
    return [(first, T - timedelta(days=2)), (final, T)]


def presence():
    es = [
        JournalEntry(
            "the guitar " + FOLLOWERS[i % 6] if i < 21 else "the have notes",
            T - timedelta(days=69 - i),
        )
        for i in range(70)
    ]
    return [(es, T)]


def coverage():
    quote = (
        "I have the guitar celadon amber ivory linen granite marble quartz jasper opal cobalt slate"
    )
    es = [
        JournalEntry(
            quote if i < 24 else "the guitar " + FOLLOWERS[i % 6] if i < 30 else "the have notes",
            T - timedelta(days=59 - i),
        )
        for i in range(60)
    ]
    return [(es, T)]


def thin():
    es = []
    for i in range(80):
        d = T - timedelta(days=31 if i < 50 else 80 - i)
        text = (
            "the have notes"
            if i % 5 == 0
            else "the guitar " + FOLLOWERS[i % 6] + ". the mandolin " + FOLLOWERS[(i + 2) % 6]
        )
        es.append(JournalEntry(text, d))
    return [(es, T)]


def mixed():
    before = []
    for i in range(80):
        text = (
            "hoy tengo insomnio y mucho dinero"
            if i >= 40 and i % 2 == 0
            else "I have the notes and the journal"
        )
        before.append(JournalEntry(text, T - timedelta(days=79 - i)))
    final = before + [
        JournalEntry("hoy tengo insomnio y mucho dinero", T + timedelta(days=k)) for k in (1, 2)
    ]
    return [(before, T), (final, T + timedelta(days=2))]


def edited_five():
    stages = edited_six()
    before, today = stages[0]
    final = [
        JournalEntry("I have " + ("guitar" if i >= 17 else "notes"), T - timedelta(days=19 - i))
        for i in range(20)
    ]
    final += [JournalEntry("I have guitar", T + timedelta(days=k)) for k in (1, 2)]
    return [(before, today), (final, T + timedelta(days=2))]


def partial_coverage():
    quote = (
        "I have the guitar celadon amber ivory linen granite marble quartz jasper opal cobalt slate"
    )
    es = [
        JournalEntry(
            quote if i < 9 else "the guitar " + FOLLOWERS[i % 6] if i < 30 else "the have notes",
            T - timedelta(days=59 - i),
        )
        for i in range(60)
    ]
    return [(es, T)]


def happy_word():
    es = [
        JournalEntry(
            "I felt Happy today" if i % 3 == 0 else "I have the notes",
            T - timedelta(days=69 - i),
            sentiment=(-0.6 if i % 3 == 0 else 0.3) + (i % 5 - 2) * 0.007,
        )
        for i in range(70)
    ]
    final = es + [
        JournalEntry("I felt Happy today", T + timedelta(days=i), sentiment=-0.6) for i in (1, 2)
    ]
    return [(es, T), (final, T + timedelta(days=2))]


def alias_variant():
    q = "I always feel sad and terribly alone in this ordinary empty room"
    first = [JournalEntry(q, T - timedelta(days=180))] + [
        JournalEntry(q + " again", T - timedelta(days=d)) for d in (10, 0)
    ]
    final = first + [JournalEntry(q + " again", T + timedelta(days=1))]
    return [(first, T), (final, T + timedelta(days=1))]


def test_six_current_mentions_still_replicate_after_edits_and_two_fresh_dates():
    # The first corpus has eight guitar mentions. Four old texts are
    # edited, then two fresh dated mentions arrive: six current mentions.
    (card,) = topics(recompute(edited_six()))
    assert card.label == "guitar"
    assert card.occurrences == 6
    assert card.detail["distinct_days"] == 6
    assert card.detail["trend"] == "rising"
    assert card.detail["p_value"] == 0.000002


def test_five_current_mentions_do_not_make_a_replicated_topic_after_edits():
    assert topics(recompute(edited_five())) == []


def test_possessive_text_keeps_the_full_content_word_on_the_topic_card():
    (card,) = topics(recompute(simple_rise("guitar's")))
    assert card.label == "guitar"
    assert card.occurrences == 12


def test_an_english_function_word_never_becomes_a_rising_topic():
    assert topics(recompute(simple_rise("about"))) == []


def test_minority_spanish_entries_keep_their_actual_language_exclusions():
    result = recompute(mixed())
    assert result.stats["language"] == "en"
    assert topics(result) == []


def test_exact_eighteen_percent_day_rate_keeps_its_native_measurements():
    # One earlier guitar date among24, eighteen recent dates among100.
    # Repeated earlier entries do not become independent calendar trials.
    (card,) = topics(recompute(rate_boundary(24, 100, 1, 18)))
    assert card.label == "guitar"
    assert card.occurrences == 23
    assert card.detail["day_share_recent"] == 0.18
    assert card.detail["day_share_earlier"] == 0.042
    assert card.detail["p_value"] == 0.000027


def test_a_rate_below_the_additive_gain_bar_does_not_print_a_topic():
    assert topics(recompute(rate_boundary(38, 100, 2, 18))) == []


def test_exact_relative_day_rate_gain_is_still_inclusive():
    (card,) = topics(recompute(rate_boundary(24, 100, 2, 25)))
    assert card.label == "guitar"
    assert card.detail["day_share_recent"] == 0.25
    assert card.detail["p_value"] == 0.000013


def test_exact_thirty_percent_presence_uses_twenty_one_native_dates():
    (card,) = topics(recompute(presence()))
    assert card.label == "guitar"
    assert card.occurrences == 21
    assert card.detail["share"] == 0.3
    assert card.detail["presence"] is True


def test_eighty_percent_phrase_coverage_explains_the_topic_presence():
    result = recompute(coverage())
    assert any(p.kind == "recurring_phrase" for p in result.surfaced)
    assert topics(result) == []


def test_partial_phrase_coverage_leaves_the_independent_topic_presence():
    (card,) = topics(recompute(partial_coverage()))
    assert card.label == "guitar"
    assert card.occurrences == 30
    assert card.detail["presence"] is True


def test_two_untestable_presence_measurements_both_reach_the_public_result():
    cards = topics(recompute(thin()))
    assert [(p.label, p.occurrences) for p in cards] == [
        ("guitar", 64),
        ("mandolin", 64),
    ]
    assert all(p.detail["presence"] is True for p in cards)


def test_a_known_mood_word_does_not_become_a_proper_name():
    result = recompute(happy_word())
    assert not any(
        p.label == "happy" and p.detail.get("source") == "person" for p in result.surfaced
    )


def test_rumination_continues_after_its_oldest_text_variant_leaves_the_window():
    result = recompute(alias_variant())
    (card,) = [p for p in result.surfaced if p.kind == "rumination"]
    assert card.detail["first_seen"] == (T - timedelta(days=180)).isoformat()
    assert card.occurrences == 3
