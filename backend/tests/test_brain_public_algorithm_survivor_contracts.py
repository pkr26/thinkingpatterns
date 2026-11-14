"""Public analysis claims after ordinary journal history and state roundtrips."""

import json
import random
from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

TODAY = date(2026, 10, 5)


def test_many_distinct_valid_tags_still_produce_a_complete_public_summary():
    entries = [
        JournalEntry(
            "I wrote ordinary notes about the quiet day.",
            TODAY - timedelta(days=i),
            sentiment=0.2,
            tags=tuple(f"activity{j:02}" for j in range(i * 7, (i + 1) * 7)),
        )
        for i in range(4)
    ]
    result = brain.update(brain.fresh_state(), entries, TODAY)
    assert result.stats["total_entries"] == 4
    assert result.stats["active_days"] == 4
    assert result.stats["avg_sentiment"] == 0.2
    assert result.stats["mood_summary"]["source"] == "explicit_mood"


def carryover_entries(channel):
    entries = []
    for i in range(70):
        day = TODAY - timedelta(days=69 - i)
        value = (0.4 if (i // 4) % 2 == 0 else -0.4) if i >= 42 else (0.3 if i % 2 == 0 else -0.3)
        if channel in {"positive_affect", "negative_affect"}:
            text = "a calm and grateful day" if value > 0 else "an anxious tired day"
            entries.append(JournalEntry(text, day))
        else:
            entries.append(JournalEntry("ordinary day notes", day, **{channel: value}))
    return entries


@pytest.mark.parametrize(
    ("channel", "kind", "label", "public_channel", "pid"),
    [
        ("sentiment", "inertia", "day-to-day mood", None, "inertia:mood"),
        ("energy", "energy_inertia", "day-to-day energy", "energy", "inertia:energy"),
        (
            "positive_affect",
            "pa_inertia",
            "day-to-day positive feelings",
            "positive_affect",
            "inertia:pa",
        ),
        (
            "negative_affect",
            "na_inertia",
            "day-to-day negative feelings",
            "negative_affect",
            "inertia:na",
        ),
    ],
)
def test_rising_carryover_keeps_its_public_channel_and_actual_comparison_window(
    channel, kind, label, public_channel, pid
):
    entries = carryover_entries(channel)
    state = brain.fresh_state()
    seen = []
    for offset in range(9):
        result = brain.update(
            brain.load_state(brain.dump_state(state)), entries, TODAY + timedelta(days=offset)
        )
        state = result.new_state
        seen.extend(card for card in result.surfaced if card.kind == kind)
    assert seen, "Repeated observed carryover must surface after repeated state roundtrips"
    card = seen[0]
    assert card.label == label
    assert card.detail["pattern_pid"] == pid
    assert card.detail.get("channel") == public_channel
    assert card.detail["window_days"] == 28
    assert card.detail["carryover_recent"] > card.detail["carryover_earlier"]
    assert card.detail["p_value"] < 0.05


@pytest.mark.parametrize(
    ("text", "language"),
    [
        ("a bad and sad day", "en"),
        ("a banana and a papaya", "en"),
        ("I was zzzzzzzzzzzz tired", "en"),
        ("bad ЯЯЯ", "other"),
        ("good ЯЯЯ", "en"),
        ("good 𝐘𝐘𝐘𝐘", "other"),
        (
            "good amaryllis bougainvillea chrysanthemum delphinium echeveria "
            "frangipani gardenia heliconia ixora",
            "en",
        ),
        ("ecstatic", "en"),
    ],
)
def test_short_mixed_script_notes_report_the_actual_text_scoring_coverage(text, language):
    result = brain.update(brain.fresh_state(), [JournalEntry(text, TODAY)], TODAY)
    assert result.stats["language"] == language
    if language == "other":
        # The tokenizer cannot supply enough supported text. The public
        # summary must say that text-derived mood is unavailable.
        assert result.stats["avg_sentiment"] is None
        assert result.stats["mood_summary"]["source"] == "unavailable"


SENSE_TEXTS = (
    "i realize the reason i felt tense was the meeting, because i "
    "understand now that the deadline caused it and i notice why",
    "i realize the reason i felt tense was the meeting, because i "
    "understand now that the deadline caused it and i notice why, and later the walk helped",
)
UNSUPPORTED_NOTE = (
    "Сегодня я размышлял о прошедшем дне и писал свои мысли в дневник. "
    "Мне было тяжело и хотелось отдохнуть. "
)


def sense_making_detail(transform):
    entries = [
        JournalEntry(
            SENSE_TEXTS[i % 2]
            if i >= 42
            else "we went to the market and i saw a friend there and walked home",
            TODAY - timedelta(days=69 - i),
        )
        for i in range(70)
    ]
    state = brain.fresh_state()
    for offset in range(6):
        entries.append(JournalEntry(SENSE_TEXTS[offset % 2], TODAY + timedelta(days=offset)))
        result = brain.update(
            brain.load_state(brain.dump_state(state)),
            transform(entries),
            TODAY + timedelta(days=offset),
        )
        state = result.new_state
        card = next((p for p in result.surfaced if p.kind == "sense_making"), None)
        if card is not None:
            return {
                key: card.detail[key]
                for key in ("density_recent", "density_earlier", "p_value", "direction")
            }
    return None


@pytest.mark.parametrize("case", ["duplicates", "leading_unsupported", "mixed_unsupported"])
def test_sense_making_uses_supported_daily_measurements(case):
    reference = sense_making_detail(list)
    assert reference is not None
    if case == "duplicates":
        # Repeating the same report within selected calendar days does
        # not change a daily mean or its comparison with earlier days.
        def transform(rows):
            return rows + [e for e in rows if e.entry_date.toordinal() % 3 == 0]
    else:
        note = JournalEntry(
            UNSUPPORTED_NOTE
            if case == "leading_unsupported"
            else UNSUPPORTED_NOTE * 3
            + " because realize understand notice why reason caused explained cause think",
            TODAY - timedelta(days=80 if case == "leading_unsupported" else 3),
        )

        def transform(rows):
            return rows + [note]

    assert sense_making_detail(transform) == reference


def test_ten_word_journal_notes_supply_real_sense_making_evidence():
    earlier = (
        "i wrote ordinary words about the quiet day at home",
        "i notice ordinary words about the quiet day at home",
    )
    recent = (
        "because reason realize understand notice i wrote words about today",
        "because reason realize understand here i wrote words about today",
    )
    entries = [
        JournalEntry((recent if i >= 42 else earlier)[i % 2], TODAY - timedelta(days=69 - i))
        for i in range(70)
    ]
    state = brain.fresh_state()
    cards = []
    for offset in range(4):
        if offset:
            entries.append(JournalEntry(recent[offset % 2], TODAY + timedelta(days=offset)))
        result = brain.update(
            brain.load_state(brain.dump_state(state)), entries, TODAY + timedelta(days=offset)
        )
        state = result.new_state
        cards.extend(p for p in result.surfaced if p.kind == "sense_making")
    assert cards, "Ten-word notes are long enough to supply measured text evidence"
    assert cards[-1].detail["direction"] == "higher"
    assert cards[-1].detail["density_recent"] > cards[-1].detail["density_earlier"]


def test_weekday_card_reports_the_supported_fraction_of_tag_days():
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        entries = []
        for offset in range(84):
            day = today - timedelta(days=offset)
            tagged = day.weekday() == 0 or offset == 1
            entries.append(
                JournalEntry(
                    "ordinary day notes",
                    day,
                    sentiment=0.8 if tagged else 0.1,
                    tags=("yoga",) if tagged else (),
                )
            )
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    card = next(p for p in result.surfaced if p.kind == "temporal" and p.label == "yoga")
    assert card.detail["day"] == "Monday"
    assert card.detail["day_count"] == 12
    assert card.detail["day_fraction"] == 0.923  # Twelve of thirteen tagged days.


def test_recent_identical_energy_and_mood_reports_have_complete_public_coupling():
    entries = []
    for i in range(70):
        recent = i >= 42
        mood = (0.4 if (i // 4) % 2 == 0 else -0.4) if recent else (0.3 if i % 2 == 0 else -0.3)
        entries.append(
            JournalEntry(
                "ordinary day notes",
                TODAY - timedelta(days=69 - i),
                sentiment=mood,
                energy=mood if recent else 0.05,
            )
        )
    state = brain.fresh_state()
    for offset in range(9):
        result = brain.update(
            brain.load_state(brain.dump_state(state)), entries, TODAY + timedelta(days=offset)
        )
        state = result.new_state
        card = next((p for p in result.surfaced if p.kind == "energy_mood_coupling"), None)
        if card is not None:
            break
    else:
        pytest.fail("Repeated concordant energy and mood must surface their coupling")
    assert card.detail["coupling_recent"] == 1.0
    assert card.detail["coupling_recent"] > card.detail["coupling_earlier"]


@pytest.mark.parametrize("boundary", ["lower_neighbor", "upper_neighbor"])
def test_ten_rated_nights_combine_with_existing_self_reported_sleep_tags(boundary):
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        mondays = [
            today - timedelta(days=i)
            for i in range(84)
            if (today - timedelta(days=i)).weekday() == 0
        ]
        entries = []
        for offset in range(84):
            day = today - timedelta(days=offset)
            quality = 1 if day in mondays[:5] else 5 if offset in (1, 2, 3, 4, 5) else None
            if boundary == "lower_neighbor" and day == mondays[4]:
                quality = 4
            if boundary == "upper_neighbor" and offset == 1:
                quality = 4
            entries.append(
                JournalEntry(
                    "ordinary day notes",
                    day,
                    sentiment=0.8 if day.weekday() == 0 else 0.1,
                    sleep_quality=quality,
                    tags=("poor sleep",) if day in mondays[5:] else (),
                )
            )
        assert sum(entry.sleep_quality is not None for entry in entries) == 10
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    # Five lower-rated Mondays join the seven Mondays already tagged by
    # the user. The middle two ratings separate those five from all other
    # nights, even when their adjacent observed values differ.
    card = next(p for p in result.surfaced if p.kind == "temporal" and p.label == "poor sleep")
    assert card.detail["day"] == "Monday"
    assert card.detail["day_count"] == 12
    assert card.occurrences == 12


def test_repeated_same_day_sleep_reports_preserve_the_actual_poor_nights():
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        entries = []
        for offset in range(84):
            day = today - timedelta(days=offset)
            monday = day.weekday() == 0
            entry = JournalEntry(
                "ordinary day notes",
                day,
                sentiment=0.8 if monday else 0.1,
                sleep_quality=1 if monday else 5,
            )
            entries.append(entry)
            if monday and day.isocalendar().week % 2 == 0:
                entries.extend([entry, entry])
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    card = next(p for p in result.surfaced if p.kind == "temporal" and p.label == "poor sleep")
    assert card.detail["day"] == "Monday"
    assert card.occurrences == 12


def test_blank_journal_text_keeps_the_users_explicit_activity_tag_evidence():
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        entries = []
        for offset in range(84):
            day = today - timedelta(days=offset)
            monday = day.weekday() == 0
            entries.append(
                JournalEntry("ordinary day notes", day, sentiment=0.8 if monday else 0.1)
            )
            if monday:
                # Text can be blanked by the bounded corpus parser while
                # its independently reported activity tag remains valid.
                entries.append(JournalEntry("", day, tags=("yoga",)))
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    card = next(p for p in result.surfaced if p.kind == "temporal" and p.label == "yoga")
    assert card.detail["day"] == "Monday"
    assert card.detail["source"] == "tag"
    assert card.occurrences == 12


def test_mood_only_checkins_still_measure_the_users_reported_carryover():
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        entries = []
        for offset in range(84):
            i = 83 - offset
            value = (
                (0.4 if (i // 4) % 2 == 0 else -0.4) if i >= 56 else (0.3 if i % 2 == 0 else -0.3)
            )
            entries.append(JournalEntry("", today - timedelta(days=offset), sentiment=value))
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    card = next(p for p in result.surfaced if p.kind == "inertia")
    assert card.detail["carryover_recent"] > card.detail["carryover_earlier"]
    assert result.stats["mood_summary"]["source"] == "explicit_mood"
    assert result.stats["mood_summary"]["observations"] == 84


def test_valid_finite_ratings_at_a_rounding_boundary_still_complete_public_analysis():
    # The precision is intentional: the final chart point is strictly
    # outside its bound, while the derived magnitude rounds to the first
    # calibration knot. These are ordinary finite ratings in [-1, 1].
    moods = [-0.2217102664043494, 0.11962972221388027] * 5
    moods += [0.9233336824943649] + [0.12434703973089331] * 10
    entries = [
        JournalEntry("ordinary day notes", TODAY - timedelta(days=20 - i), sentiment=mood)
        for i, mood in enumerate(moods)
    ]
    result = brain.update(brain.fresh_state(), entries, TODAY)
    assert result.stats["total_entries"] == 21
    assert result.stats["avg_sentiment"] == 0.079
    assert result.stats["mood_summary"]["observations"] == 21
    assert result.stats["mood_summary"]["source"] == "explicit_mood"


@pytest.mark.parametrize("supported", [True, False])
def test_a_quoted_english_theme_in_unsupported_prose_is_not_an_english_theme_day(supported):
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        entries = []
        for offset in range(84):
            day = today - timedelta(days=offset)
            monday = day.weekday() == 0
            text = "I wrote ordinary notes about the quiet day. " * 3
            if monday:
                text = "ordinary notes about work" if supported else UNSUPPORTED_NOTE + " work"
            entries.append(JournalEntry(text, day, sentiment=0.8 if monday else 0.1))
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    assert result.stats["language"] == "en"
    cards = [p for p in result.surfaced if p.kind == "temporal" and p.label == "work"]
    assert bool(cards) is supported


def test_unsupported_quoted_feeling_words_do_not_change_the_supported_affect_measurement():
    entries = carryover_entries("negative_affect")
    reference = public_carryover_detail(entries, "na_inertia")
    assert reference is not None
    entries.append(
        JournalEntry(UNSUPPORTED_NOTE * 3 + " anxious tired sad", TODAY - timedelta(days=3))
    )
    assert public_carryover_detail(entries, "na_inertia") == reference


TOPIC_CONTEXTS = (
    "read a few pages of the novel before lights out",
    "rearranged the kitchen shelves and found old receipts",
    "listened to a podcast on the commute home",
    "watered all the plants on the balcony",
    "tried a new recipe with lentils and rice",
    "fixed the squeaky door hinge at last",
    "walked past the old bookshop after lunch",
    "wrote a letter to my cousin overseas",
    "sorted through the photo box from the move",
    "repaired the bike tire in the garage",
    "watched the rain from the window with tea",
    "organized the desk drawers and old cables",
    "cooked soup for tomorrow and froze half",
    "stretched out on the couch for a while",
    "sketched the view from the kitchen window",
    "paid the utilities and filed the receipt",
    "took the long way home through the park",
    "bought oranges and bread from the corner shop",
    "brewed proper coffee instead of instant",
    "changed the burnt bulb in the hallway",
)


def test_growing_topics_replicate_from_the_first_twenty_supported_journal_days():
    entries = [
        JournalEntry(context + (" guitar" if i >= 10 else ""), TODAY - timedelta(days=19 - i))
        for i, context in enumerate(TOPIC_CONTEXTS)
    ]
    first = brain.update(brain.fresh_state(), entries, TODAY)
    entries.extend(
        [
            JournalEntry(
                "practiced the guitar after dinner, new chord shapes", TODAY + timedelta(days=1)
            ),
            JournalEntry("played the guitar before breakfast, warmups", TODAY + timedelta(days=2)),
        ]
    )
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), entries, TODAY + timedelta(days=2)
    )
    card = next(p for p in result.surfaced if p.kind == "topic" and p.label == "guitar")
    assert card.detail["trend"] == "rising"
    assert card.detail["day_share_recent"] > card.detail["day_share_earlier"]


def test_topic_growth_does_not_count_quotes_inside_unsupported_entries():
    entries = []
    for i in range(70):
        text = TOPIC_CONTEXTS[i % len(TOPIC_CONTEXTS)]
        if i in (2, 5, 8):
            text += " played the notebook a little"
        if i >= 42 and (i - 42) % 3 == 0:
            text += " spent the evening with the notebook, learning fingerpicking"
        entries.append(JournalEntry(text, TODAY - timedelta(days=69 - i)))
    entries.extend(
        JournalEntry(UNSUPPORTED_NOTE + " guitar learning fingerpicking", TODAY - timedelta(days=i))
        for i in range(0, 28, 2)
    )
    first = brain.update(brain.fresh_state(), entries, TODAY)
    entries.extend(
        [
            JournalEntry(UNSUPPORTED_NOTE + " guitar new chords", TODAY + timedelta(days=1)),
            JournalEntry(UNSUPPORTED_NOTE + " guitar finger exercise", TODAY + timedelta(days=2)),
        ]
    )
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), entries, TODAY + timedelta(days=2)
    )
    assert result.stats["language"] == "en"
    assert not any(p.kind == "topic" and p.label == "guitar" for p in result.surfaced)


def test_narrower_activity_variety_surfaces_after_two_new_measured_weeks():
    first_day = date(2026, 10, 4)
    start = first_day - timedelta(days=111)
    state = brain.fresh_state()
    cards = []
    for offset in (0, 7, 14, 21):
        today = first_day + timedelta(days=offset)
        entries = []
        for i in range((today - start).days + 1):
            week = i // 7
            distinct = (7 if week % 2 == 0 else 4) if week < 12 else (2 if week % 2 == 0 else 3)
            # Distinct labels for each week's activities avoid inventing
            # a separate persistent weekday association for those tags.
            tag = f"activity_{week:02}_{i % 7 % distinct}"
            entries.append(
                JournalEntry("ordinary day notes", start + timedelta(days=i), tags=(tag,))
            )
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
        cards.extend(p for p in result.surfaced if p.kind == "activity_diversity")
    assert cards
    card = cards[-1]
    assert card.detail["direction"] == "narrowed"
    assert card.detail["entropy_recent"] < card.detail["entropy_earlier"]
    assert card.detail["channel"] == "activity_tags"


def test_minority_spanish_theme_words_do_not_fabricate_a_personal_mood_tie():
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        entries = []
        for i in range(84):
            if i % 3 == 0:
                text = "hoy tengo insomnio" + (" insomnio" if i % 2 else "")
            else:
                text = "today I feel good" if i % 2 else "today I feel bad"
            entries.append(JournalEntry(text, today - timedelta(days=83 - i)))
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    assert result.stats["language"] == "en"
    # The minority entries retain their Spanish grammar. The negative
    # value of the sleep word itself is not independent personal evidence
    # that mood is lower whenever sleep is mentioned.
    assert not any(p.kind == "mood_correlation" and p.label == "sleep" for p in result.surfaced)


@pytest.mark.parametrize("unsupported_source", [False, True])
def test_repeated_phrase_classification_keeps_all_same_day_language_sources(unsupported_source):
    quote = "i always feel sad and terribly alone"
    entries = [
        JournalEntry("I wrote ordinary notes about the quiet day. " * 2, TODAY - timedelta(days=i))
        for i in range(70)
    ]
    for ago in (0, 4, 8):
        day = TODAY - timedelta(days=ago)
        entries.append(JournalEntry(quote + ".", day))
        if unsupported_source:
            entries.append(JournalEntry(UNSUPPORTED_NOTE * 3 + quote + ".", day))
    first = brain.update(brain.fresh_state(), entries, TODAY)
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), entries, TODAY + timedelta(days=1)
    )
    assert result.stats["language"] == "en"
    card = next(p for p in result.surfaced if p.label == quote)
    # If either same-day source is unsupported, only the repetition is
    # observable. Its stripped English quote cannot establish the
    # negative-feeling classification for that ambiguous phrase.
    assert card.kind == ("recurring_phrase" if unsupported_source else "rumination")


def test_a_later_mood_change_uses_the_normal_learned_after_the_original_alarm():
    start = TODAY - timedelta(days=83)
    state = brain.fresh_state()
    seen = []
    for offset in (0, 7, 14, 21, 28):
        today = TODAY + timedelta(days=offset)
        entries = []
        for i in range((today - start).days + 1):
            day = start + timedelta(days=i)
            if day >= TODAY + timedelta(days=10):
                mood = 0.15
            elif day == TODAY - timedelta(days=4):
                mood = -0.9
            elif day >= TODAY - timedelta(days=13):
                mood = -0.2
            else:
                mood = 0.05 if i % 2 else -0.05
            entries.append(JournalEntry("ordinary day notes", day, sentiment=mood))
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
        seen.append([p for p in result.surfaced if p.kind == "mood_shift"])
    assert any(p.detail["direction"] == "lower" for p in seen[1])
    # The original alarm includes one unusually low report. After the
    # following stable period becomes the norm, a genuinely later rise
    # must be measured against that following period.
    later = next(p for p in seen[-1] if p.detail["direction"] == "higher")
    assert later.detail["pattern_state"] == "emerging"
    assert later.detail["baseline"] == -0.2


@pytest.mark.parametrize("correlated_days", [False, True])
def test_mood_association_requires_independent_evidence_beyond_a_correlated_run(correlated_days):
    rng = random.Random(1)
    noise = 0.0
    entries = []
    for i in range(112):
        noise = (0.7 * noise if correlated_days else 0.0) + rng.gauss(0.0, 0.15)
        tagged = i % 14 < 5
        mood = max(-0.95, min(0.95, noise - (0.3 if tagged else 0.0)))
        entries.append(
            JournalEntry(
                "ordinary day notes",
                TODAY - timedelta(days=83 - i),
                sentiment=mood,
                tags=("studio",) if tagged else (),
            )
        )
    state = brain.fresh_state()
    cards = []
    for offset in (0, 7, 14, 21, 28):
        result = brain.update(
            brain.load_state(brain.dump_state(state)),
            entries[: 84 + offset],
            TODAY + timedelta(days=offset),
        )
        state = result.new_state
        cards.extend(
            p for p in result.surfaced if p.kind == "mood_correlation" and p.label == "studio"
        )
    # Both histories contain the same recurring activity and mood-level
    # contrast. Repeated correlated days supply less independent evidence;
    # this history does not earn a personal association under that
    # uncertainty. The independent-day control does earn one.
    assert bool(cards) is (not correlated_days)
    if cards:
        assert cards[-1].detail["direction"] == "lower"
    assert result.stats["mood_summary"]["observations"] == 112


def tag_history(today, priority):
    """Competing valid tags, with a clearly different kind of evidence priority."""
    entries = []
    mondays = [
        today - timedelta(days=i) for i in range(84) if (today - timedelta(days=i)).weekday() == 0
    ]
    for offset in range(84):
        day = today - timedelta(days=offset)
        if priority == "bounded":
            tags = [f"activity{i:02}" for i in range(24)]
            if day.weekday() == 0:
                tags.append("a_target")
        elif day.weekday() == 0:
            tags = [f"activity{i:02}" for i in range(24)]
            if priority == "distinct_days" and day == min(mondays):
                tags = []
            tags.append("a_target")
        else:
            tags = []
        groups = [tags[i : i + 7] for i in range(0, len(tags), 7)] or [[]]
        if priority == "mentions" and day.weekday() == 0:
            # A second ordinary entry that day mentions the same target;
            # this increases mentions without inventing another evidence day.
            groups[0].append("a_target")
        entries.extend(
            JournalEntry(
                "I wrote ordinary notes about the quiet day.",
                day,
                sentiment=0.8 if day.weekday() == 0 else 0.1,
                tags=tuple(group),
            )
            for group in groups
        )
    return entries


@pytest.mark.parametrize(
    ("priority", "expected"),
    [("distinct_days", True), ("mentions", True), ("bounded", False)],
)
def test_weekday_cards_respect_tag_evidence_priority_across_state_roundtrips(priority, expected):
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        result = brain.update(
            brain.load_state(brain.dump_state(state)), tag_history(today, priority), today
        )
        state = result.new_state
    cards = [
        card for card in result.surfaced if card.kind == "temporal" and card.label == "a_target"
    ]
    # A tag supported on more days wins; equal-day ties prefer repeated
    # mentions. A less-supported 25th theme does not bypass the bounded
    # candidate vocabulary merely because its weekday concentration is high.
    assert bool(cards) is expected
    if expected:
        assert cards[0].detail["day"] == "Monday"
        assert cards[0].occurrences == 12


def test_established_mood_shift_fades_as_the_lower_level_becomes_the_current_norm():
    start = TODAY - timedelta(days=83)
    shift = TODAY - timedelta(days=13)
    state = brain.fresh_state()
    public_states = []
    for offset in range(0, 29, 7):
        today = TODAY + timedelta(days=offset)
        entries = []
        for i in range((today - start).days + 1):
            day = start + timedelta(days=i)
            # A stable earlier range followed by a sustained, valid mood
            # dip. New journal days keep reporting the lower level.
            mood = -0.2 if day >= shift else (0.05 if i % 2 else -0.05)
            entries.append(
                JournalEntry("I wrote ordinary notes about my day.", day, sentiment=mood)
            )
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
        cards = [card for card in result.surfaced if card.kind == "mood_shift"]
        public_states.append([card.detail["pattern_state"] for card in cards])
        for card in cards:
            assert card.label == "recent mood"
            assert card.detail["direction"] == "lower"
            assert card.detail["pattern_pid"] == "mood_shift:lower"
    assert public_states[0] == [], "A first statistical qualification must not create a card"
    assert public_states[1] == ["emerging"]
    # The changed level has become the current norm. Continuing the same
    # reports must age the original change, rather than confirming it forever.
    assert public_states[-1] == ["fading"]


def phrase_budget_entries(case):
    filler = "the kettle rested beside the kitchen sink."
    target = "a blue notebook waits quietly beside my window"
    if case == "four_tokens":
        target = "blue notebooks stay nearby"
        entries = [JournalEntry(target + ".", TODAY - timedelta(days=ago)) for ago in (7, 4, 0)]
    elif case == "entry_limit":
        entries = [
            JournalEntry((" " + filler) * 40 + " " + target + ".", TODAY - timedelta(days=ago))
            for ago in (7, 4, 0)
        ]
    else:
        assert case == "window_limit"
        entries = []
        for i in range(100):
            day = TODAY - timedelta(days=i // 5)
            text = target + "." + (" " + filler) * 39 if i in (0, 40) else (" " + filler) * 40
            entries.append(JournalEntry(text, day))
        entries.append(JournalEntry(target + ".", TODAY - timedelta(days=20)))
    return entries, target


@pytest.mark.parametrize(
    ("case", "expected"),
    [("four_tokens", True), ("entry_limit", False), ("window_limit", False)],
)
def test_recurring_thought_cards_use_the_admitted_sentence_window(case, expected):
    entries, target = phrase_budget_entries(case)
    state = brain.fresh_state()
    for offset in (0, 1):
        result = brain.update(
            brain.load_state(brain.dump_state(state)), entries, TODAY + timedelta(days=offset)
        )
        state = result.new_state
    cards = [
        card for card in result.surfaced if card.kind == "recurring_phrase" and card.label == target
    ]
    # Four words form a real recurring thought. A 41st sentence within an
    # entry, or the oldest occurrence beyond the newest 4000 sentences,
    # does not supply extra evidence to create another recurring-thought card.
    assert bool(cards) is expected


def public_carryover_detail(entries, kind):
    state = brain.fresh_state()
    for offset in range(9):
        result = brain.update(
            brain.load_state(brain.dump_state(state)), entries, TODAY + timedelta(days=offset)
        )
        state = result.new_state
        card = next((p for p in result.surfaced if p.kind == kind), None)
        if card is not None:
            return {
                key: card.detail[key]
                for key in (
                    "window_days",
                    "carryover_recent",
                    "carryover_earlier",
                    "p_value",
                    "channel",
                )
            }
    return None


@pytest.mark.parametrize(
    ("channel", "kind"),
    [
        ("energy", "energy_inertia"),
        ("positive_affect", "pa_inertia"),
        ("negative_affect", "na_inertia"),
    ],
)
def test_duplicate_entries_do_not_reweight_daily_channel_carryover(channel, kind):
    entries = carryover_entries(channel)
    reference = public_carryover_detail(entries, kind)
    duplicated = entries + [e for e in entries if e.entry_date.toordinal() % 3 == 0]
    assert reference is not None
    # Repeating an identical report on selected days does not change any
    # daily mean, so it must not change the reported daily comparison.
    assert public_carryover_detail(duplicated, kind) == reference


@pytest.mark.parametrize("leading", ["unsupported", "explicit", "empty"])
def test_one_ineligible_entry_does_not_abort_later_negative_affect_measurements(leading):
    entries = carryover_entries("negative_affect")
    day = TODAY - timedelta(days=80)
    first = {
        "unsupported": JournalEntry("Сегодня мне очень тяжело и грустно bad", day),
        "explicit": JournalEntry("ordinary day notes", day, sentiment=0.1),
        "empty": JournalEntry("", day),
    }[leading]
    reference = public_carryover_detail(entries, "na_inertia")
    assert reference is not None
    assert public_carryover_detail([first] + entries, "na_inertia") == reference


def test_growing_mood_swings_report_the_actual_28_day_comparison_window():
    entries = []
    for i in range(70):
        amplitude = 0.5 if i >= 45 else 0.03
        mood = 0.05 + (amplitude if i % 2 == 0 else -amplitude)
        entries.append(
            JournalEntry("ordinary day notes", TODAY - timedelta(days=69 - i), sentiment=mood)
        )
    first = brain.update(brain.fresh_state(), entries, TODAY)
    entries.extend(
        JournalEntry(
            "ordinary day notes", TODAY + timedelta(days=k), sentiment=0.55 if k % 2 else -0.45
        )
        for k in range(1, 8)
    )
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), entries, TODAY + timedelta(days=7)
    )
    cards = [p for p in result.surfaced if p.kind == "instability"]
    assert cards
    assert cards[0].detail["window_days"] == 28
    assert cards[0].detail["spread_recent"] > cards[0].detail["spread_earlier"]


def test_a_rare_tag_does_not_hide_a_supported_weekday_card():
    state = brain.fresh_state()
    for week in range(3):
        today = TODAY + timedelta(weeks=week)
        entries = []
        for offset in range(84):
            day = today - timedelta(days=offset)
            tags = ()
            if day.weekday() == 0:
                tags = ("a_once", "a_target") if day == today else ("a_target",)
            entries.append(
                JournalEntry(
                    "ordinary day notes",
                    day,
                    sentiment=0.8 if day.weekday() == 0 else 0.1,
                    tags=tags,
                )
            )
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    cards = [p for p in result.surfaced if p.kind == "temporal" and p.label == "a_target"]
    assert cards
    assert cards[0].detail["day"] == "Monday"


def work_schedule_history(offset):
    entries = []
    for i in range(84 + offset):
        day = TODAY - timedelta(days=83 - i)
        work = day.weekday() == (0 if day <= TODAY + timedelta(days=14) else 3)
        entries.append(
            JournalEntry(
                "ordinary notes about work" if work else "ordinary day notes",
                day,
                sentiment=0.8 if work else 0.1,
            )
        )
    return entries


def test_a_saved_thoughts_accepted_opaque_identifier_does_not_restart_weekday_replication():
    state = brain.fresh_state()
    for offset in (0, 7, 14):
        result = brain.update(
            brain.load_state(brain.dump_state(state)),
            work_schedule_history(offset),
            TODAY + timedelta(days=offset),
        )
        state = result.new_state
    old = next(p for p in result.surfaced if p.kind == "temporal" and p.label == "work")
    assert old.detail["day"] == "Monday"
    thought = next(
        p
        for p in result.surfaced
        if p.kind == "recurring_phrase" and p.label == "ordinary notes about work"
    )

    # The public state decoder accepts opaque string identifiers for
    # known-kind saved records. Only the accepted identifier changes; all
    # record fields and subsequent diary entries are produced normally.
    # No claim is made that a shipped producer minted this identifier.
    saved = json.loads(brain.dump_state(state))
    saved["patterns"]["XXtemporal:work~2XX"] = saved["patterns"].pop(thought.detail["pattern_pid"])
    state = brain.load_state(json.dumps(saved).encode())
    for offset in (105, 112, 119, 126):
        result = brain.update(
            brain.load_state(brain.dump_state(state)),
            work_schedule_history(offset),
            TODAY + timedelta(days=offset),
        )
        state = result.new_state
    # The journal genuinely continues under a Thursday work schedule.
    # The new claim earns fresh evidence across separate weeks; an
    # unrelated accepted thought identifier cannot keep restarting its clock.
    assert any(
        p.kind == "temporal" and p.label == "work" and p.detail["day"] == "Thursday"
        for p in result.surfaced
    )


def test_native_text_roundoff_keeps_earlier_mood_evidence_available_for_replication():
    # These real words cancel mathematically; the native left-to-right
    # sentiment walk retains a small nonzero sleep-word contribution.
    # The other finite ratings place the first comparison at its effect
    # boundary. Nothing supplies a score, residual or detector result.
    sleep_note = " ".join(["calm"] + ["dreams"] * 350 + ["fatigued"] * 425)
    comparison_rating = 0.5498650805359924
    entries = []
    for i in range(84):
        day = TODAY - timedelta(days=83 - i)
        if i == 10:
            entries.append(JournalEntry(sleep_note, day))
        elif i % 2 == 0:
            entries.append(
                JournalEntry("ordinary account for morning", day, sentiment=0.375, tags=("sleep",))
            )
        else:
            entries.append(
                JournalEntry(
                    "ordinary account for morning",
                    day,
                    sentiment=comparison_rating + (0.02 if i % 4 == 1 else -0.02),
                )
            )
    first = brain.update(brain.fresh_state(), entries, TODAY)
    assert not any(p.kind == "mood_correlation" and p.label == "sleep" for p in first.surfaced)

    # New observed days give the same claim stronger, independent evidence.
    # Persisting the real first result must retain its earlier qualification.
    for offset in range(1, 15):
        entries.append(
            JournalEntry(
                "another ordinary account for morning",
                TODAY + timedelta(days=offset),
                sentiment=-0.5 if offset % 2 == 0 else 0.9,
                tags=("sleep",) if offset % 2 == 0 else (),
            )
        )
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), entries, TODAY + timedelta(days=14)
    )
    cards = [p for p in result.surfaced if p.kind == "mood_correlation" and p.label == "sleep"]
    assert cards, "The independently replicated sleep/mood comparison must earn its public card"
    assert cards[0].detail["direction"] == "lower"
    assert cards[0].detail["mood_delta"] > 0.3
    assert cards[0].detail["sample_days"] == 98


def test_public_transform_retains_entropy_boundary_evidence_for_forward_calendar_entries():
    # update deliberately accepts the calendar it is given, including
    # forward dates. This exercises that public library contract; the
    # server's separate entry-date validator does not produce this corpus.
    # Real two/three-tag day counts produce the exact native effect boundary.
    def week(monday, high):
        rows = []
        for offset in range(7):
            tags = ["first"]
            if high or offset == 0:
                tags.append("second")
            if high and offset < 2:
                tags.append("third")
            rows.append(JournalEntry("Ж", monday + timedelta(days=offset), tags=tuple(tags)))
        return rows

    entries = []
    for i in range(15):
        entries.extend(week(TODAY - timedelta(days=126 - 7 * i), high=i == 0))
    for i in range(15):
        entries.extend(week(TODAY - timedelta(days=21 - 7 * i), high=i >= 8))
    first = brain.update(brain.fresh_state(), entries, TODAY)
    assert not any(p.kind == "activity_diversity" for p in first.surfaced)

    # Add a separately dated week to the accepted calendar, then reload the
    # actual saved result. The earlier boundary qualification must count
    # when the stronger observation independently replicates it.
    entries.extend(week(TODAY + timedelta(days=84), high=True))
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), entries, TODAY + timedelta(days=7)
    )
    cards = [p for p in result.surfaced if p.kind == "activity_diversity"]
    assert cards, "The accepted calendar's repeated activity comparison must earn its public card"
    assert cards[0].detail["direction"] == "widened"
    assert cards[0].detail["entropy_recent"] > cards[0].detail["entropy_earlier"]
