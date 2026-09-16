"""Contract pins, exhaustive lexicon coverage, and exact behavioral boundaries.

Mutation testing exposed real test gaps: lexicon words could be dropped
silently, boundary constants could drift, and error-path semantics were
unpinned. These tests close those gaps — they double as living documentation
of the cross-platform wire contract (backend <-> mobile/src/crypto).
"""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta

import pytest

from app.security import crypto, kdf, tokens
from app.services import patterns, questions, threshold
from app.services.patterns import JournalEntry, Pattern, analyze
from app.services.threshold import Phase, evaluate

BASE = date(2026, 7, 5)  # a Sunday


# --------------------------------------------------------------------------
# Exhaustive lexicon coverage: every single word must still work.
# --------------------------------------------------------------------------

def test_every_lexicon_word_triggers_its_theme():
    for theme, words in patterns.THEME_LEXICON.items():
        for word in words:
            assert patterns.extract_themes(f"today i dealt with {word} again") == {theme}, (theme, word)


def test_theme_words_reverse_index_matches_lexicon():
    expected = {w: t for t, ws in patterns.THEME_LEXICON.items() for w in ws}
    assert patterns.THEME_WORDS == expected


def test_every_positive_word_scores_positive():
    for word in patterns.POSITIVE_WORDS:
        assert patterns.sentiment_score(f"today felt {word} overall") > 0, word


def test_every_negative_word_scores_negative():
    for word in patterns.NEGATIVE_WORDS:
        assert patterns.sentiment_score(f"today felt {word} overall") < 0, word


def test_day_names_pinned():
    assert patterns.DAY_NAMES == (
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    )


# --------------------------------------------------------------------------
# KDF / crypto contract pins (the mobile app depends on these exact bytes).
# --------------------------------------------------------------------------

def test_kdf_info_strings_pinned():
    assert kdf.AUTH_INFO == b"mindpattern/auth/v1"
    assert kdf.DATA_INFO == b"mindpattern/data/v1"


def test_salt_boundary_is_exactly_eight_bytes():
    assert kdf.MIN_SALT_SIZE == 8
    # 2026-09-16: iterations must be >= kdf.MIN_ITERATIONS now (finding A4)
    kdf.derive_master_key("p", b"12345678", kdf.MIN_ITERATIONS)  # exactly at the boundary: valid
    with pytest.raises(ValueError):
        kdf.derive_master_key("p", b"1234567", kdf.MIN_ITERATIONS)  # one byte short


def test_iteration_boundary_rejects_zero_and_negatives():
    assert kdf.KDF_ITERATIONS == 600_000
    for bad in (0, -1, -100):
        with pytest.raises(ValueError):
            kdf.derive_master_key("p", b"12345678", bad)


def test_hkdf_length_boundaries_exact():
    assert len(kdf.hkdf_sha256(b"k", None, b"i", 1)) == 1
    assert len(kdf.hkdf_sha256(b"k", None, b"i", 255 * 32)) == 255 * 32


def test_crypto_error_messages_are_part_of_the_contract():
    with pytest.raises(crypto.CryptoError, match=r"^key must be 32 bytes"):
        crypto.encrypt(b"k", b"data")
    with pytest.raises(crypto.CryptoError, match=r"^key must be 32 bytes"):
        crypto.decrypt(b"k", b"x" * 40)
    with pytest.raises(crypto.TamperError, match=r"^blob too short"):
        crypto.decrypt(crypto.generate_key(), b"short")


# --------------------------------------------------------------------------
# Token wire format.
# --------------------------------------------------------------------------

def test_token_body_is_compact_sorted_json():
    token = tokens.issue_token("u1", "secret", 60, now=1000.0)
    body, _ = token.split(".")
    padded = body + "=" * (-len(body) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    # "ep" is the revocation epoch — logout bumps it account-wide.
    assert decoded == b'{"ep":1,"exp":1060,"iat":1000,"uid":"u1"}'
    token_ep5 = tokens.issue_token("u1", "secret", 60, now=1000.0, epoch=5)
    body5 = token_ep5.split(".")[0]
    decoded5 = base64.urlsafe_b64decode(body5 + "=" * (-len(body5) % 4))
    assert decoded5 == b'{"ep":5,"exp":1060,"iat":1000,"uid":"u1"}'


def test_issue_token_rejects_non_positive_ttl():
    import pytest

    with pytest.raises(ValueError, match="ttl_seconds"):
        tokens.issue_token("u1", "secret", 0)
    with pytest.raises(ValueError, match="ttl_seconds"):
        tokens.issue_token("u1", "secret", -5)


def test_token_roundtrip_across_padding_regimes():
    # uid lengths exercise all base64url padding cases for the body.
    for i in range(1, 12):
        uid = "u" * i
        token = tokens.issue_token(uid, "secret", 60)
        assert tokens.verify_token(token, "secret")["uid"] == uid


def test_token_error_messages():
    with pytest.raises(tokens.TokenError, match=r"^malformed token"):
        tokens.verify_token("garbage", "s")
    with pytest.raises(tokens.TokenError, match=r"^bad signature"):
        tokens.verify_token(tokens.issue_token("u", "s", 60).upper(), "s")
    with pytest.raises(tokens.TokenError, match=r"^token expired"):
        tokens.verify_token(tokens.issue_token("u", "s", 1, now=1.0), "s", now=5.0)

    import hashlib
    import hmac as hmac_mod

    def signed(body: bytes) -> str:
        b = tokens._b64url_encode(body)
        sig = tokens._b64url_encode(
            hmac_mod.new(b"s", b.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{b}.{sig}"

    # Correctly signed, but the payload is not a dict with uid/exp.
    with pytest.raises(tokens.TokenError, match=r"^malformed payload"):
        tokens.verify_token(signed(json.dumps({"nonsense": 1}).encode()), "s")


def test_processing_tokens_are_43_char_urlsafe():
    from app.security.enclave import InMemoryKeyStore
    store = InMemoryKeyStore()
    key = crypto.generate_key()
    t = store.create(key, 60)
    assert len(t) == 43  # token_urlsafe(32) -> 43 chars; shorter means weaker entropy
    assert all(c.isalnum() or c in "-_" for c in t)


# --------------------------------------------------------------------------
# Enclave error semantics.
# --------------------------------------------------------------------------

def test_enclave_error_messages():
    from app.security.enclave import InMemoryKeyStore, KeyNotFound
    store = InMemoryKeyStore()
    with pytest.raises(ValueError, match=r"^key must be 32 bytes"):
        store.create(b"short", 60)
    with pytest.raises(ValueError, match=r"^ttl must be positive"):
        store.create(crypto.generate_key(), 0)
    with pytest.raises(KeyNotFound, match=r"^unknown processing session"):
        store.get("missing")
    token = store.create(crypto.generate_key(), 10, now=0.0)
    with pytest.raises(KeyNotFound, match=r"^processing session expired"):
        store.get(token, now=100.0)


# --------------------------------------------------------------------------
# Behavioral boundary tests (kill constant-drift mutants).
# --------------------------------------------------------------------------

def test_temporal_fraction_boundary_exactly_half():
    # 2 of 4 work-mentions on a Sunday: fraction == 0.5 must fire.
    entries = [
        JournalEntry(text="work deadline stress", entry_date=BASE),
        JournalEntry(text="another work meeting looms", entry_date=BASE),
        JournalEntry(text="work deadline stress", entry_date=BASE + timedelta(days=1)),
        JournalEntry(text="work deadline stress", entry_date=BASE + timedelta(days=2)),
        JournalEntry(text="calm walk by the river", entry_date=BASE + timedelta(days=3)),
        JournalEntry(text="calm walk by the river", entry_date=BASE + timedelta(days=4)),
        JournalEntry(text="calm walk by the river", entry_date=BASE + timedelta(days=5)),
        JournalEntry(text="calm walk by the river", entry_date=BASE + timedelta(days=6)),
    ]
    temporal = [p for p in analyze(entries).patterns if p.kind == "temporal"]
    assert any(p.label == "work" for p in temporal)
    work = next(p for p in temporal if p.label == "work")
    assert work.detail["day"] == "Sunday"
    assert work.detail["day_fraction"] == pytest.approx(0.5)


def test_mood_delta_boundary_exactly_point_three():
    with_theme = [JournalEntry("meeting at work", BASE + timedelta(days=i), sentiment=-0.15) for i in range(4)]
    without = [JournalEntry("walk in the park", BASE + timedelta(days=10 + i), sentiment=0.15) for i in range(4)]
    analysis = analyze(with_theme + without)
    mood = [p for p in analysis.patterns if p.kind == "mood_correlation"]
    assert mood and mood[0].detail["mood_delta"] == pytest.approx(0.3)


def test_min_theme_occurrences_boundary_is_four():
    sunday_only = [JournalEntry("work deadline", BASE + timedelta(weeks=w)) for w in range(4)]
    analysis = analyze(sunday_only)
    assert any(p.kind == "temporal" and p.label == "work" for p in analysis.patterns)


def test_two_token_sentences_below_phrase_floor():
    entries = [
        JournalEntry("morning again. then the day went on.", BASE + timedelta(weeks=w))
        for w in range(4)
    ]
    found = patterns.recurring_phrases(entries)
    assert not any(p.label == "morning again" for p in found)


def test_three_token_sentence_meets_phrase_floor():
    entries = [
        JournalEntry(f"note {i}. cannot sleep tonight. done for now.", BASE + timedelta(weeks=w))
        for i, w in enumerate(range(4))
    ]
    found = patterns.recurring_phrases(entries)
    assert any(p.label == "cannot sleep tonight" for p in found)


def test_threshold_of_one_day_is_valid():
    assert evaluate([BASE], threshold=1).phase is Phase.INSIGHT


def test_confidence_formula_pinned_for_known_corpus():
    # 5 work-mentions all Sunday, fraction 1.0:
    #   temporal confidence = min(1, 5/12 * (0.5 + 1.0/2)) = 5/12
    entries = [JournalEntry("work deadline stress", BASE + timedelta(weeks=w)) for w in range(5)]
    temporal = next(p for p in analyze(entries).patterns if p.kind == "temporal")
    assert temporal.confidence == pytest.approx(5 / 12)


# --------------------------------------------------------------------------
# Question engine pins.
# --------------------------------------------------------------------------

PIN_PATTERNS = [
    Pattern("temporal", "work", 12, 0.9, {"day": "Sunday"}),
    Pattern("mood_correlation", "sleep", 8, 0.6, {"mood_delta": 0.5}),
    Pattern("recurring_phrase", "want to disappear", 4, 0.4, {}),
]


def test_question_for_known_dates_pinned():
    # Literals pinned deliberately: template/pool/rotation edits must be conscious.
    # "want to disappear" is crisis-adjacent: its recurring-phrase questions
    # are excluded from the pool (crisis interlock), so the rotation lands
    # on generic questions for these dates.
    assert questions.question_for_today("user-a", PIN_PATTERNS, date(2026, 9, 3)) == (
        "What are you carrying into tomorrow?"
    )
    assert questions.question_for_today("user-a", PIN_PATTERNS, date(2026, 9, 4)) == (
        "What did you notice today that you usually overlook?"
    )


def test_temporal_template_falls_back_when_day_missing():
    rendered = questions.render_pattern_questions(Pattern("temporal", "x", 3, 0.5, {}))
    assert any("that day" in q for q in rendered)


def test_max_pattern_questions_constant():
    assert questions.MAX_PATTERN_QUESTIONS == 5


def test_rotation_hits_every_pool_item_within_one_cycle():
    pool = questions.build_pool(PIN_PATTERNS)
    seen = [
        questions.question_for_today("cycler", PIN_PATTERNS, date(2026, 9, 3) + timedelta(days=i))
        for i in range(len(pool))
    ]
    assert sorted(seen) == sorted(pool)  # a full cycle visits each question once


# ==========================================================================
# Round 2: survivors from the first mutation run, triaged and killed.
# ==========================================================================


def test_error_messages_round_two():
    from app.security.enclave import SecureProcessingContext
    with pytest.raises(ValueError, match=r"^salt must be at least 8 bytes"):
        kdf.derive_master_key("p", b"1234567", kdf.MIN_ITERATIONS)
    with pytest.raises(ValueError, match=r"^iterations must be at least"):
        kdf.derive_master_key("p", b"12345678", kdf.MIN_ITERATIONS - 1)
    with pytest.raises(ValueError, match=r"^invalid HKDF output length"):
        kdf.hkdf_sha256(b"k", None, b"i", 0)
    with pytest.raises(ValueError, match=r"^threshold must be at least 1 day"):
        evaluate([], threshold=0)
    with pytest.raises(ValueError, match=r"^no dates to analyze"):
        patterns._dominant_weekday([])
    with pytest.raises(ValueError, match=r"^key must be 32 bytes"):
        SecureProcessingContext(b"short")
    with pytest.raises(tokens.TokenError, match=r"^malformed token"):
        tokens.verify_token(None, "s")  # non-string input


def test_ttl_of_one_second_is_valid():
    from app.security.enclave import InMemoryKeyStore
    store = InMemoryKeyStore()
    store.create(crypto.generate_key(), 1)
    assert len(store) == 1


def test_iterations_at_the_floor_are_valid():
    # 2026-09-16: the floor replaced the old >=1 check (finding A4); one
    # iteration is now refused by the shipping library.
    assert len(kdf.derive_master_key("p", b"12345678", kdf.MIN_ITERATIONS)) == 32


def test_hkdf_just_above_max_length_rejected():
    for bad in (255 * 32 + 1, 256 * 32, 255 * 33):
        with pytest.raises(ValueError, match=r"^invalid HKDF output length"):
            kdf.hkdf_sha256(b"k", None, b"i", bad)


def test_tamper_message_anchored():
    key = crypto.generate_key()
    blob = bytearray(crypto.encrypt(key, b"payload"))
    blob[-1] ^= 1
    with pytest.raises(crypto.TamperError, match=r"^authentication failed"):
        crypto.decrypt(key, bytes(blob))


def test_purge_at_exact_expiry_boundary():
    from app.security.enclave import InMemoryKeyStore
    store = InMemoryKeyStore()
    store.create(crypto.generate_key(), 10, now=0.0)
    assert store.purge_expired(now=10.0) == 1  # expiry instant counts as expired


def test_nested_plaintext_windows_counted():
    from app.security.enclave import SecureProcessingContext, plaintext_windows
    key = crypto.generate_key()
    item = [(crypto.build_aad("e", "u", "1"), crypto.encrypt(key, b"x", crypto.build_aad("e", "u", "1")))]
    inner = SecureProcessingContext(key)
    outer_result = SecureProcessingContext(key).run(
        item, lambda plains: inner.run(item, lambda p2: plaintext_windows())
    )
    assert outer_result == 2
    assert plaintext_windows() == 0


def test_three_dot_token_reports_bad_signature():
    # body.sig split keeps "x.y" as the signed body; a forged third segment
    # must fail as a *signature* problem, not a parse problem.
    with pytest.raises(tokens.TokenError, match=r"^bad signature"):
        tokens.verify_token("x.y.z", "s")


def test_theme_names_are_the_public_pattern_labels():
    assert set(patterns.THEME_LEXICON) == {
        "work", "sleep", "social", "family", "health", "money", "study", "food", "weather",
    }


def test_phrase_threshold_boundaries_exact():
    # Exactly 3 occurrences spanning exactly 7 days: fires.
    entries = [JournalEntry("cannot sleep tonight", BASE + timedelta(days=d)) for d in (0, 3, 7)]
    found = patterns.recurring_phrases(entries)
    hit = next(p for p in found if p.label == "cannot sleep tonight")
    assert hit.detail["first"] == BASE.isoformat()
    assert hit.detail["last"] == (BASE + timedelta(days=7)).isoformat()
    # Two occurrences never fire.
    assert patterns.recurring_phrases([
        JournalEntry("cannot sleep tonight", BASE + timedelta(days=d)) for d in (0, 7)
    ]) == []
    # Three occurrences within six days never fire.
    assert patterns.recurring_phrases([
        JournalEntry("cannot sleep tonight", BASE + timedelta(days=d)) for d in (0, 2, 6)
    ]) == []


def test_phrase_scan_continues_past_rejected_sentence():
    # The below-threshold sentence comes first; the loop must not stop there.
    entries = [
        JournalEntry("alpha note here. cannot sleep tonight.", BASE + timedelta(days=0)),
        JournalEntry("cannot sleep tonight.", BASE + timedelta(days=1)),
        JournalEntry("alpha note here.", BASE + timedelta(days=2)),
        JournalEntry("cannot sleep tonight.", BASE + timedelta(days=7)),
        JournalEntry("cannot sleep tonight.", BASE + timedelta(days=14)),
    ]
    assert any(p.label == "cannot sleep tonight" for p in patterns.recurring_phrases(entries))


def test_phrase_scan_continues_past_short_span_sentence():
    entries = [
        JournalEntry("short span phrase. cannot sleep tonight.", BASE + timedelta(days=0)),
        JournalEntry("short span phrase.", BASE + timedelta(days=1)),
        JournalEntry("short span phrase.", BASE + timedelta(days=2)),
        JournalEntry("cannot sleep tonight.", BASE + timedelta(days=7)),
        JournalEntry("cannot sleep tonight.", BASE + timedelta(days=14)),
    ]
    assert any(p.label == "cannot sleep tonight" for p in patterns.recurring_phrases(entries))


def test_theme_scan_continues_past_weak_theme():
    entries = [JournalEntry("mom visited briefly", BASE)]
    entries += [JournalEntry("work deadline crunch", BASE + timedelta(weeks=w)) for w in range(4)]
    kinds = [(p.kind, p.label) for p in analyze(entries).patterns]
    assert ("temporal", "work") in kinds  # family (1 mention) must not stop the scan


def test_dominant_weekday_tie_breaks_to_earliest_day():
    # Sunday encountered first, Tuesday second, 2 mentions each -> Tuesday wins
    # (earlier weekday index is the deterministic tie-break).
    days = [BASE, BASE + timedelta(days=2), BASE + timedelta(weeks=1), BASE + timedelta(weeks=1, days=2)]
    entries = [JournalEntry("work crunch day", d) for d in days]
    temporal = next(p for p in analyze(entries).patterns if p.kind == "temporal")
    assert temporal.detail["day"] == "Tuesday"


def test_day_fraction_and_confidence_rounding_pinned():
    # 4 of 6 mentions on Sunday -> fraction 2/3 -> 0.667; conf = 6/12*(0.5+1/3) -> 0.417.
    days = [BASE + timedelta(weeks=w) for w in range(4)] + \
           [BASE + timedelta(weeks=w, days=2) for w in range(2)]
    entries = [JournalEntry("work crunch day", d) for d in days]
    temporal = next(p for p in analyze(entries).patterns if p.kind == "temporal")
    assert temporal.detail["day_fraction"] == 0.667
    assert temporal.to_dict()["confidence"] == 0.417


def test_temporal_confidence_saturation_and_boundary():
    # fraction 0.5 corpus: conf = 4/12 * 0.75 = 0.25.
    days = [BASE, BASE, BASE + timedelta(days=1), BASE + timedelta(days=2)]
    entries = [JournalEntry("work crunch day", d) for d in days]
    temporal = next(p for p in analyze(entries).patterns if p.kind == "temporal")
    assert temporal.confidence == pytest.approx(0.25)
    # 24 weekly mentions: confidence saturates at exactly 1.0.
    saturated = [JournalEntry(f"work crunch variant {w}", BASE + timedelta(weeks=w)) for w in range(24)]
    temporal24 = next(p for p in analyze(saturated).patterns if p.kind == "temporal")
    assert temporal24.confidence == 1.0


def test_phrase_confidence_pinned():
    four = [JournalEntry("cannot sleep tonight", BASE + timedelta(weeks=w)) for w in range(4)]
    phrase = patterns.recurring_phrases(four)[0]
    assert phrase.confidence == pytest.approx(4 / 8)
    sixteen = [JournalEntry("cannot sleep tonight", BASE + timedelta(weeks=w)) for w in range(16)]
    assert patterns.recurring_phrases(sixteen)[0].confidence == 1.0


def test_mood_confidence_and_rounding_pinned():
    with_theme = [JournalEntry("meeting at work", BASE + timedelta(days=i), sentiment=-0.25) for i in range(4)]
    without = [JournalEntry("walk in the park", BASE + timedelta(days=10 + i), sentiment=0.25) for i in range(4)]
    mood = next(p for p in analyze(with_theme + without).patterns if p.kind == "mood_correlation")
    assert mood.confidence == pytest.approx(4 / 12 * 0.5)
    assert mood.detail["mood_delta"] == 0.5

    third = [JournalEntry("meeting at work", BASE + timedelta(days=i), sentiment=-1 / 6) for i in range(4)]
    third_out = [JournalEntry("walk in the park", BASE + timedelta(days=10 + i), sentiment=1 / 6) for i in range(4)]
    mood3 = next(p for p in analyze(third + third_out).patterns if p.kind == "mood_correlation")
    assert mood3.detail["mood_delta"] == 0.333

    big_with = [JournalEntry(f"work crunch {i}", BASE + timedelta(weeks=i), sentiment=-1.0) for i in range(24)]
    big_without = [JournalEntry("calm river walk", BASE + timedelta(days=100 + i), sentiment=1.0) for i in range(24)]
    mood24 = next(p for p in analyze(big_with + big_without).patterns if p.kind == "mood_correlation")
    assert mood24.confidence == 1.0


def test_pattern_ordering_pinned():
    # mood (0.833) outranks temporal (0.417).
    entries = [JournalEntry("work deadline stress", BASE + timedelta(weeks=w)) for w in range(5)]
    entries += [JournalEntry("calm and grateful walk", BASE + timedelta(weeks=w, days=3)) for w in range(5)]
    assert analyze(entries).patterns[0].kind == "mood_correlation"

    # Confidence tie (0.75 each): 9-mention temporal outranks 6-mention phrase.
    tie = [JournalEntry(f"work crunch variant {w}", BASE + timedelta(weeks=w)) for w in range(9)]
    tie += [JournalEntry("cannot sleep tonight", BASE + timedelta(weeks=w, days=1)) for w in range(6)]
    ranked = [(p.kind, p.label) for p in analyze(tie).patterns if p.confidence == pytest.approx(0.75)]
    assert ranked[0] == ("temporal", "work")


def test_avg_sentiment_nonzero_pinned():
    entries = [
        JournalEntry("note one", BASE, sentiment=1.0),
        JournalEntry("note two", BASE + timedelta(days=1), sentiment=1.0),
        JournalEntry("note three", BASE + timedelta(days=2), sentiment=0.0),
    ]
    analysis = analyze(entries)
    assert analysis.avg_sentiment == pytest.approx(2 / 3)
    assert analysis.to_dict()["avg_sentiment"] == 0.667


def test_to_dict_stats_keys_pinned():
    payload = analyze([JournalEntry("work crunch", BASE)]).to_dict()
    assert set(payload) == {
        "total_entries", "active_days", "avg_sentiment", "first_date", "last_date", "patterns",
    }


def test_normalize_pinned():
    assert patterns.normalize("Hello,  world!!") == "hello world"


def test_describe_full_copy_pinned():
    temporal = Pattern("temporal", "work", 12, 0.9, {"day": "Sunday"})
    assert temporal.describe() == "You've mentioned 'work' 12 times, most often on Sundays."
    mood = Pattern("mood_correlation", "sleep", 8, 0.6, {"mood_delta": 0.7})
    assert mood.describe() == "Your entries read lower on days when 'sleep' comes up (mood drop of 0.7)."
    phrase = Pattern("recurring_phrase", "cannot sleep tonight", 4, 0.5, {})
    assert phrase.describe() == 'The phrase "cannot sleep tonight" keeps returning — 4 times so far.'
    # Defaults with no detail dict at all.
    assert Pattern("temporal", "work", 2, 0.5).describe() == (
        "You've mentioned 'work' 2 times, most often on the same days."
    )
    assert Pattern("mood_correlation", "x", 2, 0.5).describe().endswith("(mood drop of 0.0).")
    assert Pattern("mystery", "x", 2, 0.5).describe() == "'x' appeared 2 times."


def test_domain_objects_are_frozen():
    import dataclasses

    from app.services.patterns import Analysis
    from app.services.threshold import ThresholdState

    with pytest.raises(dataclasses.FrozenInstanceError):
        Pattern("a", "b", 1, 0.1).kind = "z"
    with pytest.raises(dataclasses.FrozenInstanceError):
        JournalEntry("t", BASE).text = "z"
    with pytest.raises(dataclasses.FrozenInstanceError):
        ThresholdState(1, 1, Phase.BASELINE, 29).active_days = 5
    with pytest.raises(dataclasses.FrozenInstanceError):
        analyze([]).total_entries = 5
    assert isinstance(analyze([]), Analysis)


def test_question_fallback_day_render_pinned():
    rendered = questions.render_pattern_questions(Pattern("temporal", "x", 3, 0.5, {}))
    assert rendered[0] == "'x' shows up mostly on that days — what do those days have in common?"


def test_question_pool_tie_orders_by_occurrences():
    big = Pattern("temporal", "workwork", 9, 0.75, {"day": "Sunday"})
    small = Pattern("temporal", "sleepsleep", 6, 0.75, {"day": "Tuesday"})
    pool = questions.build_pool([small, big])  # deliberately out of order
    assert "workwork" in pool[0]
