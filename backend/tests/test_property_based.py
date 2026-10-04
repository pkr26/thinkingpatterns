"""Property-based tests for the parser / crypto-input surface (2026-09-26
test-infrastructure audit, item 6).

Two load-bearing seams handle data the SERVER does not originate:

* ``app.api.insights._parse_entries`` — the payload-v2 entry point the
  recompute API uses. The plaintext is authenticated ciphertext, but the
  JSON inside crossed a client boundary and years of schema evolution:
  it must parse valid wire shapes without raising, reject malformed ones
  with ONLY the documented error family, and round-trip text exactly
  (serialize → parse → serialize is byte-stable below the truncation
  cap) — including hostile unicode a client can legally put in a string.
* ``app.security.crypto.build_aad`` — the AAD canonicalizer shared with
  the mobile/web clients. Its contract is purity (output depends only on
  the inputs), ASCII-only output regardless of input, and injectivity:
  distinct binding tuples must never collide, or two different (user,
  entry, version) triples would share authentication context.

hypothesis drives both with adversarial strings (lone surrogates, NUL,
DEL, RTL overrides, CJK, combining marks, astral-plane characters,
10k-char bodies, whitespace-only, empty), bounded-size nested JSON, and
hostile field values. Runs are derandomized: CI is deterministic and a
red run always reproduces (the hypothesis database is not relied upon).
"""

from __future__ import annotations

import json
from datetime import date, timedelta

from hypothesis import HealthCheck, given, settings, strategies as st

from app.api.insights import _parse_entries
from app.security.crypto import build_aad

# Deterministic in CI: no random-seed flakiness, failures always reproduce.
SETTINGS = settings(
    max_examples=100,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow],
)


# ---------------------------------------------------------------------------
# Adversarial string material
# ---------------------------------------------------------------------------

# Code points that historically break naive serializers/parsers: NUL and
# C0/C1 controls, DEL, the byte-order mark, RTL/LTR overrides (spoofing),
# combining diacritics, CJK, emoji (astral plane, 4-byte UTF-8), the
# replacement character, and lone surrogates (legal in Python str, illegal
# in UTF-8 — the exact class that must stay escaped, never crash).
ADVERSARIAL_CHARS = [
    "\x00",  # NUL
    "\x07",  # BEL
    "\x1b",  # ESC
    "\x7f",  # DEL
    "\u00a0",  # NBSP
    "\u0301",  # combining acute (marks ride a preceding base)
    "\u2028",  # line separator (JS-valid, JSON-fine)
    "\u202e",  # RTL override
    "\u2066",  # LTR isolate
    "\ufeff",  # BOM
    "\u65e5",  # CJK
    "\U0001f62d",  # astral (sob emoji)
    "\U0001d400",  # astral (math bold A)
    "\ufffd",  # replacement char
    "\ud800",  # lone high surrogate
    "\udfff",  # lone low surrogate
    '"',  # JSON escape bait
    "\\",  # ditto
    "\n",  # control newline
    "\t",
]

adversarial_text = st.text(
    alphabet=st.sampled_from(ADVERSARIAL_CHARS) | st.characters(),
    min_size=0,
    max_size=200,
)

big_text = st.text(max_size=10_000)  # below the 20k truncation cap

whitespace_text = st.text(alphabet=" \t\n\r\f\v\u00a0", min_size=0, max_size=100)

json_value_bounded = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53), 2**53) | st.floats(allow_nan=False),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=12,
)


# ---------------------------------------------------------------------------
# _parse_entries: valid wire shapes never raise, and round-trip byte-exactly
# ---------------------------------------------------------------------------


def _wire_bytes(payload: dict) -> bytearray:
    """Serialize exactly the way the client emulator does (helpers.py)."""
    return bytearray(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _valid_payload(text: str, day: date) -> dict:
    return {"v": 2, "text": text, "created_at": day.isoformat()}


@SETTINGS
@given(text=adversarial_text | big_text | whitespace_text)
def test_parse_entries_adversarial_text_never_raises_and_roundtrips(text):
    day = date(2026, 9, 4)
    entries = _parse_entries([_wire_bytes(_valid_payload(text, day))], [day])
    assert len(entries) == 1
    entry = entries[0]
    # Below the 20k cap the text is byte-stable through the whole
    # serialize → parse → serialize cycle.
    assert entry.text == text
    assert json.dumps(entry.text, ensure_ascii=True).encode("utf-8") == json.dumps(
        text, ensure_ascii=True
    ).encode("utf-8")


@SETTINGS
@given(
    text=adversarial_text,
    sentiment=st.none() | st.floats(min_value=-1.0, max_value=1.0, allow_nan=False),
    sleep=st.none() | st.integers(1, 5),
    tags=st.none()
    | st.lists(st.text(alphabet=st.sampled_from(ADVERSARIAL_CHARS), max_size=24), max_size=8),
    tod=st.none() | st.sampled_from(["morning", "afternoon", "evening", "night"]),
    extra=json_value_bounded,
)
def test_parse_entries_full_v2_payload_roundtrips_stably(text, sentiment, sleep, tags, tod, extra):
    day = date(2026, 3, 1)
    payload = {
        "v": 2,
        "text": text,
        "created_at": day.isoformat(),
        "unknown_future_field": extra,  # forward compatibility: ignored, never fatal
    }
    if sentiment is not None:
        payload["sentiment"] = sentiment
    if sleep is not None:
        payload["sleep"] = sleep
    if tags is not None:
        payload["tags"] = tags
    if tod is not None:
        payload["tod"] = tod
    wire = _wire_bytes(payload)
    first, second = _parse_entries([wire], [day]), _parse_entries([wire], [day])
    assert len(first) == len(second) == 1
    # Determinism: identical bytes parse to identical entries.
    assert first[0] == second[0]
    # The text leg of the payload is byte-stable through a full cycle.
    assert first[0].text == text


@SETTINGS
@given(
    hostiles=st.lists(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(allow_nan=True, allow_infinity=True),
            st.text(max_size=30),
            st.lists(st.integers(), max_size=3),
            st.dictionaries(st.text(max_size=4), st.integers(), max_size=3),
        ),
        min_size=0,
        max_size=4,
    ),
    day_offset=st.integers(-3, 3),
)
def test_parse_entries_malformed_shapes_raise_only_documented_errors(hostiles, day_offset):
    """Any field may be ANY hostile JSON value: the parser either accepts
    it or raises from the documented entry_payload_malformed family —
    never an unrelated crash (that path is a 500)."""
    from app.api.insights import _ENTRY_MALFORMED

    day = date(2026, 9, 4)
    fields = ("text", "sentiment", "energy", "sleep", "tags", "tod", "created_at")
    for index, hostile in enumerate(hostiles):
        payload: dict = {"text": "ordinary day", "created_at": day.isoformat()}
        payload[fields[index % len(fields)]] = hostile
        wire = _wire_bytes(payload)
        # Inner/outer dates within the ±1-day tolerance so a date mismatch
        # cannot mask the field-under-test's own behavior.
        outer = day + timedelta(days=day_offset % 2)
        try:
            _parse_entries([wire], [outer])
        except _ENTRY_MALFORMED:
            pass  # the documented rejection family — allowed
        except Exception as exc:  # noqa: BLE001 - the property under test
            raise AssertionError(
                f"non-documented exception {type(exc).__name__} for field "
                f"{fields[index % len(fields)]}={hostile!r}"
            ) from exc


@SETTINGS
@given(nest_depth=st.integers(1, 60), text=adversarial_text)
def test_parse_entries_bounded_deep_nesting_in_unknown_fields_is_inert(nest_depth, text):
    """Schema evolution tolerance: a future client may nest arbitrarily in
    fields this server ignores. Depth is bounded to stay clear of the
    JSON recursion limit (an OS-level property, not the parser's)."""
    nested: object = 1
    for _ in range(nest_depth):
        nested = [nested]
    day = date(2026, 6, 30)
    payload = _valid_payload(text, day)
    payload["future_deep_field"] = nested
    entries = _parse_entries([_wire_bytes(payload)], [day])
    assert entries[0].text == text


@SETTINGS
@given(texts=st.lists(adversarial_text, min_size=0, max_size=8))
def test_parse_entries_batch_preserves_each_entrys_text(texts):
    """The corpus-budget truncation at the end of _parse_entries must only
    ever blank entries ABOVE the budget — small batches keep every text."""
    day = date(2026, 1, 15)
    wires = [_wire_bytes(_valid_payload(t, day)) for t in texts]
    entries = _parse_entries(wires, [day] * len(texts))
    assert [e.text for e in entries] == texts


# ---------------------------------------------------------------------------
# build_aad: purity, ASCII-only, injectivity
# ---------------------------------------------------------------------------


@SETTINGS
@given(
    parts=st.lists(
        st.text(alphabet=st.sampled_from(ADVERSARIAL_CHARS) | st.characters(), max_size=64),
        min_size=0,
        max_size=6,
    )
)
def test_build_aad_is_pure_and_ascii_only(parts):
    aad1 = build_aad(*parts)
    aad2 = build_aad(*parts)
    # Purity: identical inputs, identical bytes — every call, every platform.
    assert aad1 == aad2
    # The cross-platform contract: every non-ASCII code unit is escaped,
    # so the AAD bytes decode as pure ASCII no matter what the parts hold.
    try:
        aad1.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AssertionError(f"non-ASCII AAD bytes for parts={parts!r}") from exc


@SETTINGS
@given(
    left=st.lists(
        st.text(alphabet=st.sampled_from(ADVERSARIAL_CHARS) | st.characters(), max_size=48),
        min_size=0,
        max_size=4,
    ),
    right=st.lists(
        st.text(alphabet=st.sampled_from(ADVERSARIAL_CHARS) | st.characters(), max_size=48),
        min_size=0,
        max_size=4,
    ),
)
def test_build_aad_is_injective_across_distinct_tuples(left, right):
    """Collision-freedom (the GCM binding's whole point): if the input
    tuples differ, the AAD bytes must differ — an escaped-array encoding
    of distinct string tuples can never fold two bindings together."""
    if left == right:
        return  # same tuple, sameness checked by the purity property
    assert build_aad(*left) != build_aad(*right), (
        f"AAD collision between distinct tuples {left!r} and {right!r}"
    )


@SETTINGS
@given(
    part=st.text(alphabet=st.sampled_from(ADVERSARIAL_CHARS) | st.characters(), max_size=128),
    version=st.integers(0, 2**31),
)
def test_entry_aad_versions_stay_distinct(part, version):
    """The v1/v2 ladder in app.security.crypto: the three-part and
    four-part AADs for the same binding must never collide, or a version
    echo could ride the wrong ciphertext's authentication."""
    from app.security.crypto import entry_aad_v1, entry_aad_v2

    v1 = entry_aad_v1("user-x", part)
    v2 = entry_aad_v2("user-x", part, version)
    assert v1 != v2
    # Both are build_aad outputs of pure-ASCII JSON arrays.
    assert v1.startswith(b'["entry"') and v2.startswith(b'["entry"')
