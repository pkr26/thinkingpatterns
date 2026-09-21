"""The question-feedback loop over HTTP (2026-09-17 audit remediation).

The loop shipped dead: the mobile client POSTs the feedback blob as a JSON
object ``{"feedback_blob": ...}`` while the endpoint declared a bare scalar
Body param, so every feedback-carrying recompute was a 422 — and no test
exercised the HTTP path on either side. These tests pin the wire contract,
the 4xx discipline for malformed/tampered blobs, and the requirement that a
tampered FEEDBACK blob never triggers the brain-state amnesia retry.
"""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta

import pytest

from app.api.insights import _chosen_pattern_pid, _utc_today
from app.security import crypto
from tests.helpers import ClientEmulator, daterange

TODAY = date.today()
FILLER = "walked the dog, cooked dinner, called my sister"


async def _mature_account(client, emu, days: int = 35) -> None:
    """Threshold-crossing account with a plain journal (no patterns needed
    for the wire-contract tests — a 200 with analyzer/phase is enough)."""
    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, TODAY):
        await emu.create_entry(client, FILLER, day, client_entry_id=f"f-{day.isoformat()}")


def _feedback_blob(
    emu: ClientEmulator, payload: dict | None = None, *, days_ago: int = 0
) -> str:
    payload = payload or {"feedback": []}
    seal_day = (_utc_today() - timedelta(days=days_ago)).isoformat()
    aad = crypto.build_aad("feedback", emu.user_id or "", seal_day)
    blob = crypto.encrypt(emu.data_key, json.dumps(payload).encode("utf-8"), aad)
    return base64.b64encode(blob).decode("ascii")


async def test_feedback_blob_is_not_replayable_across_days(client):
    # 2026-09-21 audit C-5: the AAD carries the seal date. A blob captured
    # by a hostile server used to authenticate FOREVER; anything older than
    # the today-or-yesterday tolerance window must now be refused before
    # any corpus work happens.
    emu = ClientEmulator("fb-replay", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    stale = _feedback_blob(emu, {"feedback": [{"pid": "p", "resonated": True}]}, days_ago=3)
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
        json={"feedback_blob": stale},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "feedback_blob_invalid"

    # Yesterday still passes: an honest client sealed just before UTC
    # midnight must not lose its feedback to the tolerance window.
    recent = _feedback_blob(emu, {"feedback": []}, days_ago=1)
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
        json={"feedback_blob": recent},
    )
    assert response.status_code == 200, response.text


async def test_feedback_blob_object_body_shape_is_accepted(client):
    # THE 422 regression: the mobile client's exact body shape must parse.
    emu = ClientEmulator("fb-shape", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
        # Dict-shaped taps (a tuple item would be malformed input, not a
        # wire shape, since the 2026-09-20 loud-parse fix L-11).
        json={
            "feedback_blob": _feedback_blob(emu, {"feedback": [{"pid": "x:1", "resonated": True}]})
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["phase"] == "insight"


async def test_feedback_blob_bad_base64_is_422_not_500(client):
    emu = ClientEmulator("fb-b64", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
        json={"feedback_blob": "not base64 !!"},
    )
    assert response.status_code == 422, response.text
    assert response.json()["code"] == "validation_error", response.text


async def test_tampered_feedback_blob_is_400_and_does_not_wipe_state(client):
    emu = ClientEmulator("fb-tamper", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    # First recompute establishes the encrypted brain state.
    first = await emu.recompute(client)
    assert first["phase"] == "insight"

    token = await emu.open_processing_session(client)
    # AEAD-valid shape, wrong key: another user's data key with the SAME AAD
    stranger = ClientEmulator("fb-stranger", "other-password")
    stranger.user_id = emu.user_id  # AAD binds ("feedback", user id)
    forged = _feedback_blob(stranger)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
        json={"feedback_blob": forged},
    )
    assert response.status_code == 400, response.text
    assert response.json()["code"] == "feedback_blob_invalid", response.text

    # The state survived: a clean recompute still runs the brain, and the
    # account's insights decrypt under the ORIGINAL key (amnesia would have
    # discarded the accumulated store — observable as a state reset, and
    # the tampered-blob path must never reach it).
    summary = await client.get("/api/insights", headers=emu.headers)
    assert summary.status_code == 200, summary.text
    second = await emu.recompute(client)
    assert second["phase"] == "insight"
    assert second["analyzer"] in ("brain", "llm")


# ---------------------------------------------------------------------------
# Feedback attribution: _chosen_pattern_pid must mirror build_pool's
# slice-then-skip ordering (the 2026-09-17 audit found filter-then-slice,
# which misattributes taps whenever a sensitive pattern ranks in the top 5).
# ---------------------------------------------------------------------------

from app.services import questions  # noqa: E402
from app.services.patterns import Pattern  # noqa: E402


def _pattern(label: str, pid: str, occurrences: int) -> Pattern:
    return Pattern(
        kind="recurring_phrase",
        label=label,
        occurrences=occurrences,
        confidence=0.9,
        detail={"pattern_pid": pid},
    )


def _pool_owners(patterns, user_id: str) -> list[tuple[str | None, str]]:
    """Spec mirror of build_pool: top-5 by feedback rank FIRST, sensitive
    skipped AFTER the slice — the same ordering questions.question_for_today
    consumes."""
    top = sorted(patterns, key=questions.feedback_rank)[: questions.MAX_PATTERN_QUESTIONS]
    owners: list[tuple[str | None, str]] = []
    for p in top:
        if questions.pattern_is_sensitive(p):
            continue
        for q in questions.render_pattern_questions(p):
            owners.append((p.detail["pattern_pid"], q))
    owners.extend((None, q) for q in questions.GENERIC_QUESTIONS)
    seen: set[str] = set()
    return [
        (o, q)
        for o, q in owners
        if not questions.crisis.matches_suppress(q) and not (q in seen or seen.add(q))
    ]


def test_chosen_pattern_pid_mirrors_build_pool_ordering():
    sensitive = _pattern("cutting", "pid-sensitive", 99)  # ranks #1, must be skipped
    benign = [
        _pattern("family", "pid-family", 50),
        _pattern("running", "pid-running", 40),
        _pattern("reading", "pid-reading", 30),
        _pattern("cooking", "pid-cooking", 20),
        _pattern("music", "pid-music", 10),
        _pattern("gardening", "pid-gardening", 5),  # 6th: outside the top-5 slice
    ]
    patterns = [sensitive, *benign]
    user_id = "user-ordering"
    pool_owners = _pool_owners(patterns, user_id)

    for offset in range(30):
        day = TODAY + timedelta(days=offset)
        pid = _chosen_pattern_pid(day, patterns, user_id)
        index = (day.toordinal() + questions.user_rotation_offset(user_id)) % len(pool_owners)
        expected_owner, expected_q = pool_owners[index]
        assert pid == expected_owner, (
            f"day {day}: pid {pid!r} != build_pool owner {expected_owner!r} "
            f"(question {expected_q!r})"
        )
        assert pid in (None, "pid-family", "pid-running", "pid-reading", "pid-cooking"), (
            f"day {day}: pid {pid!r} comes from outside the top-5 slice — "
            "the sensitive-skip must happen AFTER the slice, like build_pool"
        )


async def test_feedback_blob_with_mute_lists_is_accepted(client):
    """Pattern mutes (2026-09-19) ride the same encrypted blob: the muted/
    unmuted pid lists parse, apply to the brain state, and an unknown pid
    is simply ignored (patterns retire)."""
    emu = ClientEmulator("fb-mute", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    await emu.recompute(client)  # establish the encrypted brain state

    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
        json={
            "feedback_blob": _feedback_blob(
                emu,
                {"feedback": [], "muted": ["temporal:work", "bogus:pid"], "unmuted": []},
            )
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["phase"] == "insight"


def test_parse_feedback_partitions_taps_and_mutes():
    from app.api.insights import _parse_feedback
    from app.deps import ApiError

    # Well-formed blobs partition exactly as before.
    raw = json.dumps(
        {
            "feedback": [{"pid": "a:1", "resonated": True}, {"pid": "x", "resonated": False}],
            "muted": ["a:1"],
            "unmuted": ["b:2"],
        }
    ).encode("utf-8")
    events = _parse_feedback(raw)
    assert events.taps == [("a:1", True), ("x", False)]
    assert events.muted == ["a:1"]
    assert events.unmuted == ["b:2"]

    # Any malformed item now fails the WHOLE blob with the stable 400 (audit
    # L-11, 2026-09-20): partial silent application of a corrupt feedback
    # queue is gone.
    for payload in (
        {"feedback": [{"pid": "x", "resonated": "yes"}]},
        {"feedback": [{"pid": "a:1", "resonated": True}], "muted": ["a:1", 7]},
        {"feedback": [], "unmuted": ["way-too-long-" + "x" * 200]},
    ):
        with pytest.raises(ApiError) as excinfo:
            _parse_feedback(json.dumps(payload).encode("utf-8"))
        assert excinfo.value.status_code == 400
        assert excinfo.value.code == "entry_payload_malformed"


async def test_mute_only_and_unmute_only_blobs_are_accepted(client):
    """2026-09-21 fix: the shipped client always emits all three keys, but a
    queue holding ONLY a mute (or only an unmute) is a well-formed state —
    the blob must apply, not 400. Found by the 365-day user simulation:
    a mute-only blob was rejected with entry_payload_malformed."""
    from app.api.insights import _parse_feedback

    emu = ClientEmulator("fb-mute-only", "deep-password")
    await emu.register(client)
    await _mature_account(client, emu)
    await emu.recompute(client)  # establish the encrypted brain state

    for payload in ({"muted": ["temporal:work"]}, {"unmuted": ["topic:guitar"]}):
        token = await emu.open_processing_session(client)
        response = await client.post(
            "/api/insights/recompute",
            headers={**emu.headers, "X-Processing-Token": token},
            json={"feedback_blob": _feedback_blob(emu, payload)},
        )
        assert response.status_code == 200, response.text

    # Parser-level: zero taps, the mute lists carried through.
    events = _parse_feedback(json.dumps({"muted": ["a:1"]}).encode("utf-8"))
    assert events.taps == []
    assert events.muted == ["a:1"]
    assert events.unmuted == []


def test_parse_feedback_still_fails_loud_on_empty_or_garbage_shapes():
    """The leniency ends where nothing would be applied: an empty object or
    a non-dict payload remains the stable 400 — a blob that would silently
    do nothing must never be accepted as if it had done something."""
    from app.api.insights import _parse_feedback
    from app.deps import ApiError

    for raw in (b"{}", b"[]", b'"a string"', b"not json", b'{"feedback": "not-a-list"}'):
        with pytest.raises(ApiError) as excinfo:
            _parse_feedback(raw)
        assert excinfo.value.status_code == 400
        assert excinfo.value.code == "entry_payload_malformed"
