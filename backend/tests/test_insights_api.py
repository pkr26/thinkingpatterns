"""The full pipeline: encrypt -> sync -> processing session -> recompute -> gate.

This is the product's core story told end-to-end: five weeks of Sunday work
anxiety, invisible at day 29, revealed as patterns at day 30, with one
deterministic reflective question per day.
"""

from __future__ import annotations

import base64
from datetime import date, timedelta

import pytest

from app.security import crypto
from tests.helpers import ClientEmulator, daterange

TODAY = date.today()  # question blobs are AAD-bound to the server's "today"
WORK_ANXIOUS = ("Deadline at work monday, the boss piled on another project and a "
                "late meeting. Anxious, stressed, dreading the presentation.")
CALM = "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."


async def seed_corpus(client, emu, days: int) -> None:
    """Seed alternating calm days and Sunday work-anxiety days."""
    # Age the account to match the corpus: the server (correctly) refuses
    # entries that predate the account, so a synthetic N-day history needs
    # an N-day-old account.
    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, TODAY):
        if day.weekday() == 6:  # Sunday
            await emu.create_entry(client, WORK_ANXIOUS, day, client_entry_id=f"w-{day.isoformat()}")
        else:
            await emu.create_entry(client, CALM, day, client_entry_id=f"c-{day.isoformat()}")


async def test_full_pipeline_unlocks_at_threshold(client, monkeypatch):
    emu = ClientEmulator("longterm", "deep-password")
    await emu.register(client)
    # 70 days = 10 Sundays: enough mentions (≥8) for the base-rate-corrected
    # temporal test.
    await seed_corpus(client, emu, days=70)

    session_token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    assert recompute.status_code == 200, recompute.text
    body = recompute.json()
    assert body["phase"] == "insight"
    assert body["active_days"] == 70
    assert body["analyzer"] == "brain"
    # Replication gate: statistical kinds (temporal, mood_correlation) qualify
    # as candidates on the first recompute day and surface only after an
    # INDEPENDENT second observation — a second recompute day that adds new
    # evidence. A next-day recompute of the UNCHANGED corpus no longer
    # promotes: consecutive recomputes share ~179/180 window days, so that
    # was the same data scored twice.

    class _NextDay(date):
        @classmethod
        def today(cls) -> date:
            return date.today() + timedelta(days=1)

    monkeypatch.setattr("app.api.insights.date_type", _NextDay)
    # The fresh evidence: a work entry on a day the fixture wrote CALM text
    # for (never a Sunday, so the day is new work evidence every run).
    fresh_day = TODAY if TODAY.weekday() != 6 else TODAY - timedelta(days=1)
    await emu.create_entry(client, WORK_ANXIOUS, fresh_day, client_entry_id="fresh-work")
    second = await emu.recompute(client)
    assert second["phase"] == "insight"
    assert second["patterns_stored"] >= 2  # temporal + mood_correlation at minimum
    assert second["patterns_new"] >= 1  # newly surfaced on the second day

    insights = await emu.decrypt_insights(client)
    assert insights["phase"] == "insight"
    kinds = {p["kind"] for p in insights["stats"]["patterns"]}
    assert "temporal" in kinds and "mood_correlation" in kinds
    temporal = next(p for p in insights["stats"]["patterns"] if p["kind"] == "temporal")
    assert temporal["label"] == "work"
    assert temporal["detail"]["day"] == "Sunday"

    fake_today = date.today() + timedelta(days=1)
    question = await emu.decrypt_question(client, fake_today)
    assert question["for_date"] == fake_today.isoformat()
    assert question["question"].endswith("?")


async def test_baseline_phase_before_threshold(client, app):
    emu = ClientEmulator("newbie", "fresh-password")
    await emu.register(client)
    await seed_corpus(client, emu, days=29)

    session_token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    body = recompute.json()
    assert body["phase"] == "baseline"
    assert body["days_remaining"] == 1
    assert body["patterns_stored"] == 0
    assert body["analyzer"] == "none"  # nothing was decrypted or analyzed

    # Baseline stores NO insight blob at all — there is nothing to leak.
    summary = await client.get("/api/insights", headers=emu.headers)
    assert summary.json()["blob"] is None

    # The session the client opened is consumed (single-use hygiene): the
    # keystore holds no usable key while the account is pre-threshold.
    assert len(app.state.key_store) == 0

    question = await client.get("/api/questions/today", headers=emu.headers)
    assert question.status_code == 404


async def test_question_is_deterministic_within_day(client):
    emu = ClientEmulator("stable", "quiet-password")
    await emu.register(client)
    await seed_corpus(client, emu, days=35)

    # Sessions are single-use: one fresh session per recompute.
    first = await emu.recompute(client)
    second = await emu.recompute(client)
    assert first["question_stored"] and second["question_stored"]

    q1 = await emu.decrypt_question(client, TODAY)
    q2 = await emu.decrypt_question(client, TODAY)
    assert q1["question"] == q2["question"]


async def test_recompute_requires_processing_session(client, settings):
    settings.unlock_threshold_days = 1  # reach the key-requiring branch
    emu = ClientEmulator("nosession", "p")
    await emu.register(client)
    await emu.create_entry(client, "hello", TODAY)

    missing = await client.post("/api/insights/recompute", headers=emu.headers)
    assert missing.status_code == 401

    bogus = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": "forged-token"},
    )
    assert bogus.status_code == 403


async def test_processing_session_is_single_use(client, settings):
    settings.unlock_threshold_days = 1
    emu = ClientEmulator("onceonly", "p")
    await emu.register(client)
    await emu.create_entry(client, "hello", TODAY)

    token = await emu.open_processing_session(client)
    first = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
    )
    assert first.status_code == 200
    replay = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
    )
    # Replaying a consumed session token must not re-run analysis.
    assert replay.status_code == 403


async def test_processing_session_key_lifecycle(client, app, settings):
    settings.unlock_threshold_days = 1
    emu = ClientEmulator("keys", "p")
    await emu.register(client)
    await emu.create_entry(client, "hello", TODAY)
    token = await emu.open_processing_session(client)
    assert len(app.state.key_store) == 1
    held = app.state.key_store.get(token)  # an owned copy, independent of the store
    assert held == emu.data_key
    assert app.state.key_store.destroy(token) is True
    # The copy the caller holds stays usable after the session is destroyed
    # (single-use flows depend on this), while the store no longer holds it.
    assert len(app.state.key_store) == 0
    from app.security import crypto as _crypto

    assert _crypto.decrypt(bytes(held), _crypto.encrypt(held, b"probe")) == b"probe"
    expired = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
    )
    assert expired.status_code == 403


async def test_processing_session_rejects_bad_keys(client):
    emu = ClientEmulator("badkeys", "p")
    await emu.register(client)
    wrong_size = __import__("base64").b64encode(b"5-bytes!!").decode()
    response = await client.post(
        "/api/processing/sessions", headers=emu.headers, json={"data_key": wrong_size},
    )
    assert response.status_code == 422
    response = await client.post(
        "/api/processing/sessions", headers=emu.headers, json={"data_key": "@@not-b64@@"},
    )
    assert response.status_code == 422


async def test_tampered_entry_blob_fails_authentication(client):
    emu = ClientEmulator("tamper", "p")
    await emu.register(client)
    await seed_corpus(client, emu, days=31)

    # One clean recompute first, so the brain holds a prior state row: a
    # tampered ENTRY must still fail loudly even when the retry path (built
    # for tampered STATE) exists — amnesia must never mask entry tampering.
    await emu.recompute(client)

    # Corrupt one stored blob directly (a malicious server or bit rot).
    from sqlalchemy import select
    from app.models import Entry
    app = client._transport.app  # noqa: SLF001 — test reachability into state
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(Entry).where(Entry.user_id == emu.user_id))).scalars().first()
        corrupted = bytearray(bytes(row.blob))
        corrupted[-1] ^= 1
        row.blob = bytes(corrupted)
        await session.commit()

    session_token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    assert recompute.status_code == 400
    assert "authentication" in recompute.json()["detail"]


async def test_wrong_data_key_cannot_recompute(client):
    emu = ClientEmulator("rightkey", "p")
    await emu.register(client)
    await seed_corpus(client, emu, days=31)

    # A session minted by ANOTHER account is refused outright (owner binding).
    stranger = ClientEmulator("stranger", "stranger-pass")
    await stranger.register(client)
    stranger_token = await stranger.open_processing_session(client)
    cross_user = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": stranger_token},
    )
    assert cross_user.status_code == 403

    # A session opened under this account but holding the WRONG key still
    # fails at GCM authentication during decryption.
    import base64
    stranger_key_b64 = base64.b64encode(stranger.data_key).decode()
    wrong_key_session = await client.post(
        "/api/processing/sessions", headers=emu.headers, json={"data_key": stranger_key_b64},
    )
    assert wrong_key_session.status_code == 201
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": wrong_key_session.json()["session_token"]},
    )
    assert recompute.status_code == 400
    assert "authentication" in recompute.json()["detail"]


async def test_insights_phase_tracks_current_activity(client):
    emu = ClientEmulator("tracker", "p")
    await emu.register(client)
    await seed_corpus(client, emu, days=10)

    response = await client.get("/api/insights", headers=emu.headers)
    body = response.json()
    assert body["phase"] == "baseline"
    assert body["active_days"] == 10
    assert body["days_remaining"] == 20
    assert body["blob"] is None  # nothing computed yet


async def test_recompute_with_no_entries(client):
    emu = ClientEmulator("empty", "p")
    await emu.register(client)
    session_token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    assert response.status_code == 400


async def test_plaintext_windows_close_after_recompute(client):
    from app.security.enclave import plaintext_windows

    emu = ClientEmulator("hygiene", "p")
    await emu.register(client)
    await seed_corpus(client, emu, days=31)
    session_token = await emu.open_processing_session(client)
    await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    assert plaintext_windows() == 0


async def test_insights_blob_is_bound_to_user(client):
    emu = ClientEmulator("bound", "p")
    await emu.register(client)
    await seed_corpus(client, emu, days=35)
    session_token = await emu.open_processing_session(client)
    await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )

    raw = await client.get("/api/insights", headers=emu.headers)
    blob = base64.b64decode(raw.json()["blob"])
    with pytest.raises(crypto.TamperError):
        crypto.decrypt(emu.data_key, blob, crypto.build_aad("insights", "somebody-else", "patterns"))
