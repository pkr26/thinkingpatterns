"""Pins for every genuine survivor of the 2026-09-22 mutation campaign
(round 4: redteam/mutation_campaign_2026-09-22/).

Each test kills one mutant that survived BOTH its targeted suite and the
full fast suite. The clock-dependent TOTP pins freeze the RFC timestep
deterministically (no 30-second waits); the DB-defense pins seed states
the public API cannot produce (a foreign revision row, a revision counter
at its ceiling) the same way round-3's pins did.

Mutant id -> pin:
  U7  test_totp_enable_consumes_its_timestep
  U8  test_totp_disable_refuses_the_code_that_just_logged_in
  V1  test_measure_quota_is_enforced_at_the_boundary
  V8  test_measure_create_fails_closed_when_revision_cannot_advance
  V9  test_measure_page_fails_closed_when_the_collection_moves_mid_read
  V11 test_therapist_measure_mirror_fails_closed_when_the_collection_moves
  V12 test_therapist_measure_mirror_enforces_the_byte_budget_post_fetch
  W7  test_note_revisions_read_is_therapist_scoped
  W8  test_note_revisions_arrive_newest_first
  W9  test_note_revisions_page_ceiling_is_two_hundred
  X4  test_entry_aad_v2_binds_the_content_version
  X5  test_rekey_re_encrypts_under_the_v2_aad
  Y2  test_temporal_narrowing_needs_three_tod_entries
  Y4  test_temporal_narrowing_includes_the_exact_dominance_bar
  Y8  test_short_corpora_keep_the_english_default
  Z3  test_access_log_cursor_tiebreaks_on_id_within_one_timestamp
  Z4  test_therapist_access_log_is_actor_scoped
  Z6  test_wrap_key_rotation_refuses_deactivated_accounts
"""

from __future__ import annotations

import base64
import json
import os
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import literal, update
from starlette.requests import Request

from app.api import insights as insights_api
from app.api import measures as measures_api
from app.api.therapist import rotate_wrap_key
from app.api.entries import MAX_COLLECTION_REVISION
from app.models import AccessLog, Measure, TherapistNoteRevision, User
from app.schemas import WrapKeyRotateRequest
from app.security import crypto, totp
from app.services import brain
from app.services.patterns import JournalEntry
from tests.helpers import ClientEmulator, TherapistEmulator
from tests.test_es_themes import WORK_ES, consecutive as es_consecutive
from tests.test_time_of_day import _corpus as tod_corpus
from tests.test_time_of_day import _surfaced as tod_surfaced

TODAY = date.today()


def _b32_decode(secret_b32: str) -> bytes:
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    return base64.b32decode(padded)


def _freeze_totp_clock(monkeypatch, epoch: float) -> int:
    """Freeze the RFC timestep and return the frozen counter."""
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: epoch))
    return int(epoch // totp.STEP_SECONDS)


async def _totp_setup(client, th: TherapistEmulator) -> bytes:
    setup = await client.post(
        "/api/account/totp/setup",
        json={"verifier": th.auth_key_b64},
        headers=th.headers,
    )
    assert setup.status_code == 200, setup.text
    return _b32_decode(setup.json()["secret_base32"])


def _measure_payload(client_measure_id: str, size: int, when: date) -> dict:
    return {
        "client_measure_id": client_measure_id,
        "blob": base64.b64encode(b"m" * size).decode("ascii"),
        "measure_date": when.isoformat(),
    }


async def _grant(client, patient: ClientEmulator, therapist: TherapistEmulator) -> None:
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted


async def _shared_note(client, note_text: str) -> tuple[TherapistEmulator, ClientEmulator, dict]:
    therapist = TherapistEmulator("r4pin-th", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("r4pin-p", "deep-password")
    await patient.register(client)
    await _grant(client, patient, therapist)
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "r4pin-n1",
            "blob": therapist.encrypt_note(patient, "r4pin-n1", note_text),
        },
    )
    assert created.status_code == 201, created.text
    return therapist, patient, created.json()


def _note_aad(therapist: TherapistEmulator, patient: ClientEmulator) -> bytes:
    return crypto.build_aad("note", therapist.user_id or "", patient.user_id or "", "r4pin-n1")


# ===========================================================================
# U. TOTP second factor — the two replay fences the lifecycle ladder missed
# ===========================================================================


async def test_totp_enable_consumes_its_timestep(client, monkeypatch):
    """U7: confirming enrollment presents a code to the server; that exact
    code must not immediately log in (the enable consumes the timestep)."""
    th = TherapistEmulator("r4-u7-dr", "deep-password")
    await th.register(client)
    secret = await _totp_setup(client, th)

    counter = _freeze_totp_clock(monkeypatch, 1_800_000_000.0)
    code = totp._code_for_counter(secret, counter)
    enable = await client.post(
        "/api/account/totp/enable",
        json={"verifier": th.auth_key_b64, "code": code},
        headers=th.headers,
    )
    assert enable.status_code == 204, enable.text

    replay = await client.post(
        "/api/auth/login",
        json={"username": th.username, "verifier": th.auth_key_b64, "totp_code": code},
    )
    assert replay.status_code == 401, replay.text
    assert replay.json()["code"] == "totp_code_invalid"

    # Control: the NEXT timestep is a genuinely fresh proof and logs in.
    _freeze_totp_clock(monkeypatch, 1_800_000_000.0 + totp.STEP_SECONDS + 1)
    fresh = totp._code_for_counter(secret, counter + 1)
    ok = await client.post(
        "/api/auth/login",
        json={"username": th.username, "verifier": th.auth_key_b64, "totp_code": fresh},
    )
    assert ok.status_code == 200, ok.text


async def test_totp_disable_refuses_the_code_that_just_logged_in(client, monkeypatch):
    """U8: the disable fence is strictly-greater too — the code that just
    authenticated a login must not also strip the factor."""
    th = TherapistEmulator("r4-u8-dr", "deep-password")
    await th.register(client)
    secret = await _totp_setup(client, th)

    counter = _freeze_totp_clock(monkeypatch, 1_800_100_000.0)
    enable = await client.post(
        "/api/account/totp/enable",
        json={"verifier": th.auth_key_b64, "code": totp._code_for_counter(secret, counter)},
        headers=th.headers,
    )
    assert enable.status_code == 204, enable.text

    next_counter = _freeze_totp_clock(
        monkeypatch, 1_800_100_000.0 + totp.STEP_SECONDS + 1
    )
    login_code = totp._code_for_counter(secret, next_counter)
    login = await client.post(
        "/api/auth/login",
        json={"username": th.username, "verifier": th.auth_key_b64, "totp_code": login_code},
    )
    assert login.status_code == 200, login.text

    # Presenting the SAME code to disable is a replay of a consumed proof.
    replayed = await client.post(
        "/api/account/totp/disable",
        json={"verifier": th.auth_key_b64, "code": login_code},
        headers=th.headers,
    )
    assert replayed.status_code == 403, replayed.text
    assert replayed.json()["code"] == "totp_code_invalid"

    # Control: a fresh timestep disables cleanly.
    _freeze_totp_clock(monkeypatch, 1_800_100_000.0 + 2 * totp.STEP_SECONDS + 2)
    disable = await client.post(
        "/api/account/totp/disable",
        json={
            "verifier": th.auth_key_b64,
            "code": totp._code_for_counter(secret, next_counter + 1),
        },
        headers=th.headers,
    )
    assert disable.status_code == 204, disable.text


# ===========================================================================
# V. measures — quota, fail-closed guards, and the two drift fences
# ===========================================================================


async def test_measure_quota_is_enforced_at_the_boundary(client, monkeypatch):
    """V1: the per-account measure count cap must 413 (constant shrunk so
    the boundary is reachable without two thousand inserts)."""
    monkeypatch.setattr(measures_api, "MAX_MEASURES_PER_USER", 2)
    emu = ClientEmulator("r4-v1", "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    first = await client.post(
        "/api/measures", headers=emu.headers, json=_measure_payload("r4-v1-a", 96, TODAY)
    )
    second = await client.post(
        "/api/measures",
        headers=emu.headers,
        json=_measure_payload("r4-v1-b", 96, TODAY - timedelta(days=1)),
    )
    assert first.status_code == 201 and second.status_code == 201
    third = await client.post(
        "/api/measures",
        headers=emu.headers,
        json=_measure_payload("r4-v1-c", 96, TODAY - timedelta(days=2)),
    )
    assert third.status_code == 413, third.text
    assert third.json()["code"] == "quota_exceeded"


async def test_measure_create_fails_closed_when_revision_cannot_advance(client, app):
    """V8: a create whose marker UPDATE hits 0 rows must 503 and store
    nothing — an unmarked mutation would drift every continuation."""
    emu = ClientEmulator("r4-v8", "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(User)
            .where(User.id == emu.user_id)
            .values(measures_revision=MAX_COLLECTION_REVISION)
        )
        await session.commit()
    response = await client.post(
        "/api/measures", headers=emu.headers, json=_measure_payload("r4-v8-a", 96, TODAY)
    )
    assert response.status_code == 503, response.text
    assert response.json()["code"] == "service_unavailable"
    async with app.state.sessionmaker() as session:
        stored = (
            await session.execute(Measure.__table__.select().where(Measure.user_id == emu.user_id))
        ).all()
    assert stored == []


async def test_measure_page_fails_closed_when_the_collection_moves_mid_read(client, monkeypatch):
    """V9: the FINAL revision re-read must turn a mid-read create into 409
    collection_changed, never a silently shifted page."""
    emu = ClientEmulator("r4-v9", "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    created = await client.post(
        "/api/measures", headers=emu.headers, json=_measure_payload("r4-v9-a", 96, TODAY)
    )
    assert created.status_code == 201, created.text

    answers = [5, 6]

    async def moving_revision(session, user_id):
        return answers.pop(0)

    monkeypatch.setattr(measures_api, "current_measures_revision", moving_revision)
    page = await client.get("/api/measures", headers=emu.headers)
    assert page.status_code == 409, page.text
    assert page.json()["code"] == "collection_changed"


async def test_therapist_measure_mirror_fails_closed_when_the_collection_moves(
    client, monkeypatch
):
    """V11: the therapist mirror carries the same final-drift fence."""
    from app.api import therapist as therapist_api

    patient = ClientEmulator("r4-v11-p", "deep-password")
    await patient.register(client)
    await patient.backdate_account(client, days=14)
    created = await client.post(
        "/api/measures", headers=patient.headers, json=_measure_payload("r4-v11-a", 96, TODAY)
    )
    assert created.status_code == 201, created.text
    th = TherapistEmulator("r4-v11-dr", "deep-password", "Dr Mirror")
    await th.register(client)
    await _grant(client, patient, th)

    answers = [5, 6]

    async def moving_revision(session, user_id):
        return answers.pop(0)

    monkeypatch.setattr(therapist_api, "current_measures_revision", moving_revision)
    mirrored = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures", headers=th.headers
    )
    assert mirrored.status_code == 409, mirrored.text
    assert mirrored.json()["code"] == "collection_changed"


async def test_therapist_measure_mirror_enforces_the_byte_budget_post_fetch(client, app, monkeypatch):
    """V12: the post-fetch byte sanity is the defense against metadata and
    ORM blob sizes disagreeing (dialect drift, mid-read divergence)."""
    from app.api import therapist as therapist_api

    patient = ClientEmulator("r4-v12-p", "deep-password")
    await patient.register(client)
    await patient.backdate_account(client, days=14)
    async with app.state.sessionmaker() as session:
        session.add_all(
            Measure(
                user_id=patient.user_id,
                client_measure_id=f"r4-v12-{i}",
                blob=b"t" * 2048,
                measure_date=TODAY - timedelta(days=i),
            )
            for i in range(3)
        )
        await session.commit()
    th = TherapistEmulator("r4-v12-dr", "deep-password", "Dr Budget")
    await th.register(client)
    await _grant(client, patient, th)

    # The metadata query under-reports every blob to zero bytes…
    monkeypatch.setattr(therapist_api, "_measure_blob_length", lambda session: literal(0))
    # …so the walk selects all rows under a 1 KiB budget, and only the
    # post-fetch real-byte check can refuse the page.
    served = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures",
        headers=th.headers,
        params={"page_bytes": 1024},
    )
    assert served.status_code == 409, served.text
    assert served.json()["code"] == "collection_changed"


# ===========================================================================
# W. note history — scoping, order, and the page ceiling
# ===========================================================================


async def test_note_revisions_read_is_therapist_scoped(client, app):
    """W7: a revision row bearing a foreign therapist_id (impossible via
    the API — written from the note owner's session — but seeded here as
    defense-in-depth) must not surface in another therapist's read."""
    therapist, patient, note = await _shared_note(client, "v1 text")
    updated = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": therapist.encrypt_note(patient, "r4pin-n1", "v2 text")},
    )
    assert updated.status_code == 200, updated.text

    at = datetime.now(timezone.utc)
    async with app.state.sessionmaker() as session:
        session.add(
            TherapistNoteRevision(
                note_id=note["id"],
                therapist_id=patient.user_id,  # a real user row, never the owner
                blob=b"foreign" * 12,
                created_at=at,
            )
        )
        await session.commit()

    revisions = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
    )
    assert revisions.status_code == 200, revisions.text
    rows = revisions.json()
    assert len(rows) == 1, "the foreign-therapist revision must not be served"
    aad = _note_aad(therapist, patient)
    plain = crypto.decrypt(therapist.notes_key, base64.b64decode(rows[0]["blob"]), aad)
    assert json.loads(plain.decode("utf-8"))["text"] == "v1 text"


async def test_note_revisions_arrive_newest_first(client):
    """W8: after two edits the history is [v2, v1] — the most recently
    superseded text leads the timeline."""
    therapist, patient, note = await _shared_note(client, "v1 text")
    for text in ("v2 text", "v3 text"):
        updated = await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=therapist.headers,
            json={"blob": therapist.encrypt_note(patient, "r4pin-n1", text)},
        )
        assert updated.status_code == 200, updated.text

    revisions = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
    )
    rows = revisions.json()
    assert len(rows) == 2
    aad = _note_aad(therapist, patient)
    texts = [
        json.loads(
            crypto.decrypt(therapist.notes_key, base64.b64decode(row["blob"]), aad).decode()
        )["text"]
        for row in rows
    ]
    assert texts == ["v2 text", "v1 text"]


async def test_note_revisions_page_ceiling_is_two_hundred(client):
    """W9: the history read is count-bounded — limit=201 is a 422."""
    therapist, _patient, note = await _shared_note(client, "ceiling text")
    refused = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions",
        headers=therapist.headers,
        params={"limit": 201},
    )
    assert refused.status_code == 422, refused.text
    ok = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions",
        headers=therapist.headers,
        params={"limit": 200},
    )
    assert ok.status_code == 200, ok.text


# ===========================================================================
# X. entry content versioning — the AAD byte contract
# ===========================================================================


def test_entry_aad_v2_binds_the_content_version():
    """X4: the v2 AAD is build_aad(entry, user, id, str(version)) — the
    cross-platform byte contract, constructed independently here the way
    mobile and the portal construct it."""
    user_id, client_entry_id = "r4-x4-user", "r4-x4-entry"
    key = bytearray(os.urandom(32))
    plain = b'{"text": "v2 payload"}'
    blob = crypto.encrypt(key, plain, crypto.entry_aad_v2(user_id, client_entry_id, 2))

    manual_v2 = crypto.build_aad(crypto.ENTRY_CONTEXT, user_id, client_entry_id, "2")
    assert crypto.decrypt(key, blob, manual_v2) == plain
    manual_v1 = crypto.build_aad(crypto.ENTRY_CONTEXT, user_id, client_entry_id, "1")
    with pytest.raises(crypto.TamperError):
        crypto.decrypt(key, blob, manual_v1)


def test_rekey_re_encrypts_under_the_v2_aad():
    """X5: rekey must UPGRADE the generation — the output authenticates
    only under the v2 AAD of the row's content_version, never v1."""
    user_id, client_entry_id = "r4-x5-user", "r4-x5-entry"
    old_key = bytearray(os.urandom(32))
    new_key = bytearray(os.urandom(32))
    plain = b'{"text": "rekey me"}'

    v2_blob = crypto.encrypt(old_key, plain, crypto.entry_aad_v2(user_id, client_entry_id, 2))
    out = insights_api._rekey_entry_batch(
        old_key, new_key, [("r4-x5-row", client_entry_id, 2, v2_blob)], user_id
    )
    fresh = out[0][1]
    crypto.decrypt(new_key, fresh, crypto.entry_aad_v2(user_id, client_entry_id, 2))
    with pytest.raises(crypto.TamperError):
        crypto.decrypt(new_key, fresh, crypto.entry_aad_v1(user_id, client_entry_id))

    # A legacy v1 input rekeys UP to v2 as well.
    v1_blob = crypto.encrypt(old_key, plain, crypto.entry_aad_v1(user_id, client_entry_id))
    out = insights_api._rekey_entry_batch(
        old_key, new_key, [("r4-x5-row2", client_entry_id, 1, v1_blob)], user_id
    )
    upgraded = out[0][1]
    crypto.decrypt(new_key, upgraded, crypto.entry_aad_v2(user_id, client_entry_id, 1))
    with pytest.raises(crypto.TamperError):
        crypto.decrypt(new_key, upgraded, crypto.entry_aad_v1(user_id, client_entry_id))


# ===========================================================================
# Y. time-of-day evidence bars and the language floor
# ===========================================================================


def test_temporal_narrowing_needs_three_tod_entries():
    """Y2: two tod-bearing entries on the weekday do not license "Sunday
    evening" — the N>=3 evidence bar holds."""
    cards = tod_surfaced(["evening", "evening"] + [None] * 7)
    assert cards, "the weekday temporal card must still surface"
    assert "time_of_day" not in cards[0].detail


def test_temporal_narrowing_includes_the_exact_dominance_bar():
    """Y4: 7-of-10 evening (exactly 0.7) narrows — the comparison is
    inclusive at the bar."""
    cards = tod_surfaced(["evening"] * 7 + ["morning"] * 2)
    assert cards, "the weekday temporal card must still surface"
    assert cards[0].detail["time_of_day"] == "evening"


def test_short_corpora_keep_the_english_default():
    """Y8: under LANGUAGE_MIN_TOKENS scored tokens the language verdict is
    the historical English default — a handful of Spanish sentences must
    not flip the whole pipeline to 'es'."""
    entries = [
        JournalEntry(WORK_ES, day)
        for day in es_consecutive(date(2026, 9, 1), 4)
    ]
    result = brain.update(brain.load_state(None), entries, date(2026, 9, 5))
    assert result.stats["language"] == "en"


# ===========================================================================
# Z. audit trail pagination/scoping and the rotation lifecycle recheck
# ===========================================================================


async def test_access_log_cursor_tiebreaks_on_id_within_one_timestamp(client, app):
    """Z3: rows sharing one timestamp are ordered by id — the cursor must
    hand back the tie row, not skip past it."""
    emu = ClientEmulator("r4-z3", "deep-password")
    await emu.register(client)
    at = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
    async with app.state.sessionmaker() as session:
        session.add(
            AccessLog(
                id="r4z3rowaaa", actor_id=emu.user_id, actor_role="user",
                user_id=emu.user_id, action="grant", at=at,
            )
        )
        session.add(
            AccessLog(
                id="r4z3rowzzz", actor_id=emu.user_id, actor_role="user",
                user_id=emu.user_id, action="revoke", at=at,
            )
        )
        await session.commit()

    page1 = await client.get("/api/account/access-log", headers=emu.headers, params={"limit": 1})
    assert page1.status_code == 200, page1.text
    rows1 = page1.json()
    assert len(rows1) == 1
    cursor = page1.headers["X-Next-Cursor"]

    page2 = await client.get(
        "/api/account/access-log", headers=emu.headers, params={"limit": 1, "cursor": cursor}
    )
    assert page2.status_code == 200, page2.text
    rows2 = page2.json()
    assert len(rows2) == 1, "the same-timestamp tie row must not be skipped"
    assert {rows1[0]["action"], rows2[0]["action"]} == {"grant", "revoke"}


async def test_therapist_access_log_is_actor_scoped(client, app):
    """Z4: one therapist's action history contains only their own actions
    — another therapist's audited read must not leak into the page."""
    patient_a = ClientEmulator("r4-z4-pa", "deep-password")
    patient_b = ClientEmulator("r4-z4-pb", "deep-password")
    await patient_a.register(client)
    await patient_b.register(client)
    await patient_a.backdate_account(client, days=14)
    await patient_b.backdate_account(client, days=14)
    for patient in (patient_a, patient_b):
        created = await client.post(
            "/api/measures", headers=patient.headers, json=_measure_payload("r4-z4-m", 96, TODAY)
        )
        assert created.status_code == 201, created.text
    th_a = TherapistEmulator("r4-z4-dra", "deep-password", "Dr Alpha")
    th_b = TherapistEmulator("r4-z4-drb", "deep-password", "Dr Beta")
    await th_a.register(client)
    await th_b.register(client)
    await _grant(client, patient_a, th_a)
    await _grant(client, patient_b, th_b)

    # Each therapist performs one audited read on their OWN patient.
    read_a = await client.get(
        f"/api/therapist/patients/{patient_a.user_id}/measures", headers=th_a.headers
    )
    read_b = await client.get(
        f"/api/therapist/patients/{patient_b.user_id}/measures", headers=th_b.headers
    )
    assert read_a.status_code == 200 and read_b.status_code == 200

    async with app.state.sessionmaker() as session:
        names = {}
        for patient in (patient_a, patient_b):
            row = await session.get(User, patient.user_id)
            names[patient.user_id] = (row.display_name or row.username) if row else None

    history = await client.get("/api/therapist/access-log", headers=th_a.headers)
    assert history.status_code == 200, history.text
    served = [row["patient_name"] for row in history.json()]
    assert names[patient_b.user_id] not in served, "Dr Beta's actions leaked into Dr Alpha's page"
    assert names[patient_a.user_id] in served


async def test_wrap_key_rotation_refuses_deactivated_accounts(client, app):
    """Z6: the under-lock recheck is defense-in-depth — require_user 401s
    deactivated accounts at the door, so this drives the handler directly
    with a deactivated user object (the round-3 O2 pattern)."""
    from fastapi import HTTPException

    emu = TherapistEmulator("r4-z6-dr", "deep-password")
    await emu.register(client)
    successor = TherapistEmulator("r4-z6-dr", "deep-password")  # fresh keypair, unregistered
    async with app.state.sessionmaker() as session:
        await session.execute(update(User).where(User.id == emu.user_id).values(is_active=False))
        await session.commit()
        user = await session.get(User, emu.user_id)
        assert user is not None and not user.is_active

    request = Request(
        {
            "type": "http",
            "headers": [],
            "method": "PUT",
            "path": "/api/therapist/wrap-key",
            "app": app,
        }
    )
    with pytest.raises(HTTPException) as excinfo:
        await rotate_wrap_key(
            body=WrapKeyRotateRequest(
                wrap_pub_key=successor.wrap_pub_key,
                wrap_key_blob=successor.wrap_key_blob_b64(),
            ),
            request=request,
            user=user,
            session=session,
            x_account_verifier=emu.auth_key_b64,
        )
    assert excinfo.value.status_code == 404
    assert excinfo.value.detail == "account not found"
