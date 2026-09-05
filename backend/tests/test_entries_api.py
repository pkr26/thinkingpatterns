"""Entry sync API: CRUD, isolation, dedupe, ciphertext-only storage."""

from __future__ import annotations

import base64
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from app.models import Entry
from tests.helpers import ClientEmulator

TODAY = date.today()  # server clock decides "future"; keep tests relative to it


async def test_create_list_delete_roundtrip(client):
    emu = ClientEmulator("alice", "pass-1")
    await emu.register(client)
    created = await emu.create_entry(client, "feeling okay today", TODAY)

    listed = await client.get("/api/entries", headers=emu.headers)
    assert listed.status_code == 200
    body = listed.json()
    assert len(body) == 1
    assert body[0]["client_entry_id"] == created["client_entry_id"]
    assert body[0]["entry_date"] == TODAY.isoformat()

    deleted = await client.delete(f"/api/entries/{created['client_entry_id']}", headers=emu.headers)
    assert deleted.status_code == 204
    listed = await client.get("/api/entries", headers=emu.headers)
    assert listed.json() == []


async def test_entries_are_user_isolated(client):
    alice = ClientEmulator("alice", "pass-1")
    bob = ClientEmulator("bob", "pass-2")
    await alice.register(client)
    await bob.register(client)
    await alice.create_entry(client, "alice private thought", TODAY)

    bob_view = await client.get("/api/entries", headers=bob.headers)
    assert bob_view.status_code == 200
    assert bob_view.json() == []

    missing = await client.delete("/api/entries/e-1", headers=bob.headers)
    assert missing.status_code == 404


async def test_duplicate_client_entry_id_conflicts(client):
    emu = ClientEmulator("carol", "pass-3")
    await emu.register(client)
    await emu.create_entry(client, "first", TODAY, client_entry_id="fixed-id")
    response = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "fixed-id",
        "blob": emu.encrypt_entry("second", TODAY, "fixed-id"),
        "entry_date": TODAY.isoformat(),
    })
    assert response.status_code == 409


async def test_server_stores_ciphertext_only(client, app):
    emu = ClientEmulator("dave", "pass-4")
    await emu.register(client)
    secret_text = " deadline dread uniquesecretmarker "
    created = await emu.create_entry(client, secret_text, TODAY)

    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(Entry))).scalars().all()
    assert len(rows) == 1
    stored = bytes(rows[0].blob)
    assert b"uniquesecretmarker" not in stored
    assert b"deadline" not in stored
    # And it is exactly the envelope the client sent (same nonce, same bytes).
    assert stored == base64.b64decode(created["blob"])


async def test_rejects_undecodable_and_tiny_blobs(client):
    emu = ClientEmulator("erin", "pass-5")
    await emu.register(client)
    for blob in ("!!!not-base64!!!", base64.b64encode(b"tooshort").decode()):
        response = await client.post("/api/entries", headers=emu.headers, json={
            "client_entry_id": f"id-{blob[:6]}", "blob": blob, "entry_date": TODAY.isoformat(),
        })
        assert response.status_code == 422


async def test_rejects_future_entry_date(client):
    emu = ClientEmulator("frank", "pass-6")
    await emu.register(client)
    response = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "future-id",
        "blob": emu.encrypt_entry("from tomorrow", TODAY + timedelta(days=3), "future-id"),
        "entry_date": (TODAY + timedelta(days=3)).isoformat(),
    })
    assert response.status_code == 422


async def test_since_filter_and_ordering(client):
    emu = ClientEmulator("gina", "pass-7")
    await emu.register(client)
    await emu.backdate_account(client, days=10)  # entries predate "today" legitimately
    for offset in (5, 3, 1):
        day = TODAY - timedelta(days=offset)
        await emu.create_entry(client, f"day minus {offset}", day, client_entry_id=f"e{offset}")

    since = await client.get(
        "/api/entries", headers=emu.headers,
        params={"since": (TODAY - timedelta(days=3)).isoformat()},
    )
    listed = since.json()
    assert [e["client_entry_id"] for e in listed] == ["e3", "e1"]  # date-ascending
    limit_one = await client.get("/api/entries", headers=emu.headers, params={"limit": 1})
    assert len(limit_one.json()) == 1


async def test_offset_paginates_beyond_the_first_page(client):
    emu = ClientEmulator("paginator", "pass-8")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    for offset in (2, 1, 0):
        day = TODAY - timedelta(days=offset)
        await emu.create_entry(client, f"day minus {offset}", day, client_entry_id=f"p{offset}")

    page_one = await client.get("/api/entries", headers=emu.headers, params={"limit": 2})
    page_two = await client.get(
        "/api/entries", headers=emu.headers, params={"limit": 2, "offset": 2}
    )
    first_ids = [e["client_entry_id"] for e in page_one.json()]
    assert first_ids == ["p2", "p1"]
    assert [e["client_entry_id"] for e in page_two.json()] == ["p0"]
    assert len(page_one.json() + page_two.json()) == 3  # nothing lost, nothing doubled


async def test_rejects_entries_predating_the_account(client):
    emu = ClientEmulator("timecop", "pass-9")
    await emu.register(client)
    response = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "impossible",
        "blob": emu.encrypt_entry("five days ago", TODAY - timedelta(days=5), "impossible"),
        "entry_date": (TODAY - timedelta(days=5)).isoformat(),
    })
    # Backdating 30 distinct days in an afternoon must not fast-forward the
    # 30-day progressive-revelation threshold.
    assert response.status_code == 422
    assert "before this account" in response.json()["detail"]
