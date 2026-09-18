"""Account API: ciphertext-only export, hard delete cascade."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import func, select, update

from app.models import Entry, Insight, User
from tests.helpers import ClientEmulator

TODAY = date.today()  # server clock decides "future"; keep tests relative to it


async def seed(client, emu, days=32):
    from tests.helpers import daterange

    # Historical corpora are legitimate — but only after aging the account,
    # which is exactly what a real N-day user has.
    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, TODAY):
        await emu.create_entry(
            client, "walked and felt calm", day, client_entry_id=f"c-{day.isoformat()}"
        )
    await emu.recompute(client)


async def test_export_contains_ciphertext_only(client, app):
    emu = ClientEmulator("exporter", "p")
    await emu.register(client)
    await seed(client, emu)

    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200
    bundle = response.json()

    assert bundle["version"] == 1
    # 2026-09-16 (finding H2): the cleartext username is gone from the
    # bundle — it was a free account marker for anyone holding the file.
    assert "username" not in bundle
    assert bundle["user_id"] == emu.user_id  # AAD binding needs it to decrypt
    assert bundle["salt"] == emu.salt_b64
    assert len(bundle["entries"]) == 32
    assert len(bundle["insights"]) >= 1

    # The server hands back exactly what it stored — the client can decrypt.
    import base64
    import json
    from app.security import crypto

    first = bundle["entries"][0]
    payload = json.loads(
        crypto.decrypt(
            emu.data_key,
            base64.b64decode(first["blob"]),
            crypto.build_aad("entry", emu.user_id, first["client_entry_id"]),
        )
    )
    assert payload["text"] == "walked and felt calm"

    # No plaintext anywhere in the bundle bytes.
    assert b"walked and felt calm" not in response.content


async def test_export_byte_pages_are_bounded_without_truncating_bundle(client, app, monkeypatch):
    """Export streams every row even when its short-lived blob page fills.

    Keep the fixture small by reducing the page budget, then observe the
    helper's selected metadata prefixes.  This catches a regression back to
    fetching a fixed 100 opaque blobs before a streaming yield.
    """
    from app.api import account as account_api

    emu = ClientEmulator("exportpages", "p")
    await emu.register(client)
    blob = b"x" * 40
    base = datetime.now(timezone.utc) - timedelta(days=1)
    async with app.state.sessionmaker() as session:
        for index in range(3):
            session.add(
                Entry(
                    user_id=emu.user_id,
                    client_entry_id=f"export-page-entry-{index}",
                    blob=blob,
                    entry_date=TODAY,
                    received_at=base + timedelta(microseconds=index),
                )
            )
            session.add(
                Insight(
                    user_id=emu.user_id,
                    kind=f"export-page-insight-{index}",
                    for_date=None,
                    blob=blob,
                    created_at=base + timedelta(microseconds=index),
                )
            )
        await session.commit()

    monkeypatch.setattr(account_api, "EXPORT_PAGE_BLOB_BYTES", 70)
    take_page = account_api._take_export_metadata_page
    selected_page_bytes: list[int] = []

    def observe_page(rows):
        selected = take_page(rows)
        selected_page_bytes.append(sum(int(row[-1] or 0) for row in selected))
        return selected

    monkeypatch.setattr(account_api, "_take_export_metadata_page", observe_page)
    response = await client.get("/api/account/export", headers=emu.headers)

    assert response.status_code == 200
    bundle = response.json()
    assert [entry["client_entry_id"] for entry in bundle["entries"]] == [
        "export-page-entry-0",
        "export-page-entry-1",
        "export-page-entry-2",
    ]
    assert [insight["kind"] for insight in bundle["insights"]] == [
        "export-page-insight-0",
        "export-page-insight-1",
        "export-page-insight-2",
    ]
    assert selected_page_bytes
    assert all(page_bytes <= 70 for page_bytes in selected_page_bytes)


async def test_export_entry_cursor_survives_edit_between_short_pages(client, app, monkeypatch):
    """The internal export cursor must use immutable fields.

    With the historical entry_date keyset, moving the first emitted row
    later duplicated it and moving the next row earlier omitted it.  Force
    one row per export page, mutate both directions between pages, then
    prove every stable client entry id appears exactly once.
    """

    from app.api import account as account_api

    emu = ClientEmulator("exportcursor", "p")
    await emu.register(client)
    base = datetime.now(timezone.utc) - timedelta(days=1)
    rows = [
        Entry(
            id="export-cursor-a",
            user_id=emu.user_id,
            client_entry_id="export-cursor-a",
            blob=b"a" * 32,
            entry_date=TODAY - timedelta(days=1),
            received_at=base,
        ),
        Entry(
            id="export-cursor-b",
            user_id=emu.user_id,
            client_entry_id="export-cursor-b",
            blob=b"b" * 32,
            entry_date=TODAY,
            received_at=base + timedelta(microseconds=1),
        ),
        Entry(
            id="export-cursor-c",
            user_id=emu.user_id,
            client_entry_id="export-cursor-c",
            blob=b"c" * 32,
            entry_date=TODAY + timedelta(days=1),
            received_at=base + timedelta(microseconds=2),
        ),
    ]
    async with app.state.sessionmaker() as session:
        session.add_all(rows)
        await session.commit()

    monkeypatch.setattr(account_api, "EXPORT_METADATA_PAGE_SIZE", 1)
    async with app.state.sessionmaker() as session:
        fresh = await session.get(User, emu.user_id)
        assert fresh is not None
        response = await account_api.export_account(
            SimpleNamespace(app=app), user=fresh, session=session
        )

    chunks: list[str] = []
    first_entry_marker = '"client_entry_id": "export-cursor-a"'
    while True:
        chunk = await anext(response.body_iterator)
        chunks.append(chunk)
        if first_entry_marker in chunk:
            break

    # Both updates are legitimate entry-date edits. The first would move
    # after an entry_date cursor (duplicate); the second before it (omit).
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(Entry)
            .where(Entry.id == "export-cursor-a")
            .values(entry_date=TODAY + timedelta(days=3))
        )
        await session.execute(
            update(Entry)
            .where(Entry.id == "export-cursor-b")
            .values(entry_date=TODAY - timedelta(days=2))
        )
        await session.commit()

    try:
        while True:
            chunks.append(await anext(response.body_iterator))
    except StopAsyncIteration:
        pass
    bundle = json.loads("".join(chunks))
    assert [entry["client_entry_id"] for entry in bundle["entries"]] == [
        "export-cursor-a",
        "export-cursor-b",
        "export-cursor-c",
    ]


async def test_delete_account_hard_cascades(client, app):
    emu = ClientEmulator("deleter", "p")
    await emu.register(client)
    other = ClientEmulator("survivor", "p")
    await other.register(client)
    await other.create_entry(client, "other user data", TODAY, client_entry_id="keep-me")
    await seed(client, emu)

    # Deletion requires the password proof — a stolen bearer token alone
    # must not be able to destroy a journal.
    response = await client.request(
        "DELETE", "/api/account", headers=emu.headers, json={"verifier": emu.auth_key_b64}
    )
    assert response.status_code == 204

    async with app.state.sessionmaker() as session:
        counts = {}
        for model in (User, Entry, Insight):
            rows = await session.execute(select(func.count()).select_from(model))
            counts[model.__tablename__] = rows.scalar_one()
    assert counts == {"users": 1, "entries": 1, "insights": 0}, counts

    # Old token no longer authenticates (user row is gone).
    stale = await client.get("/api/entries", headers=emu.headers)
    assert stale.status_code == 401

    # Other user untouched.
    survivor_entries = await client.get("/api/entries", headers=other.headers)
    assert len(survivor_entries.json()) == 1


async def test_delete_requires_correct_verifier(client):
    emu = ClientEmulator("proof", "p")
    await emu.register(client)

    import base64 as b64mod

    wrong = b64mod.b64encode(b"\x00" * 32).decode()
    refused = await client.request(
        "DELETE", "/api/account", headers=emu.headers, json={"verifier": wrong}
    )
    # 403 verification_failed: the bearer token is valid; the password proof
    # is not. (401 means "session expired" to clients.)
    assert refused.status_code == 403
    assert refused.json()["detail"] == "invalid credentials"
    assert refused.json()["code"] == "verification_failed"

    # The failed attempt destroyed nothing.
    still_there = await client.get("/api/entries", headers=emu.headers)
    assert still_there.status_code == 200

    assert await emu.delete_account(client) == 204


async def test_delete_purges_processing_session_keys(client, app):
    emu = ClientEmulator("keypurge", "p")
    await emu.register(client)
    await emu.open_processing_session(client)
    assert len(app.state.key_store) == 1

    assert await emu.delete_account(client) == 204
    assert len(app.state.key_store) == 0


async def test_double_delete_fails_cleanly(client):
    emu = ClientEmulator("twice", "p")
    await emu.register(client)
    assert await emu.delete_account(client) == 204
    assert await emu.delete_account(client) == 401


async def test_llm_consent_records_timestamp_and_disclosure(client, monkeypatch, settings):
    """GDPR Art. 7: enabling writes the record (timestamp + disclosure
    version), disabling clears it, re-enabling refreshes it."""
    from datetime import datetime, timezone

    from app.api import account as account_api

    # Consent can only be active for an actually configured processing
    # provider.  The development fixture intentionally has none by default.
    settings.llm_url = "https://llm.example.test/v1"
    emu = ClientEmulator("consentrecord", "p")
    await emu.register(client)

    def put(enabled: bool):
        return client.put(
            "/api/account/llm-consent",
            headers=emu.headers,
            json={"enabled": enabled, "verifier": emu.auth_key_b64},
        )

    # A fresh account has no record at all.
    initial = await client.get("/api/account/llm-consent", headers=emu.headers)
    assert initial.json() == {
        "enabled": False,
        "active_for_current_policy": False,
        "llm_consent_at": None,
        "llm_consent_disclosure": None,
        "llm_consent_policy": None,
    }

    t1 = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(account_api, "utcnow", lambda: t1)
    on = await put(True)
    assert on.status_code == 200
    assert on.json()["enabled"] is True
    assert on.json()["active_for_current_policy"] is True
    assert datetime.fromisoformat(on.json()["llm_consent_at"]) == t1
    assert on.json()["llm_consent_disclosure"] == account_api.LLM_DISCLOSURE_VERSION == "v1"

    # The read path reports the same record (the client toggle reflects it).
    got = await client.get("/api/account/llm-consent", headers=emu.headers)
    assert datetime.fromisoformat(got.json()["llm_consent_at"]) == t1
    assert got.json()["llm_consent_disclosure"] == "v1"
    assert got.json()["active_for_current_policy"] is True

    # Withdrawal clears both fields — no stale consent claim on the row.
    off = await put(False)
    assert off.json() == {
        "enabled": False,
        "active_for_current_policy": False,
        "llm_consent_at": None,
        "llm_consent_disclosure": None,
        "llm_consent_policy": None,
    }

    # Re-enabling records a FRESH timestamp, not the resurrected old one.
    t2 = datetime(2026, 9, 9, 9, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(account_api, "utcnow", lambda: t2)
    on2 = await put(True)
    assert datetime.fromisoformat(on2.json()["llm_consent_at"]) == t2 > t1
    assert on2.json()["llm_consent_disclosure"] == "v1"
    assert on2.json()["active_for_current_policy"] is True


async def test_export_bundle_carries_the_consent_record(client, monkeypatch, settings):
    """The user section of the export bundle shows the same Art. 7 record."""
    from datetime import datetime, timezone

    from app.api import account as account_api

    settings.llm_url = "https://llm.example.test/v1"
    emu = ClientEmulator("consentexport", "p")
    await emu.register(client)
    t1 = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(account_api, "utcnow", lambda: t1)
    on = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert on.status_code == 200

    bundle = (await client.get("/api/account/export", headers=emu.headers)).json()
    assert bundle["llm_consent"] is True
    assert datetime.fromisoformat(bundle["llm_consent_at"]) == t1
    assert bundle["llm_consent_disclosure"] == "v1"
    assert bundle["llm_consent_policy"]
