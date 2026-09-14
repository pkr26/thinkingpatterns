"""Account API: ciphertext-only export, hard delete cascade."""

from __future__ import annotations

from datetime import date

from sqlalchemy import func, select

from app.models import Entry, Insight, User
from tests.helpers import ClientEmulator

TODAY = date.today()  # server clock decides "future"; keep tests relative to it


async def seed(client, emu, days=32):
    from tests.helpers import daterange

    # Historical corpora are legitimate — but only after aging the account,
    # which is exactly what a real N-day user has.
    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, TODAY):
        await emu.create_entry(client, "walked and felt calm", day,
                               client_entry_id=f"c-{day.isoformat()}")
    await emu.recompute(client)


async def test_export_contains_ciphertext_only(client, app):
    emu = ClientEmulator("exporter", "p")
    await emu.register(client)
    await seed(client, emu)

    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200
    bundle = response.json()

    assert bundle["version"] == 1
    assert bundle["username"] == "exporter"
    assert bundle["user_id"] == emu.user_id  # AAD binding needs it to decrypt
    assert bundle["salt"] == emu.salt_b64
    assert len(bundle["entries"]) == 32
    assert len(bundle["insights"]) >= 1

    # The server hands back exactly what it stored — the client can decrypt.
    import base64
    import json
    from app.security import crypto
    first = bundle["entries"][0]
    payload = json.loads(crypto.decrypt(
        emu.data_key,
        base64.b64decode(first["blob"]),
        crypto.build_aad("entry", emu.user_id, first["client_entry_id"]),
    ))
    assert payload["text"] == "walked and felt calm"

    # No plaintext anywhere in the bundle bytes.
    assert b"walked and felt calm" not in response.content


async def test_delete_account_hard_cascades(client, app):
    emu = ClientEmulator("deleter", "p")
    await emu.register(client)
    other = ClientEmulator("survivor", "p")
    await other.register(client)
    await other.create_entry(client, "other user data", TODAY, client_entry_id="keep-me")
    await seed(client, emu)

    # Deletion requires the password proof — a stolen bearer token alone
    # must not be able to destroy a journal.
    response = await client.request("DELETE", "/api/account", headers=emu.headers, json={"verifier": emu.auth_key_b64})
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
    refused = await client.request("DELETE", "/api/account", headers=emu.headers, json={"verifier": wrong})
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


async def test_llm_consent_records_timestamp_and_disclosure(client, monkeypatch):
    """GDPR Art. 7: enabling writes the record (timestamp + disclosure
    version), disabling clears it, re-enabling refreshes it."""
    from datetime import datetime, timezone

    from app.api import account as account_api

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
        "enabled": False, "llm_consent_at": None, "llm_consent_disclosure": None,
    }

    t1 = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(account_api, "utcnow", lambda: t1)
    on = await put(True)
    assert on.status_code == 200
    assert on.json()["enabled"] is True
    assert datetime.fromisoformat(on.json()["llm_consent_at"]) == t1
    assert on.json()["llm_consent_disclosure"] == account_api.LLM_DISCLOSURE_VERSION == "v1"

    # The read path reports the same record (the client toggle reflects it).
    got = await client.get("/api/account/llm-consent", headers=emu.headers)
    assert datetime.fromisoformat(got.json()["llm_consent_at"]) == t1
    assert got.json()["llm_consent_disclosure"] == "v1"

    # Withdrawal clears both fields — no stale consent claim on the row.
    off = await put(False)
    assert off.json() == {
        "enabled": False, "llm_consent_at": None, "llm_consent_disclosure": None,
    }

    # Re-enabling records a FRESH timestamp, not the resurrected old one.
    t2 = datetime(2026, 9, 9, 9, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(account_api, "utcnow", lambda: t2)
    on2 = await put(True)
    assert datetime.fromisoformat(on2.json()["llm_consent_at"]) == t2 > t1
    assert on2.json()["llm_consent_disclosure"] == "v1"


async def test_export_bundle_carries_the_consent_record(client, monkeypatch):
    """The user section of the export bundle shows the same Art. 7 record."""
    from datetime import datetime, timezone

    from app.api import account as account_api

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
