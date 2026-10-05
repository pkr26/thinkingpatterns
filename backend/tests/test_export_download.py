"""Native-download tickets preserve authorization and bounded streaming."""

import json

import pytest
from sqlalchemy import update

from app.models import User
from app.security import tokens
from app.security.export_ticket import EXPORT_TICKET_TTL, ExportTicketStore
from tests.helpers import ClientEmulator


async def issue(client, emu):
    response = await client.post("/api/v1/account/export-ticket", headers=emu.headers)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["expires_in"] == 60
    return response.json()["ticket"]


async def download(client, ticket):
    return await client.post(
        "/api/v1/account/export-download",
        content=f"ticket={ticket}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )


async def test_native_export_is_single_use_ciphertext_attachment(client):
    emu = ClientEmulator("downloadticket", "p")
    await emu.register(client)
    from datetime import date

    await emu.create_entry(client, "private plaintext must stay encrypted", date.today())
    ticket = await issue(client, emu)
    response = await download(client, ticket)
    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="fathom-export.json"'
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("application/json")
    assert "content-length" not in response.headers
    assert response.json()["user_id"] == emu.user_id
    assert len(response.json()["entries"]) == 1
    assert "private plaintext must stay encrypted" not in response.text
    assert (await download(client, ticket)).status_code == 401
    assert (
        await client.get("/api/v1/account/export", headers={"Authorization": f"Bearer {ticket}"})
    ).status_code == 401


@pytest.mark.parametrize("mutation", ["epoch", "inactive", "role", "logout", "secret"])
async def test_export_ticket_rechecks_issuing_session(client, app, mutation):
    emu = ClientEmulator("downloadrevoke", "p")
    await emu.register(client)
    ticket = await issue(client, emu)
    if mutation == "logout":
        response = await client.post("/api/v1/auth/logout", headers=emu.headers)
        assert response.status_code == 204
    elif mutation == "secret":
        app.state.settings.token_secret = "changed-secret-for-test"
    else:
        values = {
            "epoch": {"token_epoch": 99},
            "inactive": {"is_active": False},
            "role": {"role": "therapist"},
        }[mutation]
        async with app.state.sessionmaker() as session:
            await session.execute(update(User).where(User.id == emu.user_id).values(**values))
            await session.commit()
    assert (await download(client, ticket)).status_code == 401
    assert (await download(client, ticket)).status_code == 401


async def test_ticket_expiry_and_bearer_expiry(client, app, monkeypatch):
    emu = ClientEmulator("downloadexpire", "p")
    await emu.register(client)
    ticket = await issue(client, emu)
    import app.security.export_ticket as module

    original = module.time.monotonic
    monkeypatch.setattr(module.time, "monotonic", lambda: original() + EXPORT_TICKET_TTL + 1)
    assert (await download(client, ticket)).status_code == 401


@pytest.mark.parametrize(
    "body,content_type,status",
    [
        ("ticket=x", "application/x-www-form-urlencoded", 422),
        ("ticket=" + "a" * 43 + "&ticket=" + "a" * 43, "application/x-www-form-urlencoded", 422),
        ("ticket=" + "a" * 43 + "&extra=x", "application/x-www-form-urlencoded", 422),
        ("ticket=" + "a" * 43, "application/json", 422),
        ("ticket=" + "a" * 200, "application/x-www-form-urlencoded", 413),
    ],
)
async def test_native_form_is_small_and_unambiguous(client, body, content_type, status):
    response = await client.post(
        "/api/v1/account/export-download", content=body, headers={"content-type": content_type}
    )
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"


async def test_ticket_never_accepted_in_query_or_get(client):
    emu = ClientEmulator("downloadquery", "p")
    await emu.register(client)
    ticket = await issue(client, emu)
    response = await client.post(
        f"/api/v1/account/export-download?ticket={ticket}",
        content=f"ticket={ticket}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422
    assert (await client.get(f"/api/v1/account/export-download?ticket={ticket}")).status_code == 405
    assert (await download(client, ticket)).status_code == 200


def test_ticket_store_is_bounded_and_retains_no_capability(monkeypatch):
    import app.security.export_ticket as module

    monkeypatch.setattr(module, "EXPORT_TICKET_CAPACITY", 3)
    store = ExportTicketStore()
    import time

    args = dict(
        token_epoch=1, token_jti="jti", token_expires=time.time() + 600, secret_fingerprint="digest"
    )
    first = store.issue(user_id="one", **args)
    second = store.issue(user_id="one", **args)
    third = store.issue(user_id="one", **args)
    assert store.consume(first) is None
    assert second not in repr(store._tickets)
    store.issue(user_id="two", **args)
    with pytest.raises(RuntimeError):
        store.issue(user_id="three", **args)
    assert store.consume(third).user_id == "one"
    assert store.consume(third) is None
    store.clear()
    assert not store._tickets


async def test_ticket_handoff_streams_beyond_supported_quota_without_collecting_body(
    client, app, monkeypatch
):
    """Exercise the handoff with >256MiB, holding only a reused 1MiB chunk.

    The existing exporter separately pins byte-bounded DB pages; this pins
    that the new route delegates its iterator without buffering or a cap.
    """
    from starlette.requests import Request
    from starlette.responses import StreamingResponse

    from app.api import account

    emu = ClientEmulator("downloadstream", "p")
    await emu.register(client)
    ticket = await issue(client, emu)
    emitted = 0
    chunk = b"x" * (1024 * 1024)

    async def stream():
        nonlocal emitted
        for _ in range(350):
            emitted += 1
            yield chunk

    async def exporter(request, user, session):
        assert user.id == emu.user_id
        assert request.state.mindpattern_token_jti
        return StreamingResponse(stream(), media_type="application/json")

    monkeypatch.setattr(account, "export_account", exporter)
    body = f"ticket={ticket}".encode()

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/account/export-download",
            "query_string": b"",
            "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
            "app": app,
        },
        receive,
    )
    async with app.state.sessionmaker() as session:
        response = await account.download_export(request, session)
        assert emitted == 0
        size = 0
        async for piece in response.body_iterator:
            size += len(piece)
        assert size == 350 * 1024 * 1024
        assert emitted == 350


def test_ticket_cannot_outlive_issuer_bearer(monkeypatch):
    import time

    import app.security.export_ticket as module

    store = ExportTicketStore()
    now = time.time()
    ticket = store.issue(
        user_id="one",
        token_epoch=1,
        token_jti="jti",
        token_expires=now + 1,
        secret_fingerprint="digest",
    )
    monkeypatch.setattr(module.time, "time", lambda: now + 2)
    assert store.consume(ticket) is None
