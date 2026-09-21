"""Coverage hardening for branches the main suites leave cold.

Every test here pins a behavior that already exists (middleware edges,
quota counters, decode failure paths, commit-race 409s, malformed decrypted
payloads) — they close the gaps mutation testing would otherwise hide in.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
from datetime import date

import pytest
from unittest.mock import MagicMock
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import EVICTION_BATCH, FixedWindowCounter, MAX_TRACKED_KEYS, client_key
from app.config import _bool_env
from app.security import crypto
from app.security.tokens import TokenError, _b64url_encode, verify_token
from app.middleware import HardeningMiddleware
from tests.helpers import ClientEmulator, daterange


# ---------------------------------------------------------------------------
# middleware: raw ASGI edges the HTTP-level tests cannot express
# ---------------------------------------------------------------------------


class _Sentinel(Exception):
    pass


def _http_scope(headers: list[tuple[bytes, bytes]], method: str = "POST") -> dict:
    return {
        "type": "http",
        "asgi": {"version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "path": "/x",
        "headers": headers,
    }


async def _call_asgi(app, scope, incoming: list[dict]) -> list[dict]:
    sent: list[dict] = []
    queue = list(incoming)

    async def receive():
        if queue:
            return queue.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


async def _simple_app(scope, receive, send):
    """Echo app: reads the whole body, answers 200 with a JSON body."""
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.request":
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        else:
            break
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": b"{}"})


async def test_middleware_passes_non_http_scopes_through_untouched():
    seen = {}

    async def inner(scope, receive, send):
        seen["scope"] = scope
        await send({"type": "websocket.accept"})

    wrapped = HardeningMiddleware(inner, max_body_bytes=100)
    sent = await _call_asgi(wrapped, {"type": "websocket", "path": "/ws"}, [])
    assert seen["scope"]["type"] == "websocket"
    assert sent == [{"type": "websocket.accept"}]


async def test_middleware_rejects_non_numeric_content_length():
    wrapped = HardeningMiddleware(_simple_app, max_body_bytes=100)
    for malformed in (b"not-a-number", b"+1", b"1_000", b" 1", b"1 ", b"\xef\xbc\x91"):
        sent = await _call_asgi(wrapped, _http_scope([(b"content-length", malformed)]), [])
        assert sent[0]["status"] == 400
        assert json.loads(sent[1]["body"])["detail"] == "invalid content-length"
        # Even middleware-generated errors carry the security headers.
        header_names = {name for name, _ in sent[0]["headers"]}
        assert b"cache-control" in header_names


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"0"), (b"content-length", b"10")],
        [(b"content-length", b"10"), (b"content-length", b"0")],
        # Reject even equal duplicates: different intermediaries normalize
        # these differently, so the JSON API keeps one unambiguous framing.
        [(b"content-length", b"0"), (b"content-length", b"0")],
    ],
)
async def test_middleware_rejects_ambiguous_message_framing_before_routing(headers):
    called = False

    async def app(scope, receive, send):
        nonlocal called
        called = True

    wrapped = HardeningMiddleware(app, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope(headers),
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    assert called is False
    assert sent[0]["status"] == 400
    assert json.loads(sent[1]["body"]) == {
        "detail": "invalid content-length",
        "code": "bad_request",
    }


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"0"), (b"transfer-encoding", b"chunked")],
        [(b"transfer-encoding", b"gzip, chunked")],
        [(b"transfer-encoding", b"chunked"), (b"transfer-encoding", b"chunked")],
    ],
)
async def test_middleware_rejects_ambiguous_transfer_encoding_before_routing(headers):
    called = False

    async def app(scope, receive, send):
        nonlocal called
        called = True

    wrapped = HardeningMiddleware(app, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope(headers),
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    assert called is False
    assert sent[0]["status"] == 400
    assert json.loads(sent[1]["body"]) == {
        "detail": "ambiguous request framing",
        "code": "bad_request",
    }


async def test_middleware_accepts_normalized_chunked_body():
    wrapped = HardeningMiddleware(_simple_app, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope([(b"transfer-encoding", b"chunked")]),
        [{"type": "http.request", "body": b"ok", "more_body": False}],
    )
    assert sent[0]["status"] == 200


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
async def test_middleware_caps_unframed_bodies_for_every_http_method(method):
    """HTTP/2 bodies need not carry Content-Length or Transfer-Encoding."""
    called = False

    async def app(scope, receive, send):
        nonlocal called
        called = True

    wrapped = HardeningMiddleware(app, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope([], method=method),
        [{"type": "http.request", "body": b"x" * 11, "more_body": False}],
    )
    assert called is False
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["code"] == "payload_too_large"


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
async def test_middleware_replays_legitimate_empty_bodies_for_safe_methods(method):
    received: list[dict] = []

    async def app(scope, receive, send):
        received.append(await receive())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    wrapped = HardeningMiddleware(app, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope([], method=method),
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    assert sent[0]["status"] == 200
    assert received == [{"type": "http.request", "body": b"", "more_body": False}]


async def test_middleware_converts_streamed_overflow_into_413():
    """Body overflowed while streaming: the app sees a disconnect; if it
    never manages to answer, the middleware produces the 413 itself."""

    async def silent_app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break  # saw the converted disconnect; gives up silently

    wrapped = HardeningMiddleware(silent_app, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope([]),
        [
            {"type": "http.request", "body": b"a" * 6, "more_body": True},
            {"type": "http.request", "body": b"b" * 6, "more_body": False},
        ],
    )
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["detail"] == "request body too large"


async def test_middleware_rejects_before_a_responding_app_can_win_after_overflow():
    wrapped = HardeningMiddleware(_simple_app, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope([]),
        [
            {"type": "http.request", "body": b"a" * 6, "more_body": True},
            {"type": "http.request", "body": b"b" * 6, "more_body": False},
        ],
    )
    # The middleware drains and validates the complete request before the
    # app is called, so an app cannot turn an oversized chunked body into a
    # successful response after seeing an artificial disconnect.
    assert sent[0]["status"] == 413
    header_names = {name for name, _ in sent[0]["headers"]}
    assert b"x-frame-options" in header_names


async def test_middleware_rejects_chunked_body_even_when_app_never_reads_it():
    """Body-ignoring routes used to bypass the streaming-only counter."""

    called = False

    async def ignores_body(scope, receive, send):
        nonlocal called
        called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    wrapped = HardeningMiddleware(ignores_body, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope([]),
        [
            {"type": "http.request", "body": b"a" * 6, "more_body": True},
            {"type": "http.request", "body": b"b" * 6, "more_body": False},
        ],
    )
    assert called is False
    assert sent[0]["status"] == 413


async def test_middleware_times_out_an_incomplete_body_before_routing():
    """Pre-dispatch buffering must not turn a slowloris into an endless task."""
    called = False

    async def unreachable(scope, receive, send):
        nonlocal called
        called = True

    async def stalled_receive():
        # The outer wait_for below keeps this regression test bounded if the
        # middleware timeout is removed by a future change.
        await asyncio.sleep(1)
        return {"type": "http.request", "body": b"x", "more_body": True}

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    wrapped = HardeningMiddleware(unreachable, max_body_bytes=10, body_read_timeout_seconds=0.01)
    await asyncio.wait_for(wrapped(_http_scope([]), stalled_receive, send), timeout=0.2)
    assert called is False
    assert sent[0]["status"] == 408
    assert json.loads(sent[1]["body"]) == {
        "detail": "request body timed out",
        "code": "request_timeout",
    }


async def test_middleware_maps_recursion_error_to_400():
    async def exploding(scope, receive, send):
        raise RecursionError("json too deep")

    wrapped = HardeningMiddleware(exploding, max_body_bytes=100)
    sent = await _call_asgi(wrapped, _http_scope([]), [])
    assert sent[0]["status"] == 400
    assert json.loads(sent[1]["body"])["detail"] == "request body too deeply nested"


async def test_middleware_recursion_error_after_overflow_is_413():
    async def overflow_then_explode(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
        raise RecursionError("too deep after overflow")

    wrapped = HardeningMiddleware(overflow_then_explode, max_body_bytes=4)
    sent = await _call_asgi(
        wrapped,
        _http_scope([]),
        [{"type": "http.request", "body": b"toolarge", "more_body": False}],
    )
    assert sent[0]["status"] == 413


async def test_middleware_overflow_disconnect_surfaces_as_413_not_500():
    async def disconnects(scope, receive, send):
        message = await receive()
        assert message["type"] == "http.disconnect"  # overflow was converted
        raise OSError("client disconnected")

    wrapped = HardeningMiddleware(disconnects, max_body_bytes=4)
    sent = await _call_asgi(
        wrapped,
        _http_scope([]),
        [{"type": "http.request", "body": b"toolarge", "more_body": False}],
    )
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["detail"] == "request body too large"


async def test_middleware_unhandled_exception_is_headered_500():
    async def exploding(scope, receive, send):
        raise RuntimeError("boom with internals")

    wrapped = HardeningMiddleware(exploding, max_body_bytes=100)
    sent = await _call_asgi(wrapped, _http_scope([], method="GET"), [])
    assert sent[0]["status"] == 500
    assert json.loads(sent[1]["body"])["detail"] == "internal server error"
    body_text = b"".join(m.get("body", b"") for m in sent).decode()
    assert "boom with internals" not in body_text


# ---------------------------------------------------------------------------
# tokens: valid signature over a non-JSON body
# ---------------------------------------------------------------------------


def test_verify_token_rejects_signed_but_non_json_body():
    body = _b64url_encode(b"definitely not json")
    signature = _b64url_encode(hmac.new(b"secret", body.encode("ascii"), hashlib.sha256).digest())
    with pytest.raises(TokenError, match="^malformed payload$"):
        verify_token(f"{body}.{signature}", "secret")


# ---------------------------------------------------------------------------
# cache: stale eviction under the tracked-key cap; client identity fallback
# ---------------------------------------------------------------------------


def test_counter_evicts_stale_windows_when_capped():
    counter = FixedWindowCounter()
    for i in range(MAX_TRACKED_KEYS):
        counter.hit(f"k{i}", window_seconds=1, now=1_000.0)
    # All existing windows are stale by now=2_000; crossing the cap must
    # reclaim them rather than evicting the fresh key.
    result = counter.hit("fresh-key", window_seconds=60, now=2_000.0)
    assert result.count == 1
    assert len(counter._hits) <= MAX_TRACKED_KEYS
    assert "fresh-key" in counter._hits


def test_counter_evicts_oldest_when_nothing_is_stale():
    counter = FixedWindowCounter()
    for i in range(MAX_TRACKED_KEYS):
        counter.hit(f"k{i}", window_seconds=10_000, now=1_000.0)
    result = counter.hit("newcomer", window_seconds=10_000, now=1_001.0)
    assert result.count == 1
    # Nothing is stale, so eviction clears a whole BATCH of active keys by
    # (count, window_start) down to MAX - EVICTION_BATCH. Every pre-existing
    # key ties on both, so WHICH ones go is unspecified — but the newcomer's
    # later window start ranks it after all of them, so it always survives.
    assert len(counter._hits) == MAX_TRACKED_KEYS - EVICTION_BATCH
    assert "newcomer" in counter._hits


def test_client_key_falls_back_when_request_has_no_client():
    from starlette.requests import Request

    scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
    request = Request(scope)
    assert client_key(request) == "unknown-client"


# ---------------------------------------------------------------------------
# config / db: environment parsing branch and engine selection
# ---------------------------------------------------------------------------


def test_bool_env_defaults_when_unset_and_parses_when_set(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_COVERAGE_PROBE", raising=False)
    assert _bool_env("MINDPATTERN_COVERAGE_PROBE", True) is True
    assert _bool_env("MINDPATTERN_COVERAGE_PROBE", False) is False
    monkeypatch.setenv("MINDPATTERN_COVERAGE_PROBE", "1")
    assert _bool_env("MINDPATTERN_COVERAGE_PROBE", False) is True
    monkeypatch.setenv("MINDPATTERN_COVERAGE_PROBE", "0")
    assert _bool_env("MINDPATTERN_COVERAGE_PROBE", True) is False


def test_build_engine_selects_pooling_by_database_kind(monkeypatch):
    import app.db as db_module

    calls: list[tuple[tuple, dict]] = []

    real_create_engine = db_module.create_async_engine

    def fake_create_engine(url, **kwargs):
        calls.append(((url,), kwargs))
        # Real engine for sqlite (that branch registers a connect-event
        # listener, which a MagicMock cannot accept); the postgres branch
        # registers nothing, and building a real asyncpg engine would need
        # the driver installed.
        if url.startswith("sqlite"):
            return real_create_engine(url, **kwargs)
        return MagicMock()

    monkeypatch.setattr(db_module, "create_async_engine", fake_create_engine)
    db_module.build_engine("postgresql+asyncpg://u:p@host:5432/db")
    # Pool sizing is explicit and env-fed (MINDPATTERN_DB_POOL_*) — the
    # deployment tunes it instead of inheriting SQLAlchemy's defaults.
    # server_settings timeouts (2026-09-21 audit B-3): asyncpg wants
    # STRING milliseconds; statement_timeout bounds each query and
    # idle_in_transaction_session_timeout is the vacuum guard.
    assert calls[0][1] == {
        "echo": False,
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 10,
        "pool_timeout": 30,
        "connect_args": {
            "server_settings": {
                "statement_timeout": "30000",
                "idle_in_transaction_session_timeout": "300000",
            }
        },
    }
    db_module.build_engine(
        "postgresql+asyncpg://u:p@host:5432/db",
        pool_size=9,
        max_overflow=2,
        pool_timeout=7,
        statement_timeout_ms=1234,
        idle_in_transaction_timeout_ms=5678,
    )
    assert calls[1][1]["pool_size"] == 9
    assert calls[1][1]["max_overflow"] == 2
    assert calls[1][1]["pool_timeout"] == 7
    assert calls[1][1]["connect_args"]["server_settings"]["statement_timeout"] == "1234"
    assert (
        calls[1][1]["connect_args"]["server_settings"]["idle_in_transaction_session_timeout"]
        == "5678"
    )
    db_module.build_engine("sqlite+aiosqlite://")
    # SQLite: StaticPool, and NO pool sizing args (they'd break/mislead the
    # single shared in-memory connection).
    assert "poolclass" in calls[2][1]
    assert "pool_size" not in calls[2][1] and "max_overflow" not in calls[2][1]
    assert calls[2][1]["connect_args"] == {"check_same_thread": False}
    assert calls[2][1]["echo"] is False  # no SQL echo in either branch


# ---------------------------------------------------------------------------
# entries / auth / account API: decode failures, byte quotas, commit races
# ---------------------------------------------------------------------------


async def test_create_entry_rejects_non_base64_blob(client):
    emu = ClientEmulator("quota-user", "pw-quota-test")
    await emu.register(client)
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-bad-b64",
            "blob": "!!!not base64!!!",
            "entry_date": date.today().isoformat(),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "blob must be base64"


async def test_create_entry_enforces_total_byte_quota(client, app):
    emu = ClientEmulator("byte-quota", "pw-byte-quota")
    await emu.register(client)
    # A single entry larger than the (lowered) account byte cap.
    app.state.settings.max_user_blob_bytes = 64
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-huge",
            "blob": emu.encrypt_entry("x" * 400, date.today(), "e-huge"),
            "entry_date": date.today().isoformat(),
        },
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "storage quota reached (total size)"


async def test_create_entry_commit_race_returns_409(client, monkeypatch):
    emu = ClientEmulator("race-entries", "pw-race-entries")
    await emu.register(client)

    from sqlalchemy.exc import IntegrityError

    async def failing_commit(self):
        raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))

    monkeypatch.setattr(AsyncSession, "commit", failing_commit)
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-race",
            "blob": emu.encrypt_entry("race", date.today(), "e-race"),
            "entry_date": date.today().isoformat(),
        },
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "entry already exists"


async def test_register_commit_race_returns_409(client, monkeypatch):
    from sqlalchemy.exc import IntegrityError

    async def failing_commit(self):
        raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))

    monkeypatch.setattr(AsyncSession, "commit", failing_commit)
    emu = ClientEmulator("race-register", "pw-race-register")
    response = await client.post(
        "/api/auth/register",
        json={"username": emu.username, "salt": emu.salt_b64, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "username already taken"


async def test_login_with_undecodable_verifier_is_invalid_credentials(client):
    emu = ClientEmulator("badverifier", "pw-bad-verifier")
    await emu.register(client)
    response = await client.post(
        "/api/auth/login", json={"username": emu.username, "verifier": "%%%not-base64%%%"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid credentials"


async def test_delete_account_with_undecodable_verifier_is_403(client):
    # Wrong verifier on an AUTHENTICATED request is 403 verification_failed:
    # 401 tells clients "session expired, re-login", which is wrong here.
    emu = ClientEmulator("delbad", "pw-del-bad")
    await emu.register(client)
    response = await client.request(
        "DELETE", "/api/account", headers=emu.headers, json={"verifier": "%%%not-base64%%%"}
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "invalid credentials", "code": "verification_failed"}


async def test_delete_account_for_deactivated_account_is_404(client, app):
    """The 404-on-deactivated guard is defense-in-depth: require_user already
    401s deactivated accounts at the door, so this exercises the handler
    directly with a deactivated user object."""
    from fastapi import HTTPException
    from sqlalchemy import update
    from starlette.requests import Request

    from app.api.account import delete_account
    from app.models import User
    from app.schemas import AccountDeleteRequest

    emu = ClientEmulator("deactivated", "pw-deactivated")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        await session.execute(update(User).where(User.id == emu.user_id).values(is_active=False))
        await session.commit()
        user = await session.get(User, emu.user_id)
        assert user is not None and not user.is_active

    request = Request(
        {"type": "http", "headers": [], "method": "DELETE", "path": "/api/account", "app": app}
    )
    with pytest.raises(HTTPException) as excinfo:
        await delete_account(
            body=AccountDeleteRequest(verifier=emu.auth_key_b64),
            request=request,
            user=user,
            session=session,
        )
    assert excinfo.value.status_code == 404
    assert excinfo.value.detail == "account not found"


# ---------------------------------------------------------------------------
# insights: hostile decrypted payloads and wrong-key processing sessions
# ---------------------------------------------------------------------------


async def _seed_threshold_corpus(client, emu) -> None:
    from tests.test_insights_api import seed_corpus

    await seed_corpus(client, emu, days=35)


async def test_recompute_rejects_non_string_text(client):
    emu = ClientEmulator("badtext", "pw-bad-text")
    await emu.register(client)
    await _seed_threshold_corpus(client, emu)

    # One entry whose *plaintext* (validly encrypted) has text as a number.
    entry_id = "e-bad-text"
    payload = json.dumps(
        {"v": 1, "text": 42, "sentiment": None, "created_at": date.today().isoformat()}
    ).encode()
    aad = crypto.build_aad("entry", emu.user_id or "", entry_id)
    blob = base64.b64encode(crypto.encrypt(emu.data_key, payload, aad)).decode()
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={"client_entry_id": entry_id, "blob": blob, "entry_date": date.today().isoformat()},
    )
    assert response.status_code == 201

    token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert recompute.status_code == 400
    assert recompute.json()["detail"] == "entry payload malformed"


async def test_recompute_rejects_non_numeric_sentiment(client):
    emu = ClientEmulator("badsent", "pw-bad-sent")
    await emu.register(client)
    await _seed_threshold_corpus(client, emu)

    entry_id = "e-bad-sentiment"
    payload = json.dumps(
        {"v": 1, "text": "fine day", "sentiment": "high", "created_at": date.today().isoformat()}
    ).encode()
    aad = crypto.build_aad("entry", emu.user_id or "", entry_id)
    blob = base64.b64encode(crypto.encrypt(emu.data_key, payload, aad)).decode()
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={"client_entry_id": entry_id, "blob": blob, "entry_date": date.today().isoformat()},
    )
    assert response.status_code == 201

    token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert recompute.status_code == 400
    assert recompute.json()["detail"] == "entry payload malformed"


async def test_recompute_with_wrong_data_key_is_tampering(client):
    emu = ClientEmulator("wrongkey", "pw-wrong-key")
    await emu.register(client)
    await _seed_threshold_corpus(client, emu)

    # Open the processing session with a key that did NOT encrypt the entries.
    stranger_key = os.urandom(32)
    opened = await client.post(
        "/api/processing/sessions",
        headers=emu.headers,
        json={"data_key": base64.b64encode(stranger_key).decode()},
    )
    assert opened.status_code == 201
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": opened.json()["session_token"]},
    )
    assert recompute.status_code == 400
    assert recompute.json()["detail"] == "entry blob failed authentication"
