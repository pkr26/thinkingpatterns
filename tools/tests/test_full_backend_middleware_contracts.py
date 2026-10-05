"""ASGI framing, proxy custody, admission, and published error protocols."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "backend"
SECURITY = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
    b"cache-control": b"no-store",
    b"strict-transport-security": b"max-age=31536000; includeSubDomains",
}


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(BACKEND))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


async def exchange(
    middleware,
    *,
    path="/api/example",
    method="POST",
    headers=(),
    messages=None,
    peer=("127.0.0.1", 443),
    state=None,
):
    incoming = list(
        messages
        if messages is not None
        else [{"type": "http.request", "body": b"", "more_body": False}]
    )
    sent, reads = [], []
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": list(headers),
        "client": peer,
        "state": state if state is not None else {},
    }

    async def receive():
        reads.append(True)
        assert len(reads) <= 5, "body replay must make bounded progress"
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await asyncio.wait_for(middleware(scope, receive, send), timeout=2)
    return scope, sent, len(reads)


def envelope(sent, status, detail, code, *, legacy=True, cors=True):
    assert [message["type"] for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]
    assert sent[0]["status"] == status
    headers = dict(sent[0]["headers"])
    assert {name: headers[name] for name in SECURITY} == SECURITY
    assert headers[b"content-type"] == b"application/json"
    assert (headers.get(b"deprecation") == b"true") is legacy
    if cors:
        assert headers[b"access-control-allow-origin"] == b"https://client.example"
        assert headers[b"access-control-expose-headers"] == b"X-Cursor, Retry-After"
        assert headers[b"vary"] == b"Origin"
    assert json.loads(sent[1]["body"]) == {"detail": detail, "code": code}
    return headers


@pytest.mark.parametrize(
    ("headers", "body", "status", "detail", "code", "read_count"),
    [
        (
            [(b"content-length", b"5")],
            b"12345",
            413,
            "request body too large",
            "payload_too_large",
            0,
        ),
        (
            [(b"Content-Length", b"1"), (b"CONTENT-LENGTH", b"1")],
            b"a",
            400,
            "invalid content-length",
            "bad_request",
            0,
        ),
        (
            [(b"content-length", b"1"), (b"transfer-encoding", b"chunked")],
            b"a",
            400,
            "ambiguous request framing",
            "bad_request",
            0,
        ),
        (
            [(b"transfer-encoding", b"gzip")],
            b"a",
            400,
            "ambiguous request framing",
            "bad_request",
            0,
        ),
        (
            [(b"transfer-encoding", b"chunked"), (b"Transfer-Encoding", b"chunked")],
            b"a",
            400,
            "ambiguous request framing",
            "bad_request",
            0,
        ),
        ([], b"12345", 413, "request body too large", "payload_too_large", 1),
    ]
    + [
        (
            [(b"content-length", value)],
            b"a",
            400,
            "invalid content-length",
            "bad_request",
            0,
        )
        for value in (b"", b"+1", b"-1", b" 1", b"1 ", b"1_0", b"/", b":")
    ],
)
@pytest.mark.asyncio
async def test_framing_refusals_precede_app_dispatch_and_preserve_wire(
    headers, body, status, detail, code, read_count
):
    from app.middleware import HardeningMiddleware

    async def forbidden(*args):
        pytest.fail("refused frame reached application")

    middleware = HardeningMiddleware(
        forbidden,
        4,
        cors_origins=["https://client.example"],
        cors_expose_headers=["X-Cursor", "Retry-After"],
    )
    _, sent, reads = await exchange(
        middleware,
        headers=[*headers, (b"Origin", b"https://client.example")],
        messages=[{"type": "http.request", "body": body}],
    )
    envelope(sent, status, detail, code)
    assert reads == read_count


@pytest.mark.parametrize(
    "path",
    [
        "/api",
        "/api/example",
        "/api/v1/example",
        "/api/v1",
        "/apix",
        "/api/audiobook",
        "/api/audio",
        "/api/v1/audio/transcribe",
    ],
)
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST"])
@pytest.mark.asyncio
async def test_normal_requests_replay_original_body_and_preserve_security_headers(
    path, method
):
    from app.middleware import HardeningMiddleware

    received, tasks = [], set()
    parts = [
        {"type": "http.request", "body": b"12", "more_body": True},
        {"type": "http.request", "body": b"34", "more_body": False},
    ]

    async def app(scope, receive, send):
        assert (asyncio.current_task() in tasks) == (
            path not in {"/healthz", "/readyz"}
        )
        for _ in range(3):
            received.append(await receive())
        await send(
            {
                "type": "http.response.start",
                "status": 201,
                "headers": [(b"Cache-Control", b"private custom")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(app, 4, request_tasks=tasks)
    _, sent, reads = await exchange(
        middleware,
        path=path,
        method=method,
        headers=[(b"transfer-encoding", b"CHUNKED")],
        messages=parts,
    )
    assert received == [*parts, {"type": "http.disconnect"}] and reads == 3
    headers = sent[0]["headers"]
    assert (b"Cache-Control", b"private custom") in headers and (
        b"cache-control",
        b"no-store",
    ) not in headers
    for name, value in SECURITY.items():
        if name != b"cache-control":
            assert (name, value) in headers
    legacy = path == "/api" or (
        path.startswith("/api/") and not path.startswith("/api/v1")
    )
    assert ((b"deprecation", b"true") in headers) == legacy
    assert sent[1]["body"] == b"ok" and not tasks and middleware._body_admitted == 0


@pytest.mark.parametrize(
    ("exception", "status", "detail", "code"),
    [
        (RecursionError, 400, "request body too deeply nested", "bad_request"),
        (RuntimeError, 500, "internal server error", "internal_error"),
    ],
)
@pytest.mark.parametrize("started", [False, True])
@pytest.mark.asyncio
async def test_app_failures_do_not_leak_or_start_a_second_response(
    exception, status, detail, code, started, caplog
):
    from app.middleware import HardeningMiddleware

    observed = []

    async def app(scope, receive, send):
        if started:
            await send({"type": "http.response.start", "status": 200, "headers": []})
        raise exception("sensitive request contents")

    middleware = HardeningMiddleware(
        app,
        4,
        status_observer=observed.append,
        cors_origins=["https://client.example"],
        cors_expose_headers=["X-Cursor", "Retry-After"],
    )
    _, sent, _ = await exchange(
        middleware, headers=[(b"origin", b"https://client.example")]
    )
    if started:
        assert len(sent) == 1 and sent[0]["status"] == 200 and not observed
    else:
        envelope(sent, status, detail, code)
        assert observed == [status]
    if exception is RuntimeError:
        assert caplog.messages[-1] == "unhandled request failure"
        assert caplog.records[-1].name == "mindpattern"
    assert "sensitive" not in str(sent) and "sensitive" not in caplog.text


@pytest.mark.asyncio
async def test_capacity_guards_cancellation_and_health_exemptions():
    from app.middleware import HardeningMiddleware

    started, release = asyncio.Event(), asyncio.Event()
    tasks = set()
    healthy = False

    async def guard():
        return healthy

    async def app(scope, receive, send):
        started.set()
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(
        app, 4, guard_check=guard, request_tasks=tasks, body_buffer_concurrency=1
    )
    _, denied, reads = await exchange(middleware)
    envelope(
        denied, 503, "instance ownership unavailable", "service_unavailable", cors=False
    )
    assert reads == 0
    first = asyncio.create_task(exchange(middleware, path="/healthz"))
    await asyncio.wait_for(started.wait(), 1)
    assert not tasks
    healthy = True
    _, denied, reads = await exchange(middleware)
    headers = envelope(
        denied, 503, "request capacity reached", "service_unavailable", cors=False
    )
    assert headers[b"retry-after"] == b"1" and reads == 0
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert middleware._body_admitted == 0 and not tasks
    release.set()
    _, sent, _ = await exchange(middleware)
    assert sent[0]["status"] == 200 and not tasks


@pytest.mark.asyncio
async def test_proxy_chain_nearest_untrusted_peer_and_warning_once(caplog):
    from app.middleware import HardeningMiddleware

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(
        app,
        4,
        trust_proxy_headers=True,
        trusted_proxy_ips=["127.0.0.0/8", "10.0.0.0/8"],
    )
    state, _, _ = await exchange(
        middleware,
        headers=[
            (b"X-Forwarded-For", b"198.51.100.3, , invalid, [2001:db8::1], 10.0.0.1")
        ],
    )
    assert state["state"] == {
        "mindpattern_trusted_proxy": True,
        "mindpattern_forwarded_client": "2001:db8::1",
    }
    assert not caplog.messages
    state, _, _ = await exchange(
        middleware,
        headers=[(b"x-forwarded-for", b"198.51.100.3")],
        peer=("invalid-peer", 0),
        state={"mindpattern_forwarded_client": "forged"},
    )
    assert state["state"] == {"mindpattern_trusted_proxy": False}
    await exchange(
        middleware, headers=[(b"x-forwarded-for", b"198.51.100.3")], peer=None
    )
    assert caplog.messages == [
        "X-Forwarded-For ignored: MINDPATTERN_TRUST_PROXY_HEADERS is off or the direct peer is outside MINDPATTERN_TRUSTED_PROXY_IPS; rate limiting keys on the direct peer"
    ]
    caplog.clear()
    for _ in range(2):
        state, _, _ = await exchange(
            middleware,
            headers=[(b"x-forwarded-for", b"10.0.0.1, 127.0.0.1")],
            state={"mindpattern_forwarded_client": "stale"},
        )
        assert state["state"] == {"mindpattern_trusted_proxy": True}
    assert caplog.messages == [
        "X-Forwarded-For chain contained only trusted-proxy addresses; rate limiting falls back to the proxy address for such requests (one shared bucket). If this recurs, MINDPATTERN_TRUSTED_PROXY_IPS is probably too broad."
    ]


@pytest.mark.asyncio
async def test_rate_gate_counts_body_parse_failures_once_before_body_reads(monkeypatch):
    from app import cache
    from app.middleware import HardeningMiddleware

    monkeypatch.setattr(cache.time, "monotonic", lambda: 100.0)
    counter, observed = cache.SlidingWindowCounter(), []
    settings = SimpleNamespace(
        read_rate_limit=1, read_rate_window=30, login_limit=1, login_window=30
    )
    checks = (cache.make_rate_limiter("login", "login_limit", "login_window"),)
    rules = ((frozenset({"POST"}), re.compile("/api/login"), checks),)

    async def app(scope, receive, send):
        scope["state"]["mindpattern_body_parse_failed"] = True
        await send({"type": "http.response.start", "status": 422, "headers": []})
        await send({"type": "http.response.body", "body": b"invalid"})

    middleware = HardeningMiddleware(
        app,
        4,
        rate_limit_rules=rules,
        rate_counter=counter,
        rate_limit_settings=settings,
        status_observer=observed.append,
    )
    _, sent, _ = await exchange(middleware, path="/api/login")
    assert sent[0]["status"] == 422
    assert counter.check("login:127.0.0.1", 30, now=100).count == 1
    _, sent, reads = await exchange(middleware, path="/api/login")
    headers = envelope(sent, 429, "rate limit exceeded", "rate_limited", cors=False)
    assert headers[b"retry-after"] == b"31" and reads == 0 and observed == [429]
    # GET does not match a POST-only rule; it consumes the catchall exactly once.
    _, sent, _ = await exchange(middleware, path="/api/login", method="GET")
    assert sent[0]["status"] == 422
    assert counter.check("edge-catchall:127.0.0.1", 30, now=100).count == 1
    _, sent, reads = await exchange(middleware, path="/api/login", method="GET")
    envelope(sent, 429, "rate limit exceeded", "rate_limited", cors=False)
    assert reads == 0
    _, sent, reads = await exchange(middleware, path="/api/login", peer=None)
    headers = envelope(sent, 429, "rate limit exceeded", "rate_limited", cors=False)
    assert headers[b"retry-after"] == b"1" and reads == 0


@pytest.mark.asyncio
async def test_total_body_deadline_and_unexpected_messages_are_preserved():
    from app.middleware import HardeningMiddleware

    for invalid in (0, -1):
        with pytest.raises(
            ValueError, match=r"^body_read_timeout_seconds must be positive$"
        ):
            HardeningMiddleware(None, 4, body_read_timeout_seconds=invalid)
    delivered = []

    async def app(scope, receive, send):
        delivered.append(await receive())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    for message in (
        {"type": "http.disconnect"},
        {"type": "unexpected", "body": b"abc"},
    ):
        _, sent, _ = await exchange(HardeningMiddleware(app, 4), messages=[message])
        assert sent[0]["status"] == 200 and delivered[-1] == message
    middleware = HardeningMiddleware(app, 4, body_read_timeout_seconds=0.001)

    slow_reads = 0

    async def slow():
        nonlocal slow_reads
        slow_reads += 1
        assert slow_reads <= 2, "a total body deadline must bound slow input"
        await asyncio.sleep(1)
        return {"type": "http.request", "body": b"a", "more_body": True}

    sent = []

    async def send(message):
        sent.append(message)

    await middleware(
        {
            "type": "http",
            "path": "/api/example",
            "headers": [],
            "client": ("127.0.0.1", 0),
        },
        slow,
        send,
    )
    envelope(sent, 408, "request body timed out", "request_timeout", cors=False)


def test_live_body_policy_exact_path_caps_and_cors_variation():
    from app.middleware import HardeningMiddleware

    settings = SimpleNamespace(
        max_body_bytes=4, audio_max_body_bytes=9, body_buffer_concurrency=2
    )
    middleware = HardeningMiddleware(
        None,
        2,
        settings_provider=lambda: settings,
        cors_origins=["https://client.example"],
        cors_expose_headers=["X-Cursor", "Retry-After"],
    )
    for path, expected in [
        (None, 4),
        ("/api/example", 4),
        ("/api/audiobook", 4),
        ("/api/audio", 9),
        ("/api/audio/", 9),
        ("/api/v1/audio/attach", 9),
        ("/api/account/export-download", 128),
        ("/api/v1/account/export-download", 128),
    ]:
        assert middleware._effective_max_body_bytes(path) == expected
    settings.audio_max_body_bytes = 0
    assert middleware._effective_max_body_bytes("/api/audio") == 4
    settings.audio_max_body_bytes = 1
    assert middleware._effective_max_body_bytes("/api/audio") == 1
    settings.audio_max_body_bytes = "9"
    assert middleware._effective_max_body_bytes("/api/audio") == 4
    assert middleware._cors_extra_headers([]) == []
    assert middleware._cors_extra_headers(
        [(b"origin", b"https://untrusted.example")]
    ) == [(b"vary", b"Origin")]
    assert dict(
        middleware._cors_extra_headers([(b"Origin", b"https://client.example")])
    ) == {
        b"vary": b"Origin",
        b"access-control-allow-origin": b"https://client.example",
        b"access-control-expose-headers": b"X-Cursor, Retry-After",
    }


@pytest.mark.asyncio
async def test_chunk_sum_exact_length_default_empty_body_and_default_synthetic_headers():
    from app.middleware import HardeningMiddleware

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(app, 4)
    _, sent, _ = await exchange(
        middleware,
        headers=[(b"content-length", b"4")],
        messages=[{"type": "http.request", "body": b"1234"}],
    )
    assert sent[0]["status"] == 200
    _, sent, _ = await exchange(
        middleware,
        messages=[
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456"},
        ],
    )
    envelope(sent, 413, "request body too large", "payload_too_large", cors=False)
    _, sent, _ = await exchange(
        HardeningMiddleware(app, 1), messages=[{"type": "http.request"}]
    )
    assert sent[0]["status"] == 200
    _, sent, _ = await exchange(middleware, headers=[(b"content-length", b"9" * 5000)])
    envelope(sent, 400, "invalid content-length", "bad_request", cors=False)
    direct = []

    async def send(message):
        direct.append(message)

    await middleware._reject_over_limit(send, [], 0)
    headers = envelope(
        direct, 429, "rate limit exceeded", "rate_limited", legacy=False, cors=False
    )
    assert headers[b"retry-after"] == b"1"
    direct.clear()
    await middleware._send_simple(send, 400, b'{"detail":"example","code":"example"}')
    envelope(direct, 400, "example", "example", legacy=False, cors=False)


@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
@pytest.mark.asyncio
async def test_live_capacity_failures_preserve_cors_and_health_tracking(path):
    from app.middleware import HardeningMiddleware

    entered, release = asyncio.Event(), asyncio.Event()
    tracked = set()

    async def unhealthy():
        return False

    async def app(scope, receive, send):
        entered.set()
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    settings = SimpleNamespace(body_buffer_concurrency=1, max_body_bytes=4)
    middleware = HardeningMiddleware(
        app,
        4,
        body_buffer_concurrency=2,
        settings_provider=lambda: settings,
        guard_check=unhealthy,
        request_tasks=tracked,
        cors_origins=["https://client.example"],
        cors_expose_headers=["X-Cursor", "Retry-After"],
    )
    first = asyncio.create_task(exchange(middleware, path=path))
    await asyncio.wait_for(entered.wait(), 1)
    try:
        assert not tracked
        _, sent, reads = await exchange(
            middleware, path=path, headers=[(b"origin", b"https://client.example")]
        )
        headers = envelope(
            sent, 503, "request capacity reached", "service_unavailable", legacy=False
        )
        assert headers[b"retry-after"] == b"1" and reads == 0
        _, sent, reads = await exchange(
            middleware, headers=[(b"origin", b"https://client.example")]
        )
        envelope(sent, 503, "instance ownership unavailable", "service_unavailable")
        assert reads == 0
    finally:
        release.set()
        await asyncio.wait_for(first, 1)
    assert not tracked and middleware._body_admitted == 0


@pytest.mark.asyncio
async def test_proxy_cidr_and_partial_brackets_are_tolerant_without_trusting_defaults():
    from ipaddress import ip_network

    from app.middleware import HardeningMiddleware, _forwarded_client

    networks = (ip_network("10.0.0.0/8"),)
    for chain in (
        b"198.51.100.3, invalid",
        b"198.51.100.3, [2001:db8::1",
        b"198.51.100.3, 2001:db8::1]",
        b"\xff198.51.100.3, 10.0.0.1",
    ):
        assert (
            _forwarded_client([(b"x-forwarded-for", chain)], networks) == "198.51.100.3"
        )
    middleware = HardeningMiddleware(None, 4, trusted_proxy_ips=["10.1.2.3/8"])
    assert not middleware.trust_proxy_headers
    assert middleware._direct_peer_is_trusted({"client": ("10.1.2.3", 80)})
    assert not middleware._direct_peer_is_trusted({"client": ("198.51.100.3", 80)})
    assert not middleware._direct_peer_is_trusted({"client": ("", 0)})
    unsafe = HardeningMiddleware(None, 4, trust_proxy_headers=True)
    assert not unsafe.trust_proxy_headers
    assert middleware._cors_extra_headers([]) == []
    cors = HardeningMiddleware(None, 4, cors_origins=["https://client.example"])
    assert dict(
        cors._cors_extra_headers(
            [
                (b"origin", b"\xffhttps://client.example"),
                (b"origin", b"https://untrusted.example"),
            ]
        )
    ) == {b"vary": b"Origin", b"access-control-allow-origin": b"https://client.example"}
    assert middleware._matched_rate_checks({}) == ()


@pytest.mark.parametrize("optional", ["counter", "settings", "rules"])
@pytest.mark.asyncio
async def test_partial_rate_wiring_keeps_historical_passthrough(optional):
    from app.cache import SlidingWindowCounter, make_rate_limiter
    from app.middleware import HardeningMiddleware

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    rules = (
        (
            frozenset({"POST"}),
            re.compile("/api/example"),
            (make_rate_limiter("read", "read_rate_limit", "read_rate_window"),),
        ),
    )
    middleware = HardeningMiddleware(
        app,
        4,
        rate_counter=None if optional == "counter" else SlidingWindowCounter(),
        rate_limit_settings=None
        if optional == "settings"
        else SimpleNamespace(read_rate_limit=1, read_rate_window=30),
        rate_limit_rules=() if optional == "rules" else rules,
    )
    _, sent, _ = await exchange(middleware)
    assert sent[0]["status"] == 200


@pytest.mark.asyncio
async def test_success_and_schema_failures_do_not_double_count_body_parse_budget(
    monkeypatch,
):
    from app import cache
    from app.middleware import HardeningMiddleware

    monkeypatch.setattr(cache.time, "monotonic", lambda: 100.0)
    for status, parse_failed in ((200, False), (422, False), (200, True)):
        counter = cache.SlidingWindowCounter()
        settings = SimpleNamespace(read_rate_limit=2, read_rate_window=30)
        rules = (
            (
                frozenset({"POST"}),
                re.compile("/api/example"),
                (
                    cache.make_rate_limiter(
                        "read", "read_rate_limit", "read_rate_window"
                    ),
                ),
            ),
        )

        async def app(scope, receive, send, parse_failed=parse_failed, status=status):
            scope["state"]["mindpattern_body_parse_failed"] = parse_failed
            await send({"type": "http.response.start", "status": status, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        middleware = HardeningMiddleware(
            app,
            4,
            rate_counter=counter,
            rate_limit_settings=settings,
            rate_limit_rules=rules,
        )
        _, sent, _ = await exchange(middleware)
        assert sent[0]["status"] == status
        assert counter.check("read:127.0.0.1", 30, now=100).count == 0


@pytest.mark.asyncio
async def test_default_body_deadline_and_capacity_are_bounded(monkeypatch):
    from app.middleware import HardeningMiddleware

    recorded, original = [], asyncio.wait_for

    async def measured(awaitable, timeout):
        recorded.append(timeout)
        return await original(awaitable, timeout)

    monkeypatch.setattr(asyncio, "wait_for", measured)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(app, 4)
    await exchange(middleware)
    assert 29.9 < max(recorded) <= 30
    assert middleware._body_capacity == 100


@pytest.mark.asyncio
async def test_optional_terminal_body_fields_dispatch_without_waiting_for_disconnect():
    from app.middleware import HardeningMiddleware

    reads, sent = 0, []

    async def receive():
        nonlocal reads
        reads += 1
        if reads == 1:
            return {"type": "http.request"}
        await asyncio.Event().wait()

    async def app(scope, receive, send):
        assert await receive() == {"type": "http.request"}
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def send(message):
        sent.append(message)

    middleware = HardeningMiddleware(app, 1, body_read_timeout_seconds=0.02)
    await asyncio.wait_for(
        middleware(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/example",
                "headers": [],
                "client": ("127.0.0.1", 0),
            },
            receive,
            send,
        ),
        1,
    )
    assert reads == 1 and sent[0]["status"] == 200


@pytest.mark.asyncio
async def test_two_live_body_slots_refuse_a_third_request_and_release_both():
    from app.middleware import HardeningMiddleware

    started = asyncio.Queue()
    release = asyncio.Event()
    tasks = set()

    async def app(scope, receive, send):
        started.put_nowait(True)
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(
        app, 4, body_buffer_concurrency=2, request_tasks=tasks
    )
    holders = [asyncio.create_task(exchange(middleware)) for _ in range(2)]
    try:
        for _ in holders:
            await asyncio.wait_for(started.get(), 1)
        assert middleware._body_admitted == 2 and len(tasks) == 2
        _, refused, reads = await exchange(middleware)
        envelope(
            refused, 503, "request capacity reached", "service_unavailable", cors=False
        )
        assert reads == 0
    finally:
        release.set()
        await asyncio.gather(*holders)
    assert middleware._body_admitted == 0 and not tasks


@pytest.mark.asyncio
async def test_socketless_rate_refusal_is_observed_as_429():
    from app.cache import SlidingWindowCounter
    from app.middleware import HardeningMiddleware, RateLimitCheck

    observed = []
    settings = SimpleNamespace(limit=1, window=30)
    rules = [
        (
            frozenset({"POST"}),
            re.compile(r"^/api/example$"),
            (RateLimitCheck("edge", "limit", "window"),),
        )
    ]

    async def app(scope, receive, send):
        pytest.fail("unavailable peer must be refused before dispatch")

    middleware = HardeningMiddleware(
        app,
        4,
        rate_counter=SlidingWindowCounter(),
        rate_limit_settings=settings,
        rate_limit_rules=rules,
        status_observer=observed.append,
    )
    _, sent, reads = await exchange(middleware, peer=None)
    envelope(sent, 429, "rate limit exceeded", "rate_limited", cors=False)
    assert reads == 0 and observed == [429]


@pytest.mark.asyncio
async def test_extension_receive_message_is_handed_to_app_without_draining_following_input():
    from app.middleware import HardeningMiddleware

    first = {"type": "extension.message", "body": b"opaque"}

    async def app(scope, receive, send):
        assert await receive() == first
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    _, sent, reads = await exchange(
        HardeningMiddleware(app, 1),
        messages=[first, {"type": "http.request", "body": b"oversize"}],
    )
    assert sent[0]["status"] == 200 and reads == 1


@pytest.mark.asyncio
async def test_audio_body_policy_is_used_at_actual_dispatch():
    from app.middleware import HardeningMiddleware

    settings = SimpleNamespace(
        max_body_bytes=1, audio_max_body_bytes=4, body_buffer_concurrency=2
    )

    async def app(scope, receive, send):
        assert (await receive())["body"] == b"1234"
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(app, 1, settings_provider=lambda: settings)
    _, sent, _ = await exchange(
        middleware,
        path="/api/audio",
        messages=[{"type": "http.request", "body": b"1234"}],
    )
    assert sent[0]["status"] == 200


@pytest.mark.asyncio
async def test_legacy_response_preserves_an_existing_deprecation_header_once():
    from app.middleware import HardeningMiddleware

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"deprecation", b"true")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    _, sent, _ = await exchange(HardeningMiddleware(app, 4))
    assert [
        value for name, value in sent[0]["headers"] if name.lower() == b"deprecation"
    ] == [b"true"]


@pytest.mark.asyncio
@pytest.mark.parametrize("length", [b"0", b"9", b"0009"])
async def test_decimal_framing_accepts_zero_and_nine_digits(length):
    from app.middleware import HardeningMiddleware

    body = b"a" * int(length)

    async def app(scope, receive, send):
        assert (await receive())["body"] == body
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    _, sent, reads = await exchange(
        HardeningMiddleware(app, 9),
        headers=[(b"content-length", length)],
        messages=[{"type": "http.request", "body": body, "more_body": False}],
    )
    assert sent[0]["status"] == 200 and reads == 1


@pytest.mark.asyncio
async def test_exhausted_positive_body_deadline_refuses_before_reading():
    from app.middleware import HardeningMiddleware

    async def app(scope, receive, send):
        pytest.fail("an already exhausted body budget must refuse before dispatch")

    # A positive interval smaller than the monotonic clock's precision is
    # already exhausted before the first receive, rather than in wait_for.
    _, sent, reads = await exchange(
        HardeningMiddleware(app, 4, body_read_timeout_seconds=1e-300)
    )
    assert sent[0]["status"] == 408 and reads == 0
    assert json.loads(sent[1]["body"]) == {
        "detail": "request body timed out",
        "code": "request_timeout",
    }
