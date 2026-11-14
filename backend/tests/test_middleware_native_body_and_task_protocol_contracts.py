"""ASGI body replay and constructor task custody remain observable to callers."""

import asyncio

from app.middleware import HardeningMiddleware


def test_asgi_downstream_receives_the_original_chunked_body_and_declared_task_custody():
    async def exercise():
        for path in ("/api/v1/echo", "/healthz", "/readyz"):
            tasks = set()
            body = b"a" * 512 + b"b" * 512
            inputs = iter(
                [
                    {"type": "http.request", "body": body[:512], "more_body": True},
                    {"type": "http.request", "body": body[512:], "more_body": False},
                    {"type": "http.disconnect"},
                ]
            )
            sent = []
            observed = []

            async def receive():
                return next(inputs, {"type": "http.disconnect"})

            async def send(message):
                sent.append(message)

            async def downstream(scope, receive, send):
                observed.append(asyncio.current_task() in tasks)
                chunks = []
                for _ in range(3):
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        break
                    chunks.append(message["body"])
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"".join(chunks)})

            middleware = HardeningMiddleware(downstream, max_body_bytes=1024, request_tasks=tasks)
            await middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": path,
                    "headers": [(b"transfer-encoding", b"CHUNKED")],
                    "client": ("127.0.0.1", 443),
                    "state": {},
                },
                receive,
                send,
            )
            assert sent[0]["status"] == 200
            assert sent[1]["body"] == body
            assert observed == [path not in {"/healthz", "/readyz"}]
            assert not tasks

    asyncio.run(exercise())


def test_valid_decimal_framing_delivers_zero_and_nine_digit_request_bodies():
    async def exercise():
        for length in (b"0", b"9", b"0009"):
            body = b"a" * int(length)
            sent = []
            inputs = iter([{"type": "http.request", "body": body, "more_body": False}])

            async def receive():
                return next(inputs, {"type": "http.disconnect"})

            async def send(message):
                sent.append(message)

            async def downstream(scope, receive, send):
                received = await receive()
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": received["body"]})

            middleware = HardeningMiddleware(downstream, max_body_bytes=1024)
            await middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/api/v1/echo",
                    "headers": [(b"content-length", length)],
                    "client": ("127.0.0.1", 443),
                    "state": {},
                },
                receive,
                send,
            )
            assert sent[0]["status"] == 200
            assert sent[1]["body"] == body

    asyncio.run(exercise())
