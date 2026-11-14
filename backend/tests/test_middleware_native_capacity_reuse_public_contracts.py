"""ASGI admission reuses the default capacity after completed requests."""

import asyncio

from app.middleware import HardeningMiddleware


def test_native_default_admission_capacity_and_request_task_retirement():
    async def exercise():
        request_tasks = set()
        release = asyncio.Event()
        entered = {}

        async def app(scope, receive, send):
            if scope["path"] == "/held":
                entered[scope["request_index"]].set()
                await release.wait()
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = HardeningMiddleware(app, max_body_bytes=1024, request_tasks=request_tasks)

        async def request(path, index=None):
            sent = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            await middleware(
                {
                    "type": "http",
                    "method": "GET",
                    "path": path,
                    "headers": [],
                    "client": ("127.0.0.1", 443),
                    "state": {},
                    "request_index": index,
                },
                receive,
                send,
            )
            return sent

        for wave in range(2):
            release.clear()
            tasks = []
            try:
                # Exercise the released default100 through actual held ASGI calls.
                for index in range(100):
                    marker = (wave, index)
                    entered[marker] = asyncio.Event()
                    task = asyncio.create_task(request("/held", marker))
                    tasks.append(task)
                    observed = asyncio.create_task(entered[marker].wait())
                    try:
                        await asyncio.wait((task, observed), return_when=asyncio.FIRST_COMPLETED)
                        assert entered[marker].is_set()
                    finally:
                        observed.cancel()
                        await asyncio.gather(observed, return_exceptions=True)
                refused = await request("/probe")
                assert refused[0]["status"] == 503
                assert request_tasks == set(tasks)
            finally:
                release.set()
                completed = await asyncio.gather(*tasks, return_exceptions=True)
            assert all(
                isinstance(messages, list) and messages[0]["status"] == 204
                for messages in completed
            )
            assert not request_tasks
        assert (await request("/probe"))[0]["status"] == 204
        assert not request_tasks

    asyncio.run(exercise())
