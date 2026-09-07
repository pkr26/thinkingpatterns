"""Hardening middleware (pure ASGI, outermost of the user middleware stack).

Responsibilities, in order:
 1. Reject oversized request bodies (413) *before* the JSON is read — the
    schema-level caps only bound what is stored, not what is buffered.
 2. Stamp the security headers (nosniff / DENY / no-referrer / no-store /
    HSTS) on EVERY response — including 500s and the 413/400s this middleware
    itself produces. (A BaseHTTPMiddleware or exception-handler approach
    cannot cover unhandled exceptions; sitting as raw ASGI can.)
 3. Convert unhandled exceptions into a logged, header-stamped 500 with no
    internals leaked; deeply-nested JSON (RecursionError) becomes a 400.
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger("mindpattern")

SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    # HSTS: once the API is ever reached over TLS, browsers must keep it that
    # way (no-op over plain HTTP, which is exactly when it cannot help).
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
)

_OVERSIZE_BODY = json.dumps({"detail": "request body too large"}).encode("utf-8")
_NESTED_BODY = json.dumps({"detail": "request body too deeply nested"}).encode("utf-8")
_BAD_LENGTH = json.dumps({"detail": "invalid content-length"}).encode("utf-8")
_INTERNAL = json.dumps({"detail": "internal server error"}).encode("utf-8")


class HardeningMiddleware:
    """ASGI middleware: body-size cap + security headers + last-ditch 500s."""

    def __init__(self, app, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # --- 1. Cheap content-length rejection, before anything is read ----
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_body_bytes:
                    await self._send_simple(send, 413, _OVERSIZE_BODY)
                    return
            except ValueError:
                await self._send_simple(send, 400, _BAD_LENGTH)
                return

        # --- 2. Count streamed bytes (covers chunked bodies) ----------------
        state = {"seen": 0, "rejected": False}

        async def limited_receive():
            message = await receive()
            if message["type"] == "http.request":
                state["seen"] += len(message.get("body", b""))
                if state["seen"] > self.max_body_bytes:
                    state["rejected"] = True
                    return {"type": "http.disconnect"}
            return message

        response_started = False

        async def send_with_headers(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                existing = {name.lower() for name, _ in message.get("headers", [])}
                extra = [h for h in SECURITY_HEADERS if h[0] not in existing]
                message.setdefault("headers", []).extend(extra)
            await send(message)

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except RecursionError:
            if not response_started:
                await self._send_simple(
                    send, 413 if state["rejected"] else 400,
                    _OVERSIZE_BODY if state["rejected"] else _NESTED_BODY,
                )
            return
        except Exception:
            if state["rejected"] and not response_started:
                # The app saw a mid-stream disconnect because the body
                # overflowed; that is a 413, not a server error.
                await self._send_simple(send, 413, _OVERSIZE_BODY)
                return
            # Last-ditch: log with traceback, answer without internals.
            logger.exception("unhandled error serving %s %s",
                             scope.get("method"), scope.get("path"))
            if not response_started:
                await self._send_simple(send, 500, _INTERNAL)
            return

        if state["rejected"] and not response_started:
            # Body overflowed while streaming but the app never answered
            # (it saw a disconnect instead); produce the 413 ourselves.
            await self._send_simple(send, 413, _OVERSIZE_BODY)

    @staticmethod
    async def _send_simple(send, status: int, body: bytes) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), *SECURITY_HEADERS],
        })
        await send({"type": "http.response.body", "body": body})
