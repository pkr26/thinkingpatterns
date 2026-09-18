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
 4. Warn once at first sight of X-Forwarded-For while trust_proxy_headers is
    off — the usual symptom of a proxy deployment that forgot to opt in, in
    which case rate limiting keys on the proxy's address for every client.

Error bodies here carry the same {"detail", "code"} envelope the app's
exception handlers emit (they bypass those handlers by design, see 2).
"""

from __future__ import annotations

import asyncio
import json
import logging
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

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

_OVERSIZE_BODY = json.dumps(
    {"detail": "request body too large", "code": "payload_too_large"}
).encode("utf-8")
_NESTED_BODY = json.dumps(
    {"detail": "request body too deeply nested", "code": "bad_request"}
).encode("utf-8")
_BAD_LENGTH = json.dumps({"detail": "invalid content-length", "code": "bad_request"}).encode(
    "utf-8"
)
_BAD_FRAMING = json.dumps({"detail": "ambiguous request framing", "code": "bad_request"}).encode(
    "utf-8"
)
_BODY_TIMEOUT = json.dumps({"detail": "request body timed out", "code": "request_timeout"}).encode(
    "utf-8"
)
_INTERNAL = json.dumps({"detail": "internal server error", "code": "internal_error"}).encode(
    "utf-8"
)


def _forwarded_client(
    raw_headers: list[tuple[bytes, bytes]],
    trusted_networks: tuple[IPv4Network | IPv6Network, ...],
) -> str | None:
    """Return the nearest untrusted address from X-Forwarded-For.

    A trusted proxy appends the peer it observed.  Walking from the right and
    skipping configured proxy networks works for one or several trusted
    proxy hops, while a client-supplied leftmost value cannot choose its own
    rate-limit bucket.  Malformed values are deliberately ignored: the safe
    fallback is the direct proxy peer, not a value an attacker invented.
    """
    entries: list[str] = []
    for name, value in raw_headers:
        if name.lower() == b"x-forwarded-for":
            entries.extend(
                part.strip() for part in value.decode("ascii", "ignore").split(",") if part.strip()
            )
    for candidate in reversed(entries):
        # XFF normally contains bare IPs. Bracketed IPv6 is accepted for
        # interoperability, but host:port and opaque identifiers are not a
        # client identity we can safely rate-limit by.
        unbracketed = (
            candidate[1:-1] if candidate.startswith("[") and candidate.endswith("]") else candidate
        )
        try:
            address = ip_address(unbracketed)
        except ValueError:
            continue
        if not any(address in network for network in trusted_networks):
            return str(address)
    return None


class HardeningMiddleware:
    """ASGI middleware: body-size cap + security headers + last-ditch 500s."""

    def __init__(
        self,
        app,
        max_body_bytes: int,
        body_read_timeout_seconds: float = 30,
        trust_proxy_headers: bool = False,
        trusted_proxy_ips: list[str] | tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        if body_read_timeout_seconds <= 0:
            raise ValueError("body_read_timeout_seconds must be positive")
        self.body_read_timeout_seconds = body_read_timeout_seconds
        self.trusted_proxy_networks = tuple(
            ip_network(value, strict=False) for value in trusted_proxy_ips
        )
        # The config layer rejects this combination at startup. Retaining a
        # defensive false here protects direct middleware consumers/tests too:
        # an accidental boolean alone can never make an arbitrary socket peer
        # authoritative for X-Forwarded-For.
        self.trust_proxy_headers = trust_proxy_headers and bool(self.trusted_proxy_networks)
        self._xff_warned = False

    def _direct_peer_is_trusted(self, scope) -> bool:
        client = scope.get("client")
        host = client[0] if client else None
        if not host:
            return False
        try:
            peer = ip_address(host)
        except ValueError:
            return False
        return any(peer in network for network in self.trusted_proxy_networks)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # --- 1. Cheap content-length rejection, before anything is read ----
        raw_headers = scope.get("headers", [])
        headers = {k.lower(): v for k, v in raw_headers}
        direct_peer_is_trusted = self._direct_peer_is_trusted(scope)
        trusted_forwarding = self.trust_proxy_headers and direct_peer_is_trusted
        # State is the authenticated handoff between this outer ASGI layer
        # and rate limiting. `client_key` does not inspect XFF directly: it
        # consumes only this decision, made while the raw socket peer was
        # still available (and without uvicorn --proxy-headers mutating it).
        state = scope.setdefault("state", {})
        state["mindpattern_trusted_proxy"] = trusted_forwarding
        if trusted_forwarding:
            forwarded = _forwarded_client(raw_headers, self.trusted_proxy_networks)
            if forwarded is not None:
                state["mindpattern_forwarded_client"] = forwarded
            else:
                state.pop("mindpattern_forwarded_client", None)
        else:
            state.pop("mindpattern_forwarded_client", None)
        if b"x-forwarded-for" in headers and not trusted_forwarding and not self._xff_warned:
            # One operator-visible nudge, then quiet: with trust off OR an
            # untrusted direct peer, the header is ignored and rate limiting
            # keys on the socket address instead.
            self._xff_warned = True
            logger.warning(
                "X-Forwarded-For ignored: MINDPATTERN_TRUST_PROXY_HEADERS is off "
                "or the direct peer is outside MINDPATTERN_TRUSTED_PROXY_IPS; "
                "rate limiting keys on the direct peer"
            )
        # RFC 9112 message framing is security-sensitive.  Do not let a
        # reverse proxy and this ASGI layer choose different duplicate
        # Content-Length values: that is the classic request-smuggling
        # boundary. Equal duplicate values are legal in some tolerant
        # implementations, but
        # rejecting every duplicate is the safer contract for this small
        # JSON API and keeps the parser unambiguous.
        content_lengths = [
            value for name, value in raw_headers if name.lower() == b"content-length"
        ]
        transfer_encodings = [
            value for name, value in raw_headers if name.lower() == b"transfer-encoding"
        ]
        if len(content_lengths) > 1:
            await self._send_simple(send, 400, _BAD_LENGTH)
            return
        # A request may use either a length OR chunked transfer coding, never
        # both. The ASGI server normally normalizes legitimate HTTP/1.1
        # chunked requests to one literal ``Transfer-Encoding: chunked``;
        # reject all other transfer-coding chains rather than making this
        # layer disagree with an upstream proxy about message boundaries.
        if content_lengths and transfer_encodings:
            await self._send_simple(send, 400, _BAD_FRAMING)
            return
        if transfer_encodings and (
            len(transfer_encodings) != 1 or transfer_encodings[0].lower() != b"chunked"
        ):
            await self._send_simple(send, 400, _BAD_FRAMING)
            return
        content_length = content_lengths[0] if content_lengths else None
        declared_length: int | None = None
        if content_length is not None:
            try:
                # Grammar-strict decimal digits only. Do not delegate to
                # Python's permissive integer parser: forms such as ``+1``,
                # ``1_000``, or surrounding whitespace can be interpreted
                # differently by a proxy and would reopen a framing split.
                if not content_length or any(
                    byte < ord("0") or byte > ord("9") for byte in content_length
                ):
                    await self._send_simple(send, 400, _BAD_LENGTH)
                    return
                declared_length = int(content_length)
                if declared_length > self.max_body_bytes:
                    await self._send_simple(send, 413, _OVERSIZE_BODY)
                    return
            except ValueError:
                await self._send_simple(send, 400, _BAD_LENGTH)
                return

        # --- 2. Bound-and-replay the COMPLETE body before dispatch ----------
        #
        # Counting only when the downstream application calls receive() is
        # not a request-size boundary: body-ignoring routes (and an app that
        # answers after an artificial disconnect) can return 200 while an
        # oversized chunked body is still arriving.  The API deliberately
        # accepts only small JSON payloads, so buffering up to the configured
        # cap is both safe and simpler than trying to police arbitrary receive
        # patterns.  Replay the original ASGI messages so Starlette/FastAPI
        # still sees normal streaming semantics.
        buffered: list[dict] = []
        seen = 0
        # Drain EVERY HTTP request before routing, including GET, HEAD, and
        # OPTIONS.  Those methods are normally bodyless, but HTTP/2 can carry
        # an unframed body with neither Content-Length nor Transfer-Encoding;
        # exempting "safe" methods would let that body bypass the one
        # authoritative byte cap.  A conforming ASGI server emits an empty
        # terminal http.request event for a legitimate bodyless request.  The
        # same bounded deadline turns a broken/slow peer into a 408 instead
        # of allowing a worker to deadlock indefinitely.
        #
        # This is a TOTAL request-body deadline, not a per-chunk idle
        # timeout. A slowloris that sends one byte every few seconds must not
        # renew its claim on a worker forever. The Docker entrypoint also caps
        # global Uvicorn concurrency; both layers matter.
        deadline = asyncio.get_running_loop().time() + self.body_read_timeout_seconds
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                await self._send_simple(send, 408, _BODY_TIMEOUT)
                return
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except TimeoutError:
                await self._send_simple(send, 408, _BODY_TIMEOUT)
                return
            buffered.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                # ASGI HTTP receive has only request/disconnect messages in
                # practice. Preserve an unexpected message for the app rather
                # than silently changing protocol semantics.
                break
            seen += len(message.get("body", b""))
            if seen > self.max_body_bytes:
                await self._send_simple(send, 413, _OVERSIZE_BODY)
                return
            if not message.get("more_body", False):
                break

        replay_index = 0

        async def limited_receive():
            nonlocal replay_index
            if replay_index < len(buffered):
                message = buffered[replay_index]
                replay_index += 1
                return message
            # The request body is complete, but that is not a disconnect.
            # In particular, StreamingResponse starts a listener that calls
            # receive() while it emits bytes; returning a synthetic disconnect
            # here would cancel a healthy slow download.  Hand subsequent
            # calls back to the real receive channel so it blocks until an
            # actual client disconnect, exactly as ASGI requires.
            return await receive()

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
                    send,
                    400,
                    _NESTED_BODY,
                )
            return
        except Exception:
            # Last-ditch: log with traceback, answer without internals.
            # Do not log raw paths: deployments may put identifiers in a
            # legacy/unknown URL path and exception logs commonly have a much
            # wider retention/access surface than application data.
            logger.exception("unhandled error serving method=%s", scope.get("method"))
            if not response_started:
                await self._send_simple(send, 500, _INTERNAL)
            return

    @staticmethod
    async def _send_simple(send, status: int, body: bytes) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), *SECURITY_HEADERS],
            }
        )
        await send({"type": "http.response.body", "body": body})
