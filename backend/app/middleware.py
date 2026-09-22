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
 5. Count malformed-JSON bodies into the route's own rate-limit bucket
    (M-1, 2026-09-20). FastAPI raises RequestValidationError while PARSING
    the body, before any route dependency runs — so a flood of garbage JSON
    used to draw unlimited 422s that no limiter ever saw. The validation
    handler in main.py marks such requests in scope state; this layer then
    (a) counts the failed parse into the same bucket the route's limiter
    dependency would have used, and (b) short-circuits with a 429 once the
    bucket is full — BEFORE the body is handed to FastAPI at all, so an
    over-limit client costs no further parsing.
 6. Mirror the CORS allow-list onto this middleware's own short-circuit
    responses (400/408/413/429/500). CORSMiddleware sits INSIDE this layer,
    so its headers never reach responses generated here — a browser client
    saw only opaque failures for oversized bodies (L-4, 2026-09-20).

Error bodies here carry the same {"detail", "code"} envelope the app's
exception handlers emit (they bypass those handlers by design, see 2).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Callable
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from .cache import FixedWindowCounter, RateLimitCheck, client_key_from_scope
from .config import Settings

logger = logging.getLogger("mindpattern")

# One rate-limit rule per bucketed route: (methods, compiled path pattern,
# limiter checks). Built once at app-startup by walking the router (see
# main.py), so it can never drift from the routes' own dependencies.
RateLimitRule = tuple[frozenset[str], re.Pattern[str], tuple[RateLimitCheck, ...]]

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
_RATE_LIMITED = json.dumps({"detail": "rate limit exceeded", "code": "rate_limited"}).encode(
    "utf-8"
)


def _is_legacy_api_path(path: str) -> bool:
    """True when the path is served by the deprecated unversioned /api
    mount (anything under /api that is not /api/v1 — see main.py, where
    the same routers are included twice)."""
    if path == "/api":
        return True
    return path.startswith("/api/") and not path.startswith("/api/v1")


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
        rate_limit_rules: tuple[RateLimitRule, ...] = (),
        rate_counter: FixedWindowCounter | None = None,
        rate_limit_settings: Settings | None = None,
        cors_origins: list[str] | tuple[str, ...] = (),
        cors_expose_headers: list[str] | tuple[str, ...] = (),
        status_observer: Callable[[int], None] | None = None,
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
        self._no_untrusted_xff_warned = False
        # Malformed-body rate counting (M-1). All three pieces must be
        # present; any direct consumer that omits them keeps the historical
        # behavior (no edge counting, no pre-dispatch 429s).
        self._rate_rules = rate_limit_rules
        self._rate_counter = rate_counter
        self._rate_limit_settings = rate_limit_settings
        # Exact-match CORS allow-list + the expose list, mirroring what
        # CORSMiddleware (which sits INSIDE this layer) would put on a
        # normal response. Empty allow-list (the default deployment: the
        # mobile app is a native client) disables the mirroring entirely.
        self._cors_origins = frozenset(cors_origins)
        self._cors_expose_value = b", ".join(h.encode("ascii") for h in cors_expose_headers)
        # Optional tap for responses this layer synthesizes that the inner
        # MetricsMiddleware can never see (M-26): the last-ditch 500 and the
        # recursion 400 are produced from exceptions that blow straight
        # through the metrics layer, and the pre-dispatch 429 replaces an
        # app response that was never produced. Pre-parse rejections
        # (413/408/framing 400s) stay unobserved — the documented exclusion.
        self._status_observer = status_observer

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

    def _cors_extra_headers(
        self, raw_headers: list[tuple[bytes, bytes]]
    ) -> list[tuple[bytes, bytes]]:
        """CORS headers to mirror onto a short-circuit response (L-4).

        CORSMiddleware sits INSIDE this layer, so responses generated here
        would otherwise carry no CORS headers at all and a browser client
        sees only an opaque failure (it cannot even read the {"detail",
        "code"} envelope). Mirroring only what the inner middleware would
        add to a simple (non-preflight) cross-origin response keeps the
        surface identical: the exact allowed origin when the request's
        Origin is allow-listed, plus the configured expose list. A
        non-allowed or absent Origin adds nothing — matching CORSMiddleware,
        which leaves such responses untouched. Preflight handling stays
        with the inner CORS middleware: a preflight carries no body and
        passes through this layer's body checks untouched.
        """
        if not self._cors_origins:
            return []
        origin: str | None = None
        for name, value in raw_headers:
            if name.lower() == b"origin":
                origin = value.decode("ascii", "ignore")
                break
        if origin is None or origin not in self._cors_origins:
            return []
        headers = [(b"access-control-allow-origin", origin.encode("ascii", "ignore"))]
        if self._cors_expose_value:
            headers.append((b"access-control-expose-headers", self._cors_expose_value))
        return headers

    def _matched_rate_checks(self, scope: dict) -> tuple[RateLimitCheck, ...]:
        """The limiter checks of the route this request resolves to, if any.

        Path matching reuses each route's own compiled pattern (built in
        main.py from the live router), so the edge counter and the route
        dependency are guaranteed to key the SAME bucket for the SAME
        request — including parameterized paths. First match wins, exactly
        like the router itself.
        """
        method = scope.get("method", "")
        path = scope.get("path", "")
        for methods, pattern, checks in self._rate_rules:
            if method in methods and pattern.fullmatch(path) is not None:
                return checks
        return ()

    async def _reject_over_limit(
        self,
        send,
        raw_headers: list[tuple[bytes, bytes]],
        retry_after: int,
        legacy: bool = False,
    ) -> None:
        # Same envelope and Retry-After contract as cache._limit_response;
        # this copy exists because that helper builds an HTTPException for
        # the FastAPI dependency path, which has no meaning at raw-ASGI level.
        if self._status_observer is not None:
            self._status_observer(429)
        await self._send_simple(
            send,
            429,
            _RATE_LIMITED,
            raw_headers=raw_headers,
            extra_headers=[(b"retry-after", str(max(1, retry_after)).encode("ascii"))],
            legacy=legacy,
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # --- 1. Cheap content-length rejection, before anything is read ----
        raw_headers = scope.get("headers", [])
        # 2026-09-22 audit round 3 (A-8 wording): middleware-SYNTHESIZED
        # responses (429/413/400/408/500 below) carry the same legacy-mount
        # Deprecation header the app-path injection adds, so "every response
        # the deprecated /api mount serves" is true without qualification.
        legacy_api = _is_legacy_api_path(scope.get("path", ""))
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
                # Every chain entry was inside the trusted networks: the
                # request's rate-limit identity silently degrades to the
                # proxy's own address (all clients share ONE bucket). A
                # well-formed deployment never does this — the rightmost
                # entry is the client the proxy actually observed — so say
                # so once instead of failing quietly (2026-09-19 round).
                if not self._no_untrusted_xff_warned:
                    self._no_untrusted_xff_warned = True
                    logger.warning(
                        "X-Forwarded-For chain contained only trusted-proxy "
                        "addresses; rate limiting falls back to the proxy "
                        "address for such requests (one shared bucket). If "
                        "this recurs, MINDPATTERN_TRUSTED_PROXY_IPS is "
                        "probably too broad."
                    )
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
            await self._send_simple(send, 400, _BAD_LENGTH, raw_headers=raw_headers, legacy=legacy_api)
            return
        # A request may use either a length OR chunked transfer coding, never
        # both. The ASGI server normally normalizes legitimate HTTP/1.1
        # chunked requests to one literal ``Transfer-Encoding: chunked``;
        # reject all other transfer-coding chains rather than making this
        # layer disagree with an upstream proxy about message boundaries.
        if content_lengths and transfer_encodings:
            await self._send_simple(send, 400, _BAD_FRAMING, raw_headers=raw_headers, legacy=legacy_api)
            return
        if transfer_encodings and (
            len(transfer_encodings) != 1 or transfer_encodings[0].lower() != b"chunked"
        ):
            await self._send_simple(send, 400, _BAD_FRAMING, raw_headers=raw_headers, legacy=legacy_api)
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
                    await self._send_simple(send, 400, _BAD_LENGTH, raw_headers=raw_headers, legacy=legacy_api)
                    return
                declared_length = int(content_length)
                if declared_length > self.max_body_bytes:
                    await self._send_simple(send, 413, _OVERSIZE_BODY, raw_headers=raw_headers, legacy=legacy_api)
                    return
            except ValueError:
                await self._send_simple(send, 400, _BAD_LENGTH, raw_headers=raw_headers, legacy=legacy_api)
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
                await self._send_simple(send, 408, _BODY_TIMEOUT, raw_headers=raw_headers, legacy=legacy_api)
                return
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except TimeoutError:
                await self._send_simple(send, 408, _BODY_TIMEOUT, raw_headers=raw_headers, legacy=legacy_api)
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
                await self._send_simple(send, 413, _OVERSIZE_BODY, raw_headers=raw_headers, legacy=legacy_api)
                return
            if not message.get("more_body", False):
                break

        replay_index = 0

        # --- 3. Pre-dispatch malformed-body rate gate (M-1, 2026-09-20) -----
        #
        # FastAPI parses the body BEFORE route dependencies run, so a request
        # whose JSON never parses draws a 422 that no limiter ever counted:
        # an unauthenticated flood used to get unlimited 422s, each costing a
        # full body buffer + parse. Two moves close it, both keyed to the
        # SAME bucket (and client identity) the route's limiter dependency
        # uses — the rules were built from the live router in main.py:
        #   * pre-dispatch (here): a client already at its bucket's limit is
        #     refused before FastAPI spends anything on the request at all;
        #   * post-response (in send_with_headers below): a 422 the
        #     validation handler marked as a body-parse failure is counted
        #     into the bucket — the dependency never ran for that request,
        #     so this is the ONE count, never a double.
        # Boundary parity with the dependency: dependencies 429 once the
        # post-hit count EXCEEDS the limit, which is exactly a pre-hit
        # check() count >= limit — a valid request sees the same admission
        # decision it always had, one layer earlier and without the parse.
        rate_counter = self._rate_counter
        rate_settings = self._rate_limit_settings
        matched_checks: tuple[RateLimitCheck, ...] = ()
        rate_key: str | None = None
        if rate_counter is not None and rate_settings is not None and self._rate_rules:
            matched_checks = self._matched_rate_checks(scope)
            if matched_checks:
                rate_key = client_key_from_scope(scope, self.trust_proxy_headers)
                for check in matched_checks:
                    limit = getattr(rate_settings, check.limit_attr)
                    window = getattr(rate_settings, check.window_attr)
                    result = rate_counter.check(f"{check.bucket}:{rate_key}", window)
                    if result.count >= limit:
                        await self._reject_over_limit(send, raw_headers, result.retry_after, legacy=legacy_api)
                        return

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
                # 2026-09-21 audit A-8: every response the deprecated
                # unversioned /api mount serves carries the standard
                # Deprecation header, so a client can notice
                # programmatically (alongside /api/meta's api_version,
                # which points at the canonical /api/v1 base).
                if "deprecation" not in existing and _is_legacy_api_path(
                    scope.get("path", "")
                ):
                    message["headers"].append((b"deprecation", b"true"))
                # M-1: the validation handler flagged this 422 as a BODY-PARSE
                # failure (error type json_invalid — schema failures flow
                # through the route dependencies and are counted there).
                # scope["state"] is the same dict the handler wrote to; the
                # response-start message fires exactly once per response.
                if (
                    matched_checks
                    and rate_key is not None
                    and rate_counter is not None
                    and rate_settings is not None
                    and message["status"] == 422
                    and (scope.get("state") or {}).get("mindpattern_body_parse_failed")
                ):
                    for check in matched_checks:
                        window = getattr(rate_settings, check.window_attr)
                        rate_counter.hit(f"{check.bucket}:{rate_key}", window)
            await send(message)

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except RecursionError:
            if not response_started:
                # An exception the app raised blows straight through the
                # inner MetricsMiddleware without producing a response —
                # observe it here so the status family stays countable.
                if self._status_observer is not None:
                    self._status_observer(400)
                await self._send_simple(
                    send,
                    400,
                    _NESTED_BODY,
                    raw_headers=raw_headers,
                    legacy=legacy_api,
                )
            return
        except Exception:
            # Last-ditch: log with traceback, answer without internals.
            # Do not log raw paths: deployments may put identifiers in a
            # legacy/unknown URL path and exception logs commonly have a much
            # wider retention/access surface than application data.
            logger.exception("unhandled error serving method=%s", scope.get("method"))
            if not response_started:
                # M-26 (2026-09-20): a crash-class 500 used to be invisible
                # to mindpattern_requests_total — the metrics layer sits
                # INSIDE this one and never saw a response. Observing the
                # synthesized 500 here keeps an operator's status="5xx"
                # signal alive during exactly the crash loops that matter.
                if self._status_observer is not None:
                    self._status_observer(500)
                await self._send_simple(send, 500, _INTERNAL, raw_headers=raw_headers, legacy=legacy_api)
            return

    async def _send_simple(
        self,
        send,
        status: int,
        body: bytes,
        raw_headers: list[tuple[bytes, bytes]] | None = None,
        extra_headers: list[tuple[bytes, bytes]] | None = None,
        legacy: bool = False,
    ) -> None:
        headers = [(b"content-type", b"application/json"), *SECURITY_HEADERS]
        if raw_headers is not None:
            # L-4: mirror the CORS allow-list so browser clients can read
            # these envelope bodies instead of seeing opaque failures.
            headers.extend(self._cors_extra_headers(raw_headers))
        if extra_headers:
            headers.extend(extra_headers)
        if legacy:
            # A-8/round-3: synthesized envelopes on the deprecated unversioned
            # /api mount carry the same Deprecation header app responses do.
            headers.append((b"deprecation", b"true"))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body})
