"""Stateless HMAC-signed session tokens (no server-side session state).

Format:  base64url(payload_json) . base64url(hmac_sha256(secret, body))
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time


class TokenError(Exception):
    """Raised when a token is malformed, forged, or expired."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def issue_token(
    user_id: str,
    secret: str,
    ttl_seconds: int,
    now: float | None = None,
    epoch: int = 1,
) -> str:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    issued = int(now if now is not None else time.time())
    payload = {"uid": user_id, "iat": issued, "exp": issued + ttl_seconds, "ep": epoch}
    body = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = _b64url_encode(
        hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{body}.{signature}"


def verify_token(token: str, secret: str, now: float | None = None) -> dict:
    """Verify signature and expiry; return the payload dict."""
    if not isinstance(token, str) or "." not in token:
        raise TokenError("malformed token")
    try:
        body, signature = token.rsplit(".", 1)
        body_bytes = body.encode("ascii")
        signature_bytes = signature.encode("ascii")
    except (ValueError, UnicodeEncodeError) as exc:
        raise TokenError("malformed token") from exc
    expected = _b64url_encode(
        hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).digest()
    )
    if not hmac.compare_digest(signature_bytes, expected.encode("ascii")):
        raise TokenError("bad signature")
    try:
        payload = json.loads(_b64url_decode(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError("malformed payload") from exc
    if not isinstance(payload, dict) or "uid" not in payload or "exp" not in payload:
        raise TokenError("malformed payload")
    exp = payload["exp"]
    # A non-numeric exp ("tomorrow", null, ...) would raise TypeError on the
    # comparison below and surface as a 500; bool is rejected explicitly even
    # though it IS an int — JSON true is not a timestamp. Non-finite floats
    # parse fine in Python's json (NaN/Infinity literals) and break the
    # expiry check: ``nan <= now`` is False, so a NaN exp would never expire.
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
        raise TokenError("malformed payload")
    if exp <= (now if now is not None else time.time()):
        raise TokenError("token expired")
    return payload
