"""Stateless HMAC-signed session tokens (no server-side session state).

Format:  base64url(payload_json) . base64url(hmac_sha256(secret, body))

2026-09-26 remediation wave — payload now carries three more claims:

  * ``jti`` — 128-bit random id. Single-token logout records it in an
    in-process revocation store (ttl = the token's own expiry) checked in
    deps.require_user; the account-wide epoch bump remains the global
    revocation primitive (credential rotation, deletion). Legacy tokens
    without a jti are accepted but only ever revocable account-wide —
    the logout path falls back to the epoch bump for them.
  * ``purpose`` — "patient" | "therapist", pinned at issue time from the
    account role. The database role remains the authorization authority
    (require_regular_user / require_therapist); the claim makes the token
    type explicit on the wire so future surfaces can branch without a DB
    round-trip and a mis-issued token is detectable in logs.
  * ``ksv`` — key-scheme version of the signing secret configuration
    (1 = legacy/derived MINDPATTERN_TOKEN_SECRET, 2 = explicit
    MINDPATTERN_AUTH_TOKEN_SECRET). Rotating to a split secret invalidates
    cleanly EVEN IF an operator sets the same bytes: the version check in
    deps fails every token minted under the previous scheme.

Constant-time discipline (documented where it lives): the SIGNATURE check
below is ``hmac.compare_digest`` over the encoded MAC — the one comparison
an attacker can probe byte-by-byte. The remaining payload fields need no
constant-time handling: ``uid`` is used as a database key (an index lookup,
not a string comparison), ``exp``/``ep``/``ksv`` are numeric comparisons
against server-side values whose guess space is not reduced by timing, and
``jti`` is a 128-bit random value looked up in a hash map (probe timing
reveals only membership, which the 401 answer reveals anyway).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time

# Upper bound on a plausible `exp` claim: 2263-01-01T00:00:00Z. JSON ints are
# arbitrary precision, so without a bound a forged-but-signed exp of 10**400
# is "finite" as far as Python is concerned — and `math.isfinite` itself
# raises OverflowError converting it to float (H-17: that raised a 500 out of
# a module whose contract is never-500). No legitimate token lives 237 years.
MAX_EXP_EPOCH = 32_503_680_000

PURPOSE_PATIENT = "patient"
PURPOSE_THERAPIST = "therapist"
#: Token purpose values on the wire. Deliberately closed: "refresh" is NOT
#: added (the 24h TTL stands; per-token logout makes short sessions safe to
#: keep without a refresh-token lifecycle).
KNOWN_PURPOSES = frozenset({PURPOSE_PATIENT, PURPOSE_THERAPIST})

#: jti shape: 16 random bytes, hex-encoded (32 chars). 128 bits keeps a
#: revocation-table guess (or collision) beyond any practical budget.
JTI_HEX_CHARS = 32


class TokenError(Exception):
    """Raised when a token is malformed, forged, or expired."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def new_jti() -> str:
    """Fresh 128-bit token id (hex)."""
    return secrets.token_hex(16)


def issue_token(
    user_id: str,
    secret: str,
    ttl_seconds: int,
    now: float | None = None,
    epoch: int = 1,
    purpose: str = PURPOSE_PATIENT,
    ksv: int = 1,
    jti: str | None = None,
) -> str:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    if purpose not in KNOWN_PURPOSES:
        raise ValueError(f"purpose must be one of {sorted(KNOWN_PURPOSES)}")
    issued = int(now if now is not None else time.time())
    payload = {
        "uid": user_id,
        "iat": issued,
        "exp": issued + ttl_seconds,
        "ep": epoch,
        # Every new token is individually revocable and scheme-stamped.
        # jti defaults fresh-random per call; the injectable parameter is
        # for deterministic tests only (never a request path).
        "jti": jti if jti is not None else new_jti(),
        "purpose": purpose,
        "ksv": ksv,
    }
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
    expected = _b64url_encode(hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).digest())
    # The signature comparison is the timing-sensitive one: compare_digest,
    # never ==, so a forger cannot recover the MAC byte-by-byte.
    if not hmac.compare_digest(signature_bytes, expected.encode("ascii")):
        raise TokenError("bad signature")
    try:
        payload = json.loads(_b64url_decode(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError("malformed payload") from exc
    if not isinstance(payload, dict) or "uid" not in payload or "exp" not in payload:
        raise TokenError("malformed payload")
    # Field-shape hardening (reachable only with the signing secret, but the
    # module's contract is TokenError-or-payload, never a 500): `uid` is used
    # directly as a SQLAlchemy key downstream, so any JSON value that is not
    # a non-empty string is rejected here. `ep` feeds `payload.get("ep", 1)`
    # compared against the account epoch in deps.require_user — JSON `true`
    # compares equal to integer 1, so bools are rejected explicitly.
    uid = payload["uid"]
    if not isinstance(uid, str) or not uid:
        raise TokenError("malformed payload")
    if "ep" in payload:
        ep = payload["ep"]
        if ep is not None and (isinstance(ep, bool) or not isinstance(ep, int)):
            raise TokenError("malformed payload")
    exp = payload["exp"]
    # A non-numeric exp ("tomorrow", null, ...) would raise TypeError on the
    # comparison below and surface as a 500; bool is rejected explicitly even
    # though it IS an int — JSON true is not a timestamp. Non-finite floats
    # parse fine in Python's json (NaN/Infinity literals) and break the
    # expiry check: ``nan <= now`` is False, so a NaN exp would never expire.
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise TokenError("malformed payload")
    # Python ints are arbitrary precision: json.loads happily yields exp =
    # 10**400, and math.isfinite() converts to float — which OVERFLOWS and
    # raises (the 2026-09 NaN/Infinity round left exactly this hole open).
    # An oversized exp is malformed, not an exception to propagate.
    try:
        finite = math.isfinite(exp)
    except OverflowError:
        finite = False
    if not finite or exp > MAX_EXP_EPOCH:
        raise TokenError("malformed payload")
    # jti / purpose / ksv: shape-only here — the revocation-store lookup and
    # the ksv equality live in deps (they need app state), and an unknown
    # purpose must fail closed at the same boundary. A missing jti or
    # purpose is LEGACY (pre-2026-09-26 tokens): accepted for signature
    # compatibility, handled defensively downstream.
    if "jti" in payload:
        jti = payload["jti"]
        if (
            not isinstance(jti, str)
            or len(jti) != JTI_HEX_CHARS
            or any(c not in "0123456789abcdef" for c in jti)
        ):
            raise TokenError("malformed payload")
    if "purpose" in payload:
        if payload["purpose"] not in KNOWN_PURPOSES:
            raise TokenError("malformed payload")
    if "ksv" in payload:
        ksv = payload["ksv"]
        if isinstance(ksv, bool) or not isinstance(ksv, int) or ksv < 1:
            raise TokenError("malformed payload")
    if exp <= (now if now is not None else time.time()):
        raise TokenError("token expired")
    return payload
