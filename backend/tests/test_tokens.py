"""HMAC session tokens."""

from __future__ import annotations

import pytest

from app.security import tokens

SECRET = "unit-test-secret"


def test_roundtrip():
    token = tokens.issue_token("user-1", SECRET, ttl_seconds=60)
    payload = tokens.verify_token(token, SECRET)
    assert payload["uid"] == "user-1"
    assert payload["exp"] - payload["iat"] == 60


def test_expiry_enforced():
    token = tokens.issue_token("user-1", SECRET, ttl_seconds=60, now=1_000.0)
    tokens.verify_token(token, SECRET, now=1_059.0)  # still valid
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(token, SECRET, now=1_060.0)  # exactly at expiry
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(token, SECRET, now=1_061.0)


def test_wrong_secret_rejected():
    token = tokens.issue_token("user-1", SECRET, 60)
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(token, "other-secret")


def test_tampered_body_rejected():
    token = tokens.issue_token("user-1", SECRET, 60)
    body, sig = token.rsplit(".", 1)
    # Flip a character inside the payload body.
    flipped = ("W" if body[0] != "W" else "X") + body[1:]
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(f"{flipped}.{sig}", SECRET)


def test_tampered_signature_rejected():
    token = tokens.issue_token("user-1", SECRET, 60)
    body, sig = token.rsplit(".", 1)
    forged = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(f"{body}.{forged}", SECRET)


def test_malformed_tokens_rejected():
    for bad in ("", "no-dot-here", "a.b.c.d", "!!!.???", "====.===="):
        with pytest.raises(tokens.TokenError):
            tokens.verify_token(bad, SECRET)


def test_payload_must_have_uid_and_exp():
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    payload = b64(json.dumps({"something": "else"}).encode())
    sig = b64(hmac_mod.new(SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(f"{payload}.{sig}", SECRET)


def test_non_numeric_exp_rejected_not_500():
    """A well-signed token whose exp is not a number must raise TokenError,
    never the TypeError an unchecked ``exp <= now`` comparison throws."""
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def signed(payload_dict: dict) -> str:
        body = b64(json.dumps(payload_dict).encode())
        sig = b64(hmac_mod.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    for bad_exp in ("tomorrow", "9999999999", None, [1], {"t": 1}, True):
        with pytest.raises(tokens.TokenError):
            tokens.verify_token(signed({"uid": "u", "exp": bad_exp}), SECRET)


def test_non_finite_exp_rejected():
    """Python's json.loads accepts NaN/Infinity literals, and ``nan <= now``
    is False — a well-signed NaN-exp token would never expire without an
    explicit finiteness check."""
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def signed(payload_dict: dict) -> str:
        body = b64(json.dumps(payload_dict).encode())
        sig = b64(hmac_mod.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    for bad_exp in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(tokens.TokenError):
            tokens.verify_token(signed({"uid": "u", "exp": bad_exp}), SECRET)


def test_huge_integer_exp_rejected_not_overflow():
    """H-17 (2026-09-20): JSON integers are arbitrary precision, so
    json.loads yields exp = 10**400 happily — and math.isfinite() raises
    OverflowError converting it to float, which used to escape as a 500 from
    a module whose contract is TokenError-or-payload, never an exception."""
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    # json.dumps refuses inf/out-of-range floats but serializes huge ints
    # losslessly — exactly the attacker shape.
    for bad_exp in (10**400, -(10**400), 2**2048):
        payload = json.dumps({"uid": "u", "exp": bad_exp}, separators=(",", ":")).encode()
        body = b64(payload)
        sig = b64(hmac_mod.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
        with pytest.raises(tokens.TokenError):
            tokens.verify_token(f"{body}.{sig}", SECRET)


def test_absurd_but_finite_exp_rejected_by_bound():
    """exp far past year 3000 is finite yet indefensible (a signed "never
    expires" token); MAX_EXP_EPOCH bounds it to malformed."""
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def signed(exp) -> str:
        payload = json.dumps({"uid": "u", "exp": exp}, separators=(",", ":")).encode()
        body = b64(payload)
        sig = b64(hmac_mod.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    # float('inf') is handled by the finiteness check; 1e18 is a plain
    # finite float ~year 33,586,969 — still far beyond the bound.
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(signed(tokens.MAX_EXP_EPOCH + 1), SECRET)
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(signed(1e18), SECRET)
    # Exactly at the bound is a normal (far-future but parseable) token.
    assert tokens.verify_token(signed(tokens.MAX_EXP_EPOCH), SECRET)["uid"] == "u"


def test_payload_field_types_hardened():
    """L-2: uid must be a non-empty str (it is used as a DB key downstream),
    ep must be an int or None — JSON ``true`` compares equal to epoch 1 in
    deps.require_user, so a bool ep must not survive verification."""
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def signed(payload_dict: dict) -> str:
        body = b64(json.dumps(payload_dict).encode())
        sig = b64(hmac_mod.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    for bad_uid in ("", 42, 1.5, True, None, [], {}, ["user-1"]):
        with pytest.raises(tokens.TokenError):
            tokens.verify_token(signed({"uid": bad_uid, "exp": 9999999999}), SECRET)
    for bad_ep in (True, False, "1", 1.5, [], {}):
        with pytest.raises(tokens.TokenError):
            tokens.verify_token(signed({"uid": "u", "exp": 9999999999, "ep": bad_ep}), SECRET)
    # The shapes the issuer actually produces stay valid.
    assert tokens.verify_token(signed({"uid": "u", "exp": 9999999999, "ep": 3}), SECRET)["ep"] == 3
    # ep absent (legacy) and ep null both parse; the epoch comparison in
    # deps.require_user fails closed for null.
    assert "ep" not in tokens.verify_token(signed({"uid": "u", "exp": 9999999999}), SECRET)
    assert (
        tokens.verify_token(signed({"uid": "u", "exp": 9999999999, "ep": None}), SECRET)["ep"]
        is None
    )


def test_issued_tokens_carry_hardened_shapes():
    """The issuer's own tokens must always satisfy the verifier's hardened
    field shapes (uid non-empty str, ep int, exp inside the bound)."""
    token = tokens.issue_token("user-1", SECRET, ttl_seconds=60, epoch=7)
    payload = tokens.verify_token(token, SECRET)
    assert isinstance(payload["uid"], str) and payload["uid"]
    assert isinstance(payload["ep"], int) and not isinstance(payload["ep"], bool)
    assert payload["exp"] <= tokens.MAX_EXP_EPOCH
