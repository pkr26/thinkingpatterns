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
