"""RFC 6238 TOTP for optional therapist second-factor login (delivered
2026-09-22; the 2026-09-21 audit's C-2/F-4 "optional TOTP" item, previously
a documented deferral in SECURITY_RESIDUALS.md).

Deliberately dependency-free: HMAC-SHA1 over a 30-second timestep with six
digits is the authenticator-app contract (Google Authenticator, Aegis,
1Password, ...). Anything more exotic would silently exclude the exact
population a second factor is for.

The shared secret is stored WRAPPED at rest (AES-256-GCM under an HKDF
subkey of the server's ``token_secret``): a stolen database dump must not
turn the second factor into a field in a SELECT. The wrap is domain-
separated from token signing and from the decoy-salt subkey. Rotation of
``token_secret`` would invalidate wrapped secrets — the same documented
caveat as the decoy salts (see SECURITY_RESIDUALS.md); if that rotation is
ever exercised, operators must also clear ``users.totp_*``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import hkdf_sha256

# RFC 6238 parameters — the authenticator-app contract; do not vary.
STEP_SECONDS = 30
DIGITS = 6
SECRET_BYTES = 20  # 160 bits, the RFC-recommended size
#: Accept codes from the previous, current, and next timestep: one
#: authenticator clock skews freely; more drift than that is a wrong code.
ALLOWED_DRIFT = 1

WRAP_INFO = b"mindpattern/totp-at-rest/v1"
WRAP_PREFIX = "v1:"


def generate_secret() -> tuple[bytes, str]:
    """A fresh secret: raw bytes plus the base32 form authenticators take."""
    raw = secrets.token_bytes(SECRET_BYTES)
    return raw, base64.b32encode(raw).decode("ascii").rstrip("=")


def _code_for_counter(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**DIGITS)
    return f"{value:0{DIGITS}d}"


def verify_code(
    secret: bytes, code: str, *, at: float | None = None, drift: int = ALLOWED_DRIFT
) -> int | None:
    """Return the matched timestep counter, or None for a wrong code.

    The caller persists the matched counter and must reject any later code
    whose counter is not strictly greater — a valid code is a bearer proof
    and must not be replayable inside the drift window.
    """
    if at is None:
        at = time.time()
    normalized = code.strip()
    if len(normalized) != DIGITS or not normalized.isdigit():
        return None
    current = int(at // STEP_SECONDS)
    for candidate in range(current - drift, current + drift + 1):
        expected = _code_for_counter(secret, candidate)
        if hmac.compare_digest(normalized, expected):
            return candidate
    return None


def otpauth_uri(secret_b32: str, username: str, issuer: str = "MindPattern") -> str:
    """The manual-enrollment URI (no QR dependency — the portal renders the
    secret and this URI as copyable text)."""
    from urllib.parse import quote

    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )


def _server_key(token_secret: str) -> bytes:
    return hkdf_sha256(token_secret.encode("utf-8"), None, WRAP_INFO)


def wrap_secret(secret: bytes, token_secret: str) -> str:
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(_server_key(token_secret)).encrypt(nonce, secret, b"totp")
    return WRAP_PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def unwrap_secret(blob: str | None, token_secret: str) -> bytes | None:
    """None for absent/garbage — callers decide how to fail closed."""
    if not blob or not blob.startswith(WRAP_PREFIX):
        return None
    try:
        raw = base64.b64decode(blob[len(WRAP_PREFIX) :], validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 12 + 16:  # nonce + minimum GCM tag
        return None
    try:
        return AESGCM(_server_key(token_secret)).decrypt(raw[:12], raw[12:], b"totp")
    except Exception:  # noqa: BLE001 - any AEAD failure means "not the key"
        return None
