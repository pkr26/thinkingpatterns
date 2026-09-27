"""RFC 6238 TOTP for optional therapist second-factor login (delivered
2026-09-22; the 2026-09-21 audit's C-2/F-4 "optional TOTP" item, previously
a documented deferral in SECURITY_RESIDUALS.md).

Deliberately dependency-free: HMAC-SHA1 over a 30-second timestep with six
digits is the authenticator-app contract (Google Authenticator, Aegis,
1Password, ...). Anything more exotic would silently exclude the exact
population a second factor is for.

The shared secret is stored WRAPPED at rest (AES-256-GCM under an HKDF
subkey of the server's TOTP-wrap secret — ``Settings.totp_wrap_secret``
since the 2026-09-26 purpose split: explicit MINDPATTERN_TOTP_WRAP_SECRET,
else the legacy token secret, so existing wrapped blobs stay valid): a
stolen database dump must not turn the second factor into a field in a
SELECT. The wrap is domain-separated from token signing and from the
decoy-salt subkey. Rotation of the wrap secret would invalidate wrapped
secrets — the same documented caveat as the decoy salts (see
SECURITY_RESIDUALS.md); if that rotation is ever exercised, operators
must also clear ``users.totp_*`` AND the ``totp_backup_codes`` table
(recovery-code digests key off the same secret; a lost-authenticator
clear must drop both, which POST /account/totp/disable already does
in-transaction).
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
#: 2026-09-26 remediation (LOW e): the accepted drift window is now the
#: previous timestep and the current one (-1..0) — a FUTURE code is no
#: longer accepted. Rationale: accepting +1 let a code live up to 90
#: seconds and, more importantly, made an attacker's observed code usable
#: BEFORE the user's own clock reaches it; the strictly-monotonic replay
#: fence (totp_last_counter, the atomic conditional UPDATE at login)
#: already compensates for the loss — the previous timestep stays
#: accepted, so an honest authenticator with modest clock skew still
#: logs in first try. ``drift`` therefore means "steps INTO THE PAST
#: accepted"; the verify window is [current - drift, current].
ALLOWED_DRIFT = 1

WRAP_INFO = b"mindpattern/totp-at-rest/v1"
WRAP_PREFIX = "v1:"

# Recovery codes (2026-09-26 pentest S-3): generated at enable time from
# the pairing alphabet (unambiguous, human-transcribable) at 10 chars ≈
# 49.1 bits — unreachable inside the TOTP failure bucket's budget. Stored
# as HMAC digests only (see sharing.backup_code_digest); shown to the
# therapist exactly once at enrollment.
from .sharing import PAIRING_ALPHABET as _CODE_ALPHABET  # noqa: E402

BACKUP_CODE_COUNT = 8
BACKUP_CODE_CHARS = 10


def generate_backup_code() -> str:
    """One recovery code: rejection-sampled from the pairing alphabet so
    every symbol stays equally likely (same modulo-bias reclaim as
    generate_pairing_code; the loop is bounded by fresh os.urandom)."""
    import os

    n = len(_CODE_ALPHABET)
    limit = 256 - (256 % n)
    chars: list[str] = []
    while len(chars) < BACKUP_CODE_CHARS:
        for byte in os.urandom(BACKUP_CODE_CHARS * 2):
            if byte < limit:
                chars.append(_CODE_ALPHABET[byte % n])
                if len(chars) == BACKUP_CODE_CHARS:
                    break
    return "".join(chars)


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
    # Past-and-current only (see ALLOWED_DRIFT): the upper bound is the
    # CURRENT timestep, never current + drift.
    for candidate in range(current - drift, current + 1):
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
