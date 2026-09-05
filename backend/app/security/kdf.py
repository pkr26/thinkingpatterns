"""Client-side key schedule (reference implementation).

    master_key = PBKDF2-HMAC-SHA256(password, salt, 600_000)
    auth_key   = HKDF-SHA256(master_key, info="mindpattern/auth/v1")   # sent to server
    data_key   = HKDF-SHA256(master_key, info="mindpattern/data/v1")   # NEVER sent,
                                                       # except into a processing session

The server stores scrypt(auth_key) and can therefore verify logins without
ever holding a key that decrypts entries. The mobile client derives the same
three values locally (shared/vectors.json pins the exact bytes on both
platforms).
"""

from __future__ import annotations

import hashlib
import hmac

KDF_ITERATIONS = 600_000
AUTH_INFO = b"mindpattern/auth/v1"
DATA_INFO = b"mindpattern/data/v1"
MIN_SALT_SIZE = 8


def derive_master_key(
    password: str | bytes, salt: bytes, iterations: int = KDF_ITERATIONS
) -> bytes:
    """Derive the 256-bit master key from the user's password."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if len(salt) < MIN_SALT_SIZE:
        raise ValueError(f"salt must be at least {MIN_SALT_SIZE} bytes")
    if iterations < 1:
        raise ValueError("iterations must be positive")
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations)


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) extract-and-expand."""
    if length < 1 or length > 255 * 32:
        raise ValueError("invalid HKDF output length")
    salt = salt if salt else b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_auth_key(master_key: bytes) -> bytes:
    """Key whose scrypt hash the server stores for login verification."""
    return hkdf_sha256(master_key, None, AUTH_INFO)


def derive_data_key(master_key: bytes) -> bytes:
    """Key that encrypts entries, insights and questions."""
    return hkdf_sha256(master_key, None, DATA_INFO)
