"""AES-256-GCM envelope encryption.

Wire format:  nonce(12) || ciphertext || tag(16)

The AAD (additional authenticated data) binds every blob to its owner and
purpose — user_id, entry id and context — so a malicious or buggy server
cannot move a blob between entries or users without the client detecting
tampering at decryption time.

This module is the server-side *reference implementation* of the envelope
format; the mobile client implements the identical format (see
mobile/src/crypto/ and shared/vectors.json for cross-platform test vectors).
"""

from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
MIN_BLOB_SIZE = NONCE_SIZE + TAG_SIZE


class CryptoError(Exception):
    """Base class for envelope crypto failures."""


class TamperError(CryptoError):
    """Raised when a blob fails GCM authentication (wrong key, AAD, or bits)."""


def generate_key() -> bytes:
    """Generate a fresh 256-bit key (testing / enclave bootstrap only)."""
    return os.urandom(KEY_SIZE)


def encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Encrypt and authenticate *plaintext* under *key*, returning the envelope.

    *nonce* is a test seam: when omitted (every production call) a fresh
    random nonce is generated; when given it must be exactly NONCE_SIZE bytes
    and is used verbatim (shared/vectors.json pins fixed-nonce output).
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    elif len(nonce) != NONCE_SIZE:
        raise CryptoError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt(key: bytes | bytearray, blob: bytes, aad: bytes | None = None) -> bytes:
    """Verify and decrypt an envelope; raises TamperError on any mismatch.

    ``key`` is any bytes-like: AESGCM accepts bytearray, and the enclave
    deliberately passes ONE reusable mutable buffer (zeroized after the
    batch) instead of an immutable per-call copy that would linger until GC.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(blob) < MIN_BLOB_SIZE:
        raise TamperError(f"blob too short: {len(blob)} bytes")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise TamperError("authentication failed") from exc


def build_aad(*parts: str) -> bytes:
    """Canonical unambiguous AAD: JSON array of the binding parts.

    ``ensure_ascii=True`` (explicit: it is a cross-platform contract, not a
    style choice) means every non-ASCII code unit is escaped as \\uXXXX, so
    the AAD bytes are pure ASCII regardless of the parts' content. The mobile
    client implements the identical escaping (see mobile/src/crypto/aad.ts);
    shared/vectors.json pins the behavior with non-ASCII vectors.
    """
    return json.dumps(list(parts), separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class SecureBuffer:
    """Best-effort zeroizable container for plaintext inside the enclave.

    Python cannot guarantee memory erasure (immutable copies may exist), but
    every buffer the enclave owns is passed through zeroize() on exit so the
    observable plaintext lifetime is bounded to the processing window.
    """

    __slots__ = ("_buf",)

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._buf = bytearray(data)

    @property
    def data(self) -> bytearray:
        return self._buf

    def zeroize(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0

    def is_zeroized(self) -> bool:
        return all(b == 0 for b in self._buf)

    def __len__(self) -> int:
        return len(self._buf)
